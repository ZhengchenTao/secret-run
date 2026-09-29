using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace SecretsWeb.Audit;

/// <summary>One audit line. The structure has no "value" field — a value cannot end up in here.</summary>
public sealed record AuditRecord
{
    [JsonPropertyName("ts")] public required string Timestamp { get; init; }
    [JsonPropertyName("event")] public required string Event { get; init; }
    [JsonPropertyName("sub")] public string? Subject { get; init; }
    [JsonPropertyName("path")] public string? EntryPath { get; init; }
    [JsonPropertyName("field")] public string? Field { get; init; }
    [JsonPropertyName("action")] public string? Action { get; init; }
    [JsonPropertyName("result")] public string? Result { get; init; }
    [JsonPropertyName("reason")] public string? Reason { get; init; }

    /// <summary>How many lines of the same kind were suppressed (not written) by rate limiting.</summary>
    [JsonPropertyName("suppressed_before")] public int? SuppressedBefore { get; init; }

    /// <summary>
    /// For reference only. Behind a reverse proxy this is the proxy's address unless <c>Network:KnownProxies</c> /
    /// <c>Network:KnownNetworks</c> is configured; and anything running on the host next to the proxy can connect directly.
    /// </summary>
    [JsonPropertyName("ip")] public string? RemoteIp { get; init; }
}

/// <summary>Audit write failed (callers must refuse to return plaintext). A rotation failure does not count, see <see cref="AuditLog"/>.</summary>
public sealed class AuditWriteException(string message, Exception inner) : Exception(message, inner);

public interface IAuditLog
{
    /// <summary>Write one line; on failure throws <see cref="AuditWriteException"/> (callers then refuse to return plaintext — fail closed).</summary>
    void Write(AuditRecord record);
}

/// <summary>
/// JSONL audit with size-based rotation: after a line is written, if the file exceeds <c>Audit:MaxBytes</c> it is rotated
/// into <c>audit.log.1 … .N</c> (keeping <c>Audit:KeepFiles</c>).
/// **A rotation failure is only logged, never thrown**: rotation has nothing to do with whether this write succeeded, and
/// throwing would turn the decrypt path into "can't write → refuse" even when the disk isn't full.
/// Only a write that really fails throws <see cref="AuditWriteException"/>. New files are explicitly set to 0600 on POSIX.
/// </summary>
public sealed class AuditLog(IOptions<AuditOptions> options, ILogger<AuditLog> logger) : IAuditLog
{
    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly object _gate = new();
    private readonly AuditOptions _o = options.Value;

    public void Write(AuditRecord record)
    {
        var line = JsonSerializer.Serialize(record, Json) + "\n";
        lock (_gate)
        {
            long length;
            try
            {
                length = Append(line);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                // A full /data and similar: the one thing that can help is rotation (dropping the oldest file), so rotate and retry
                // once — otherwise fail-closed would lock the decrypt path forever.
                logger.LogWarning("Audit write failed ({Type}); rotating and retrying", ex.GetType().Name);
                TryRotate();
                try
                {
                    length = Append(line);
                }
                catch (Exception retry) when (retry is IOException or UnauthorizedAccessException or NotSupportedException)
                {
                    throw new AuditWriteException("Audit log write failed (still failing after rotating and retrying)", retry);
                }
            }

            if (_o.MaxBytes > 0 && length >= _o.MaxBytes) TryRotate();
        }
    }

    private long Append(string line)
    {
        var dir = Path.GetDirectoryName(_o.Path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        using var fs = new FileStream(_o.Path, FileMode.Append, FileAccess.Write, FileShare.Read);
        TrySetOwnerOnly(_o.Path); // set on creation, and tighten an existing file too (e.g. one that used to be 644)
        fs.Write(Encoding.UTF8.GetBytes(line));
        fs.Flush(flushToDisk: true);
        return fs.Length;
    }

    /// <summary>audit.log.(N-1) → .N, audit.log → .1, the oldest is deleted. Failures are only logged.</summary>
    private void TryRotate()
    {
        try
        {
            var keep = Math.Max(1, _o.KeepFiles);
            var oldest = $"{_o.Path}.{keep}";
            if (File.Exists(oldest)) File.Delete(oldest);
            for (var i = keep - 1; i >= 1; i--)
            {
                var from = $"{_o.Path}.{i}";
                if (File.Exists(from)) File.Move(from, $"{_o.Path}.{i + 1}", overwrite: true);
            }
            File.Move(_o.Path, $"{_o.Path}.1", overwrite: true);
            TrySetOwnerOnly($"{_o.Path}.1");
            logger.LogInformation("Audit log rotated (keeping {Keep} files)", keep);
        }
        catch (Exception ex)
        {
            logger.LogError("Audit log rotation failed (the write itself succeeded): {Type} {Msg}", ex.GetType().Name, ex.Message);
        }
    }

    private void TrySetOwnerOnly(string path)
    {
        if (OperatingSystem.IsWindows()) return; // on Windows the directory ACL decides; the container is POSIX
        const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        try
        {
            if (File.GetUnixFileMode(path) == ownerOnly) return;
            File.SetUnixFileMode(path, ownerOnly);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning("Setting audit log permissions failed: {Type}", ex.GetType().Name);
        }
    }

    public static AuditRecord For(HttpContext ctx, string @event, string? sub = null) => new()
    {
        Timestamp = DateTimeOffset.UtcNow.ToString("O"),
        Event = @event,
        Subject = sub ?? ctx.User.FindFirst("sub")?.Value,
        RemoteIp = ctx.Connection.RemoteIpAddress?.ToString(),
    };
}
