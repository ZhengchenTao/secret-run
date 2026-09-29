using System.Text;
using Microsoft.Extensions.Options;
using SecretsWeb.Audit;
using SecretsWeb.Format;
using SecretsWeb.Repo;
using SecretsWeb.Security;

namespace SecretsWeb.Services;

public enum EntryError { NotFound, WrongType, TooLarge, Invalid, Unavailable, RateLimited, BadRequest, Conflict, WriteFailed }

public sealed class EntryException(EntryError error, string message) : Exception(message)
{
    public EntryError Error { get; } = error;

    public int StatusCode => Error switch
    {
        EntryError.NotFound => StatusCodes.Status404NotFound,
        EntryError.WrongType => StatusCodes.Status400BadRequest,
        EntryError.TooLarge => StatusCodes.Status413PayloadTooLarge,
        EntryError.Invalid => StatusCodes.Status502BadGateway,
        EntryError.RateLimited => StatusCodes.Status429TooManyRequests,
        EntryError.BadRequest => StatusCodes.Status400BadRequest,
        EntryError.Conflict => StatusCodes.Status409Conflict,
        EntryError.WriteFailed => StatusCodes.Status500InternalServerError,
        _ => StatusCodes.Status503ServiceUnavailable,
    };
}

public sealed record FileView(bool IsText, string? Text, int Size);

/// <summary>
/// Every decryption goes through here: audit first (no plaintext is returned if the audit line can't be written), then the result.
/// Audit lines only carry sub / entry path / field name / action / source; structurally they cannot contain a value.
/// </summary>
public sealed class EntryService(
    ISecretRepository repo, IAuditLog audit, DecryptRateLimiter limiter, IOptions<RepoOptions> options, ILogger<EntryService> logger)
{
    private readonly RepoOptions _o = options.Value;

    /// <summary>Find an entry regardless of whether its metadata is valid (pages use it to show why an entry is unavailable).</summary>
    public async Task<(RepoSnapshot Snapshot, CatalogEntry Entry)> FindAnyAsync(string path, CancellationToken ct)
    {
        RepoSnapshot snap;
        try { snap = await repo.GetSnapshotAsync(ct); }
        catch (Exception ex) when (ex is RepoUnavailableException or SecretFormatException or TimeoutException)
        {
            logger.LogError("Repo not readable: {Msg}", ex.Message);
            throw new EntryException(EntryError.Unavailable, "The secrets repo is currently not readable");
        }
        var entry = snap.Catalog.Find(path) ?? throw new EntryException(EntryError.NotFound, "Entry not found");
        return (snap, entry);
    }

    /// <summary>Find an entry whose value may be read: invalid metadata is always an error (nothing is decrypted).</summary>
    public async Task<(RepoSnapshot Snapshot, CatalogEntry Entry)> FindAsync(string path, CancellationToken ct)
    {
        var (snap, entry) = await FindAnyAsync(path, ct);
        if (!entry.IsValid)
            throw new EntryException(EntryError.Invalid, "Invalid entry metadata: " + string.Join("; ", entry.Errors));
        return (snap, entry);
    }

    public async Task<string> GetFieldAsync(HttpContext http, string path, string field, string action, CancellationToken ct)
    {
        var (snap, entry) = await FindAsync(path, ct);
        if (entry.Type != "kv") throw new EntryException(EntryError.WrongType, "Not a kv entry");
        if (!entry.Fields.Contains(field, StringComparer.Ordinal)) throw new EntryException(EntryError.NotFound, "Field not found");

        var plain = await DecryptAudited(http, snap, entry, field, action, _o.FileMaxBytes, ct);
        try
        {
            IReadOnlyList<KeyValuePair<string, string>> kv;
            try { kv = KvParser.Parse(plain); }
            catch (SecretFormatException ex)
            {
                logger.LogError("Parsing a kv entry failed: {Msg}", ex.Message);
                throw new EntryException(EntryError.Invalid, "Entry content does not follow the kv format");
            }
            var keys = kv.Select(p => p.Key).ToHashSet(StringComparer.Ordinal);
            if (!keys.SetEquals(entry.Fields))
                throw new EntryException(EntryError.Invalid, "Fields in the ciphertext do not match the catalog");
            return kv.First(p => p.Key == field).Value;
        }
        finally
        {
            Array.Clear(plain);
        }
    }

    /// <summary>For "Load current content" on the edit page: the kv plaintext as-is (KEY=VALUE lines). Audited as a view as well.</summary>
    public async Task<string> GetKvTextAsync(HttpContext http, string path, CancellationToken ct)
    {
        var (snap, entry) = await FindAsync(path, ct);
        if (entry.Type != "kv") throw new EntryException(EntryError.WrongType, "Not a kv entry");
        var plain = await DecryptAudited(http, snap, entry, null, "view", _o.FileMaxBytes, ct);
        try
        {
            KvParser.Parse(plain); // validate first, so broken data never lands in the form
            return RestrictedToml.DecodeUtf8Strict(plain, "kv plaintext");
        }
        catch (SecretFormatException ex)
        {
            throw new EntryException(EntryError.Invalid, "Entry content does not follow the kv format: " + ex.Message);
        }
        finally
        {
            Array.Clear(plain);
        }
    }

    public async Task<string> GetDocAsync(HttpContext http, string path, CancellationToken ct)
    {
        var (snap, entry) = await FindAsync(path, ct);
        if (entry.Type != "doc") throw new EntryException(EntryError.WrongType, "Not a doc entry");
        var plain = await DecryptAudited(http, snap, entry, null, "view", _o.DocMaxBytes, ct);
        try
        {
            var text = RestrictedToml.DecodeUtf8Strict(plain, "doc");
            return text.Length > 0 && text[0] == '\uFEFF' ? text[1..] : text;
        }
        catch (SecretFormatException)
        {
            throw new EntryException(EntryError.Invalid, "doc entry is not valid UTF-8");
        }
        finally
        {
            Array.Clear(plain);
        }
    }

    public async Task<FileView> GetFileViewAsync(HttpContext http, string path, CancellationToken ct)
    {
        var (snap, entry) = await FindAsync(path, ct);
        if (entry.Type != "file") throw new EntryException(EntryError.WrongType, "Not a file entry");
        var plain = await DecryptAudited(http, snap, entry, null, "view", _o.FileMaxBytes, ct);
        try
        {
            if (plain.Length <= _o.FileTextMaxBytes && TryDecodeText(plain, out var text))
                return new FileView(true, text, plain.Length);
            return new FileView(false, null, plain.Length);
        }
        finally
        {
            Array.Clear(plain);
        }
    }

    /// <summary>Download: the caller wipes the returned bytes after writing them out.</summary>
    public async Task<(CatalogEntry Entry, byte[] Bytes)> DownloadAsync(HttpContext http, string path, CancellationToken ct)
    {
        var (snap, entry) = await FindAsync(path, ct);
        if (entry.Type != "file") throw new EntryException(EntryError.WrongType, "Not a file entry");
        return (entry, await DecryptAudited(http, snap, entry, null, "download", _o.FileMaxBytes, ct));
    }

    private async Task<byte[]> DecryptAudited(HttpContext http, RepoSnapshot snap, CatalogEntry entry, string? field, string action, int max, CancellationToken ct)
    {
        var rec = AuditLog.For(http, "decrypt") with { EntryPath = entry.Path, Field = field, Action = action };

        // Per-session decryption rate limit: damage control if a cookie is stolen (over the limit: no decryption, no audit entry line)
        if (!limiter.TryAcquire(DecryptRateLimiter.KeyFor(http)))
            throw new EntryException(EntryError.RateLimited, "Too many decryption requests; please try again later");

        byte[] plain;
        try
        {
            plain = await repo.DecryptAsync(snap, entry, max, ct);
        }
        catch (Exception ex) when (ex is SecretFormatException or DecryptFailedException or PlaintextTooLargeException or RepoUnavailableException or TimeoutException)
        {
            var (err, msg, reason) = ex switch
            {
                PlaintextTooLargeException => (EntryError.TooLarge, "Entry exceeds the size limit", "too_large"),
                SecretFormatException => (EntryError.Invalid, "Invalid ciphertext", "invalid_ciphertext"),
                DecryptFailedException => (EntryError.Invalid, "Decryption failed", "decrypt_failed"),
                _ => (EntryError.Unavailable, "The secrets repo is currently not readable", "unavailable"),
            };
            logger.LogError("Decryption failed: {Reason}", reason);
            TryWrite(rec with { Result = "error", Reason = reason });
            throw new EntryException(err, msg);
        }

        try
        {
            audit.Write(rec with { Result = "ok" });
        }
        catch (AuditWriteException ex)
        {
            Array.Clear(plain);
            logger.LogError("Audit write failed, refusing to return plaintext: {Type}", ex.InnerException?.GetType().Name ?? "unknown");
            throw new EntryException(EntryError.Unavailable, "The audit log is not writable; request refused");
        }
        limiter.RecordEntry(entry.Path!);
        return plain;
    }

    private void TryWrite(AuditRecord r)
    {
        try { audit.Write(r); } catch (Exception ex) { logger.LogError("Audit write failed: {Type}", ex.GetType().Name); }
    }

    private static bool TryDecodeText(byte[] bytes, out string text)
    {
        text = "";
        if (Array.IndexOf(bytes, (byte)0) >= 0) return false;
        try
        {
            text = new UTF8Encoding(false, true).GetString(bytes);
            if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..];
            return true;
        }
        catch (DecoderFallbackException) { return false; }
    }
}
