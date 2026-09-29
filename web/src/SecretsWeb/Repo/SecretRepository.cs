using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SecretsWeb.Format;

namespace SecretsWeb.Repo;

public sealed class RepoUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>View of the repo at one commit. Entry reads are pinned to this commit, so HEAD can't move between reading the catalog and reading ciphertext.</summary>
public sealed record RepoSnapshot(string Commit, Catalog Catalog, Recipients Recipients, StoreConsistency Consistency);

/// <summary>Lightweight catalog / store / lock consistency: only counts and booleans, no names (used by /health).</summary>
public sealed record StoreConsistency(int CatalogEntries, int StoreFiles, int? LockLines, bool Consistent);

public interface ISecretRepository
{
    Task<RepoSnapshot> GetSnapshotAsync(CancellationToken ct = default);

    /// <summary>Read ciphertext → check path and header → age decrypt; plaintext only in memory. Beyond <paramref name="maxPlaintext"/> throws <see cref="PlaintextTooLargeException"/>.</summary>
    Task<byte[]> DecryptAsync(RepoSnapshot snapshot, CatalogEntry entry, int maxPlaintext, CancellationToken ct = default);
}

public sealed class PlaintextTooLargeException() : Exception("Plaintext exceeds the size limit");

public sealed class SecretRepository(IOptions<RepoOptions> options, ILogger<SecretRepository> logger) : ISecretRepository
{
    private static readonly Regex CommitId = new("^[0-9a-f]{40}([0-9a-f]{24})?\\z", RegexOptions.CultureInvariant);
    private const int TomlMaxBytes = 4 * 1024 * 1024;

    private readonly RepoOptions _o = options.Value;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private RepoSnapshot? _cached;

    private TimeSpan Timeout => TimeSpan.FromSeconds(_o.CommandTimeoutSeconds);

    private IEnumerable<string> GitArgs(params string[] rest) =>
        // The read-only bare repo is owned by a different user than the container → dubious ownership; allow it for this command only
        // (see ProcessRunner.ForcedVars for why the global config file is what actually makes this work).
        new[] { "-c", "safe.directory=*", "-c", "core.fsmonitor=false", "--git-dir", _o.GitDir }.Concat(rest);

    public async Task<string> GetHeadAsync(CancellationToken ct = default)
    {
        var r = await RunGit(["rev-parse", "--verify", "HEAD^{commit}"], 1024, ct);
        var head = System.Text.Encoding.ASCII.GetString(r).Trim();
        if (!CommitId.IsMatch(head)) throw new RepoUnavailableException("HEAD is not a valid commit id");
        return head;
    }

    public async Task<RepoSnapshot> GetSnapshotAsync(CancellationToken ct = default)
    {
        var head = await GetHeadAsync(ct);
        var cached = _cached;
        if (cached is not null && cached.Commit == head) return cached;

        await _lock.WaitAsync(ct);
        try
        {
            if (_cached is not null && _cached.Commit == head) return _cached;
            var recipientsText = RestrictedToml.DecodeUtf8Strict(await ReadBlob(head, "recipients.toml", TomlMaxBytes, ct), "recipients.toml");
            var catalogText = RestrictedToml.DecodeUtf8Strict(await ReadBlob(head, "catalog.toml", TomlMaxBytes, ct), "catalog.toml");
            var recipients = Recipients.Parse(recipientsText);
            var catalog = Catalog.Parse(catalogText, recipients);
            foreach (var e in recipients.Errors) logger.LogWarning("{Err}", e);
            foreach (var w in catalog.Warnings) logger.LogWarning("catalog.toml: {Warn}", w);
            foreach (var e in catalog.Entries.Where(e => !e.IsValid))
                logger.LogWarning("catalog.toml: entry starting at line {Line} is unavailable: {Errors}", e.Line, string.Join("; ", e.Errors));
            var consistency = await CheckConsistency(head, catalog, ct);
            _cached = new RepoSnapshot(head, catalog, recipients, consistency);
            logger.LogInformation("Catalog loaded: commit {Commit}, {Count} entries ({Invalid} unavailable), consistent {Consistent}",
                head, catalog.Entries.Count, catalog.InvalidCount, consistency.Consistent);
            return _cached;
        }
        finally
        {
            _lock.Release();
        }
    }

    private const string LockPath = "store/.recipients.lock";
    private const string LockHeader = "# secret recipients lock v1";

    private async Task<StoreConsistency> CheckConsistency(string commit, Catalog catalog, CancellationToken ct)
    {
        var listing = System.Text.Encoding.UTF8.GetString(
            await RunGit(["ls-tree", "-r", "-z", "--name-only", commit, "--", "store"], TomlMaxBytes, ct));
        var names = listing.Split('\0', StringSplitOptions.RemoveEmptyEntries);
        var storeFiles = names.Where(n => n.EndsWith(".age", StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal);

        HashSet<string>? lockPaths = null;
        var lockOk = false;
        if (names.Contains(LockPath, StringComparer.Ordinal))
        {
            var text = System.Text.Encoding.UTF8.GetString(await ReadBlob(commit, LockPath, TomlMaxBytes, ct)).Replace("\r\n", "\n");
            lockPaths = new HashSet<string>(StringComparer.Ordinal);
            lockOk = text.EndsWith('\n');
            var lines = text.TrimEnd('\n').Split('\n');
            if (lines[0] != LockHeader) lockOk = false;
            foreach (var line in lines.Skip(1))
            {
                var cols = line.Split("  ");
                if (cols.Length != 3 || !lockPaths.Add(cols[2])) lockOk = false;
            }
        }

        var catalogPaths = catalog.Entries.Where(e => e.HasAddress).Select(e => e.StorePath).ToHashSet(StringComparer.Ordinal);
        var consistent = lockOk
                         && catalog.Entries.All(e => e.HasAddress)
                         && catalogPaths.Count == catalog.Entries.Count
                         && catalogPaths.SetEquals(storeFiles)
                         && lockPaths!.SetEquals(storeFiles);
        return new StoreConsistency(catalog.Entries.Count, storeFiles.Count, lockPaths?.Count, consistent);
    }

    public async Task<byte[]> DecryptAsync(RepoSnapshot snapshot, CatalogEntry entry, int maxPlaintext, CancellationToken ct = default)
    {
        var storePath = entry.StorePath;
        if (!StoreRules.IsValidStorePath(storePath)) throw new SecretFormatException("Invalid ciphertext path");

        // Ciphertext is slightly larger than plaintext (age header + a 16-byte tag per 64 KiB); leave plenty of headroom
        var maxCipher = maxPlaintext + maxPlaintext / 64 + 64 * 1024;
        var ciphertext = await ReadBlob(snapshot.Commit, storePath, maxCipher, ct);
        if (!StoreRules.HasAgeHeader(ciphertext)) throw new SecretFormatException("Ciphertext header is not age-encryption.org/v1");

        var r = await ProcessRunner.RunAsync(_o.AgePath, ["-d", "-i", _o.Identity], ciphertext, maxPlaintext, Timeout, ct);
        if (r.Truncated) throw new PlaintextTooLargeException();
        if (r.ExitCode != 0)
        {
            Array.Clear(r.Stdout);
            // age's stderr only has an error description, never plaintext
            logger.LogWarning("age decryption failed (exit code {Code}): {Err}", r.ExitCode, FirstLine(r.Stderr));
            throw new DecryptFailedException();
        }
        return r.Stdout;
    }

    private async Task<byte[]> ReadBlob(string commit, string path, int max, CancellationToken ct) =>
        await RunGit(["cat-file", "blob", $"{commit}:{path}"], max, ct);

    private async Task<byte[]> RunGit(string[] args, int max, CancellationToken ct)
    {
        ProcessResult r;
        try
        {
            r = await ProcessRunner.RunAsync(_o.GitPath, GitArgs(args), null, max, Timeout, ct);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or TimeoutException)
        {
            throw new RepoUnavailableException("git could not be run", ex);
        }
        if (r.Truncated) throw new RepoUnavailableException("git output exceeds the limit");
        if (r.ExitCode != 0)
        {
            logger.LogWarning("git {Cmd} failed (exit code {Code}): {Err}", args[0], r.ExitCode,
                args[0] == "cat-file" ? "(stderr contains the path, omitted)" : FirstLine(r.Stderr));
            throw new RepoUnavailableException($"git {args[0]} failed");
        }
        return r.Stdout;
    }

    private static string FirstLine(string s)
    {
        var line = s.Split('\n', 2)[0].Trim();
        return line.Length > 200 ? line[..200] : line;
    }
}

public sealed class DecryptFailedException() : Exception("Decryption failed");
