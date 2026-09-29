using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SecretsWeb.Format;

namespace SecretsWeb.Repo;

/// <summary>Write refused: callers map it to 4xx / 409 / 500.</summary>
public sealed class WriteRejectedException(WriteError error, string message) : Exception(message)
{
    public WriteError Error { get; } = error;
}

public enum WriteError
{
    /// <summary>Invalid user input (catalog rules, kv format, size).</summary>
    Invalid,
    /// <summary>Entry does not exist / already exists.</summary>
    Conflict,
    /// <summary>The repo itself is inconsistent and must be fixed with the CLI first.</summary>
    RepoInconsistent,
    /// <summary>Push keeps being rejected (someone else is writing at the same time).</summary>
    PushConflict,
    /// <summary>Any other failure (git / age / disk).</summary>
    Failed,
}

public sealed record EntrySpec(
    string Path,
    string Type,
    string Title,
    string? Description,
    IReadOnlyList<string>? Fields,
    IReadOnlyList<string>? Tags,
    IReadOnlyList<string>? Aliases,
    string? Target,
    string? Acl,
    IReadOnlyList<string>? Machines,
    string? Rotate,
    IReadOnlyList<string>? Readers,
    string? Priority,
    IReadOnlyList<string>? Linked);

public sealed record WriteResult(string Commit, string Summary);

public interface IRepoWriter
{
    bool Enabled { get; }
    Task<WriteResult> CreateAsync(EntrySpec spec, byte[] plaintext, CancellationToken ct);

    /// <summary>
    /// <paramref name="plaintext"/> null = metadata-only change, content untouched.
    /// <paramref name="expectedFingerprint"/> = fingerprint of the entry block as seen by the edit page (optimistic concurrency; mismatch = conflict).
    /// </summary>
    Task<WriteResult> UpdateAsync(string path, EntrySpec spec, byte[]? plaintext, string? expectedFingerprint, CancellationToken ct);

    Task<WriteResult> DeleteAsync(string path, CancellationToken ct);
}

/// <summary>
/// Web writes: a working clone inside the container (`Repo:WorkDir`, default /data/work) fetches the latest state from the
/// read-only bare repo `Repo:GitDir`, applies the change → commit (author and committer fixed to secrets-web) → push to the
/// git server (ssh, deploy key). **The read path still reads the bare repo.**
/// Plaintext only flows through memory and the pipe to age; the working clone only ever contains .age ciphertext.
/// </summary>
public sealed class RepoWriter(IOptions<RepoOptions> options, ILogger<RepoWriter> logger) : IRepoWriter
{
    private const string LockPath = "store/.recipients.lock";
    private const string LockHeader = "# secret recipients lock v1";
    private const int MaxPushAttempts = 3;
    private const int TomlMaxBytes = 4 * 1024 * 1024;

    /// <summary>Test-only seam: touch the working clone right before the post-write check, to prove a failing check rolls back and does not push.</summary>
    internal static Action<string>? AfterApplyForTests;

    private readonly RepoOptions _o = options.Value;
    private readonly SemaphoreSlim _writeLock = new(1, 1); // single in-process write lock

    public bool Enabled => !string.IsNullOrWhiteSpace(_o.PushUrl);

    private TimeSpan Timeout => TimeSpan.FromSeconds(_o.CommandTimeoutSeconds);
    private string WorkDir => _o.WorkDir;

    public Task<WriteResult> CreateAsync(EntrySpec spec, byte[] plaintext, CancellationToken ct) =>
        RunWithRetry($"web: add {spec.Path} ({spec.Type})", (ws, c) => Apply(ws, spec.Path, spec, plaintext, create: true, c, null), ct);

    public Task<WriteResult> UpdateAsync(string path, EntrySpec spec, byte[]? plaintext, string? expectedFingerprint, CancellationToken ct) =>
        RunWithRetry($"web: edit {path} ({spec.Type})",
            (ws, c) => Apply(ws, path, spec, plaintext, create: false, c, expectedFingerprint), ct);

    public Task<WriteResult> DeleteAsync(string path, CancellationToken ct) =>
        RunWithRetry($"web: remove {path}", (ws, c) => Remove(ws, path, c), ct);

    // ---------------------------------------------------------------- orchestration: lock → sync clone → pre-check → change → post-check → commit → push

    private async Task<WriteResult> RunWithRetry(string message, Func<string, CancellationToken, Task<string>> apply, CancellationToken ct)
    {
        if (!Enabled) throw new WriteRejectedException(WriteError.Failed, "Writes are not configured on this instance (Repo:PushUrl is empty)");
        await _writeLock.WaitAsync(ct);
        try
        {
            for (var attempt = 1; attempt <= MaxPushAttempts; attempt++)
            {
                await SyncWorkspace(ct);
                await CheckConsistency(ct, "Pre-write");
                string summary;
                try
                {
                    summary = await apply(WorkDir, ct);
                    AfterApplyForTests?.Invoke(WorkDir);
                    await CheckConsistency(ct, "Post-write");
                }
                catch (Exception)
                {
                    await HardReset(ct);
                    throw;
                }

                await Git(["add", "-A"], ct);
                await Git(
                [
                    "-c", $"user.name={_o.CommitAuthorName}", "-c", $"user.email={_o.CommitAuthorEmail}",
                    "commit", "-q", "-m", message,
                ], ct);
                var commit = (await GitText(["rev-parse", "HEAD"], ct)).Trim();

                var push = await GitRaw(["push", _o.PushUrl, "HEAD:refs/heads/" + _o.Branch], ct, push: true);
                if (push.ExitCode == 0)
                {
                    logger.LogInformation("Pushed {Commit}: {Message}", commit[..7], message);
                    return new WriteResult(commit, message);
                }

                // Push rejected: almost certainly the CLI pushed first. Drop this commit, fetch again and replay just this one operation on the new HEAD.
                logger.LogWarning("Push rejected (attempt {Attempt}): {Err}", attempt, FirstLine(push.Stderr));
                await HardReset(ct);
            }
            throw new WriteRejectedException(WriteError.PushConflict, "The repo was just changed elsewhere and retrying did not succeed; please try again later");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Clone the bare repo the first time, then fetch + hard reset to its HEAD (the clone is derived state; any local change can be discarded).</summary>
    private async Task SyncWorkspace(CancellationToken ct)
    {
        try
        {
            if (!Directory.Exists(Path.Combine(WorkDir, ".git")))
            {
                if (Directory.Exists(WorkDir)) Directory.Delete(WorkDir, true);
                Directory.CreateDirectory(Path.GetDirectoryName(WorkDir)!);
                await GitBare(["clone", "--quiet", "--no-hardlinks", _o.GitDir, WorkDir], ct);
            }
            await Git(["fetch", "--quiet", _o.GitDir, _o.Branch], ct);
            await Git(["reset", "--hard", "--quiet", "FETCH_HEAD"], ct);
            await Git(["clean", "-fdq"], ct);
        }
        catch (WriteRejectedException) { throw; }
        catch (Exception ex)
        {
            throw new WriteRejectedException(WriteError.Failed, "Syncing the working clone failed: " + ex.Message);
        }
    }

    private Task HardReset(CancellationToken ct) => SyncWorkspace(ct);

    // ---------------------------------------------------------------- the three operations

    private async Task<string> Apply(string ws, string path, EntrySpec spec, byte[]? plaintext, bool create,
        CancellationToken ct, string? expectedFingerprint)
    {
        var (blocks, leading) = ReadCatalog(ws);
        var existing = blocks.FirstOrDefault(b => b.Name == "entry" && b.GetString("path") == path);
        if (create && existing is not null) throw new WriteRejectedException(WriteError.Conflict, "Entry already exists");
        if (!create && existing is null) throw new WriteRejectedException(WriteError.Conflict, "Entry not found");
        if (!create && existing!.GetString("type") != spec.Type)
            throw new WriteRejectedException(WriteError.Invalid, "The entry type cannot be changed; delete and recreate the entry");

        // Optimistic concurrency: the version the edit page saw must be the version in the repo now
        if (!create && string.IsNullOrWhiteSpace(expectedFingerprint))
            throw new WriteRejectedException(WriteError.Invalid, "Missing entry fingerprint; refusing to overwrite");
        if (!create && Catalog.Fingerprint(existing!) != expectedFingerprint)
            throw new WriteRejectedException(WriteError.Conflict, "This entry was changed after you opened the edit page; reload and edit again");

        var block = BuildBlock(spec, existing);
        var newBlocks = blocks.ToList();
        if (existing is null) newBlocks.Add(block);
        else newBlocks[newBlocks.IndexOf(existing)] = block;

        var catalogText = TomlWriter.Write(newBlocks, leading);
        var recipients = ReadRecipients(ws);
        var catalog = ParseCatalogOrReject(catalogText, recipients);
        var entry = catalog.Find(path) ?? throw new WriteRejectedException(WriteError.Invalid, "Invalid entry path");
        if (!entry.IsValid) throw new WriteRejectedException(WriteError.Invalid, "Invalid entry metadata: " + string.Join("; ", entry.Errors));

        var storePath = entry.StorePath;

        // Lock integrity gate (same as the CLI): before touching it, the existing ciphertext bytes must match the CHash recorded
        // in the lock; otherwise someone changed the ciphertext behind the CLI's back — and writing now would erase the evidence.
        CheckLockHash(ws, storePath, mustExist: !create);

        if (plaintext is not null)
        {
            var policy = PolicyDocument.Parse(File.ReadAllText(Path.Combine(ws, "policy.toml")));
            var (keys, err) = policy.Expand(storePath, recipients);
            if (err is not null) throw new WriteRejectedException(WriteError.RepoInconsistent, err);

            var ciphertext = await EncryptVerified(plaintext, keys, ct);
            WriteBytes(ws, storePath, ciphertext);
            UpdateLockLine(ws, storePath, Policy.RecipientSetHash(keys), Sha256(ciphertext));
        }
        else if (!File.Exists(Path.Combine(ws, storePath.Replace('/', Path.DirectorySeparatorChar))))
        {
            throw new WriteRejectedException(WriteError.RepoInconsistent, "Ciphertext file is missing; fix it with the CLI first");
        }

        File.WriteAllBytes(Path.Combine(ws, "catalog.toml"), Utf8(catalogText));
        return create ? "add" : "edit";
    }

    private Task<string> Remove(string ws, string path, CancellationToken ct)
    {
        var (blocks, leading) = ReadCatalog(ws);
        var existing = blocks.FirstOrDefault(b => b.Name == "entry" && b.GetString("path") == path)
                       ?? throw new WriteRejectedException(WriteError.Conflict, "Entry not found");
        var type = existing.GetString("type") ?? throw new WriteRejectedException(WriteError.RepoInconsistent, "Entry has no type");
        var storePath = StoreRules.StorePathFor(path, type);
        if (!StoreRules.IsValidStorePath(storePath)) throw new WriteRejectedException(WriteError.RepoInconsistent, "Invalid ciphertext path");

        CheckLockHash(ws, storePath, mustExist: true);

        var remaining = blocks.Where(b => !ReferenceEquals(b, existing)).ToList();
        File.WriteAllBytes(Path.Combine(ws, "catalog.toml"), Utf8(TomlWriter.Write(remaining, leading)));

        var full = Path.Combine(ws, storePath.Replace('/', Path.DirectorySeparatorChar));
        if (File.Exists(full)) File.Delete(full);
        RemoveLockLine(ws, storePath);
        _ = ct;
        return Task.FromResult("remove");
    }

    private TomlBlock BuildBlock(EntrySpec spec, TomlBlock? existing)
    {
        var values = new List<KeyValuePair<string, TomlValue>>();
        void Str(string key, string? v)
        {
            if (!string.IsNullOrWhiteSpace(v)) values.Add(new(key, new TomlValue.Str(StoreRules.Nfc(v))));
        }
        void Arr(string key, IReadOnlyList<string>? v)
        {
            if (v is { Count: > 0 }) values.Add(new(key, new TomlValue.StrArray(v.Select(StoreRules.Nfc).ToList())));
        }
        void Aliases(IReadOnlyList<string>? v)
        {
            // FORMAT aliases: normalize before storing (strip [[ ]], backslash → slash, drop .md, NFC), otherwise it isn't the string the CLI stores
            var norm = (v ?? []).Select(a => Format.Aliases.Normalize(a)).Where(a => a.Length > 0).ToList();
            if (norm.Count > 0) values.Add(new("aliases", new TomlValue.StrArray(norm)));
        }

        Str("path", spec.Path);
        Str("type", spec.Type);
        Str("title", spec.Title);
        Str("description", spec.Description);
        Arr("fields", spec.Fields);
        Str("target", spec.Target);
        Str("acl", spec.Acl);
        Arr("machines", spec.Machines);
        Arr("tags", spec.Tags);
        Aliases(spec.Aliases);
        Str("rotate", spec.Rotate);
        Arr("readers", spec.Readers);
        Str("priority", spec.Priority);
        Arr("linked", spec.Linked);
        values.Add(new("updated", new TomlValue.Str(DateOnly.FromDateTime(DateTime.Now).ToString("yyyy-MM-dd"))));

        // Keep existing keys this write doesn't know about (forward compatibility: optional keys added to FORMAT later aren't wiped by a web edit)
        if (existing is not null)
            foreach (var kv in existing.Values)
                if (!values.Any(v => v.Key == kv.Key))
                    values.Add(kv);

        return TomlWriter.Block("entry", existing?.Line ?? 0, values);
    }

    // ---------------------------------------------------------------- encryption / checks / lock

    /// <summary>Encrypt, then immediately decrypt again and compare plaintext SHA-256 (like the CLI); nothing is written on a mismatch.</summary>
    private async Task<byte[]> EncryptVerified(byte[] plaintext, IReadOnlyList<string> recipientKeys, CancellationToken ct)
    {
        var args = new List<string>();
        foreach (var k in recipientKeys) { args.Add("-r"); args.Add(k); }
        var max = Math.Max(_o.FileMaxBytes, plaintext.Length) * 2 + 64 * 1024;
        var enc = await ProcessRunner.RunAsync(_o.AgePath, args, plaintext, max, Timeout, ct);
        if (enc.ExitCode != 0 || enc.Truncated)
        {
            logger.LogError("age encryption failed: {Err}", FirstLine(enc.Stderr));
            throw new WriteRejectedException(WriteError.Failed, "Encryption failed");
        }
        if (!StoreRules.HasAgeHeader(enc.Stdout)) throw new WriteRejectedException(WriteError.Failed, "Encryption output is not age ciphertext");

        var back = await ProcessRunner.RunAsync(_o.AgePath, ["-d", "-i", _o.Identity], enc.Stdout, max, Timeout, ct);
        try
        {
            if (back.ExitCode != 0 || back.Truncated)
            {
                logger.LogError("Write self-check decryption failed: {Err}", FirstLine(back.Stderr));
                throw new WriteRejectedException(WriteError.Failed, "Write self-check failed: this service's identity cannot decrypt the ciphertext it just wrote");
            }
            if (!Sha256(back.Stdout).Equals(Sha256(plaintext), StringComparison.Ordinal))
                throw new WriteRejectedException(WriteError.Failed, "Write self-check failed: the decrypted result differs from the original");
        }
        finally
        {
            Array.Clear(back.Stdout);
        }
        return enc.Stdout;
    }

    /// <summary>The target ciphertext must match the hash recorded in the lock (a missing lock line or file is judged by mustExist).</summary>
    private static void CheckLockHash(string ws, string storePath, bool mustExist)
    {
        var full = Path.Combine(ws, storePath.Replace('/', Path.DirectorySeparatorChar));
        var line = ReadLock(ws).FirstOrDefault(l => LockPathOf(l) == storePath);
        var exists = File.Exists(full);

        if (!exists && !mustExist)
        {
            if (line is not null) throw new WriteRejectedException(WriteError.RepoInconsistent, "The lock lists this path but the ciphertext does not exist; investigate with the CLI first (secret check)");
            return;
        }
        if (!exists) throw new WriteRejectedException(WriteError.RepoInconsistent, "Ciphertext file is missing; investigate with the CLI first (secret check)");
        if (line is null) throw new WriteRejectedException(WriteError.RepoInconsistent, "The lock has no line for this ciphertext; investigate with the CLI first (secret check)");

        var cols = line.Split("  ");
        if (cols.Length != 3) throw new WriteRejectedException(WriteError.RepoInconsistent, "Malformed lock line; investigate with the CLI first (secret check)");
        if (!string.Equals(cols[1], Sha256(File.ReadAllBytes(full)), StringComparison.Ordinal))
            throw new WriteRejectedException(WriteError.RepoInconsistent,
                "Ciphertext does not match the hash recorded in the lock (possibly changed behind the CLI's back); investigate with the CLI first (secret check) — the web UI will not overwrite it");
    }

    private static void UpdateLockLine(string ws, string storePath, string recipientHash, string cipherHash)
    {
        var lines = ReadLock(ws).Where(l => LockPathOf(l) != storePath).ToList();
        lines.Add($"{recipientHash}  {cipherHash}  {storePath}");
        WriteLock(ws, lines);
    }

    private static void RemoveLockLine(string ws, string storePath) =>
        WriteLock(ws, ReadLock(ws).Where(l => LockPathOf(l) != storePath).ToList());

    private static List<string> ReadLock(string ws)
    {
        var p = Path.Combine(ws, LockPath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(p)) return [];
        return File.ReadAllText(p).Replace("\r\n", "\n").Split('\n')
            .Skip(1).Where(l => l.Length > 0).ToList();
    }

    private static void WriteLock(string ws, List<string> lines)
    {
        var p = Path.Combine(ws, LockPath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(p)!);
        var ordered = lines.OrderBy(LockPathOf, StringComparer.Ordinal);
        File.WriteAllBytes(p, Utf8(LockHeader + "\n" + string.Concat(ordered.Select(l => l + "\n"))));
    }

    private static string LockPathOf(string line)
    {
        var cols = line.Split("  ");
        return cols.Length == 3 ? cols[2] : line;
    }

    /// <summary>catalog ↔ store ↔ lock must correspond one to one, otherwise writes are refused (with a hint to fix it with the CLI first).</summary>
    private async Task CheckConsistency(CancellationToken ct, string when)
    {
        _ = ct;
        var ws = WorkDir;
        Recipients recipients;
        Catalog catalog;
        try
        {
            recipients = ReadRecipients(ws);
            catalog = Catalog.Parse(File.ReadAllText(Path.Combine(ws, "catalog.toml")), recipients);
        }
        catch (SecretFormatException ex)
        {
            throw new WriteRejectedException(WriteError.RepoInconsistent, $"{when} check failed: catalog.toml is invalid ({ex.Message}); fix the repo with the CLI first");
        }

        var storeDir = Path.Combine(ws, "store");
        var storeFiles = Directory.Exists(storeDir)
            ? Directory.GetFiles(storeDir, "*.age", SearchOption.AllDirectories)
                .Select(f => Path.GetRelativePath(ws, f).Replace(Path.DirectorySeparatorChar, '/'))
                .ToHashSet(StringComparer.Ordinal)
            : [];
        var lockPaths = ReadLock(ws).Select(LockPathOf).ToHashSet(StringComparer.Ordinal);
        var catalogPaths = catalog.Entries.Where(e => e.HasAddress).Select(e => e.StorePath).ToHashSet(StringComparer.Ordinal);

        string? problem = null;
        if (catalog.InvalidCount > 0) problem = "the catalog has unavailable entries";
        else if (catalogPaths.Count != catalog.Entries.Count) problem = "the catalog has duplicate entries or entries without an address";
        else if (!catalogPaths.SetEquals(storeFiles)) problem = "catalog and store disagree";
        else if (!lockPaths.SetEquals(storeFiles)) problem = "lock and store disagree";
        if (problem is not null)
            throw new WriteRejectedException(WriteError.RepoInconsistent, $"{when} check failed: {problem}; fix the repo with the CLI first (secret check)");
    }

    // ---------------------------------------------------------------- helpers

    private static Catalog ParseCatalogOrReject(string text, Recipients recipients)
    {
        try { return Catalog.Parse(text, recipients); }
        catch (SecretFormatException ex) { throw new WriteRejectedException(WriteError.Invalid, "catalog.toml is invalid after the change: " + ex.Message); }
    }

    private static Recipients ReadRecipients(string ws) =>
        Recipients.Parse(File.ReadAllText(Path.Combine(ws, "recipients.toml")));

    private static (List<TomlBlock> Blocks, string Leading) ReadCatalog(string ws)
    {
        var text = File.ReadAllText(Path.Combine(ws, "catalog.toml"));
        return (RestrictedToml.Parse(text).ToList(), TomlWriter.LeadingComments(text));
    }

    private static void WriteBytes(string ws, string repoPath, byte[] bytes)
    {
        var full = Path.Combine(ws, repoPath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, bytes);
    }

    private static byte[] Utf8(string s) => new UTF8Encoding(false).GetBytes(s);

    public static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private IEnumerable<KeyValuePair<string, string>> PushEnv()
    {
        if (string.IsNullOrWhiteSpace(_o.SshKey)) yield break;
        var known = string.IsNullOrWhiteSpace(_o.KnownHosts) ? "" : $" -o UserKnownHostsFile=\"{_o.KnownHosts}\"";
        yield return new("GIT_SSH_COMMAND",
            $"ssh -i \"{_o.SshKey}\" -o IdentitiesOnly=yes{known} -o StrictHostKeyChecking=yes -o BatchMode=yes");
    }

    private async Task<ProcessResult> GitRaw(string[] args, CancellationToken ct, bool push = false)
    {
        var full = new[] { "-c", "safe.directory=*", "-C", WorkDir }.Concat(args);
        return await ProcessRunner.RunAsync(_o.GitPath, full, null, TomlMaxBytes, Timeout, ct,
            push ? PushEnv() : null);
    }

    private async Task<string> GitText(string[] args, CancellationToken ct) =>
        Encoding.UTF8.GetString((await Git(args, ct)).Stdout);

    private async Task<ProcessResult> Git(string[] args, CancellationToken ct)
    {
        var r = await GitRaw(args, ct);
        if (r.ExitCode != 0)
        {
            logger.LogError("git {Cmd} failed: {Err}", args[0], FirstLine(r.Stderr));
            throw new WriteRejectedException(WriteError.Failed, $"git {args[0]} failed");
        }
        return r;
    }

    /// <summary>
    /// Calls against the bare repo (`Repo:GitDir`, owned by the git server's uid). **Don't count on `-c safe.directory=…`**:
    /// git only reads that key from protected scopes (system / global) and ignores the command line and GIT_CONFIG_*
    /// (a first real write failed with `detected dubious ownership in repository at '/repo'`).
    /// What actually allows it is `GIT_CONFIG_GLOBAL` in `ProcessRunner.ForcedVars` → `/app/gitconfig` in the image.
    /// </summary>
    private async Task GitBare(string[] args, CancellationToken ct)
    {
        var r = await ProcessRunner.RunAsync(_o.GitPath, args, null, TomlMaxBytes, Timeout, ct);
        if (r.ExitCode != 0)
        {
            logger.LogError("git {Cmd} failed: {Err}", args[0], FirstLine(r.Stderr));
            throw new WriteRejectedException(WriteError.Failed, $"git {args[0]} failed");
        }
    }

    private static string FirstLine(string s)
    {
        var line = s.Split('\n', 2)[0].Trim();
        return line.Length > 200 ? line[..200] : line;
    }
}
