using System.Text;
using Microsoft.Extensions.Options;
using SecretsWeb.Audit;
using SecretsWeb.Format;
using SecretsWeb.Repo;
using SecretsWeb.Security;

namespace SecretsWeb.Services;

/// <summary>Reference relationships of one entry (for the delete confirmation page and the delete response).</summary>
public sealed record EntryReferences(
    IReadOnlyList<string> Readers,
    IReadOnlyList<string> Linked,
    IReadOnlyList<string> InboundLinked);

/// <summary>One write submitted from the web UI. The value only lives in memory; only ciphertext reaches the disk.</summary>
public sealed record WriteRequest(
    string Path,
    string Type,
    EntrySpec Spec,
    byte[]? Plaintext,
    string? ExpectedFingerprint);

/// <summary>
/// Entry point for writes: input validation (FORMAT catalog / kv rules), rate limiting, audit. <see cref="IRepoWriter"/> does the repo work.
/// Audit lines carry action, entry path, field names, result and commit id — **never values**.
/// </summary>
public sealed class EntryWriteService(
    IRepoWriter writer, ISecretRepository repo, IAuditLog audit, DecryptRateLimiter limiter, HealthService health,
    IOptions<RepoOptions> options, ILogger<EntryWriteService> logger)
{
    private readonly RepoOptions _o = options.Value;

    public bool Enabled => writer.Enabled;

    public async Task<WriteResult> CreateAsync(HttpContext http, WriteRequest req, CancellationToken ct)
    {
        EnsureWritable();
        AcquireQuota(http);
        var rec = AuditLog.For(http, "write") with { EntryPath = req.Path, Action = "create", Field = FieldList(req.Spec) };
        return await Run(rec, () => writer.CreateAsync(req.Spec, req.Plaintext!, ct));
    }

    public async Task<WriteResult> UpdateAsync(HttpContext http, WriteRequest req, CancellationToken ct)
    {
        // Order: first "can this instance write at all", then business validation, and only then take rate-limit quota (refused requests must not consume it)
        EnsureWritable();
        // Optimistic concurrency is mandatory: without a fingerprint there's no telling which version you edited, so refuse (hand-crafted requests too)
        if (string.IsNullOrWhiteSpace(req.ExpectedFingerprint))
            throw new EntryException(EntryError.BadRequest,
                "Missing entry fingerprint 'expected': submit from the edit page (or compute the fingerprint of the current entry block yourself)");
        AcquireQuota(http);
        var rec = AuditLog.For(http, "write") with
        {
            EntryPath = req.Path,
            Action = req.Plaintext is null ? "update-meta" : "update",
            Field = FieldList(req.Spec),
        };
        return await Run(rec, () => writer.UpdateAsync(req.Path, req.Spec, req.Plaintext, req.ExpectedFingerprint, ct));
    }

    public async Task<(WriteResult Result, EntryReferences References)> DeleteAsync(HttpContext http, string path, CancellationToken ct)
    {
        EnsureWritable();
        var refs = await GetReferencesAsync(path, ct);
        if (refs.InboundLinked.Count > 0)
        {
            var rejected = AuditLog.For(http, "write") with { EntryPath = path, Action = "delete", Result = "error", Reason = "linked_by_others" };
            Write(rejected);
            throw new EntryException(EntryError.Conflict,
                "Other entries still link to it (linked): " + string.Join(", ", refs.InboundLinked) +
                ". Remove those references first, or force-delete with the CLI");
        }
        AcquireQuota(http);
        var rec = AuditLog.For(http, "write") with { EntryPath = path, Action = "delete" };
        return (await Run(rec, () => writer.DeleteAsync(path, ct)), refs);
    }

    /// <summary>Relationships to show before deleting: who reads it / what it links to / what links to it.</summary>
    public async Task<EntryReferences> GetReferencesAsync(string path, CancellationToken ct)
    {
        RepoSnapshot snap;
        try { snap = await repo.GetSnapshotAsync(ct); }
        catch (Exception ex) when (ex is RepoUnavailableException or SecretFormatException or TimeoutException)
        {
            throw new EntryException(EntryError.Unavailable, "The secrets repo is currently not readable");
        }
        var entry = snap.Catalog.Find(path) ?? throw new EntryException(EntryError.NotFound, "Entry not found");
        var inbound = snap.Catalog.Entries
            .Where(e => e.HasAddress && e.Path != path && e.Linked.Contains(path, StringComparer.Ordinal))
            .Select(e => e.Path!)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();
        return new EntryReferences(entry.Readers, entry.Linked, inbound);
    }

    /// <summary>Refuse right away on a read-only instance (before any business validation, so the error message is the right one).</summary>
    private void EnsureWritable()
    {
        if (!Enabled) throw new EntryException(EntryError.WrongType, "This instance is read-only (Repo:PushUrl is not configured)");
    }

    /// <summary>Take one unit of write quota. Placed after every pre-check: refused requests don't consume quota.</summary>
    private void AcquireQuota(HttpContext http)
    {
        if (!limiter.TryAcquireWrite(DecryptRateLimiter.KeyFor(http)))
            throw new EntryException(EntryError.RateLimited, "Too many write requests; please try again later");
    }

    private async Task<WriteResult> Run(AuditRecord rec, Func<Task<WriteResult>> action)
    {
        try
        {
            var result = await action();
            health.Invalidate();
            limiter.RecordWrittenEntry(rec.EntryPath ?? "");
            Write(rec with { Result = "ok", Reason = result.Commit });
            return result;
        }
        catch (WriteRejectedException ex)
        {
            Write(rec with { Result = "error", Reason = ex.Error.ToString() });
            logger.LogWarning("Write refused ({Error}): {Msg}", ex.Error, ex.Message);
            throw new EntryException(ex.Error switch
            {
                WriteError.Invalid => EntryError.BadRequest,
                WriteError.Conflict => EntryError.Conflict,
                WriteError.PushConflict => EntryError.Conflict,
                WriteError.RepoInconsistent => EntryError.Unavailable,
                _ => EntryError.WriteFailed,
            }, ex.Message);
        }
        catch (Exception ex)
        {
            Write(rec with { Result = "error", Reason = ex.GetType().Name });
            logger.LogError("Write failed: {Type} {Msg}", ex.GetType().Name, ex.Message);
            throw new EntryException(EntryError.WriteFailed, "Write failed; see the server log for details");
        }
    }

    private void Write(AuditRecord rec)
    {
        try { audit.Write(rec); }
        catch (AuditWriteException ex) { logger.LogError("Writing the audit line failed: {Type}", ex.InnerException?.GetType().Name ?? "unknown"); }
    }

    private static string? FieldList(EntrySpec spec) => spec.Fields is { Count: > 0 } f ? string.Join(",", f) : null;

    // ---------------------------------------------------------------- form → WriteRequest

    /// <summary>
    /// Turn the form into a write request. <paramref name="requireContent"/> false allows leaving the content unchanged (metadata edit).
    /// kv content is parsed strictly per FORMAT and errors are shown to the user as-is (line numbers and rules only, never the content).
    /// </summary>
    public WriteRequest BuildRequest(IFormCollection form, IFormFile? upload, bool requireContent)
    {
        string S(string key) => form[key].ToString().Trim();
        string? Opt(string key) => S(key).Length == 0 ? null : StoreRules.Nfc(S(key));
        IReadOnlyList<string>? List(string key)
        {
            var raw = form[key].ToString();
            var items = raw.Split([',', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(x => StoreRules.Nfc(x.Trim())).Where(x => x.Length > 0).ToList();
            return items.Count == 0 ? null : items;
        }

        var path = S("path");
        var type = S("type");
        if (!StoreRules.Types.Contains(type)) throw new EntryException(EntryError.BadRequest, "Invalid type");
        if (!StoreRules.IsValidLogicalPath(path))
            throw new EntryException(EntryError.BadRequest, "path must be <domain>/<group>/<name>: three segments, each made of lowercase letters, digits and hyphens (not starting with a hyphen, not a reserved device name such as con or nul)");

        byte[]? plaintext = null;
        IReadOnlyList<string>? fields = null;

        var contentText = form["content"].ToString();
        if (upload is not null && upload.Length > 0)
        {
            if (type != "file") throw new EntryException(EntryError.BadRequest, "Only file entries can take an upload");
            if (upload.Length > _o.FileMaxBytes) throw new EntryException(EntryError.TooLarge, $"Upload exceeds {_o.FileMaxBytes} bytes");
            using var ms = new MemoryStream();
            upload.CopyTo(ms);
            plaintext = ms.ToArray();
        }
        else if (contentText.Length > 0)
        {
            var normalized = type == "file" ? contentText.Replace("\r\n", "\n") : contentText.Replace("\r\n", "\n");
            if (type is "kv" or "doc" && !normalized.EndsWith('\n')) normalized += "\n";
            plaintext = new UTF8Encoding(false).GetBytes(normalized);
            if (plaintext.Length > _o.FileMaxBytes) throw new EntryException(EntryError.TooLarge, $"Content exceeds {_o.FileMaxBytes} bytes");
        }

        if (plaintext is null && requireContent) throw new EntryException(EntryError.BadRequest, "Content must not be empty");

        if (type == "kv")
        {
            if (plaintext is not null)
            {
                IReadOnlyList<KeyValuePair<string, string>> kv;
                try { kv = KvParser.Parse(plaintext); }
                catch (SecretFormatException ex)
                {
                    throw new EntryException(EntryError.BadRequest,
                        "Invalid kv content: " + ex.Message + " (every line must be KEY=VALUE; KEY uses uppercase letters, digits and underscores and starts with a letter; lines starting with # are comments)");
                }
                if (kv.Count == 0) throw new EntryException(EntryError.BadRequest, "kv needs at least one field");
                fields = kv.Select(p => p.Key).ToList();
            }
            else
            {
                // Metadata-only edit: field names must stay as they are in the repo; filled in from the current catalog below
                fields = null;
            }
        }

        var spec = new EntrySpec(
            Path: path,
            Type: type,
            Title: S("title"),
            Description: Opt("description"),
            Fields: fields,
            Tags: List("tags"),
            Aliases: List("aliases"),
            Target: type == "file" ? Opt("target") : null,
            Acl: type == "file" ? Opt("acl") : null,
            Machines: type == "file" ? List("machines") : null,
            Rotate: Opt("rotate"),
            Readers: List("readers"),
            Priority: Opt("priority"),
            Linked: List("linked"));

        return new WriteRequest(path, type, spec, plaintext, S("expected"));
    }

    /// <summary>Editing a kv entry without new content keeps the field names currently in the repo.</summary>
    public async Task<WriteRequest> FillFieldsFromCatalog(WriteRequest req, CancellationToken ct)
    {
        if (req.Type != "kv" || req.Spec.Fields is not null) return req;
        var snap = await repo.GetSnapshotAsync(ct);
        var existing = snap.Catalog.Find(req.Path) ?? throw new EntryException(EntryError.NotFound, "Entry not found");
        return req with { Spec = req.Spec with { Fields = existing.Fields } };
    }
}
