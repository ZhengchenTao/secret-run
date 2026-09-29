using SecretsWeb.Repo;

namespace SecretsWeb.Services;

/// <summary>/health is anonymous: the result is cached for 10 seconds so anonymous requests can't keep spawning git. The response only has counts and booleans, never entry names.</summary>
public sealed class HealthService(ISecretRepository repo, TimeProvider time, ILogger<HealthService> logger)
{
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(10);

    private readonly SemaphoreSlim _lock = new(1, 1);
    private (DateTimeOffset At, bool Ok, object Body)? _cached;

    /// <summary>Called after a successful write: the next /health reflects the new HEAD and counts immediately.</summary>
    public void Invalidate() => _cached = null;

    public async Task<(bool Ok, object Body)> GetAsync(CancellationToken ct)
    {
        var c = _cached;
        if (c is { } hit && time.GetUtcNow() - hit.At < CacheFor) return (hit.Ok, hit.Body);

        await _lock.WaitAsync(ct);
        try
        {
            c = _cached;
            if (c is { } hit2 && time.GetUtcNow() - hit2.At < CacheFor) return (hit2.Ok, hit2.Body);
            var (ok, body) = await ComputeAsync(ct);
            _cached = (time.GetUtcNow(), ok, body);
            return (ok, body);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<(bool, object)> ComputeAsync(CancellationToken ct)
    {
        try
        {
            var snap = await repo.GetSnapshotAsync(ct);
            var c = snap.Consistency;
            return (true, new
            {
                status = "ok",
                head = snap.Commit,
                format = snap.Catalog.Format,
                entries = snap.Catalog.Entries.Count,
                invalidEntries = snap.Catalog.InvalidCount,
                consistency = new
                {
                    consistent = c.Consistent,
                    catalogEntries = c.CatalogEntries,
                    storeFiles = c.StoreFiles,
                    lockLines = c.LockLines,
                },
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Error details may contain entry names; they only go to the local log
            logger.LogError("Health check failed: {Type} {Msg}", ex.GetType().Name, ex.Message);
            return (false, new { status = "error", head = (string?)null, format = (string?)null, entries = (int?)null });
        }
    }
}
