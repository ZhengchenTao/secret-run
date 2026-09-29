using System.Text.Json;

namespace SecretsWeb.Services;

/// <summary>
/// Favorites (web UI only): a list of entry paths stored at `Repo:FavoritesPath` (default /data/favorites.json).
///
/// **Why not in catalog.toml**: a favorite is a personal browsing preference, not a fact about the entry. Putting it in the
/// catalog would mean changing the FORMAT contract and the CLI's known keys and key order (otherwise the CLI would drop the
/// key when it edits an entry), and every star would produce a git commit. As a server-side file it is shared by every
/// device using the same service and leaves the CLI and the data repo untouched; the price is that it isn't versioned and
/// is lost with /data — acceptable for a "sort these first" preference.
///
/// File format: `{"paths":["personal/a/b", ...]}`. Anything unreadable (missing file, broken JSON, no permission) counts as
/// empty so it never breaks list rendering. Writes go "temp file + rename" to avoid half-written files.
/// </summary>
public sealed class FavoriteStore(string path, ILogger<FavoriteStore> logger)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private HashSet<string>? _cache;

    private sealed class Doc { public List<string> Paths { get; set; } = []; }

    public async Task<IReadOnlySet<string>> GetAsync(CancellationToken ct = default)
    {
        if (_cache is not null) return _cache;
        await _gate.WaitAsync(ct);
        try
        {
            if (_cache is null)
            {
                var set = new HashSet<string>(StringComparer.Ordinal);
                try
                {
                    if (File.Exists(path))
                    {
                        var doc = JsonSerializer.Deserialize<Doc>(await File.ReadAllTextAsync(path, ct));
                        foreach (var p in doc?.Paths ?? []) set.Add(p);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogWarning("Favorites could not be read, treating as empty: {Err}", ex.Message);
                }
                _cache = set;
            }
            return _cache;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Add to or remove from favorites; returns whether the entry is a favorite afterwards.</summary>
    public async Task<bool> SetAsync(string entryPath, bool on, CancellationToken ct = default)
    {
        await GetAsync(ct);
        await _gate.WaitAsync(ct);
        try
        {
            var set = new HashSet<string>(_cache!, StringComparer.Ordinal);
            if (on) set.Add(entryPath); else set.Remove(entryPath);

            var json = JsonSerializer.Serialize(new Doc { Paths = [.. set.OrderBy(p => p, StringComparer.Ordinal)] },
                new JsonSerializerOptions { WriteIndented = true });
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = path + ".tmp";
            await File.WriteAllTextAsync(tmp, json, ct);
            File.Move(tmp, path, overwrite: true);

            _cache = set;
            return on;
        }
        finally { _gate.Release(); }
    }
}
