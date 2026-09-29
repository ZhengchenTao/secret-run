using Microsoft.AspNetCore.Mvc.RazorPages;
using SecretsWeb.Format;
using SecretsWeb.Repo;

namespace SecretsWeb.Pages;

/// <summary>List / tree / search: reads the catalog only, never decrypts.</summary>
public sealed class IndexModel(ISecretRepository repo, SecretsWeb.Services.EntryWriteService write,
    SecretsWeb.Services.FavoriteStore favorites, ILogger<IndexModel> logger) : PageModel
{
    public bool WriteEnabled => write.Enabled;

    public string Query { get; private set; } = "";
    public bool Unavailable { get; private set; }
    public IReadOnlyList<CatalogEntry> Results { get; private set; } = [];
    public int Total { get; private set; }

    /// <summary>Paths of favorite entries (stored server-side, see FavoriteStore).</summary>
    public IReadOnlySet<string> Favorites { get; private set; } = new HashSet<string>();

    /// <summary>Favorite entries sorted by path; shown as a separate group at the top of the list.</summary>
    public IReadOnlyList<CatalogEntry> Starred { get; private set; } = [];

    public bool IsStarred(CatalogEntry e) => e.Path is not null && Favorites.Contains(e.Path);

    public async Task OnGetAsync(string? q, CancellationToken ct)
    {
        Query = (q ?? "").Trim();
        try
        {
            var snap = await repo.GetSnapshotAsync(ct);
            Total = snap.Catalog.Entries.Count;
            Results = Search(snap.Catalog.Entries, Query);
            Favorites = await favorites.GetAsync(ct);
            Starred = [.. Results.Where(IsStarred)];
        }
        catch (Exception ex) when (ex is RepoUnavailableException or SecretFormatException or TimeoutException)
        {
            logger.LogError("Repo not readable: {Msg}", ex.Message);
            Unavailable = true;
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        }
    }

    /// <summary>Split on spaces; every term must match one of path / title / description / tags (case-insensitive).</summary>
    public static IReadOnlyList<CatalogEntry> Search(IEnumerable<CatalogEntry> entries, string query)
    {
        var terms = StoreRules.Nfc(query).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return entries
            .Where(e => terms.All(t =>
                (e.Path?.Contains(t, StringComparison.OrdinalIgnoreCase) ?? false) ||
                e.Title.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                (e.Description?.Contains(t, StringComparison.OrdinalIgnoreCase) ?? false) ||
                e.Tags.Any(tag => tag.Contains(t, StringComparison.OrdinalIgnoreCase))))
            .OrderBy(e => e.Path ?? "", StringComparer.Ordinal)
            .ToList();
    }
}
