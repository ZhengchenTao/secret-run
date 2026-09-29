using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecretsWeb.Format;
using SecretsWeb.Services;

namespace SecretsWeb.Pages;

/// <summary>
/// Entry page. kv and file values are only fetched through POST /api/*.
/// doc: GET only decrypts and renders when Sec-Fetch-Site is same-origin / none (a click inside the site or typed into the
/// address bar); otherwise (cross-site navigation, clients without the header) it only shows a "Click to view" button,
/// and this page's POST (antiforgery) decrypts.
/// </summary>
public sealed class EntryModel(EntryService svc, EntryWriteService write, FavoriteStore favorites) : PageModel
{
    public bool WriteEnabled => write.Enabled;

    /// <summary>Whether this entry is a favorite (stored server-side, see FavoriteStore).</summary>
    public bool IsFavorite { get; private set; }

    public CatalogEntry? Entry { get; private set; }
    public string? DocHtml { get; private set; }
    public bool DocNeedsClick { get; private set; }
    public string? Error { get; private set; }

    public Task OnGetAsync(string domain, string group, string name, CancellationToken ct) =>
        Load(domain, group, name, allowDocDecrypt: IsSameOriginNavigation(Request), ct);

    public Task OnPostAsync(string domain, string group, string name, CancellationToken ct) =>
        Load(domain, group, name, allowDocDecrypt: true, ct);

    public static bool IsSameOriginNavigation(HttpRequest r) =>
        r.Headers["Sec-Fetch-Site"].ToString() is "same-origin" or "none";

    private async Task Load(string domain, string group, string name, bool allowDocDecrypt, CancellationToken ct)
    {
        var path = $"{domain}/{group}/{name}";
        try
        {
            if (!StoreRules.IsValidLogicalPath(path)) throw new EntryException(EntryError.NotFound, "Entry not found");
            (_, var entry) = await svc.FindAnyAsync(path, ct);
            Entry = entry;
            IsFavorite = (await favorites.GetAsync(ct)).Contains(path);
            if (!entry.IsValid)
            {
                Error = "Invalid entry metadata: " + string.Join("; ", entry.Errors);
                Response.StatusCode = StatusCodes.Status502BadGateway;
                return;
            }
            if (entry.Type == "doc")
            {
                if (allowDocDecrypt) DocHtml = MarkdownRenderer.Render(await svc.GetDocAsync(HttpContext, path, ct));
                else DocNeedsClick = true;
            }
        }
        catch (EntryException ex)
        {
            Error = ex.Message;
            Response.StatusCode = ex.StatusCode;
        }
    }
}
