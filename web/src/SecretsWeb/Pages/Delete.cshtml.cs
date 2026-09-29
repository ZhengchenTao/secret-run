using Microsoft.AspNetCore.Mvc.RazorPages;
using SecretsWeb.Format;
using SecretsWeb.Security;
using SecretsWeb.Services;

namespace SecretsWeb.Pages;

/// <summary>Delete confirmation page: issues a one-time token (bound to session + path, 5 minutes); POST /api/entry/delete does the actual delete.</summary>
public sealed class DeleteModel(EntryService read, EntryWriteService write, ConfirmTokens confirm) : PageModel
{
    public string Path { get; private set; } = "";
    public string Name { get; private set; } = "";
    public string Type { get; private set; } = "";
    public string Title { get; private set; } = "";
    public string ConfirmToken { get; private set; } = "";
    public EntryReferences? References { get; private set; }
    public string? Error { get; private set; }

    public async Task OnGetAsync(string domain, string group, string name, CancellationToken ct)
    {
        Path = $"{domain}/{group}/{name}";
        Name = name;
        try
        {
            if (!write.Enabled) throw new EntryException(EntryError.WrongType, "This instance is read-only (no push URL configured)");
            if (!StoreRules.IsValidLogicalPath(Path)) throw new EntryException(EntryError.NotFound, "Entry not found");
            var (_, e) = await read.FindAnyAsync(Path, ct);
            Type = e.Type ?? "";
            Title = e.DisplayTitle;
            References = await write.GetReferencesAsync(Path, ct);
            ConfirmToken = confirm.Issue(DecryptRateLimiter.KeyFor(HttpContext), Path);
        }
        catch (EntryException ex)
        {
            Error = ex.Message;
            Response.StatusCode = ex.StatusCode;
        }
    }
}
