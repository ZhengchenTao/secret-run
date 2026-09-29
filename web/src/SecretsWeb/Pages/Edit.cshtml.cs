using Microsoft.AspNetCore.Mvc.RazorPages;
using SecretsWeb.Format;
using SecretsWeb.Services;

namespace SecretsWeb.Pages;

/// <summary>
/// Edit page. GET only shows metadata and **does not decrypt**; only "Load current content" (POST + antiforgery) decrypts the
/// current plaintext into the textarea (audited as view). Saving with empty content = metadata-only change.
/// </summary>
public sealed class EditModel(EntryService read, EntryWriteService write) : PageModel
{
    public bool WriteEnabled => write.Enabled;
    public string Path { get; private set; } = "";
    public EntryFormData? Form { get; private set; }
    public string? Error { get; private set; }

    public Task OnGetAsync(string domain, string group, string name, CancellationToken ct) =>
        Load(domain, group, name, withContent: false, ct);

    public Task OnPostLoadAsync(string domain, string group, string name, CancellationToken ct) =>
        Load(domain, group, name, withContent: true, ct);

    private async Task Load(string domain, string group, string name, bool withContent, CancellationToken ct)
    {
        Path = $"{domain}/{group}/{name}";
        try
        {
            if (!StoreRules.IsValidLogicalPath(Path)) throw new EntryException(EntryError.NotFound, "Entry not found");
            var (_, e) = await read.FindAsync(Path, ct);

            var content = "";
            if (withContent)
                content = e.Type switch
                {
                    "doc" => await read.GetDocAsync(HttpContext, Path, ct),
                    "kv" => await read.GetKvTextAsync(HttpContext, Path, ct),
                    "file" => (await read.GetFileViewAsync(HttpContext, Path, ct)).Text
                              ?? throw new EntryException(EntryError.WrongType, "Binary files cannot be edited in the browser; upload a new file instead"),
                    _ => "",
                };

            Form = new EntryFormData
            {
                IsEdit = true,
                Action = "/api/entry/update",
                CancelUrl = "/entry/" + Path,
                Path = Path,
                Type = e.Type!,
                Title = e.Title,
                Description = e.Description ?? "",
                Tags = string.Join(", ", e.Tags),
                Aliases = string.Join(", ", e.Aliases),
                Target = e.Target ?? "",
                Acl = e.Acl ?? "",
                Machines = string.Join(", ", e.Machines),
                Rotate = e.Rotate ?? "",
                Readers = string.Join(", ", e.Readers),
                Priority = e.Priority ?? "",
                Linked = string.Join(", ", e.Linked),
                Content = content,
                Expected = e.Fingerprint,
            };
        }
        catch (EntryException ex)
        {
            Error = ex.Message;
            Response.StatusCode = ex.StatusCode;
        }
    }
}
