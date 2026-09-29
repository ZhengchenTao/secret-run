using Microsoft.AspNetCore.Mvc.RazorPages;
using SecretsWeb.Services;

namespace SecretsWeb.Pages;

public sealed class NewModel(EntryWriteService write) : PageModel
{
    public bool WriteEnabled => write.Enabled;

    public EntryFormData Form { get; private set; } = null!;

    public void OnGet(string? type) =>
        Form = new EntryFormData
        {
            IsEdit = false,
            Action = "/api/entry/create",
            CancelUrl = "/",
            Type = type is "kv" or "doc" or "file" ? type : "kv",
        };
}
