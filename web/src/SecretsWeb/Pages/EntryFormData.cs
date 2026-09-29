namespace SecretsWeb.Pages;

/// <summary>View data for the create / edit form. <c>Content</c> only has a value after the user explicitly clicks "Load current content".</summary>
public sealed record EntryFormData
{
    public required bool IsEdit { get; init; }
    public required string Action { get; init; }
    public required string CancelUrl { get; init; }
    public string Path { get; init; } = "";
    public string Type { get; init; } = "kv";
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string Tags { get; init; } = "";
    public string Aliases { get; init; } = "";
    public string Target { get; init; } = "";
    public string Acl { get; init; } = "";
    public string Machines { get; init; } = "";
    public string Rotate { get; init; } = "";
    public string Readers { get; init; } = "";
    public string Priority { get; init; } = "";
    public string Linked { get; init; } = "";
    public string Content { get; init; } = "";

    /// <summary>When editing: the entry block fingerprint at the moment the page was opened, for optimistic concurrency on submit.</summary>
    public string Expected { get; init; } = "";
}
