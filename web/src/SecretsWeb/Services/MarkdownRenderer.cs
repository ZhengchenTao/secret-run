using System.Text;
using Markdig;
using Markdig.Renderers;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;

namespace SecretsWeb.Services;

/// <summary>
/// Markdig: raw HTML disabled; no generic attributes; links only allow http/https/mailto/site-relative, anything else becomes #;
/// rel=noopener noreferrer everywhere; images only keep data:image/ and site-relative URLs — external images (which would leak
/// the time of viewing and the IP) are replaced by their alt text.
/// </summary>
public static class MarkdownRenderer
{
    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder()
        .DisableHtml()
        .UsePipeTables()
        .UseEmphasisExtras()
        .UseTaskLists()
        .UseAutoLinks()
        .UseReferralLinks("noopener", "noreferrer")
        .Build();

    public static string Render(string markdown)
    {
        var doc = Markdown.Parse(markdown, Pipeline);

        foreach (var link in doc.Descendants<LinkInline>().ToList())
        {
            if (link.IsImage)
            {
                if (!IsSafeImageUrl(link.Url)) link.ReplaceBy(new LiteralInline(AltText(link)));
            }
            else if (!IsSafeUrl(link.Url))
            {
                link.Url = "#";
            }
        }
        foreach (var link in doc.Descendants<AutolinkInline>())
            if (!IsSafeUrl(link.Url)) link.Url = "#";

        using var writer = new StringWriter();
        var renderer = new HtmlRenderer(writer);
        Pipeline.Setup(renderer);
        renderer.Render(doc);
        writer.Flush();
        return writer.ToString();
    }

    private static string AltText(ContainerInline c)
    {
        var sb = new StringBuilder();
        foreach (var l in c.Descendants<LiteralInline>()) sb.Append(l.Content.ToString());
        return sb.ToString();
    }

    private static bool IsSiteRelative(string u) => u.StartsWith('/') && !u.StartsWith("//") && !u.StartsWith("/\\");

    public static bool IsSafeImageUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        var u = url.Trim();
        if (u.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase)) return true;
        return IsSiteRelative(u) && !u.Contains('\\');
    }

    public static bool IsSafeUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;
        var u = url.Trim();
        if (u.StartsWith('#') || IsSiteRelative(u)) return true;
        if (u.StartsWith("//")) return true; // protocol-relative external link, same as an https link
        if (!Uri.TryCreate(u, UriKind.Absolute, out var abs)) return !u.Contains(':');
        return abs.Scheme is "http" or "https" or "mailto";
    }
}
