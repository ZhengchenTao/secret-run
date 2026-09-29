using System.Text;

namespace SecretsWeb.Format;

/// <summary>
/// Canonical writer for the restricted TOML (FORMAT): one blank line between blocks, strings always as basic strings with
/// only the mandatory escapes, the leading run of comment lines preserved verbatim, LF, UTF-8 without BOM.
/// It writes <see cref="TomlBlock"/>s, so **unknown keys are preserved as-is** (forward compatibility).
/// </summary>
public static class TomlWriter
{
    /// <summary>Key order of catalog entries (as fixed by FORMAT); unknown keys follow in their original order.</summary>
    public static readonly string[] EntryKeyOrder =
    [
        "path", "type", "title", "description", "fields", "target", "acl", "machines", "tags",
        "rotate", "readers", "priority", "linked", "aliases", "updated",
    ];

    public static string Write(IEnumerable<TomlBlock> blocks, string leadingComments = "")
    {
        var sb = new StringBuilder();
        if (leadingComments.Length > 0)
        {
            sb.Append(leadingComments.TrimEnd('\n'));
            sb.Append('\n');
        }
        var first = sb.Length == 0;
        foreach (var b in blocks)
        {
            if (!first) sb.Append('\n');
            first = false;
            sb.Append("[[").Append(b.Name).Append("]]\n");
            foreach (var key in OrderedKeys(b))
                sb.Append(key).Append(" = ").Append(Value(b.Values[key])).Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>The leading run of comment lines (blank lines included), preserved verbatim.</summary>
    public static string LeadingComments(string text)
    {
        var sb = new StringBuilder();
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.TrimStart('\uFEFF');
            if (line.StartsWith('#')) sb.Append(line).Append('\n');
            else if (line.Trim().Length == 0 && sb.Length > 0) continue;
            else break;
        }
        return sb.ToString();
    }

    private static IEnumerable<string> OrderedKeys(TomlBlock b)
    {
        var known = EntryKeyOrder.Where(b.Values.ContainsKey);
        var rest = b.Values.Keys.Where(k => !EntryKeyOrder.Contains(k, StringComparer.Ordinal));
        return b.Name == "entry" ? known.Concat(rest) : b.Values.Keys;
    }

    public static string Value(TomlValue v) => v switch
    {
        TomlValue.Str s => Quote(s.Value),
        TomlValue.Bool b => b.Value ? "true" : "false",
        TomlValue.StrArray a => a.Values.Count == 0 ? "[]" : "[" + string.Join(", ", a.Values.Select(Quote)) + "]",
        _ => throw new SecretFormatException("TOML value type that cannot be written"),
    };

    public static string Quote(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\t': sb.Append("\\t"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (c <= '' || c == '') sb.Append("\\u").Append(((int)c).ToString("X4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    public static TomlBlock Block(string name, int line, IEnumerable<KeyValuePair<string, TomlValue>> values)
    {
        var d = new Dictionary<string, TomlValue>(StringComparer.Ordinal);
        foreach (var kv in values) d[kv.Key] = kv.Value;
        return new TomlBlock(name, line, d);
    }
}
