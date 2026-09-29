using System.Text.RegularExpressions;

namespace SecretsWeb.Format;

/// <summary>FORMAT: the kv dotenv subset, parsed strictly: any invalid line fails the whole entry. Errors carry line numbers only, never line content.</summary>
public static class KvParser
{
    public static readonly Regex KeyRegex = new("^[A-Z][A-Z0-9_]*\\z", RegexOptions.CultureInvariant);

    public static IReadOnlyList<KeyValuePair<string, string>> Parse(byte[] plaintext)
    {
        var text = RestrictedToml.DecodeUtf8Strict(plaintext, "kv plaintext");
        if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..]; // readers tolerate a leading BOM

        var result = new List<KeyValuePair<string, string>>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.EndsWith('\r')) line = line[..^1]; // strip at most one \r
            if (line.Length == 0 || line[0] == '#') continue;

            var eq = line.IndexOf('=');
            if (eq <= 0) throw new SecretFormatException($"kv line {i + 1} is not KEY=VALUE");
            var key = line[..eq];
            if (!KeyRegex.IsMatch(key)) throw new SecretFormatException($"kv line {i + 1} has an invalid key");
            var value = line[(eq + 1)..];
            if (value.Contains('\r') || value.Contains('\0'))
                throw new SecretFormatException($"kv line {i + 1} has a value containing \\r or NUL");
            if (!seen.Add(key)) throw new SecretFormatException($"kv key {key} is duplicated");
            result.Add(new(key, value));
        }
        return result;
    }
}
