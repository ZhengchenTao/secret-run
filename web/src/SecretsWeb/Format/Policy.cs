using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SecretsWeb.Format;

/// <summary>FORMAT: glob semantics and the recipient-set hash, implemented exactly like the CLI (writes depend on it).</summary>
public static class Policy
{
    /// <summary>Anchored to the whole string: ** → .*, * → [^/]*, ? → [^/], everything else escaped literally.</summary>
    public static Regex GlobToRegex(string pattern)
    {
        var sb = new StringBuilder("^");
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '*' && i + 1 < pattern.Length && pattern[i + 1] == '*') { sb.Append(".*"); i++; }
            else if (c == '*') sb.Append("[^/]*");
            else if (c == '?') sb.Append("[^/]");
            else sb.Append(Regex.Escape(c.ToString()));
        }
        sb.Append("\\z"); // \z rather than $: in .NET, $ also matches before a trailing newline
        return new Regex(sb.ToString(), RegexOptions.CultureInvariant | RegexOptions.Singleline);
    }

    public static bool GlobMatch(string pattern, string path) => GlobToRegex(pattern).IsMatch(path);

    /// <summary>Deduplicate public keys, sort ordinally, join with \n (no trailing newline), UTF-8 SHA-256 as lowercase hex.</summary>
    public static string RecipientSetHash(IEnumerable<string> publicKeys)
    {
        var sorted = publicKeys.Distinct(StringComparer.Ordinal).OrderBy(k => k, StringComparer.Ordinal);
        var joined = string.Join('\n', sorted);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(joined)));
    }
}
