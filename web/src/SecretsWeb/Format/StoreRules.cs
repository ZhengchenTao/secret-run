using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace SecretsWeb.Format;

/// <summary>FORMAT: path segments and ciphertext validity rules.</summary>
public static class StoreRules
{
    public const string CatalogFormat = "1";

    /// <summary>Every .age file must start with these bytes.</summary>
    public static ReadOnlySpan<byte> AgeHeader => "age-encryption.org/v1\n"u8;

    private static readonly Regex Segment = new("^[a-z0-9][a-z0-9-]*\\z", RegexOptions.CultureInvariant);

    private static readonly Regex StorePath = new(
        "^store/[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*\\.(kv|file|doc)\\.age\\z",
        RegexOptions.CultureInvariant);

    private static readonly Regex Date = new("^[0-9]{4}-[0-9]{2}-[0-9]{2}\\z", RegexOptions.CultureInvariant);

    public static readonly IReadOnlySet<string> Types = new HashSet<string>(StringComparer.Ordinal) { "kv", "file", "doc" };

    private static readonly HashSet<string> Reserved = BuildReserved();

    private static HashSet<string> BuildReserved()
    {
        var set = new HashSet<string>(StringComparer.Ordinal) { "con", "prn", "aux", "nul" };
        for (var i = 1; i <= 9; i++) { set.Add($"com{i}"); set.Add($"lpt{i}"); }
        return set;
    }

    /// <summary>Windows reserved device name (case-insensitive; <c>con.txt</c> with an extension counts too). Used for target path segments.</summary>
    public static bool IsReservedName(string segment)
    {
        var dot = segment.IndexOf('.');
        var stem = (dot >= 0 ? segment[..dot] : segment).TrimEnd().ToLowerInvariant();
        return Reserved.Contains(stem);
    }

    public static bool IsValidSegment(string segment) =>
        Segment.IsMatch(segment) && !Reserved.Contains(segment);

    /// <summary>
    /// Logical path <c>&lt;domain&gt;/&lt;group&gt;/&lt;name&gt;</c>: exactly three segments, each matching the segment regex and not a
    /// reserved name. The domain is not a fixed list — it is any valid segment (e.g. <c>personal</c>, <c>work</c>, <c>team</c>).
    /// </summary>
    public static bool IsValidLogicalPath(string path)
    {
        var parts = path.Split('/');
        return parts.Length == 3 && parts.All(IsValidSegment);
    }

    /// <summary>Ciphertext path inside the repo: regex + reserved-name exclusion for every segment.</summary>
    public static bool IsValidStorePath(string repoPath)
    {
        if (!StorePath.IsMatch(repoPath)) return false;
        var parts = repoPath.Split('/'); // store / domain / group / name.type.age
        var name = parts[3][..parts[3].IndexOf('.')];
        return IsValidSegment(parts[1]) && IsValidSegment(parts[2]) && IsValidSegment(name);
    }

    public static string StorePathFor(string logicalPath, string type) => $"store/{logicalPath}.{type}.age";

    public static bool HasAgeHeader(ReadOnlySpan<byte> ciphertext) => ciphertext.StartsWith(AgeHeader);

    public static bool IsValidDate(string s) =>
        Date.IsMatch(s) && DateOnly.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);

    public static string Nfc(string s) => s.Normalize(NormalizationForm.FormC);
}
