using System.Text.RegularExpressions;

namespace SecretsWeb.Format;

public sealed record Recipient(string Name, string Type, string Key, string Status, string Added);

/// <summary>
/// FORMAT recipients.toml. The web UI uses it to validate catalog <c>machines</c> and to expand policies when writing.
/// A TOML syntax error fails as a whole; a value problem in one record only drops that record and adds to <see cref="Errors"/>
/// (the same per-item judgement as the catalog).
/// </summary>
public sealed record Recipients(IReadOnlyList<Recipient> Items, IReadOnlyList<string> Errors)
{
    private static readonly Regex KeyRegex = new("^age1[02-9ac-hj-np-z]{58}\\z", RegexOptions.CultureInvariant);

    public static readonly Recipients Empty = new([], []);

    public bool IsDeviceName(string name) => Items.Any(r => r.Type == "device" && r.Name == name);

    public static Recipients Parse(string text)
    {
        var list = new List<Recipient>();
        var errors = new List<string>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var b in RestrictedToml.Parse(text))
        {
            if (b.Name != "recipient") continue;
            var errs = new List<string>();

            string? Str(string key, bool required)
            {
                if (!b.Values.TryGetValue(key, out var v)) { if (required) errs.Add($"missing {key}"); return null; }
                if (v is TomlValue.Str s) return s.Value;
                errs.Add($"{key} must be a string");
                return null;
            }

            var name = Str("name", true);
            var type = Str("type", true);
            var key = Str("key", true);
            var status = Str("status", true);
            var added = Str("added", true);
            Str("backup", false);
            Str("note", false);

            if (name is not null && !StoreRules.IsValidSegment(name)) errs.Add("invalid name");
            if (type is not null && type is not ("device" or "service" or "recovery")) errs.Add("invalid type");
            if (key is not null && !KeyRegex.IsMatch(key)) errs.Add("key is not a valid age X25519 public key (must be all lowercase)");
            if (status is not null && status is not ("active" or "pending" or "revoked")) errs.Add("invalid status");
            if (added is not null && !StoreRules.IsValidDate(added)) errs.Add("added is not YYYY-MM-DD");
            if (b.Has("backup") && type != "recovery") errs.Add("backup is only allowed for recovery");
            if (name is not null && errs.Count == 0 && !names.Add(name)) errs.Add("duplicate name");
            if (key is not null && errs.Count == 0 && !keys.Add(key)) errs.Add("key duplicates another recipient");

            if (errs.Count > 0) errors.Add($"recipients.toml, record starting at line {b.Line}: " + string.Join("; ", errs));
            else list.Add(new Recipient(name!, type!, key!, status!, added!));
        }
        return new Recipients(list, errors);
    }
}
