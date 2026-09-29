namespace SecretsWeb.Format;

/// <summary>
/// One [[entry]] of the catalog. Non-empty <see cref="Errors"/> = this entry is unavailable (flagged in the list, an error
/// when opened) without affecting other entries. Error descriptions only name the rule, never any value.
/// </summary>
public sealed record CatalogEntry(
    int Line,
    string? Path,
    string? Type,
    string Title,
    string? Description,
    IReadOnlyList<string> Fields,
    IReadOnlyList<string> Tags,
    IReadOnlyList<string> Aliases,
    string? Updated,
    string? Target,
    string? Acl,
    IReadOnlyList<string> Machines,
    string? Rotate,
    IReadOnlyList<string> Readers,
    string? Priority,
    IReadOnlyList<string> Linked,
    string Fingerprint,
    IReadOnlyList<string> Errors)
{
    public const string InvalidGroup = "(invalid path)";

    public bool IsValid => Errors.Count == 0;

    /// <summary>Both path and type are valid: the ciphertext path can be computed and the entry can be routed to.</summary>
    public bool HasAddress => Path is not null && StoreRules.IsValidLogicalPath(Path) && Type is not null && StoreRules.Types.Contains(Type);

    public string Domain => HasAddress ? Path!.Split('/')[0] : InvalidGroup;
    public string Group => HasAddress ? Path!.Split('/')[1] : InvalidGroup;
    public string Name => HasAddress ? Path!.Split('/')[2] : "";
    public string StorePath => HasAddress ? StoreRules.StorePathFor(Path!, Type!) : throw new InvalidOperationException("Entry has no valid address");
    public string DisplayTitle => string.IsNullOrWhiteSpace(Title) ? "(untitled)" : Title;
}

public sealed record Catalog(string Format, IReadOnlyList<CatalogEntry> Entries, IReadOnlyList<string> Warnings)
{
    private readonly Dictionary<string, CatalogEntry> _byPath = BuildIndex(Entries);

    private static Dictionary<string, CatalogEntry> BuildIndex(IReadOnlyList<CatalogEntry> entries)
    {
        var d = new Dictionary<string, CatalogEntry>(StringComparer.Ordinal);
        foreach (var e in entries)
            if (e.HasAddress) d.TryAdd(e.Path!, e); // duplicate path: the first one wins, later ones carry a duplicate error
        return d;
    }

    public CatalogEntry? Find(string path) => _byPath.GetValueOrDefault(StoreRules.Nfc(path));

    /// <summary>Fingerprint of an entry block (first 16 hex chars of the SHA-256 of its canonical form): optimistic concurrency (If-Match) when editing.</summary>
    public static string Fingerprint(TomlBlock b) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(TomlWriter.Write([b]))))[..16];

    public int InvalidCount => Entries.Count(e => !e.IsValid);

    /// <summary>
    /// FORMAT catalog rules. The only whole-file failures (throwing <see cref="SecretFormatException"/>) are: a TOML syntax
    /// error, a first block that isn't [[meta]], or a missing / unknown format. Every other value problem only makes that
    /// entry unavailable (matching the per-entry judgement of the CLI's Sec-LoadCatalog).
    /// </summary>
    public static Catalog Parse(string text, Recipients recipients)
    {
        var blocks = RestrictedToml.Parse(text);
        if (blocks.Count == 0 || blocks[0].Name != "meta")
            throw new SecretFormatException("The first block of catalog.toml must be [[meta]]");
        if (!blocks[0].Values.TryGetValue("format", out var fv) || fv is not TomlValue.Str { Value: StoreRules.CatalogFormat })
            throw new SecretFormatException("catalog.toml format is missing or not supported by this service");

        var warnings = new List<string>();
        var entries = new List<CatalogEntry>();
        var paths = new HashSet<string>(StringComparer.Ordinal);
        var aliasesSeen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var b in blocks.Skip(1))
        {
            if (b.Name == "meta") { warnings.Add($"line {b.Line}: extra [[meta]] (ignored)"); continue; }
            if (b.Name != "entry") continue; // unknown table array name: ignored
            entries.Add(ParseEntry(b, recipients, paths, aliasesSeen));
        }

        // linked must point at existing entries (only known once everything is parsed)
        var known = entries.Where(e => e.HasAddress).Select(e => e.Path!).ToHashSet(StringComparer.Ordinal);
        for (var i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            if (e.Linked.Any(l => !known.Contains(l)))
                entries[i] = e with { Errors = [.. e.Errors, "linked points at an entry that does not exist"] };
        }
        return new Catalog(StoreRules.CatalogFormat, entries, warnings);
    }

    private static CatalogEntry ParseEntry(TomlBlock b, Recipients recipients, HashSet<string> paths, HashSet<string> aliasesSeen)
    {
        var errors = new List<string>();

        string? Str(string key, bool required)
        {
            if (!b.Values.TryGetValue(key, out var v)) { if (required) errors.Add($"missing {key}"); return null; }
            if (v is TomlValue.Str s) return s.Value;
            errors.Add($"{key} must be a string");
            return null;
        }

        IReadOnlyList<string>? Arr(string key)
        {
            if (!b.Values.TryGetValue(key, out var v)) return null;
            if (v is TomlValue.StrArray a) return a.Values;
            errors.Add($"{key} must be a string array");
            return null;
        }

        var path = Str("path", true);
        var type = Str("type", true);
        var title = Str("title", true);
        var description = Str("description", false);
        var updated = Str("updated", true);
        var target = Str("target", false);
        var acl = Str("acl", false);
        var fields = Arr("fields");
        var machines = Arr("machines");
        var tags = Arr("tags");
        var aliases = Arr("aliases");

        if (path is not null && !StoreRules.IsValidLogicalPath(path)) errors.Add("invalid path");
        if (type is not null && !StoreRules.Types.Contains(type)) errors.Add("invalid type");
        if (path is not null && StoreRules.IsValidLogicalPath(path) && !paths.Add(path)) errors.Add("duplicate path");
        if (title is not null && string.IsNullOrWhiteSpace(title)) errors.Add("title is empty");

        var rotate = Str("rotate", false);
        if (rotate is not null && string.IsNullOrWhiteSpace(rotate)) errors.Add("rotate is empty");
        var priority = Str("priority", false);
        if (priority is not null && priority is not ("high" or "normal" or "low")) errors.Add("invalid priority (only high / normal / low)");
        var readers = Arr("readers");
        var linked = Arr("linked");
        foreach (var (key, list) in new (string, IReadOnlyList<string>?)[] { ("tags", tags), ("readers", readers), ("linked", linked) })
            if (list is not null && list.Any(string.IsNullOrWhiteSpace))
                errors.Add($"{key} contains an empty element");
        if (linked is not null && linked.Any(l => !StoreRules.IsValidLogicalPath(l))) errors.Add("a linked element is not a valid entry path");
        if (updated is not null && !StoreRules.IsValidDate(updated)) errors.Add("updated is not a valid date YYYY-MM-DD");

        if (type == "kv")
        {
            if (!b.Has("fields")) errors.Add("kv entry is missing fields");
            else if (fields is not null)
            {
                if (fields.Count == 0) errors.Add("fields is empty");
                if (fields.Any(f => !KvParser.KeyRegex.IsMatch(f))) errors.Add("fields contains an invalid field name");
                if (fields.Distinct(StringComparer.Ordinal).Count() != fields.Count) errors.Add("fields has duplicates");
            }
        }
        else if (b.Has("fields")) errors.Add("fields is only allowed for kv entries");

        if (type != "file")
            foreach (var k in new[] { "target", "acl", "machines" })
                if (b.Has(k)) errors.Add($"{k} is only allowed for file entries");
        if (acl is not null && acl is not ("private" or "inherit")) errors.Add("invalid acl");
        if (target is not null && TargetSyntax.Check(target) is { } terr) errors.Add("invalid target: " + terr);
        if (machines is not null && machines.Any(m => !recipients.IsDeviceName(m))) errors.Add("machines may only name recipients of type device");

        if (aliases is not null)
            foreach (var a in aliases)
            {
                var err = global::SecretsWeb.Format.Aliases.Check(a);
                if (err is not null) { errors.Add(err); continue; }
                if (!aliasesSeen.Add(global::SecretsWeb.Format.Aliases.Normalize(a))) errors.Add("alias duplicates another entry");
            }

        return new CatalogEntry(
            b.Line, path, type, title ?? "", description, fields ?? [], tags ?? [], aliases ?? [], updated,
            target, acl, machines ?? [], rotate, readers ?? [], priority, linked ?? [], Fingerprint(b), errors);
    }
}

/// <summary>FORMAT target syntax, rule for rule the same as the CLI's Sec-CheckTargetSyntax (allowed roots ~/.ssh/ and {workspace}/).</summary>
public static class TargetSyntax
{
    /// <summary>Returns null when valid, otherwise an error description.</summary>
    public static string? Check(string target)
    {
        if (string.IsNullOrEmpty(target)) return "empty";
        string rest;
        if (target.StartsWith("~/.ssh/", StringComparison.Ordinal)) rest = target[7..];
        else if (target.StartsWith("{workspace}/", StringComparison.Ordinal)) rest = target[12..];
        else if (target.StartsWith("~/", StringComparison.Ordinal)) return "outside the allowed roots (~/.ssh/, {workspace}/)";
        else return "must start with ~/.ssh/ or {workspace}/";
        if (rest.Length == 0) return "no file name after the root";
        foreach (var ch in rest)
        {
            if (ch < 32 || ch == 127) return "control character";
            if (ch == '\\') return "backslash";
            if (ch is '{' or '}') return "placeholder outside the start";
            if (ch == ':') return "drive letter or colon";
        }
        foreach (var s in rest.Split('/'))
        {
            if (s.Length == 0) return "empty segment";
            if (s is "." or "..") return ". or .. segment";
            if (s.EndsWith('.') || s.EndsWith(' ')) return "segment ending in dot or space";
            if (StoreRules.IsReservedName(s)) return "reserved device name";
        }
        return null;
    }
}

/// <summary>
/// FORMAT aliases: legacy pointers of the form <c>&lt;source&gt;:&lt;path&gt;[#&lt;anchor&gt;]</c>, e.g. <c>notes:infra/db.md#Prod</c>.
/// The source is not a fixed list — any name matching <see cref="SourceRegex"/> — so each deployment can name its own
/// note stores, wikis or config repos.
/// </summary>
public static class Aliases
{
    public static readonly System.Text.RegularExpressions.Regex SourceRegex =
        new("^[a-z][a-z0-9-]*\\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    public static string Normalize(string alias)
    {
        var s = alias.Trim();
        if (s.StartsWith("[[", StringComparison.Ordinal) && s.EndsWith("]]", StringComparison.Ordinal) && s.Length >= 4)
            s = s[2..^2];
        s = StoreRules.Nfc(s.Replace('\\', '/'));
        var hash = s.LastIndexOf('#');
        var pathPart = hash >= 0 ? s[..hash] : s;
        var anchor = hash >= 0 ? s[hash..] : "";
        if (pathPart.EndsWith(".md", StringComparison.Ordinal)) pathPart = pathPart[..^3];
        return pathPart + anchor;
    }

    /// <summary>Returns null when valid. Requires a well-formed source prefix and a non-empty path after the colon (anchor removed).</summary>
    public static string? Check(string alias)
    {
        var n = Normalize(alias);
        var hash = n.LastIndexOf('#');
        var pathPart = hash >= 0 ? n[..hash] : n;
        var colon = pathPart.IndexOf(':');
        if (colon <= 0 || !SourceRegex.IsMatch(pathPart[..colon])) return "alias is missing a valid source prefix (<source>:<path>)";
        if (pathPart[(colon + 1)..].Trim().Length == 0) return "alias path is empty";
        return null;
    }
}
