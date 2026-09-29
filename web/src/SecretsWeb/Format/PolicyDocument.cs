namespace SecretsWeb.Format;

public sealed record PolicyRule(string Path, IReadOnlyList<string> Recipients, int Line);

/// <summary>
/// FORMAT policy.toml: rule → recipients. **The last matching rule wins** (rules are not merged);
/// groups are implicit: <c>@all</c> = every active recipient, <c>@device</c> / <c>@service</c> / <c>@recovery</c> = every active recipient of that type.
/// </summary>
public sealed record PolicyDocument(IReadOnlyList<PolicyRule> Rules, IReadOnlyList<string> Errors)
{
    public static PolicyDocument Parse(string text)
    {
        var rules = new List<PolicyRule>();
        var errors = new List<string>();
        foreach (var b in RestrictedToml.Parse(text))
        {
            if (b.Name != "rule") continue;
            var path = b.Values.TryGetValue("path", out var p) && p is TomlValue.Str s ? s.Value : null;
            var recipients = b.Values.TryGetValue("recipients", out var r) && r is TomlValue.StrArray a ? a.Values : null;
            if (path is null || recipients is null)
            {
                errors.Add($"policy.toml: the [[rule]] starting at line {b.Line} is missing path or recipients");
                continue;
            }
            rules.Add(new PolicyRule(path, recipients, b.Line));
        }
        return new PolicyDocument(rules, errors);
    }

    /// <summary>Expand the recipient public keys for a ciphertext path (deduplicated, ordinal order). No matching rule or an empty result returns an error.</summary>
    public (IReadOnlyList<string> Keys, string? Error) Expand(string storePath, Recipients recipients)
    {
        PolicyRule? match = null;
        foreach (var rule in Rules)
            if (Policy.GlobMatch(rule.Path, storePath))
                match = rule; // the last match wins
        if (match is null) return ([], $"policy.toml has no rule matching {storePath}");

        var active = recipients.Items.Where(r => r.Status == "active").ToList();
        var keys = new List<string>();
        foreach (var name in match.Recipients)
        {
            IEnumerable<Recipient> picked = name switch
            {
                "@all" => active,
                "@device" => active.Where(r => r.Type == "device"),
                "@service" => active.Where(r => r.Type == "service"),
                "@recovery" => active.Where(r => r.Type == "recovery"),
                _ => active.Where(r => r.Name == name), // unknown or non-active names are ignored (the CLI reports a WARN)
            };
            keys.AddRange(picked.Select(r => r.Key));
        }
        var result = keys.Distinct(StringComparer.Ordinal).OrderBy(k => k, StringComparer.Ordinal).ToList();
        if (result.Count == 0) return ([], "The policy expands to an empty recipient set; refusing to encrypt");
        return (result, null);
    }
}
