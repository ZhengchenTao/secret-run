using System.Security.Claims;

namespace SecretsWeb;

public sealed class SiteOptions
{
    /// <summary>Public origin, e.g. https://secrets.example.com. When set, every request's Scheme/Host is rewritten to it (redirect_uri depends on it).</summary>
    public string PublicOrigin { get; set; } = "";
}

/// <summary>
/// What sits in front of this service. It decrypts every secret encrypted to its identity, so it must never be reachable
/// without a network access layer (Tailscale, Cloudflare Access, a VPN, an authenticating reverse proxy ...).
/// </summary>
public sealed class DeploymentOptions
{
    public const string Section = "Deployment";

    /// <summary>
    /// Free text describing the access layer (e.g. <c>tailscale</c>, <c>cloudflare-access</c>, <c>vpn</c>).
    /// Required in Production; the literal <c>none</c> starts the service but logs a prominent warning.
    /// </summary>
    public string AccessLayer { get; set; } = "";
}

/// <summary>Reverse proxies whose X-Forwarded-For / X-Forwarded-Proto are trusted. Both empty = forwarded headers are ignored.</summary>
public sealed class NetworkOptions
{
    public const string Section = "Network";

    /// <summary>IP addresses of trusted proxies, e.g. <c>["172.17.0.1"]</c>.</summary>
    public string[] KnownProxies { get; set; } = [];

    /// <summary>CIDR ranges of trusted proxies, e.g. <c>["10.0.0.0/8"]</c>.</summary>
    public string[] KnownNetworks { get; set; } = [];
}

public sealed class OidcOptions
{
    public const string Section = "Auth";

    /// <summary>Used when <see cref="Scopes"/> ends up empty.</summary>
    public static readonly string[] DefaultScopes = ["openid", "email", "profile"];

    /// <summary>Claim that carries the email address on the session principal. Only present when the IdP said <c>email_verified</c> = true.</summary>
    public const string VerifiedEmailClaim = "verified_email";

    public string Authority { get; set; } = "";
    public string ClientId { get; set; } = "";

    /// <summary>Only injected from the environment variable Auth__ClientSecret; keep it empty in appsettings.</summary>
    public string ClientSecret { get; set; } = "";

    public string CallbackPath { get; set; } = "/signin-oidc";

    /// <summary>
    /// Default comes from appsettings.json (<c>openid email profile</c>). The class default stays empty on purpose:
    /// the configuration binder appends to an existing array instead of replacing it.
    /// </summary>
    public string[] Scopes { get; set; } = [];

    /// <summary>Optional: add an RFC 8707 <c>resource</c> parameter to the authorization request; empty = not sent.</summary>
    public string Resource { get; set; } = "";

    /// <summary>id_token <c>sub</c> values that may sign in (exact, case-sensitive match).</summary>
    public string[] AllowedSubjects { get; set; } = [];

    /// <summary>
    /// Email addresses that may sign in (trimmed, case-insensitive). Only honored when the id_token says
    /// <c>email_verified</c> is true. Both allowlists empty = nobody can sign in, so startup fails (fail closed).
    /// </summary>
    public string[] AllowedEmails { get; set; } = [];

    /// <summary>When non-empty, the id_token's <c>amr</c> must contain this value.</summary>
    public string RequireAmr { get; set; } = "";

    public int IdleTimeoutMinutes { get; set; } = 15;
    public int MaxLifetimeHours { get; set; } = 8;

    public bool HasAllowlist =>
        AllowedSubjects.Any(s => !string.IsNullOrWhiteSpace(s)) || AllowedEmails.Any(e => !string.IsNullOrWhiteSpace(e));

    /// <summary>
    /// <paramref name="verifiedEmail"/> must only be passed when the IdP marked it verified — an unverified address
    /// is just a string the user typed into their IdP profile.
    /// </summary>
    public bool IsAllowed(string? sub, string? verifiedEmail = null) =>
        (!string.IsNullOrEmpty(sub) && AllowedSubjects.Contains(sub, StringComparer.Ordinal))
        || IsAllowedEmail(verifiedEmail);

    public bool IsAllowedEmail(string? email)
    {
        var e = email?.Trim();
        return !string.IsNullOrEmpty(e)
               && AllowedEmails.Any(a => string.Equals(a?.Trim(), e, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Checks a session principal (the normalized one built at sign-in).</summary>
    public bool IsAllowed(ClaimsPrincipal? principal) =>
        principal is not null && IsAllowed(principal.FindFirst("sub")?.Value, principal.FindFirst(VerifiedEmailClaim)?.Value);
}

public sealed class RepoOptions
{
    public const string Section = "Repo";

    public string GitDir { get; set; } = "/repo";
    public string Identity { get; set; } = "/identity/identity.txt";
    public string GitPath { get; set; } = "git";
    public string AgePath { get; set; } = "age";
    public int CommandTimeoutSeconds { get; set; } = 30;
    public int FileTextMaxBytes { get; set; } = 256 * 1024;
    public int FileMaxBytes { get; set; } = 1024 * 1024;
    public int DocMaxBytes { get; set; } = 1024 * 1024;

    // ---- Writes (create / edit / delete from the web UI). Empty PushUrl = this instance is read-only ----

    /// <summary>Push URL, e.g. <c>ssh://git@git.example.com/you/secrets.git</c>. Empty = the web UI is read-only.</summary>
    public string PushUrl { get; set; } = "";

    public string Branch { get; set; } = "main";

    /// <summary>Working clone inside the container (must be writable; with a read-only root filesystem it lives under /data).</summary>
    public string WorkDir { get; set; } = "/data/work";

    /// <summary>Deploy key for the git server (read-only mount, mode 600). Empty = default ssh behavior (not needed for local-path pushes).</summary>
    public string SshKey { get; set; } = "";

    public string KnownHosts { get; set; } = "";

    public string CommitAuthorName { get; set; } = "secrets-web";
    public string CommitAuthorEmail { get; set; } = "secrets-web@localhost";

    /// <summary>
    /// Favorites list (web UI only, see <see cref="Services.FavoriteStore"/>). A server-side file that is neither in the
    /// data repo nor in the catalog, so the CLI and the format contract are unaffected; every device sees the same list.
    /// </summary>
    public string FavoritesPath { get; set; } = "/data/favorites.json";
}

public sealed class AuditOptions
{
    public const string Section = "Audit";
    public string Path { get; set; } = "/data/audit.log";

    /// <summary>Rotate once the file exceeds this size; &lt;= 0 disables rotation.</summary>
    public long MaxBytes { get; set; } = 8 * 1024 * 1024;

    /// <summary>How many rotated files to keep (audit.log.1 … .N).</summary>
    public int KeepFiles { get; set; } = 5;
}

/// <summary>Per-session decryption rate limits and the decryption-volume anomaly alert.</summary>
public sealed class DecryptLimitOptions
{
    public const string Section = "DecryptLimits";
    public int PerMinute { get; set; } = 20;

    /// <summary>Write operations (create / edit / delete) per session per minute.</summary>
    public int WritePerMinute { get; set; } = 10;
    public int PerHour { get; set; } = 200;
    public int DistinctWindowMinutes { get; set; } = 10;
    public int DistinctThreshold { get; set; } = 30;
}

public sealed class AlertOptions
{
    public const string Section = "Alerts";

    /// <summary>
    /// Generic webhook: alerts are POSTed as JSON <c>{"title", "text", "severity"}</c>. Empty = alerts are only logged.
    /// Point it at whatever relays to your chat / pager (a small adapter, ntfy, a Slack-compatible relay ...).
    /// </summary>
    public string WebhookUrl { get; set; } = "";

    /// <summary>Optional; sent as <c>Authorization: Bearer &lt;token&gt;</c>. Keep it in .env only.</summary>
    public string WebhookToken { get; set; } = "";

    public int MinIntervalMinutes { get; set; } = 10;

    /// <summary>Alert once when more than this many **distinct entries** are changed within the window (the alert never names entries).</summary>
    public int WriteDistinctEntries { get; set; } = 5;

    public int WriteWindowMinutes { get; set; } = 10;
}
