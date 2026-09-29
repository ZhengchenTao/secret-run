using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SecretsWeb.Alerts;

namespace SecretsWeb.Security;

/// <summary>
/// Rate limiting of decryptions within a signed-in session (damage control if a cookie is stolen: no decrypting every
/// entry within seconds) + the decryption-volume anomaly alert. See <see cref="KeyFor"/> for how a session is identified.
/// </summary>
public sealed class DecryptRateLimiter(
    IOptions<DecryptLimitOptions> options, IOptions<AlertOptions> alertOptions, TimeProvider time,
    IAlertService alerts, ILogger<DecryptRateLimiter> logger)
{
    private readonly DecryptLimitOptions _o = options.Value;
    private readonly AlertOptions _alerts = alertOptions.Value;
    private readonly object _gate = new();
    private readonly Dictionary<string, List<DateTimeOffset>> _hits = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<DateTimeOffset>> _writes = new(StringComparer.Ordinal);
    private readonly List<(DateTimeOffset At, string Path)> _distinct = [];
    private readonly List<(DateTimeOffset At, string Path)> _written = [];
    private const int MaxTrackedSessions = 1000;

    public const string SessionCookieName = "__Host-secrets-web";

    /// <summary>Random session id put into the ticket at sign-in: sliding renewal re-issues the cookie (the string changes), this claim does not.</summary>
    public const string SessionIdClaim = "sid";

    /// <summary>
    /// Rate-limit key. **sub + sid claim first**: the cookie uses SlidingExpiration and is re-issued past half the window,
    /// so keying on the raw cookie would give the same session a new key every few minutes and make the hourly cap meaningless.
    /// Only without a sid (e.g. an older ticket) fall back to a cookie hash, and only then to sub.
    /// </summary>
    public static string KeyFor(HttpContext ctx)
    {
        var sub = ctx.User.FindFirst("sub")?.Value;
        var sid = ctx.User.FindFirst(SessionIdClaim)?.Value;
        if (!string.IsNullOrEmpty(sub) && !string.IsNullOrEmpty(sid)) return $"u:{sub}|{sid}";

        var cookie = ctx.Request.Cookies[SessionCookieName];
        if (!string.IsNullOrEmpty(cookie))
            return "s:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(cookie)))[..16];
        return "u:" + (sub ?? "anonymous");
    }

    /// <summary>Over the limit → false (caller returns 429). Otherwise counts one hit.</summary>
    public bool TryAcquire(string key)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (_hits.Count > MaxTrackedSessions) _hits.Clear();
            if (!_hits.TryGetValue(key, out var list)) _hits[key] = list = [];
            list.RemoveAll(t => now - t > TimeSpan.FromHours(1));
            var perMinute = list.Count(t => now - t <= TimeSpan.FromMinutes(1));
            if (perMinute >= _o.PerMinute || list.Count >= _o.PerHour)
            {
                logger.LogWarning("Decrypt rate limit hit: per minute {Min}/{MaxMin}, per hour {Hour}/{MaxHour}",
                    perMinute, _o.PerMinute, list.Count, _o.PerHour);
                return false;
            }
            list.Add(now);
            return true;
        }
    }

    /// <summary>Write rate limit (looser than decryption). Over the limit → false (caller returns 429).</summary>
    public bool TryAcquireWrite(string key)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (_writes.Count > MaxTrackedSessions) _writes.Clear();
            if (!_writes.TryGetValue(key, out var list)) _writes[key] = list = [];
            list.RemoveAll(t => now - t > TimeSpan.FromMinutes(1));
            if (list.Count >= _o.WritePerMinute)
            {
                logger.LogWarning("Write rate limit hit: per minute {Count}/{Max}", list.Count, _o.WritePerMinute);
                return false;
            }
            list.Add(now);
            return true;
        }
    }

    /// <summary>
    /// Record an entry after a successful write: more distinct entries changed within the window than the threshold → one alert
    /// (the text only has counts and thresholds, never entry names). Shares the alert rate limit with the decryption anomaly alert.
    /// </summary>
    public void RecordWrittenEntry(string entryPath)
    {
        var window = TimeSpan.FromMinutes(Math.Max(1, _alerts.WriteWindowMinutes));
        bool fire;
        lock (_gate)
        {
            var now = time.GetUtcNow();
            _written.RemoveAll(x => now - x.At > window);
            _written.Add((now, entryPath));
            fire = _written.Select(x => x.Path).Distinct(StringComparer.Ordinal).Count() > _alerts.WriteDistinctEntries;
        }
        if (fire)
            alerts.Raise($"Unusual write volume (more than {_alerts.WriteDistinctEntries} distinct entries changed within {_alerts.WriteWindowMinutes} minutes)");
    }

    /// <summary>Record an entry after a successful decryption, for the "too many distinct entries in a short time" alert (the alert never names entries).</summary>
    public void RecordEntry(string entryPath)
    {
        var window = TimeSpan.FromMinutes(_o.DistinctWindowMinutes);
        bool fire;
        lock (_gate)
        {
            var now = time.GetUtcNow();
            _distinct.RemoveAll(x => now - x.At > window);
            _distinct.Add((now, entryPath));
            fire = _distinct.Select(x => x.Path).Distinct(StringComparer.Ordinal).Count() > _o.DistinctThreshold;
        }
        if (fire) alerts.Raise($"Unusual decryption volume (more than {_o.DistinctThreshold} distinct entries decrypted within {_o.DistinctWindowMinutes} minutes)");
    }
}
