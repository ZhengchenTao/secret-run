namespace SecretsWeb.Security;

/// <summary>
/// Rate limit for failure audit lines on the anonymous surface (/signin-oidc).
/// The key is the client IP only — **never a client-supplied header**: anything a client can set, an attacker can set too,
/// and rotating a header value would let one noisy source bypass its own per-key limit.
/// **Mind the topology**: behind a reverse proxy the remote IP is the proxy's unless <c>Network:KnownProxies</c> /
/// <c>Network:KnownNetworks</c> is configured, and then "per IP" effectively becomes global — any client hammering the
/// callback could push the failure lines of a real attack out. Configure the trusted proxy so the real client IP is used.
/// A global cap per minute is kept on top, so many distinct keys still can't flood the audit log.
/// </summary>
public sealed class LoginFailureLimiter(TimeProvider time)
{
    public const int PerMinute = 10;
    public const int GlobalPerMinute = 60;
    private const int MaxTrackedKeys = 10_000;

    private readonly object _gate = new();
    private readonly Dictionary<string, (DateTimeOffset Window, int Count, int Suppressed)> _byKey = new(StringComparer.Ordinal);
    private DateTimeOffset _globalWindow;
    private int _globalCount;
    private int _globalSuppressed;

    /// <summary>Limiter key: <c>ip:&lt;remote address&gt;</c> (after trusted forwarded-header processing, if configured).</summary>
    public static string KeyFor(HttpContext ctx) =>
        "ip:" + (ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown");

    /// <summary>Returns null = don't write this line (it has been counted); otherwise write it, and the value is how many were suppressed before.</summary>
    public int? TryAcquire(string? key)
    {
        var k = string.IsNullOrEmpty(key) ? "unknown" : key;
        var now = time.GetUtcNow();
        var minute = TimeSpan.FromMinutes(1);
        lock (_gate)
        {
            if (now - _globalWindow >= minute) { _globalWindow = now; _globalCount = 0; }
            if (_globalCount >= GlobalPerMinute) { _globalSuppressed++; return null; }

            if (_byKey.Count > MaxTrackedKeys) _byKey.Clear();
            var suppressed = 0;
            if (!_byKey.TryGetValue(k, out var s) || now - s.Window >= minute)
            {
                suppressed = _byKey.TryGetValue(k, out var old) ? old.Suppressed : 0;
                _byKey[k] = (now, 1, 0);
            }
            else if (s.Count >= PerMinute)
            {
                _byKey[k] = s with { Suppressed = s.Suppressed + 1 };
                return null;
            }
            else
            {
                _byKey[k] = s with { Count = s.Count + 1 };
            }

            _globalCount++;
            var total = suppressed + _globalSuppressed;
            _globalSuppressed = 0;
            return total;
        }
    }
}
