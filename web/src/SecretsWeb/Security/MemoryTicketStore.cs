using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace SecretsWeb.Security;

/// <summary>
/// Server-side session: the cookie only holds a random session id, the ticket lives in process memory.
/// Memory entries carry the same idle sliding expiry + absolute expiry since login; a restart invalidates every session
/// (acceptable for a small allowlist: just sign in again).
/// </summary>
public sealed class MemoryTicketStore(IMemoryCache cache, IOptions<OidcOptions> options, TimeProvider time) : ITicketStore
{
    private const string Prefix = "ticket:";
    private readonly OidcOptions _o = options.Value;

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        Put(key, ticket);
        return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        Put(key, ticket);
        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key) =>
        Task.FromResult(cache.TryGetValue(Prefix + key, out AuthenticationTicket? t) ? t : null);

    public Task RemoveAsync(string key)
    {
        cache.Remove(Prefix + key);
        return Task.CompletedTask;
    }

    private void Put(string key, AuthenticationTicket ticket)
    {
        var login = SessionPolicy.GetLoginUtc(ticket.Properties) ?? time.GetUtcNow();
        cache.Set(Prefix + key, ticket, new MemoryCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromMinutes(_o.IdleTimeoutMinutes),
            AbsoluteExpiration = login + TimeSpan.FromHours(_o.MaxLifetimeHours),
        });
    }

    private static string Base64UrlEncode(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public static class SessionPolicy
{
    public const string LoginUtcKey = ".secrets-web.login_utc";

    public static DateTimeOffset? GetLoginUtc(AuthenticationProperties props) =>
        props.Items.TryGetValue(LoginUtcKey, out var v) &&
        DateTimeOffset.TryParse(v, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d)
            ? d
            : null;

    /// <summary>Older than the maximum lifetime since login (or login time missing / in the future) → reject.</summary>
    public static bool IsExpired(AuthenticationProperties props, DateTimeOffset now, TimeSpan maxLifetime)
    {
        var login = GetLoginUtc(props);
        return login is null || now - login.Value > maxLifetime || login.Value > now + TimeSpan.FromMinutes(5);
    }

    public static Task ValidatePrincipal(CookieValidatePrincipalContext ctx, OidcOptions o, TimeProvider time)
    {
        // the allowlist is re-checked on every request, so removing someone from it takes effect without a restart
        if (IsExpired(ctx.Properties, time.GetUtcNow(), TimeSpan.FromHours(o.MaxLifetimeHours)) || !o.IsAllowed(ctx.Principal))
        {
            ctx.RejectPrincipal();
            return ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
        return Task.CompletedTask;
    }
}
