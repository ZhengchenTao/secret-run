using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using SecretsWeb.Alerts;
using SecretsWeb.Audit;

namespace SecretsWeb.Security;

public static class AuthSetup
{
    public const string AuditedFlag = "secrets-web.login-audited";

    /// <summary>HttpContext.Items key: the identity of a caller whose login was refused (shown back to them only).</summary>
    public const string DeniedIdentityKey = "secrets-web.denied-identity";

    /// <summary>The caller's own identity as the IdP asserted it, kept only for the "access denied" response.</summary>
    public sealed record DeniedIdentity(string? Sub, string? Email, bool EmailVerified, string Reason);

    public static void AddSecretsWebAuth(this IServiceCollection services, OidcOptions o, CookieProfile? cookies = null)
    {
        var profile = cookies ?? CookieProfile.Strict;
        // Fail fast: don't start with required OIDC settings missing (ClientSecret only comes from the environment)
        if (string.IsNullOrWhiteSpace(o.Authority) || string.IsNullOrWhiteSpace(o.ClientId) || string.IsNullOrWhiteSpace(o.ClientSecret))
            throw new InvalidOperationException(
                "Auth:Authority / Auth:ClientId / Auth:ClientSecret must be configured (ClientSecret via the environment variable Auth__ClientSecret)");
        if (!o.HasAllowlist)
            throw new InvalidOperationException(
                "Auth:AllowedSubjects and Auth:AllowedEmails are both empty, so nobody could sign in. Add at least one entry.");

        services.AddSingleton<MemoryTicketStore>();
        services.AddSingleton<LoginFailureLimiter>();
        services.AddSingleton<IdTokenVerifier>();
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<MemoryTicketStore, TimeProvider>((c, store, time) =>
            {
                ConfigureCookie(c, o, time, profile);
                c.SessionStore = store;
            });

        services.AddAuthentication(a =>
            {
                a.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                a.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(oidc => ConfigureOidc(oidc, o, profile));

        services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .RequireAssertion(ctx => o.IsAllowed(ctx.User))
                .Build());
    }

    /// <summary>Only accept site-relative paths: RedirectHttpResult.IsLocalUrl is true and there are no control characters or backslashes.</summary>
    public static bool IsSafeReturnUrl(string? url) =>
        !string.IsNullOrEmpty(url)
        && url[0] == '/'                       // no app-relative ~/ form
        && RedirectHttpResult.IsLocalUrl(url)
        && !url.Any(ch => char.IsControl(ch) || ch == '\\');

    public static void ConfigureCookie(CookieAuthenticationOptions c, OidcOptions o, TimeProvider time, CookieProfile? cookies = null)
    {
        var profile = cookies ?? CookieProfile.Strict;
        c.Cookie.Name = profile.Name("secrets-web");
        c.Cookie.HttpOnly = true;
        c.Cookie.SecurePolicy = profile.SecurePolicy;
        c.Cookie.SameSite = SameSiteMode.Lax; // the OIDC callback is a cross-site top-level GET redirect, Lax is enough
        c.Cookie.Path = "/";
        c.ExpireTimeSpan = TimeSpan.FromMinutes(o.IdleTimeoutMinutes);
        c.SlidingExpiration = true;
        c.LoginPath = "/login";
        c.AccessDeniedPath = "/denied";
        c.Events = new CookieAuthenticationEvents
        {
            OnSigningIn = ctx =>
            {
                ctx.Properties.IsPersistent = false;
                if (SessionPolicy.GetLoginUtc(ctx.Properties) is null)
                    ctx.Properties.Items[SessionPolicy.LoginUtcKey] = time.GetUtcNow().ToString("O");
                // Successful-login audit lives here: the cookie is only issued after the OIDC handler has validated nonce / state / id_token
                TryAudit(ctx.HttpContext, AuditLog.For(ctx.HttpContext, "login", ctx.Principal?.FindFirst("sub")?.Value) with { Result = "ok" });
                return Task.CompletedTask;
            },
            OnValidatePrincipal = ctx => SessionPolicy.ValidatePrincipal(ctx, o, time),
            OnRedirectToLogin = ctx =>
            {
                if (IsApiRequest(ctx.Request)) ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                else ctx.Response.Redirect(ctx.RedirectUri);
                return Task.CompletedTask;
            },
            OnRedirectToAccessDenied = ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            },
        };
    }

    private static bool IsApiRequest(HttpRequest r) =>
        !HttpMethods.IsGet(r.Method) || r.Headers.ContainsKey(CsrfHeader.Name);

    /// <summary>
    /// <c>email_verified</c> as asserted in the id_token: JSON boolean true or the string "true" (some IdPs send strings).
    /// Anything else, including a missing claim, is "not verified".
    /// </summary>
    public static bool IsEmailVerified(ClaimsPrincipal? principal)
    {
        var c = principal?.FindFirst("email_verified");
        if (c is null) return false;
        return c.Value == "true"
               || (c.ValueType == ClaimValueTypes.Boolean && string.Equals(c.Value, "true", StringComparison.OrdinalIgnoreCase));
    }

    public static void ConfigureOidc(OpenIdConnectOptions oidc, OidcOptions o, CookieProfile? cookies = null)
    {
        var profile = cookies ?? CookieProfile.Strict;
        oidc.Authority = o.Authority;
        oidc.ClientId = o.ClientId;
        oidc.ClientSecret = o.ClientSecret;              // client_secret_post
        oidc.CallbackPath = o.CallbackPath;
        oidc.ResponseType = "code";
        // The IdP redirects back with a 302 + query string. That's the default for the code flow and supported by
        // Google and other mainstream IdPs; unlike form_post it works with SameSite=Lax correlation/nonce cookies.
        oidc.ResponseMode = "query";
        oidc.UsePkce = true;
        oidc.RequireHttpsMetadata = true;
        // After a JWKS rotation the new keys can be force-refreshed after 1 minute (default 5), paired with IdTokenVerifier's retry on signature failure
        oidc.RefreshInterval = TimeSpan.FromMinutes(1);
        oidc.SaveTokens = false;                         // keep no tokens, only the identity
        oidc.GetClaimsFromUserInfoEndpoint = false;
        oidc.MapInboundClaims = false;                   // keep raw sub / amr / email / email_verified
        oidc.UseTokenLifetime = false;
        oidc.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        oidc.Scope.Clear();
        foreach (var s in o.Scopes.Length > 0 ? o.Scopes : OidcOptions.DefaultScopes) oidc.Scope.Add(s);
        oidc.TokenValidationParameters.ValidAlgorithms = ["RS256"];
        oidc.TokenValidationParameters.RequireSignedTokens = true;
        oidc.TokenValidationParameters.NameClaimType = "sub";
        // Google may put either issuer spelling into id_tokens; the handler validates the issuer too (see IdTokenVerifier).
        var issuers = IdTokenVerifier.IssuerVariants(o.Authority);
        if (issuers.Length > 1) oidc.TokenValidationParameters.ValidIssuers = issuers;
        oidc.CorrelationCookie.SecurePolicy = profile.SecurePolicy;
        oidc.CorrelationCookie.SameSite = SameSiteMode.Lax;
        oidc.NonceCookie.SecurePolicy = profile.SecurePolicy;
        oidc.NonceCookie.SameSite = SameSiteMode.Lax;

        oidc.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = ctx =>
            {
                if (!string.IsNullOrWhiteSpace(o.Resource)) ctx.ProtocolMessage.Parameters["resource"] = o.Resource;
                return Task.CompletedTask;
            },
            OnTokenValidated = async ctx =>
            {
                var http = ctx.HttpContext;

                // Independently re-verify the raw id_token (signature present and RS256, JWKS signature check, iss / aud / lifetime)
                string? verifyError;
                if (ctx.ProtocolMessage?.IdToken is { Length: > 0 })
                    verifyError = "id_token_in_authorization_response"; // code flow only: the authorization response must not carry an id_token
                else
                {
                    verifyError = await http.RequestServices.GetRequiredService<IdTokenVerifier>().VerifyAsync(
                        ctx.TokenEndpointResponse?.IdToken, ctx.Options.ConfigurationManager!, ctx.Options.ClientId!, http.RequestAborted);
                }
                if (verifyError is not null)
                {
                    http.Items[AuditedFlag] = true;
                    AuditLoginFailure(http, "login_failed", null, verifyError);
                    Alert(http, "Login failed (id_token validation did not pass)");
                    ctx.Fail("id_token validation failed");
                    return;
                }

                var sub = ctx.Principal?.FindFirst("sub")?.Value;
                var email = ctx.Principal?.FindFirst("email")?.Value?.Trim();
                var emailVerified = !string.IsNullOrEmpty(email) && IsEmailVerified(ctx.Principal);
                string? denyReason = null;
                if (!o.IsAllowed(sub, emailVerified ? email : null)) denyReason = "subject_not_allowed";
                else if (!string.IsNullOrWhiteSpace(o.RequireAmr) &&
                         !(ctx.Principal?.FindAll("amr").Any(c => c.Value == o.RequireAmr) ?? false))
                    denyReason = "amr_not_satisfied";

                if (denyReason is not null)
                {
                    http.Items[AuditedFlag] = true;
                    http.Items[DeniedIdentityKey] = new DeniedIdentity(sub, email, emailVerified, denyReason);
                    AuditLoginFailure(http, "login_denied", sub, denyReason);
                    Alert(http, denyReason == "subject_not_allowed"
                        ? "Sign-in attempt by an account that is not on the allowlist"
                        : "Sign-in method does not satisfy the required amr");
                    ctx.Fail("Login denied");
                    return;
                }

                // Normalize the principal: keep only sub / name (+ the email if, and only if, it is verified); drop every other IdP claim.
                // sid: a random session id that travels with the ticket. Sliding renewal re-issues the cookie (the cookie string changes),
                // this does not — rate limiting is keyed on it (see DecryptRateLimiter).
                var claims = new List<Claim>
                {
                    new("sub", sub!),
                    new(DecryptRateLimiter.SessionIdClaim,
                        Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16))),
                };
                var name = ctx.Principal!.FindFirst("name")?.Value ?? ctx.Principal.FindFirst("preferred_username")?.Value;
                if (!string.IsNullOrEmpty(name)) claims.Add(new Claim("name", name));
                if (emailVerified) claims.Add(new Claim(OidcOptions.VerifiedEmailClaim, email!));
                ctx.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, ctx.Scheme.Name, "sub", "role"));
            },
            OnRemoteFailure = ctx =>
            {
                var http = ctx.HttpContext;
                if (!http.Items.ContainsKey(AuditedFlag))
                {
                    AuditLoginFailure(http, "login_failed", null, ctx.Failure?.GetType().Name ?? "unknown");
                    Alert(http, "Login failed (callback or id_token validation did not pass)");
                }
                ctx.HandleResponse();
                http.Response.StatusCode = StatusCodes.Status403Forbidden;
                if (http.Items[DeniedIdentityKey] is DeniedIdentity denied)
                {
                    http.Response.ContentType = "text/html; charset=utf-8";
                    return http.Response.WriteAsync(DeniedPage(denied));
                }
                http.Response.ContentType = "text/plain; charset=utf-8";
                return http.Response.WriteAsync("Login failed or not authorized.");
            },
        };
    }

    /// <summary>
    /// "Access denied" page for a validated but non-allowlisted login. It shows the caller **their own** identity as the IdP
    /// asserted it, so they can hand it to whoever runs this service. Every value is HTML-encoded; no script, CSP-compatible.
    /// </summary>
    public static string DeniedPage(DeniedIdentity d)
    {
        static string E(string? s) => HtmlEncoder.Default.Encode(s ?? "");
        var hint = d.Reason == "amr_not_satisfied"
            ? "<p>Your account is allowed, but the sign-in method does not satisfy <code>Auth:RequireAmr</code>. Sign in again with the required method.</p>"
            : "<p>This account is not on the allowlist. To grant access, the administrator adds your subject to "
              + "<code>Auth:AllowedSubjects</code>" + (d.EmailVerified ? " or your email to <code>Auth:AllowedEmails</code>" : "")
              + ".</p>";
        var emailLine = string.IsNullOrEmpty(d.Email)
            ? "<li>email: (none in the id_token — request the <code>email</code> scope to use Auth:AllowedEmails)</li>"
            : d.EmailVerified
                ? $"<li>email: <code>{E(d.Email)}</code> (verified)</li>"
                : $"<li>email: <code>{E(d.Email)}</code> (<strong>not verified</strong> by the identity provider, so Auth:AllowedEmails cannot match it)</li>";
        return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" />"
               + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"
               + "<title>Access denied · secrets</title><link rel=\"stylesheet\" href=\"/app.css\" /></head><body>"
               + "<header class=\"top\"><a class=\"brand\" href=\"/\">secrets</a></header><main>"
               + "<h1>Access denied</h1>" + hint
               + $"<ul class=\"refs\"><li>subject (sub): <code>{E(d.Sub)}</code></li>{emailLine}</ul>"
               + "<p><a href=\"/login\">Try again</a></p></main></body></html>";
    }

    private static void Alert(HttpContext http, string kind) =>
        http.RequestServices.GetRequiredService<IAlertService>().Raise(kind);

    /// <summary>Failure audit on the anonymous surface: rate limited per client IP, lines beyond the limit are only counted.</summary>
    private static void AuditLoginFailure(HttpContext http, string @event, string? sub, string reason)
    {
        var limiter = http.RequestServices.GetRequiredService<LoginFailureLimiter>();
        var suppressed = limiter.TryAcquire(LoginFailureLimiter.KeyFor(http));
        if (suppressed is null) return;
        TryAudit(http, AuditLog.For(http, @event, sub) with
        {
            Reason = reason,
            SuppressedBefore = suppressed > 0 ? suppressed : null,
        });
    }

    private static void TryAudit(HttpContext http, AuditRecord r)
    {
        try { http.RequestServices.GetRequiredService<IAuditLog>().Write(r); }
        catch (Exception ex)
        {
            http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Audit")
                .LogError("Audit write failed: {Type}", ex.GetType().Name);
        }
    }
}

/// <summary>Decrypting POSTs require this custom header on top of the antiforgery token (a cross-site form cannot send custom headers).</summary>
public static class CsrfHeader
{
    public const string Name = "X-Secrets-Web";
}

/// <summary>
/// Cookie hardening. Every environment except Development: <c>__Host-</c> names and Secure-only, so the service works
/// only behind HTTPS (Production also refuses a non-https PublicOrigin at startup). Development: plain names and
/// SameAsRequest so <c>dotnet run</c> on http://localhost works -- a <c>__Host-</c> cookie without Secure would be
/// rejected by the browser, and antiforgery refuses Secure-only cookies on a plain-http request.
/// </summary>
public sealed record CookieProfile(bool AllowHttp)
{
    public static readonly CookieProfile Strict = new(false);

    public static CookieProfile For(IHostEnvironment env) => new(env.IsDevelopment());

    public CookieSecurePolicy SecurePolicy => AllowHttp ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;

    public string Name(string baseName) => AllowHttp ? baseName : "__Host-" + baseName;
}
