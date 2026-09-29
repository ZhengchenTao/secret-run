using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using SecretsWeb;
using SecretsWeb.Alerts;
using SecretsWeb.Audit;
using SecretsWeb.Repo;
using SecretsWeb.Security;
using SecretsWeb.Services;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k => k.AddServerHeader = false);

var site = builder.Configuration.Get<SiteOptions>() ?? new SiteOptions();
var oidc = builder.Configuration.GetSection(OidcOptions.Section).Get<OidcOptions>() ?? new OidcOptions();
var deployment = builder.Configuration.GetSection(DeploymentOptions.Section).Get<DeploymentOptions>() ?? new DeploymentOptions();
var network = builder.Configuration.GetSection(NetworkOptions.Section).Get<NetworkOptions>() ?? new NetworkOptions();

builder.Services.Configure<OidcOptions>(builder.Configuration.GetSection(OidcOptions.Section));
builder.Services.Configure<RepoOptions>(builder.Configuration.GetSection(RepoOptions.Section));
builder.Services.Configure<AuditOptions>(builder.Configuration.GetSection(AuditOptions.Section));
builder.Services.Configure<AlertOptions>(builder.Configuration.GetSection(AlertOptions.Section));
builder.Services.Configure<DecryptLimitOptions>(builder.Configuration.GetSection(DecryptLimitOptions.Section));

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddMemoryCache();
builder.Services.AddHttpClient(AlertService.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddSingleton<IAlertService, AlertService>();
builder.Services.AddSingleton<IAuditLog, AuditLog>();
builder.Services.AddSingleton<ISecretRepository, SecretRepository>();
builder.Services.AddSingleton<DecryptRateLimiter>();
builder.Services.AddSingleton<ConfirmTokens>();
builder.Services.AddSingleton<IRepoWriter, RepoWriter>();
builder.Services.AddSingleton<EntryService>();
builder.Services.AddSingleton<EntryWriteService>();
builder.Services.AddSingleton<HealthService>();
builder.Services.AddSingleton(sp => new FavoriteStore(
    sp.GetRequiredService<IOptions<RepoOptions>>().Value.FavoritesPath,
    sp.GetRequiredService<ILogger<FavoriteStore>>()));

if (builder.Environment.IsProduction() && string.IsNullOrWhiteSpace(site.PublicOrigin))
    throw new InvalidOperationException("PublicOrigin must be configured in Production (for example https://secrets.example.com)");

// Refuse to start in Production unless an access layer is declared (see StartupChecks for the reasoning).
var accessLayer = StartupChecks.CheckAccessLayer(builder.Environment, deployment);

// Trusted reverse proxy: only when explicitly configured. Null = X-Forwarded-* is never read.
var forwarded = StartupChecks.BuildForwardedHeaders(network);

builder.Services.AddSecretsWebAuth(oidc);
builder.Services.AddAntiforgery(a =>
{
    a.Cookie.Name = "__Host-secrets-web-af";
    a.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    a.Cookie.SameSite = SameSiteMode.Strict;
    a.HeaderName = "RequestVerificationToken";
    a.FormFieldName = "__RequestVerificationToken";
});
builder.Services.AddRazorPages();
// Uploads: reject oversized multipart bodies before any business validation (Repo:FileMaxBytes is checked again later)
builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = 4L * 1024 * 1024;
    o.ValueLengthLimit = 4 * 1024 * 1024;
});
// Don't turn non-ASCII text (accents, CJK, emoji in titles) into &#x…; entities; HTML special characters are still encoded
builder.Services.Configure<Microsoft.Extensions.WebEncoders.WebEncoderOptions>(o =>
    o.TextEncoderSettings = new System.Text.Encodings.Web.TextEncoderSettings(System.Text.Unicode.UnicodeRanges.All));

var app = builder.Build();

if (accessLayer == AccessLayerStatus.ExplicitlyNone)
    app.Logger.LogWarning(StartupChecks.AccessLayerNoneWarning);
else if (accessLayer == AccessLayerStatus.Declared)
    app.Logger.LogInformation("Access layer: {AccessLayer}", deployment.AccessLayer.Trim());

// Must run before anything that reads RemoteIpAddress (login-failure limiter, audit ip) or the request scheme.
if (forwarded is not null) app.UseForwardedHeaders(forwarded);
app.UsePublicOrigin(site.PublicOrigin);
app.UseSecurityHeaders();
app.UseExceptionHandler("/error");
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", async (HealthService health, CancellationToken ct) =>
{
    var (ok, body) = await health.GetAsync(ct);
    return Results.Json(body, statusCode: ok ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
}).AllowAnonymous();

app.MapGet("/login", (HttpContext ctx, string? returnUrl) =>
{
    var target = AuthSetup.IsSafeReturnUrl(returnUrl) ? returnUrl! : "/";
    return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, [OpenIdConnectDefaults.AuthenticationScheme]);
}).AllowAnonymous();

app.MapPost("/logout", async (HttpContext ctx, IAntiforgery af, IOptionsMonitor<OpenIdConnectOptions> oidcOptions) =>
{
    if (!ctx.Request.HasFormContentType) return Results.StatusCode(StatusCodes.Status400BadRequest);
    try { await af.ValidateRequestAsync(ctx); }
    catch (AntiforgeryValidationException) { return Results.StatusCode(StatusCodes.Status400BadRequest); }
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    // RP-initiated logout: without it the IdP's own SSO session stays alive, and the next person who clicks
    // "sign in" in the same browser is signed straight back in as the previous user. The OIDC handler takes
    // end_session_endpoint from discovery and redirects there with post_logout_redirect_uri=/signout-callback-oidc
    // + state; after the round trip the user lands on /signed-out.
    // Fallbacks (the local session is already gone in both cases):
    //  - the IdP publishes no end_session_endpoint (Google, for one): normal, go straight to /signed-out;
    //  - discovery can't be fetched (IdP unreachable): log a warning and go to /signed-out.
    var log = ctx.RequestServices.GetRequiredService<ILogger<Program>>();
    try
    {
        var o = oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);
        var config = o.Configuration ?? (o.ConfigurationManager is { } cm ? await cm.GetConfigurationAsync(ctx.RequestAborted) : null);
        if (string.IsNullOrEmpty(config?.EndSessionEndpoint))
        {
            log.LogDebug("IdP has no end_session_endpoint; cleared the local session only");
            return Results.Redirect("/signed-out");
        }
        await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme,
            new AuthenticationProperties { RedirectUri = "/signed-out" });
        return Results.Empty;
    }
    catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or IOException)
    {
        log.LogWarning(ex, "RP-initiated logout failed (IdP unreachable?); only the local session was cleared");
        return Results.Redirect("/signed-out");
    }
});

var api = app.MapGroup("/api").AddEndpointFilter(async (efc, next) =>
{
    var ctx = efc.HttpContext;
    if (!ctx.Request.HasFormContentType) return Results.StatusCode(StatusCodes.Status400BadRequest);
    var af = ctx.RequestServices.GetRequiredService<IAntiforgery>();
    try { await af.ValidateRequestAsync(ctx); }
    catch (AntiforgeryValidationException) { return Results.StatusCode(StatusCodes.Status400BadRequest); }
    try { return await next(efc); }
    catch (EntryException ex) { return Results.Json(new { error = ex.Message }, statusCode: ex.StatusCode); }
}).DisableAntiforgery();

api.MapPost("/field", async (HttpContext ctx, EntryService svc, CancellationToken ct) =>
{
    if (!ctx.Request.Headers.ContainsKey(CsrfHeader.Name)) return Results.StatusCode(StatusCodes.Status400BadRequest);
    var form = await ctx.Request.ReadFormAsync(ct);
    var mode = form["mode"].ToString();
    if (mode is not ("show" or "copy")) return Results.BadRequest();
    var value = await svc.GetFieldAsync(ctx, form["path"].ToString(), form["field"].ToString(), mode, ct);
    return Results.Json(new { value });
});

api.MapPost("/file", async (HttpContext ctx, EntryService svc, CancellationToken ct) =>
{
    if (!ctx.Request.Headers.ContainsKey(CsrfHeader.Name)) return Results.StatusCode(StatusCodes.Status400BadRequest);
    var form = await ctx.Request.ReadFormAsync(ct);
    var view = await svc.GetFileViewAsync(ctx, form["path"].ToString(), ct);
    return Results.Json(new { isText = view.IsText, text = view.Text, size = view.Size });
});

// Favorites: only touches the server-side favorites.json — never the secrets repo, never decrypts — so it does not use
// decryption quota and is not audited (it reveals no value; logging it would only dilute the audit log).
// Protections are still the same as every other endpoint: POST + antiforgery + custom header + login.
api.MapPost("/favorite", async (HttpContext ctx, FavoriteStore favorites, ISecretRepository repo, CancellationToken ct) =>
{
    if (!ctx.Request.Headers.ContainsKey(CsrfHeader.Name)) return Results.StatusCode(StatusCodes.Status400BadRequest);
    var form = await ctx.Request.ReadFormAsync(ct);
    var path = form["path"].ToString();
    var on = form["on"].ToString() == "1";
    var snapshot = await repo.GetSnapshotAsync(ct);
    if (!snapshot.Catalog.Entries.Any(e => e.Path == path))
        return Results.Json(new { error = "Entry not found" }, statusCode: 404);
    var now = await favorites.SetAsync(path, on, ct);
    return Results.Json(new { favorite = now });
});

// ---- Writes (create / edit / delete): same protections as the decrypt endpoints (POST + antiforgery + custom header + allowlist + rate limit) ----

api.MapPost("/entry/create", async (HttpContext ctx, EntryWriteService svc, CancellationToken ct) =>
{
    if (!ctx.Request.Headers.ContainsKey(CsrfHeader.Name)) return Results.StatusCode(StatusCodes.Status400BadRequest);
    var form = await ctx.Request.ReadFormAsync(ct);
    var req = svc.BuildRequest(form, form.Files["upload"], requireContent: true);
    var result = await svc.CreateAsync(ctx, req, ct);
    return Results.Json(new { commit = result.Commit, redirect = "/entry/" + req.Path });
}).DisableAntiforgery();

api.MapPost("/entry/update", async (HttpContext ctx, EntryWriteService svc, CancellationToken ct) =>
{
    if (!ctx.Request.Headers.ContainsKey(CsrfHeader.Name)) return Results.StatusCode(StatusCodes.Status400BadRequest);
    var form = await ctx.Request.ReadFormAsync(ct);
    var req = await svc.FillFieldsFromCatalog(svc.BuildRequest(form, form.Files["upload"], requireContent: false), ct);
    var result = await svc.UpdateAsync(ctx, req, ct);
    return Results.Json(new { commit = result.Commit, redirect = "/entry/" + req.Path });
}).DisableAntiforgery();

api.MapPost("/entry/delete", async (HttpContext ctx, EntryWriteService svc, ConfirmTokens confirm, CancellationToken ct) =>
{
    if (!ctx.Request.Headers.ContainsKey(CsrfHeader.Name)) return Results.StatusCode(StatusCodes.Status400BadRequest);
    var form = await ctx.Request.ReadFormAsync(ct);
    var path = form["path"].ToString();
    if (!confirm.Consume(DecryptRateLimiter.KeyFor(ctx), path, form["confirm"].ToString()))
        return Results.Json(new { error = "Confirmation expired; go back to the entry page and click delete again" }, statusCode: StatusCodes.Status400BadRequest);
    var (result, refs) = await svc.DeleteAsync(ctx, path, ct);
    return Results.Json(new
    {
        commit = result.Commit,
        redirect = "/",
        references = new { readers = refs.Readers, linked = refs.Linked, linkedBy = refs.InboundLinked },
    });
}).DisableAntiforgery();

// Download is a plain form POST (browser downloads can't carry a custom header): antiforgery token + SameSite prevent CSRF
api.MapPost("/download", async (HttpContext ctx, EntryService svc, CancellationToken ct) =>
{
    var form = await ctx.Request.ReadFormAsync(ct);
    var (entry, bytes) = await svc.DownloadAsync(ctx, form["path"].ToString(), ct);
    try
    {
        ctx.Response.ContentType = "application/octet-stream";
        ctx.Response.Headers.ContentDisposition = $"attachment; filename=\"{entry.Name}\"";
        ctx.Response.ContentLength = bytes.Length;
        await ctx.Response.Body.WriteAsync(bytes, ct);
        return Results.Empty;
    }
    finally
    {
        Array.Clear(bytes);
    }
});

app.MapRazorPages();
app.Run();

public partial class Program;
