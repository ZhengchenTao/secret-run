namespace SecretsWeb.Security;

public static class SecurityMiddleware
{
    public const string Csp =
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

    /// <summary>The service binds to 127.0.0.1 behind an access layer / reverse proxy: rewrite Scheme/Host to PublicOrigin so redirect_uri is correct.</summary>
    public static IApplicationBuilder UsePublicOrigin(this IApplicationBuilder app, string publicOrigin)
    {
        if (string.IsNullOrWhiteSpace(publicOrigin)) return app;
        if (!Uri.TryCreate(publicOrigin, UriKind.Absolute, out var uri) || uri.AbsolutePath != "/" || uri.Scheme is not ("https" or "http"))
            throw new InvalidOperationException("PublicOrigin must be an origin of the form https://host[:port]");
        var scheme = uri.Scheme;
        var host = new HostString(uri.Authority);
        return app.Use((ctx, next) =>
        {
            ctx.Request.Scheme = scheme;
            ctx.Request.Host = host;
            return next(ctx);
        });
    }

    /// <summary>Every response: strict CSP, no framing, no referrer, nosniff, no-store (responses carrying values included).</summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) =>
        app.Use((ctx, next) =>
        {
            ctx.Response.OnStarting(() =>
            {
                var h = ctx.Response.Headers;
                h.ContentSecurityPolicy = Csp;
                h.XFrameOptions = "DENY";
                h["Referrer-Policy"] = "no-referrer";
                h.XContentTypeOptions = "nosniff";
                h.CacheControl = "no-store";
                h.Pragma = "no-cache";
                h["Cross-Origin-Opener-Policy"] = "same-origin";
                h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
                if (ctx.Request.IsHttps) h.StrictTransportSecurity = "max-age=31536000";
                return Task.CompletedTask;
            });
            return next(ctx);
        });
}
