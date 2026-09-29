using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace SecretsWeb.Tests;

/// <summary>Collects log entries so tests can assert on what was (or wasn't) logged.</summary>
public sealed class CollectingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<(string Category, LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);
    public void Dispose() { }

    private sealed class Logger(CollectingLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            owner.Entries.Enqueue((category, logLevel, formatter(state, exception), exception));
    }
}

/// <summary>
/// RP-initiated logout: when discovery has an end_session_endpoint, redirect there (with post_logout_redirect_uri + state);
/// when it has none (Google, for example) or the IdP is unreachable, fall back to /signed-out.
/// </summary>
public sealed class LogoutFactory : WebApplicationFactory<Program>
{
    public TestRepoFixture Repo { get; } = new();
    public CollectingLoggerProvider Logs { get; } = new();

    /// <summary>What discovery says: null = no discovery injected (Authority is an unreachable .invalid host, i.e. IdP down).</summary>
    public OpenIdConnectConfiguration? Discovery { get; init; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Auth:Authority", "https://auth.example.invalid");
        builder.UseSetting("Auth:ClientId", "secrets-web-test");
        builder.UseSetting("Auth:ClientSecret", "test-only-placeholder");
        builder.UseSetting("Auth:AllowedSubjects:0", "alice");
        builder.UseSetting("Repo:GitDir", Repo.BareDir);
        builder.UseSetting("Repo:Identity", Repo.IdentityPath);
        builder.UseSetting("Audit:Path", Repo.AuditPath);
        builder.UseSetting("Repo:FavoritesPath", Repo.FavoritesPath);
        builder.ConfigureLogging(l => l.AddProvider(Logs));
        builder.ConfigureTestServices(s =>
        {
            s.AddAuthentication().AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
            s.PostConfigure<AuthenticationOptions>(a =>
            {
                a.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                a.DefaultChallengeScheme = TestAuthHandler.SchemeName;
                a.DefaultForbidScheme = TestAuthHandler.SchemeName;
            });
            if (Discovery is not null)
                s.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, o =>
                {
                    // The framework's PostConfigure has already built a ConfigurationManager from Authority (which would fetch
                    // discovery over the network); setting Configuration alone isn't enough, the manager must be replaced too
                    o.Configuration = Discovery;
                    o.ConfigurationManager = new Microsoft.IdentityModel.Protocols.StaticConfigurationManager<OpenIdConnectConfiguration>(Discovery);
                });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) Repo.Dispose();
    }
}

public sealed class LogoutTests
{
    private static async Task<HttpResponseMessage> PostLogout(LogoutFactory f)
    {
        var c = f.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true,
        });
        c.DefaultRequestHeaders.Add(TestAuthHandler.Header, "alice");
        var html = await c.GetStringAsync("/");
        var m = Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"");
        Assert.True(m.Success, "no antiforgery token on the home page");
        return await c.PostAsync("/logout", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["__RequestVerificationToken"] = m.Groups[1].Value }));
    }

    [Fact]
    public async Task Logout_Redirects_To_IdP_End_Session_With_Callback_And_State()
    {
        using var f = new LogoutFactory { Discovery = new OpenIdConnectConfiguration { EndSessionEndpoint = "https://auth.example.invalid/logout" } };
        var res = await PostLogout(f);

        Assert.Equal(System.Net.HttpStatusCode.Redirect, res.StatusCode);
        var loc = res.Headers.Location!;
        Assert.True(loc.IsAbsoluteUri, "should redirect to the IdP, landed on " + loc.OriginalString);
        Assert.Equal("https://auth.example.invalid/logout", loc.GetLeftPart(UriPartial.Path));
        var q = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(loc.Query);
        Assert.Equal("https://localhost/signout-callback-oidc", q["post_logout_redirect_uri"].ToString());
        Assert.False(string.IsNullOrEmpty(q["state"].ToString()));
    }

    /// <summary>Google's discovery document has no end_session_endpoint: clear the local session, go to /signed-out, no exception log.</summary>
    [Fact]
    public async Task Logout_Without_End_Session_Endpoint_Falls_Back_Quietly()
    {
        using var f = new LogoutFactory { Discovery = new OpenIdConnectConfiguration { Issuer = "https://accounts.example.invalid" } };
        var res = await PostLogout(f);

        Assert.Equal(System.Net.HttpStatusCode.Redirect, res.StatusCode);
        Assert.Equal("/signed-out", res.Headers.Location!.OriginalString);
        Assert.DoesNotContain(f.Logs.Entries, e => e.Exception is not null);
        Assert.DoesNotContain(f.Logs.Entries, e => e.Level >= LogLevel.Warning && e.Message.Contains("logout", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Logout_IdP_Unreachable_Falls_Back_To_Signed_Out_Page()
    {
        using var f = new LogoutFactory();
        var res = await PostLogout(f);

        Assert.Equal(System.Net.HttpStatusCode.Redirect, res.StatusCode);
        Assert.Equal("/signed-out", res.Headers.Location!.OriginalString);
    }
}
