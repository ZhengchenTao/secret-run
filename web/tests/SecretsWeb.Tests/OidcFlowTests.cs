using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SecretsWeb.Security;

namespace SecretsWeb.Tests;

/// <summary>Fake IdP: static discovery (the JWKS holds an RSA public key plus a symmetric key, to prove HS256 is never accepted); the token endpoint returns whatever id_token the test sets.</summary>
public sealed class FakeIdp : HttpMessageHandler
{
    public const string Issuer = "https://idp.example.invalid";
    public const string HsSecret = "hs-test-only-placeholder-0123456789abcdef";
    public readonly RsaSecurityKey Rsa = new(RSA.Create(2048)) { KeyId = "k1" };
    public readonly RsaSecurityKey OtherRsa = new(RSA.Create(2048)) { KeyId = "k1" };
    public Func<string> NextIdToken = () => "";

    public OpenIdConnectConfiguration Config()
    {
        var c = new OpenIdConnectConfiguration { Issuer = Issuer, AuthorizationEndpoint = Issuer + "/authorize", TokenEndpoint = Issuer + "/token" };
        c.SigningKeys.Add(Rsa);
        c.SigningKeys.Add(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(HsSecret)) { KeyId = "hs" });
        return c;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
    {
        var json = $"{{\"access_token\":\"x\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"id_token\":\"{NextIdToken()}\"}}";
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") });
    }

    public string Token(string? nonce, string sub = "alice", string aud = "secrets-web", string iss = Issuer, SigningCredentials? cred = null, int expMin = 60,
        IReadOnlyDictionary<string, object>? extra = null)
    {
        var claims = new Dictionary<string, object> { ["sub"] = sub };
        if (nonce is not null) claims["nonce"] = nonce;
        foreach (var (k, v) in extra ?? new Dictionary<string, object>()) claims[k] = v;
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = iss,
            Audience = aud,
            Claims = claims,
            IssuedAt = now.AddMinutes(Math.Min(-1, expMin - 60)),
            NotBefore = now.AddMinutes(Math.Min(-1, expMin - 60)),
            Expires = now.AddMinutes(expMin),
            SigningCredentials = cred ?? new SigningCredentials(Rsa, SecurityAlgorithms.RsaSha256),
        });
    }
}

public sealed class OidcFactory : WebApplicationFactory<Program>
{
    public TestRepoFixture Repo { get; } = new();
    public FakeIdp Idp { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder b)
    {
        b.UseEnvironment("Production");
        b.UseSetting("PublicOrigin", "https://secrets.example.com");
        b.UseSetting("Auth:Authority", FakeIdp.Issuer);
        b.UseSetting("Auth:ClientId", "secrets-web");
        b.UseSetting("Auth:ClientSecret", "test-only-placeholder");
        b.UseSetting("Auth:AllowedSubjects:0", "alice");
        b.UseSetting("Deployment:AccessLayer", "test-harness");
        b.UseSetting("Repo:GitDir", Repo.BareDir);
        b.UseSetting("Repo:Identity", Repo.IdentityPath);
        b.UseSetting("Audit:Path", Repo.AuditPath);
        b.ConfigureTestServices(s =>
            s.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, o =>
            {
                o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(Idp.Config());
                o.Backchannel = new HttpClient(Idp);
            }));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) Repo.Dispose();
    }
}

public sealed class OidcFlowTests(OidcFactory f) : IClassFixture<OidcFactory>
{
    private HttpClient Client(WebApplicationFactory<Program>? factory = null) => (factory ?? f).CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://secrets.example.com"),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    private async Task<HttpResponseMessage> Login(HttpClient c, Func<string?, string> token, string? returnUrl = null)
    {
        var r1 = await c.GetAsync("/login" + (returnUrl is null ? "" : "?returnUrl=" + Uri.EscapeDataString(returnUrl)));
        Assert.Equal(HttpStatusCode.Redirect, r1.StatusCode);
        var q = HttpUtility.ParseQueryString(r1.Headers.Location!.Query);
        Assert.Equal("https://secrets.example.com/signin-oidc", q["redirect_uri"]);
        f.Idp.NextIdToken = () => token(q["nonce"]);
        return await c.GetAsync($"/signin-oidc?code=abc&state={Uri.EscapeDataString(q["state"]!)}");
    }

    private static bool HasSessionCookie(HttpResponseMessage r) =>
        r.Headers.TryGetValues("Set-Cookie", out var v) && v.Any(x => x.StartsWith("__Host-secrets-web=", StringComparison.Ordinal) && !x.Contains("expires=Thu, 01 Jan 1970"));

    private static string Unsigned(string token, string headerJson)
    {
        var p = token.Split('.');
        return Base64UrlEncoder.Encode(headerJson) + "." + p[1] + ".";
    }

    [Fact]
    public async Task Valid_RS256_Token_Logs_In_And_Audits_After_Validation()
    {
        using var c = Client();
        var cb = await Login(c, n => f.Idp.Token(n));
        Assert.Equal(HttpStatusCode.Redirect, cb.StatusCode);
        Assert.True(HasSessionCookie(cb));
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/")).StatusCode);
        Assert.Contains(File.ReadAllLines(f.Repo.AuditPath), l => l.Contains("\"event\":\"login\"") && l.Contains("\"sub\":\"alice\""));
    }

    public static TheoryData<string> BadTokens => new()
    {
        "alg-none", "rs256-empty-signature", "hs256-key-in-jwks", "rs256-other-key-same-kid",
        "wrong-aud", "wrong-iss", "expired", "wrong-nonce", "sub-not-allowed", "sub-wrong-case",
    };

    [Theory]
    [MemberData(nameof(BadTokens))]
    public async Task Bad_Id_Tokens_Never_Get_A_Session(string kind)
    {
        var idp = f.Idp;
        Func<string?, string> tok = kind switch
        {
            "alg-none" => n => Unsigned(idp.Token(n), "{\"alg\":\"none\",\"typ\":\"JWT\"}"),
            "rs256-empty-signature" => n => Unsigned(idp.Token(n), "{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"JWT\"}"),
            "hs256-key-in-jwks" => n => idp.Token(n, cred: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(FakeIdp.HsSecret)) { KeyId = "hs" }, SecurityAlgorithms.HmacSha256)),
            "rs256-other-key-same-kid" => n => idp.Token(n, cred: new SigningCredentials(idp.OtherRsa, SecurityAlgorithms.RsaSha256)),
            "wrong-aud" => n => idp.Token(n, aud: "other-app"),
            "wrong-iss" => n => idp.Token(n, iss: "https://auth.evil.invalid"),
            "expired" => n => idp.Token(n, expMin: -30),
            "wrong-nonce" => n => idp.Token("x" + n),
            "sub-not-allowed" => n => idp.Token(n, sub: "mallory"),
            "sub-wrong-case" => n => idp.Token(n, sub: "ALICE"),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        using var c = Client();
        var cb = await Login(c, tok);
        Assert.False(HasSessionCookie(cb), $"{kind} must not get a session");
        Assert.NotEqual(HttpStatusCode.OK, (await c.GetAsync("/")).StatusCode);
    }

    [Fact]
    public async Task Verifier_Rejects_Unsigned_And_Hs256_Directly()
    {
        var cfg = f.Idp.Config();
        var good = f.Idp.Token(null);
        Assert.Null(await IdTokenVerifier.VerifyAsync(good, cfg, "secrets-web"));
        Assert.NotNull(await IdTokenVerifier.VerifyAsync(Unsigned(good, "{\"alg\":\"none\"}"), cfg, "secrets-web"));
        Assert.NotNull(await IdTokenVerifier.VerifyAsync(Unsigned(good, "{\"alg\":\"RS256\",\"kid\":\"k1\"}"), cfg, "secrets-web"));
        Assert.NotNull(await IdTokenVerifier.VerifyAsync(good + "x", cfg, "secrets-web"));
        Assert.NotNull(await IdTokenVerifier.VerifyAsync(f.Idp.Token(null, cred: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(FakeIdp.HsSecret)) { KeyId = "hs" }, SecurityAlgorithms.HmacSha256)), cfg, "secrets-web"));
        Assert.NotNull(await IdTokenVerifier.VerifyAsync(good, cfg, "other-client"));
        Assert.NotNull(await IdTokenVerifier.VerifyAsync(null, cfg, "secrets-web"));
    }

    [Theory]
    [InlineData("/\t/evil.example")]
    [InlineData("/\n/evil.example")]
    [InlineData("//evil.example")]
    [InlineData("/\\evil.example")]
    [InlineData("https://evil.example")]
    [InlineData("evil.example")]
    [InlineData("/%09/evil.example")]
    public async Task Open_Redirect_Return_Urls_Fall_Back_To_Root(string returnUrl)
    {
        using var c = Client();
        var cb = await Login(c, n => f.Idp.Token(n), returnUrl);
        Assert.Equal(HttpStatusCode.Redirect, cb.StatusCode);
        var loc = cb.Headers.Location!.OriginalString;
        Assert.True(loc == "/" || (loc.StartsWith('/') && !loc.StartsWith("//") && !loc.Contains('\\') && !loc.Any(char.IsControl)),
            $"unsafe redirect: {loc}");
        if (returnUrl.Contains('\t') || returnUrl.Contains('\n') || returnUrl.StartsWith("//") || returnUrl.StartsWith("/\\") || !returnUrl.StartsWith('/'))
            Assert.Equal("/", loc);
    }

    [Fact]
    public async Task Local_Return_Url_Is_Kept()
    {
        using var c = Client();
        var cb = await Login(c, n => f.Idp.Token(n), "/entry/personal/test/api");
        Assert.Equal("/entry/personal/test/api", cb.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData("/entry/x", true)]
    [InlineData("/", true)]
    [InlineData("/\t/evil", false)]
    [InlineData("/a", false)]
    [InlineData("//evil", false)]
    [InlineData("/\\evil", false)]
    [InlineData("/a\\b", false)]
    [InlineData("~/x", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Safe_Return_Url(string? url, bool ok) => Assert.Equal(ok, AuthSetup.IsSafeReturnUrl(url));

    [Fact]
    public void Production_Without_PublicOrigin_Fails_Fast()
    {
        using var f2 = f.WithWebHostBuilder(b => b.UseSetting("PublicOrigin", ""));
        Assert.Throws<InvalidOperationException>(() => f2.CreateClient());
    }

    [Fact]
    public void Production_With_Http_PublicOrigin_Fails_Fast()
    {
        // Secure-only cookies would make every page fail right after sign-in; refuse at startup instead.
        using var f2 = f.WithWebHostBuilder(b => b.UseSetting("PublicOrigin", "http://localhost:8099"));
        var ex = Assert.Throws<InvalidOperationException>(() => f2.CreateClient());
        Assert.Contains("https://", ex.Message);
    }

    // ---------------------------------------------------------------- Deployment:AccessLayer guard

    [Fact]
    public void Production_Without_Access_Layer_Refuses_To_Start()
    {
        using var f2 = f.WithWebHostBuilder(b => b.UseSetting("Deployment:AccessLayer", ""));
        var ex = Assert.Throws<InvalidOperationException>(() => f2.CreateClient());
        Assert.Contains("Deployment:AccessLayer", ex.Message);
        Assert.Contains("access layer", ex.Message);
    }

    [Fact]
    public async Task Production_With_Access_Layer_None_Starts_And_Warns()
    {
        var logs = new CollectingLoggerProvider();
        using var f2 = f.WithWebHostBuilder(b =>
        {
            b.UseSetting("Deployment:AccessLayer", "none");
            b.ConfigureLogging(l => l.AddProvider(logs));
        });
        using var c = Client(f2);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/health")).StatusCode);
        Assert.Contains(logs.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("AccessLayer is 'none'"));
        // nothing about it in the UI
        Assert.DoesNotContain("AccessLayer", await (await c.GetAsync("/signed-out")).Content.ReadAsStringAsync());
    }

    [Fact]
    public void Access_Layer_Is_Not_Enforced_In_Development()
    {
        var env = new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = "Development" };
        Assert.Equal(AccessLayerStatus.NotEnforced, StartupChecks.CheckAccessLayer(env, new DeploymentOptions()));
        env.EnvironmentName = "Production";
        Assert.Throws<InvalidOperationException>(() => StartupChecks.CheckAccessLayer(env, new DeploymentOptions { AccessLayer = "  " }));
        Assert.Equal(AccessLayerStatus.ExplicitlyNone, StartupChecks.CheckAccessLayer(env, new DeploymentOptions { AccessLayer = "None" }));
        Assert.Equal(AccessLayerStatus.Declared, StartupChecks.CheckAccessLayer(env, new DeploymentOptions { AccessLayer = "vpn" }));
    }

    // ---------------------------------------------------------------- email allowlist

    private WebApplicationFactory<Program> EmailOnlyFactory() => f.WithWebHostBuilder(b =>
    {
        b.UseSetting("Auth:AllowedSubjects:0", "");
        b.UseSetting("Auth:AllowedEmails:0", " Alice@Example.com ");
    });

    public static TheoryData<string, object, bool> EmailCases => new()
    {
        { "alice@example.com", true, true },          // JSON boolean true
        { "alice@example.com", "true", true },        // string "true"
        { "ALICE@EXAMPLE.COM", true, true },          // case-insensitive
        { "alice@example.com", false, false },        // unverified
        { "alice@example.com", "false", false },
        { "alice@example.com", "yes", false },
        { "bob@example.com", true, false },           // not on the list
    };

    [Theory]
    [MemberData(nameof(EmailCases))]
    public async Task Email_Allowlist_Requires_Verified_Email(string email, object verified, bool allowed)
    {
        using var f2 = EmailOnlyFactory();
        using var c = Client(f2);
        var cb = await Login(c, n => f.Idp.Token(n, sub: "google-sub-123",
            extra: new Dictionary<string, object> { ["email"] = email, ["email_verified"] = verified }));
        Assert.Equal(allowed, HasSessionCookie(cb));
        Assert.Equal(allowed, (await c.GetAsync("/")).StatusCode == HttpStatusCode.OK);
    }

    [Fact]
    public async Task Email_Allowlist_Ignores_Missing_Email_Verified()
    {
        using var f2 = EmailOnlyFactory();
        using var c = Client(f2);
        var cb = await Login(c, n => f.Idp.Token(n, sub: "google-sub-123",
            extra: new Dictionary<string, object> { ["email"] = "alice@example.com" }));
        Assert.False(HasSessionCookie(cb));
    }

    [Fact]
    public async Task Denied_Login_Shows_The_Callers_Own_Identity_And_A_Hint()
    {
        // a fresh host = a fresh login-failure limiter, so earlier failures in this class can't suppress the audit line
        using var f2 = f.WithWebHostBuilder(_ => { });
        using var c = Client(f2);
        var cb = await Login(c, n => f.Idp.Token(n, sub: "mallory-sub",
            extra: new Dictionary<string, object> { ["email"] = "mallory<b>@example.com", ["email_verified"] = true }));
        Assert.Equal(HttpStatusCode.Forbidden, cb.StatusCode);
        Assert.False(HasSessionCookie(cb));
        var html = await cb.Content.ReadAsStringAsync();
        Assert.Contains("mallory-sub", html);
        Assert.Contains("Auth:AllowedSubjects", html);
        Assert.Contains("Auth:AllowedEmails", html);
        Assert.DoesNotContain("<b>", html); // HTML-encoded
        Assert.Contains(File.ReadAllLines(f.Repo.AuditPath),
            l => l.Contains("\"event\":\"login_denied\"") && l.Contains("mallory-sub"));
    }
}

public class LoginFailureLimiterTests
{
    private sealed class FixedClock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.Parse("2026-09-17T00:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void Ten_Per_Minute_Per_Ip_Then_Counts()
    {
        var clock = new FixedClock();
        var l = new LoginFailureLimiter(clock);
        for (var i = 0; i < LoginFailureLimiter.PerMinute; i++) Assert.Equal(0, l.TryAcquire("1.2.3.4"));
        Assert.Null(l.TryAcquire("1.2.3.4"));
        Assert.Null(l.TryAcquire("1.2.3.4"));
        Assert.Equal(0, l.TryAcquire("5.6.7.8"));
        clock.Now = clock.Now.AddMinutes(1);
        Assert.Equal(2, l.TryAcquire("1.2.3.4"));
        Assert.Equal(0, l.TryAcquire("1.2.3.4"));
    }
}
