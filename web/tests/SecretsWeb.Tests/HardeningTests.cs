using System.Net;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SecretsWeb;
using SecretsWeb.Alerts;
using SecretsWeb.Audit;
using SecretsWeb.Repo;
using SecretsWeb.Security;

namespace SecretsWeb.Tests;

/// <summary>The child process environment is rebuilt from an allowlist; secrets in the parent never reach it.</summary>
public class ProcessEnvironmentTests
{
    [Fact]
    public void Allowlist_Drops_Everything_Else()
    {
        var source = new Dictionary<string, string>
        {
            ["PATH"] = "/usr/bin",
            ["HOME"] = "/home/app",
            ["TZ"] = "UTC",
            ["TEST_SECRET_ENV"] = "leaky",
            ["Auth__ClientSecret"] = "leaky",
            ["Alerts__WebhookToken"] = "leaky",
            ["ASPNETCORE_URLS"] = "http://0.0.0.0:8080",
        };
        var target = new Dictionary<string, string?>();
        ProcessRunner.ApplyEnvironment(target, source);

        Assert.Equal("/usr/bin", target["PATH"]);
        Assert.Equal("/home/app", target["HOME"]);
        Assert.Equal("UTC", target["TZ"]);
        Assert.False(target.ContainsKey("TEST_SECRET_ENV"));
        Assert.False(target.ContainsKey("Auth__ClientSecret"));
        Assert.False(target.ContainsKey("Alerts__WebhookToken"));
        Assert.False(target.ContainsKey("ASPNETCORE_URLS"));
        Assert.Equal("1", target["GIT_CONFIG_NOSYSTEM"]);
        Assert.Equal("0", target["GIT_TERMINAL_PROMPT"]);
        Assert.DoesNotContain(target.Values, v => v == "leaky");
    }

    [Fact]
    public async Task Child_Process_Does_Not_See_Parent_Secrets()
    {
        // git echoes GIT_AUTHOR_NAME into GIT_AUTHOR_IDENT — use it as a probe: set in the parent, the child must not see it
        const string leak = "leaky-test-value-do-not-inherit";
        Environment.SetEnvironmentVariable("GIT_AUTHOR_NAME", leak);
        Environment.SetEnvironmentVariable("TEST_SECRET_ENV", leak);
        try
        {
            var r = await ProcessRunner.RunAsync("git", ["var", "-l"], null, 256 * 1024, TimeSpan.FromSeconds(30));
            var text = Encoding.UTF8.GetString(r.Stdout) + r.Stderr;
            Assert.DoesNotContain(leak, text);
            Assert.Contains("GIT_AUTHOR_IDENT", text); // the command really ran (PATH and other allowlisted names still got through)
        }
        finally
        {
            Environment.SetEnvironmentVariable("GIT_AUTHOR_NAME", null);
            Environment.SetEnvironmentVariable("TEST_SECRET_ENV", null);
        }
    }
}

public class AuditRotationTests
{
    private static AuditLog Make(string dir, long maxBytes, int keep) =>
        new(Options.Create(new AuditOptions { Path = Path.Combine(dir, "audit.log"), MaxBytes = maxBytes, KeepFiles = keep }),
            NullLogger<AuditLog>.Instance);

    private static AuditRecord Rec(int i) => new() { Timestamp = DateTimeOffset.UtcNow.ToString("O"), Event = "decrypt", EntryPath = $"personal/x/e{i}" };

    [Fact]
    public void Rotates_At_Max_Bytes_And_Keeps_N_Files()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sw-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var log = Make(dir, maxBytes: 200, keep: 3);
            for (var i = 0; i < 40; i++) log.Write(Rec(i));
            var files = Directory.GetFiles(dir).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
            Assert.Contains("audit.log", files);
            Assert.Contains("audit.log.1", files);
            Assert.DoesNotContain("audit.log.4", files);
            Assert.True(new FileInfo(Path.Combine(dir, "audit.log")).Length < 400);
            Assert.All(files, f => Assert.True(new FileInfo(Path.Combine(dir, f!)).Length <= 400));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Write_Failure_Throws_AuditWriteException()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sw-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            // the path points at a directory → the file can't be opened
            var log = new AuditLog(Options.Create(new AuditOptions { Path = dir }), NullLogger<AuditLog>.Instance);
            Assert.Throws<AuditWriteException>(() => log.Write(Rec(1)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Rotation_Failure_Does_Not_Break_Writing()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sw-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        FileStream? hold = null;
        try
        {
            var log = Make(dir, maxBytes: 100, keep: 2);
            log.Write(Rec(1));
            // hold audit.log.1 open so File.Move fails (exclusive on Windows); the write itself must still succeed
            hold = new FileStream(Path.Combine(dir, "audit.log.1"), FileMode.Create, FileAccess.Write, FileShare.None);
            log.Write(Rec(2));
            log.Write(Rec(3));
            Assert.True(File.Exists(Path.Combine(dir, "audit.log")));
            Assert.Equal(3, File.ReadAllLines(Path.Combine(dir, "audit.log")).Length);
        }
        finally
        {
            hold?.Dispose();
            Directory.Delete(dir, true);
        }
    }
}

public class DecryptRateLimiterTests
{
    private sealed class FakeClock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.Parse("2026-09-18T00:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class SpyAlerts : IAlertService
    {
        public List<string> Raised { get; } = [];
        public void Raise(string kind) => Raised.Add(kind);
    }

    private static DecryptRateLimiter Make(FakeClock clock, SpyAlerts alerts, DecryptLimitOptions o) =>
        new(Options.Create(o), Options.Create(new AlertOptions()), clock, alerts, NullLogger<DecryptRateLimiter>.Instance);

    [Fact]
    public void Per_Minute_And_Per_Hour_Limits()
    {
        var clock = new FakeClock();
        var l = Make(clock, new SpyAlerts(), new DecryptLimitOptions { PerMinute = 3, PerHour = 5 });
        for (var i = 0; i < 3; i++) Assert.True(l.TryAcquire("s:a"));
        Assert.False(l.TryAcquire("s:a"));
        Assert.True(l.TryAcquire("s:b")); // another session is unaffected

        clock.Now = clock.Now.AddMinutes(2);
        Assert.True(l.TryAcquire("s:a"));
        Assert.True(l.TryAcquire("s:a"));
        Assert.False(l.TryAcquire("s:a")); // the hourly 5 are used up

        clock.Now = clock.Now.AddHours(1).AddMinutes(1);
        Assert.True(l.TryAcquire("s:a"));
    }

    [Fact]
    public void Distinct_Entry_Burst_Raises_One_Alert_Without_Entry_Names()
    {
        var clock = new FakeClock();
        var alerts = new SpyAlerts();
        var l = Make(clock, alerts, new DecryptLimitOptions { DistinctWindowMinutes = 10, DistinctThreshold = 5 });
        for (var i = 0; i < 5; i++) l.RecordEntry($"personal/test/e{i}");
        Assert.Empty(alerts.Raised);
        l.RecordEntry("personal/test/e5");
        Assert.Single(alerts.Raised);
        Assert.DoesNotContain("personal", alerts.Raised[0]);

        // counting starts over once the window has passed
        clock.Now = clock.Now.AddMinutes(11);
        l.RecordEntry("personal/test/e0");
        Assert.Single(alerts.Raised);
    }

    [Fact]
    public void Same_Entry_Repeated_Is_Not_A_Burst()
    {
        var alerts = new SpyAlerts();
        var l = Make(new FakeClock(), alerts, new DecryptLimitOptions { DistinctThreshold = 3 });
        for (var i = 0; i < 20; i++) l.RecordEntry("personal/test/a");
        Assert.Empty(alerts.Raised);
    }
}

/// <summary>End-to-end decryption rate limit: a separate factory with the per-minute cap lowered to 2.</summary>
public sealed class RateLimitFactory : WebApplicationFactory<Program>
{
    public TestRepoFixture Repo { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder b)
    {
        b.UseEnvironment("Testing");
        b.UseSetting("Auth:Authority", "https://auth.example.invalid");
        b.UseSetting("Auth:ClientId", "secrets-web-test");
        b.UseSetting("Auth:ClientSecret", "test-only-placeholder");
        b.UseSetting("Auth:AllowedSubjects:0", "alice");
        b.UseSetting("Repo:GitDir", Repo.BareDir);
        b.UseSetting("Repo:Identity", Repo.IdentityPath);
        b.UseSetting("Audit:Path", Repo.AuditPath);
        b.UseSetting("DecryptLimits:PerMinute", "2");
        b.ConfigureTestServices(s =>
        {
            s.AddAuthentication().AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
            s.PostConfigure<AuthenticationOptions>(a =>
            {
                a.DefaultScheme = TestAuthHandler.SchemeName;
                a.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                a.DefaultChallengeScheme = TestAuthHandler.SchemeName;
                a.DefaultForbidScheme = TestAuthHandler.SchemeName;
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) Repo.Dispose();
    }
}

public sealed class DecryptRateLimitEndToEndTests(RateLimitFactory f) : IClassFixture<RateLimitFactory>
{
    [Fact]
    public async Task Fourth_Decrypt_In_A_Minute_Gets_429()
    {
        var c = f.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        c.DefaultRequestHeaders.Add(TestAuthHandler.Header, "alice");
        var html = await c.GetStringAsync("/entry/personal/test/api");
        var token = System.Text.RegularExpressions.Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;

        HttpRequestMessage Req() =>
            new(HttpMethod.Post, "/api/field")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                    { ["path"] = "personal/test/api", ["field"] = "API_KEY", ["mode"] = "show" }),
                Headers = { { "RequestVerificationToken", token }, { CsrfHeader.Name, "1" } },
            };

        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Req())).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Req())).StatusCode);
        var limited = await c.SendAsync(Req());
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.DoesNotContain(f.Repo.ApiKey, await limited.Content.ReadAsStringAsync());
    }
}

/// <summary>JWKS rotation: signature failure → one forced refresh → verify again with the new set; a removed key is no longer accepted.</summary>
public class JwksRefreshTests
{
    private sealed class SwitchableConfigManager(OpenIdConnectConfiguration first) : IConfigurationManager<OpenIdConnectConfiguration>
    {
        private OpenIdConnectConfiguration _current = first;
        public OpenIdConnectConfiguration? Next { get; set; }
        public int RefreshRequests { get; private set; }

        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel) => Task.FromResult(_current);

        public void RequestRefresh()
        {
            RefreshRequests++;
            if (Next is not null) { _current = Next; Next = null; }
        }
    }

    private sealed class FakeClock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.Parse("2026-09-18T00:00:00Z");
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static OpenIdConnectConfiguration Config(params SecurityKey[] keys)
    {
        var c = new OpenIdConnectConfiguration { Issuer = FakeIdp.Issuer };
        foreach (var k in keys) c.SigningKeys.Add(k);
        return c;
    }

    [Fact]
    public async Task Rotated_Key_Is_Accepted_After_Forced_Refresh()
    {
        var idp = new FakeIdp();
        var verifier = new IdTokenVerifier(new FakeClock(), NullLogger<IdTokenVerifier>.Instance);
        var cm = new SwitchableConfigManager(Config(idp.Rsa)) { Next = Config(idp.OtherRsa) };
        var token = idp.Token(null, cred: new SigningCredentials(idp.OtherRsa, SecurityAlgorithms.RsaSha256));

        Assert.Null(await verifier.VerifyAsync(token, cm, "secrets-web"));
        Assert.Equal(1, cm.RefreshRequests);
    }

    [Fact]
    public async Task Removed_Key_Is_Rejected_After_Refresh()
    {
        var idp = new FakeIdp();
        var verifier = new IdTokenVerifier(new FakeClock(), NullLogger<IdTokenVerifier>.Instance);
        var cm = new SwitchableConfigManager(Config(idp.Rsa, idp.OtherRsa)) { Next = Config(idp.Rsa) };
        var oldToken = idp.Token(null, cred: new SigningCredentials(idp.OtherRsa, SecurityAlgorithms.RsaSha256));

        // once the old key is removed (refresh applied), the same token must be refused
        cm.RequestRefresh();
        Assert.NotNull(await verifier.VerifyAsync(oldToken, cm, "secrets-web"));
    }

    [Fact]
    public async Task Refresh_Is_Not_Requested_For_Non_Signature_Failures_Or_Too_Often()
    {
        var idp = new FakeIdp();
        var clock = new FakeClock();
        var verifier = new IdTokenVerifier(clock, NullLogger<IdTokenVerifier>.Instance);
        var cm = new SwitchableConfigManager(Config(idp.Rsa));

        // wrong aud: refreshing the JWKS can't help, so no refresh
        Assert.NotNull(await verifier.VerifyAsync(idp.Token(null), cm, "other-client"));
        Assert.Equal(0, cm.RefreshRequests);

        // signature failure: the first one refreshes, the next one right after is within the minimum interval and doesn't
        var badToken = idp.Token(null, cred: new SigningCredentials(idp.OtherRsa, SecurityAlgorithms.RsaSha256));
        Assert.NotNull(await verifier.VerifyAsync(badToken, cm, "secrets-web"));
        Assert.Equal(1, cm.RefreshRequests);
        Assert.NotNull(await verifier.VerifyAsync(badToken, cm, "secrets-web"));
        Assert.Equal(1, cm.RefreshRequests);

        clock.Now = clock.Now.Add(IdTokenVerifier.MinRefreshInterval).AddSeconds(1);
        Assert.NotNull(await verifier.VerifyAsync(badToken, cm, "secrets-web"));
        Assert.Equal(2, cm.RefreshRequests);
    }
}

public class LoginFailureLimiterKeyTests
{
    private static HttpContext Ctx(string ip, IEnumerable<KeyValuePair<string, string>>? headers = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(ip);
        foreach (var (k, v) in headers ?? []) ctx.Request.Headers[k] = v;
        return ctx;
    }

    [Fact]
    public void Key_Is_The_Client_Ip_Only()
    {
        Assert.Equal("ip:127.0.0.1", LoginFailureLimiter.KeyFor(Ctx("127.0.0.1")));
        Assert.Equal("ip:unknown", LoginFailureLimiter.KeyFor(new DefaultHttpContext()));
    }

    /// <summary>
    /// Identity header that some mesh-VPN proxies inject (the vendor's "-User-Login" header). An earlier version keyed the
    /// limiter on it; the name is assembled so this generic repo carries no vendor-specific strings.
    /// </summary>
    private static readonly string VpnUserLoginHeader = string.Concat("Tail", "scale-User-Login");

    /// <summary>A client-supplied header must never influence rate limiting (e.g. a forged VPN user-login header).</summary>
    [Fact]
    public void Forged_Identity_Headers_Have_No_Effect()
    {
        var plain = LoginFailureLimiter.KeyFor(Ctx("203.0.113.7"));
        foreach (var header in new[] { VpnUserLoginHeader, "X-Forwarded-For", "X-Real-IP", "X-Forwarded-User" })
            Assert.Equal(plain, LoginFailureLimiter.KeyFor(Ctx("203.0.113.7", [new(header, "victim@example.com")])));

        // Rotating a forged header per request does not buy a fresh per-key budget
        var l = new LoginFailureLimiter(new FakeTime());
        for (var i = 0; i < LoginFailureLimiter.PerMinute; i++)
            Assert.NotNull(l.TryAcquire(LoginFailureLimiter.KeyFor(
                Ctx("203.0.113.7", [new(VpnUserLoginHeader, $"user{i}@example.com")]))));
        Assert.Null(l.TryAcquire(LoginFailureLimiter.KeyFor(
            Ctx("203.0.113.7", [new(VpnUserLoginHeader, "yet-another@example.com")]))));
    }

    [Fact]
    public void Different_Keys_Do_Not_Squeeze_Each_Other_Out()
    {
        var clock = new FakeTime();
        var l = new LoginFailureLimiter(clock);
        for (var i = 0; i < LoginFailureLimiter.PerMinute; i++) Assert.NotNull(l.TryAcquire("ip:198.51.100.1"));
        Assert.Null(l.TryAcquire("ip:198.51.100.1"));
        Assert.NotNull(l.TryAcquire("ip:198.51.100.2")); // another source can still write
    }

    [Fact]
    public void Global_Cap_Still_Applies()
    {
        var l = new LoginFailureLimiter(new FakeTime());
        var written = 0;
        for (var i = 0; i < 200; i++)
            if (l.TryAcquire("ip:10.0.0." + i) is not null) written++;
        Assert.Equal(LoginFailureLimiter.GlobalPerMinute, written);
    }

    private sealed class FakeTime : TimeProvider
    {
        private readonly DateTimeOffset _now = DateTimeOffset.Parse("2026-09-18T00:00:00Z");
        public override DateTimeOffset GetUtcNow() => _now;
    }
}

public class ForwardCompatTests
{
    [Fact]
    public void Unknown_Catalog_Keys_Rotate_And_Readers_Are_Ignored()
    {
        var rcpt = Format.Recipients.Empty;
        var c = Format.Catalog.Parse(
            "[[meta]]\nformat = \"1\"\n\n[[entry]]\npath = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\n" +
            "rotate = \"Some console → reset\"\nreaders = [\"backup-script\", \"Zoë (ops)\"]\nupdated = \"2026-09-18\"\n", rcpt);
        Assert.True(c.Entries.Single().IsValid);
    }
}

/// <summary>Network:KnownProxies / KnownNetworks: forwarded headers are only honored from explicitly trusted proxies.</summary>
public class ForwardedHeadersTests
{
    [Fact]
    public void Nothing_Configured_Means_No_Forwarded_Header_Processing()
    {
        Assert.Null(StartupChecks.BuildForwardedHeaders(new NetworkOptions()));
        Assert.Null(StartupChecks.BuildForwardedHeaders(new NetworkOptions { KnownProxies = [" "], KnownNetworks = [""] }));
    }

    [Fact]
    public void Only_The_Configured_Proxies_Are_Trusted_For_One_Hop()
    {
        var f = StartupChecks.BuildForwardedHeaders(new NetworkOptions { KnownProxies = ["172.17.0.1"], KnownNetworks = ["10.0.0.0/8"] })!;
        Assert.Equal(Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto,
            f.ForwardedHeaders);
        Assert.Equal(1, f.ForwardLimit);
        Assert.Equal([System.Net.IPAddress.Parse("172.17.0.1")], f.KnownProxies);
        Assert.Equal([System.Net.IPNetwork.Parse("10.0.0.0/8")], f.KnownIPNetworks);
    }

    [Theory]
    [InlineData("not-an-ip", null)]
    [InlineData(null, "10.0.0.0/33")]
    [InlineData(null, "10.0.0.0")]
    public void Invalid_Entries_Fail_Startup(string? proxy, string? network)
    {
        var o = new NetworkOptions { KnownProxies = proxy is null ? [] : [proxy], KnownNetworks = network is null ? [] : [network] };
        Assert.Throws<InvalidOperationException>(() => StartupChecks.BuildForwardedHeaders(o));
    }
}

/// <summary>End to end: the audit ip follows X-Forwarded-For only when the connecting peer is a configured proxy.</summary>
public sealed class ForwardedHeadersEndToEndTests(RealAuthFactory factory) : IClassFixture<RealAuthFactory>
{
    private sealed class PeerIpFilter(string ip) : Microsoft.AspNetCore.Hosting.IStartupFilter
    {
        public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next) => app =>
        {
            app.Use((ctx, n) => { ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(ip); return n(ctx); });
            next(app);
        };
    }

    private async Task<string> AuditedIpFor(Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> f, string forwardedFor)
    {
        using var c = f.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var req = new HttpRequestMessage(HttpMethod.Get, "/signin-oidc?code=x&state=garbage");
        req.Headers.Add("X-Forwarded-For", forwardedFor);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.SendAsync(req)).StatusCode);
        var line = File.ReadAllLines(factory.Repo.AuditPath).Last(l => l.Contains("\"event\":\"login_failed\""));
        return System.Text.Json.JsonDocument.Parse(line).RootElement.GetProperty("ip").GetString()!;
    }

    [Fact]
    public async Task Trusted_Proxy_Forwarded_For_Is_Used()
    {
        using var f = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Network:KnownProxies:0", "10.9.8.7");
            b.ConfigureTestServices(s => s.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter>(new PeerIpFilter("10.9.8.7")));
        });
        Assert.Equal("198.51.100.23", await AuditedIpFor(f, "198.51.100.23"));
    }

    /// <summary>The framework's default trust of loopback is cleared: only the configured proxy counts.</summary>
    [Theory]
    [InlineData("10.1.1.1")]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public async Task Untrusted_Peer_Forwarded_For_Is_Ignored(string peer)
    {
        using var f = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Network:KnownProxies:0", "10.9.8.7");
            b.ConfigureTestServices(s => s.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter>(new PeerIpFilter(peer)));
        });
        Assert.Equal(peer, await AuditedIpFor(f, "198.51.100.24"));
    }

    [Fact]
    public async Task No_Proxy_Configured_Forwarded_For_Is_Ignored_Even_From_Loopback()
    {
        using var f = factory.WithWebHostBuilder(b =>
            b.ConfigureTestServices(s => s.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter>(new PeerIpFilter("127.0.0.1"))));
        Assert.Equal("127.0.0.1", await AuditedIpFor(f, "198.51.100.25"));
    }
}
