using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecretsWeb.Security;

namespace SecretsWeb.Tests;

/// <summary>Test authentication scheme: replaces OIDC + cookie; the identity comes from the X-Test-Sub request header, no header = anonymous.</summary>
public sealed class TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> o, ILoggerFactory l, UrlEncoder e)
    : AuthenticationHandler<AuthenticationSchemeOptions>(o, l, e)
{
    public const string SchemeName = "Test";
    public const string Header = "X-Test-Sub";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var sub = Request.Headers[Header].ToString();
        if (string.IsNullOrEmpty(sub)) return Task.FromResult(AuthenticateResult.NoResult());
        var sid = Request.Headers["X-Test-Sid"].ToString();
        var claims = new List<Claim> { new("sub", sub) };
        if (sid.Length > 0) claims.Add(new Claim("sid", sid));
        var id = new ClaimsIdentity(claims, SchemeName, "sub", "role");
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(id), SchemeName)));
    }
}

public sealed class AppFactory : WebApplicationFactory<Program>
{
    public TestRepoFixture Repo { get; } = new();

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
        builder.ConfigureTestServices(s =>
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

public sealed class IntegrationTests(AppFactory factory) : IClassFixture<AppFactory>
{
    private TestRepoFixture R => factory.Repo;

    private HttpClient Client(string? sub = "alice")
    {
        var c = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true,
        });
        if (sub is not null) c.DefaultRequestHeaders.Add(TestAuthHandler.Header, sub);
        return c;
    }

    private static async Task<string> TokenFrom(HttpClient c, string path)
    {
        var html = await c.GetStringAsync(path);
        var m = Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"");
        Assert.True(m.Success, "no antiforgery token on the page");
        return m.Groups[1].Value;
    }

    private static HttpRequestMessage FieldRequest(string token, string path, string field, string mode, bool header = true)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/field")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["path"] = path, ["field"] = field, ["mode"] = mode }),
        };
        req.Headers.Add("RequestVerificationToken", token);
        if (header) req.Headers.Add(CsrfHeader.Name, "1");
        return req;
    }

    private string[] AuditLines() =>
        File.Exists(R.AuditPath) ? File.ReadAllLines(R.AuditPath) : [];

    [Fact]
    public async Task Anonymous_Entry_Page_Is_Challenged()
    {
        using var c = Client(sub: null);
        var resp = await c.GetAsync("/entry/personal/test/api");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        var post = await c.PostAsync("/api/field", new FormUrlEncodedContent(new Dictionary<string, string> { ["path"] = "personal/test/api" }));
        Assert.True(post.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Non_Allowed_Subject_Is_Forbidden()
    {
        using var c = Client(sub: "mallory");
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/entry/personal/test/api")).StatusCode);
    }

    [Fact]
    public async Task List_And_Search_Do_Not_Decrypt()
    {
        var before = AuditLines().Length;
        using var c = Client();
        var html = await c.GetStringAsync("/");
        foreach (var p in TestRepoFixture.EntryPaths) Assert.Contains(p, html);
        var search = await c.GetStringAsync("/?q=testtag");
        Assert.Contains("personal/test/api", search);
        Assert.DoesNotContain("work/test/config", search);
        Assert.Contains("work/test/config", html); // a non-personal domain is listed like any other
        Assert.DoesNotContain(R.ApiKey, html + search);
        Assert.Equal(before, AuditLines().Length);
    }

    [Fact]
    public async Task Kv_Get_Page_Has_No_Values()
    {
        using var c = Client();
        var resp = await c.GetAsync("/entry/personal/test/api");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("API_KEY", html);
        Assert.DoesNotContain(R.ApiKey, html);
        Assert.DoesNotContain(R.ApiUser, html);
        Assert.Equal("no-store", resp.Headers.CacheControl?.ToString());
        // a GET on the API doesn't return the value either
        var get = await c.GetAsync("/api/field?path=personal/test/api&field=API_KEY&mode=show");
        Assert.NotEqual(HttpStatusCode.OK, get.StatusCode);
        Assert.DoesNotContain(R.ApiKey, await get.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Kv_Single_Field_Post_Returns_Value_And_Audits_Without_Value()
    {
        using var c = Client();
        var token = await TokenFrom(c, "/entry/personal/test/api");
        var resp = await c.SendAsync(FieldRequest(token, "personal/test/api", "API_KEY", "copy"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("no-store", resp.Headers.CacheControl?.ToString());
        var body = await resp.Content.ReadAsStringAsync();
        var value = JsonDocument.Parse(body).RootElement.GetProperty("value").GetString();
        Assert.Equal(R.ApiKey, value);
        Assert.DoesNotContain(R.ApiUser, body); // only the clicked field is returned

        var line = AuditLines().Last(l => l.Contains("\"field\":\"API_KEY\"") && l.Contains("\"action\":\"copy\""));
        using var j = JsonDocument.Parse(line);
        Assert.Equal("decrypt", j.RootElement.GetProperty("event").GetString());
        Assert.Equal("alice", j.RootElement.GetProperty("sub").GetString());
        Assert.Equal("personal/test/api", j.RootElement.GetProperty("path").GetString());
        Assert.Equal("ok", j.RootElement.GetProperty("result").GetString());
        var all = string.Join("\n", AuditLines());
        Assert.DoesNotContain(R.ApiKey, all);
        Assert.DoesNotContain(R.ApiUser, all);
    }

    [Fact]
    public async Task Kv_Post_Without_Antiforgery_Or_Custom_Header_Is_Rejected()
    {
        using var c = Client();
        var token = await TokenFrom(c, "/entry/personal/test/api");
        var noHeader = await c.SendAsync(FieldRequest(token, "personal/test/api", "API_KEY", "show", header: false));
        Assert.Equal(HttpStatusCode.BadRequest, noHeader.StatusCode);
        var badToken = await c.SendAsync(FieldRequest("bogus", "personal/test/api", "API_KEY", "show"));
        Assert.Equal(HttpStatusCode.BadRequest, badToken.StatusCode);
        Assert.DoesNotContain(R.ApiKey, await noHeader.Content.ReadAsStringAsync() + await badToken.Content.ReadAsStringAsync());
        var unknownField = await c.SendAsync(FieldRequest(token, "personal/test/api", "NOPE", "show"));
        Assert.Equal(HttpStatusCode.NotFound, unknownField.StatusCode);
    }

    [Fact]
    public async Task Doc_Renders_Markdown_Without_Raw_Html_Or_Js_Links()
    {
        using var c = Client();
        var req = new HttpRequestMessage(HttpMethod.Get, "/entry/personal/test/notes");
        req.Headers.Add("Sec-Fetch-Site", "same-origin");
        var resp = await c.SendAsync(req);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.DoesNotContain("evil.example", html);
        Assert.Contains("leak-alt", html);
        Assert.Contains("<img src=\"/app.css\"", html);
        Assert.Contains(R.DocMarker, html);
        Assert.DoesNotContain("<script>alert", html);
        Assert.DoesNotContain("javascript:", html);
        Assert.Contains("rel=\"noopener noreferrer\"", html);
        Assert.Contains("\"path\":\"personal/test/notes\"", string.Join("\n", AuditLines()));
    }

    [Fact]
    public async Task File_Text_View_And_Binary_Download()
    {
        using var c = Client();
        var token = await TokenFrom(c, "/entry/work/test/config");
        var get = await c.GetStringAsync("/entry/work/test/config");
        Assert.DoesNotContain(R.FileText.Trim(), get);

        var req = new HttpRequestMessage(HttpMethod.Post, "/api/file")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["path"] = "work/test/config" }),
        };
        req.Headers.Add("RequestVerificationToken", token);
        req.Headers.Add(CsrfHeader.Name, "1");
        var view = JsonDocument.Parse(await (await c.SendAsync(req)).Content.ReadAsStringAsync()).RootElement;
        Assert.True(view.GetProperty("isText").GetBoolean());
        Assert.Equal(R.FileText, view.GetProperty("text").GetString());

        var dl = new HttpRequestMessage(HttpMethod.Post, "/api/download")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
                { ["path"] = "personal/test/blob", ["__RequestVerificationToken"] = token }),
        };
        var dlResp = await c.SendAsync(dl);
        Assert.Equal(HttpStatusCode.OK, dlResp.StatusCode);
        Assert.Equal("no-store", dlResp.Headers.CacheControl?.ToString());
        Assert.Equal(new byte[] { 0x00, 0xFF, 0x10, 0x00, 0x42 }, await dlResp.Content.ReadAsByteArrayAsync());
        Assert.Contains(AuditLines(), l => l.Contains("\"path\":\"personal/test/blob\"") && l.Contains("\"action\":\"download\""));
    }

    [Fact]
    public async Task Health_Returns_Head_And_No_Entry_Names()
    {
        using var c = Client(sub: null);
        var resp = await c.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        var j = JsonDocument.Parse(body).RootElement;
        Assert.Equal("ok", j.GetProperty("status").GetString());
        Assert.Equal(R.Head, j.GetProperty("head").GetString());
        Assert.Equal("1", j.GetProperty("format").GetString());
        Assert.Equal(TestRepoFixture.EntryPaths.Length, j.GetProperty("entries").GetInt32());
        foreach (var p in TestRepoFixture.EntryPaths) Assert.DoesNotContain(p.Split('/')[2], body);
        Assert.Equal(1, j.GetProperty("invalidEntries").GetInt32());
        var cons = j.GetProperty("consistency");
        Assert.True(cons.GetProperty("consistent").GetBoolean());
        Assert.Equal(TestRepoFixture.EntryPaths.Length, cons.GetProperty("storeFiles").GetInt32());
        Assert.Equal(TestRepoFixture.EntryPaths.Length, cons.GetProperty("lockLines").GetInt32());
    }

    [Fact]
    public async Task Invalid_Entry_Metadata_Only_Affects_That_Entry()
    {
        using var c = Client();
        var list = await c.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        var html = await list.Content.ReadAsStringAsync();
        Assert.Contains("unavailable", html);
        var entry = await c.GetAsync("/entry/personal/test/badmeta");
        Assert.Equal(HttpStatusCode.BadGateway, entry.StatusCode);
        var entryHtml = await entry.Content.ReadAsStringAsync();
        Assert.Contains("title is empty", entryHtml);
        Assert.DoesNotContain(R.DocMarker, entryHtml);
        Assert.DoesNotContain(AuditLines(), l => l.Contains("personal/test/badmeta"));
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/entry/personal/test/api")).StatusCode);
    }

    [Fact]
    public async Task Doc_Cross_Site_Get_Shows_Button_And_Post_Decrypts()
    {
        using var c = Client();
        foreach (var site in new[] { "cross-site", "same-site", "" })
        {
            var req = new HttpRequestMessage(HttpMethod.Get, "/entry/personal/test/notes");
            if (site.Length > 0) req.Headers.Add("Sec-Fetch-Site", site);
            var html = await (await c.SendAsync(req)).Content.ReadAsStringAsync();
            Assert.DoesNotContain(R.DocMarker, html);
            Assert.Contains("Click to view", html);
        }
        var token = await TokenFrom(c, "/entry/personal/test/notes");
        var post = new HttpRequestMessage(HttpMethod.Post, "/entry/personal/test/notes")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }),
        };
        var resp = await c.SendAsync(post);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains(R.DocMarker, await resp.Content.ReadAsStringAsync());

        var noToken = await c.PostAsync("/entry/personal/test/notes", new FormUrlEncodedContent([]));
        Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);
    }

    /// <summary>
    /// Favorites (web UI only): toggling writes the server-side file and the list shows favorites as the first group; unknown
    /// entry 404; missing custom header 400 (like every other /api); not audited and no decryption quota used (it never touches values).
    /// </summary>
    [Fact]
    public async Task Favorite_Toggles_And_Sorts_First()
    {
        using var c = Client();
        var token = await TokenFrom(c, "/entry/personal/test/notes");

        HttpRequestMessage Fav(string path, string on, bool header = true)
        {
            var r = new HttpRequestMessage(HttpMethod.Post, "/api/favorite")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["path"] = path, ["on"] = on }),
            };
            r.Headers.Add("RequestVerificationToken", token);
            if (header) r.Headers.Add(CsrfHeader.Name, "1");
            return r;
        }

        Assert.Equal(HttpStatusCode.BadRequest, (await c.SendAsync(Fav("personal/test/notes", "1", header: false))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.SendAsync(Fav("personal/test/nope", "1"))).StatusCode);

        var auditBefore = AuditLines().Length;
        var on = await c.SendAsync(Fav("personal/test/notes", "1"));
        Assert.Equal(HttpStatusCode.OK, on.StatusCode);
        Assert.True(JsonDocument.Parse(await on.Content.ReadAsStringAsync()).RootElement.GetProperty("favorite").GetBoolean());
        Assert.True(File.Exists(R.FavoritesPath));
        Assert.Contains("personal/test/notes", await File.ReadAllTextAsync(R.FavoritesPath));
        Assert.Equal(auditBefore, AuditLines().Length);

        var list = await c.GetStringAsync("/");
        var starred = list.IndexOf("g-starred", StringComparison.Ordinal);
        Assert.True(starred > 0, "no favorites group in the list");
        Assert.True(starred < list.IndexOf("\"g-personal-test\"", StringComparison.Ordinal), "favorites are not listed first");

        var off = await c.SendAsync(Fav("personal/test/notes", "0"));
        Assert.False(JsonDocument.Parse(await off.Content.ReadAsStringAsync()).RootElement.GetProperty("favorite").GetBoolean());
        Assert.DoesNotContain("g-starred", await c.GetStringAsync("/"));
    }

    [Fact]
    public async Task Api_Non_Form_Content_Type_Is_400()
    {
        using var c = Client();
        var token = await TokenFrom(c, "/entry/personal/test/api");
        foreach (var url in new[] { "/api/field", "/api/file", "/api/download" })
        {
            var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json") };
            req.Headers.Add("RequestVerificationToken", token);
            req.Headers.Add(CsrfHeader.Name, "1");
            Assert.Equal(HttpStatusCode.BadRequest, (await c.SendAsync(req)).StatusCode);
            var empty = new HttpRequestMessage(HttpMethod.Post, url);
            empty.Headers.Add("RequestVerificationToken", token);
            empty.Headers.Add(CsrfHeader.Name, "1");
            Assert.Equal(HttpStatusCode.BadRequest, (await c.SendAsync(empty)).StatusCode);
        }
    }

    [Fact]
    public async Task Tampered_Ciphertext_Reports_Error_Without_Crashing()
    {
        using var c = Client();
        var token = await TokenFrom(c, "/entry/personal/test/broken");
        var resp = await c.SendAsync(FieldRequest(token, "personal/test/broken", "X", "show"));
        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        Assert.Contains("Invalid ciphertext", await resp.Content.ReadAsStringAsync());
        Assert.Contains(AuditLines(), l => l.Contains("\"path\":\"personal/test/broken\"") && l.Contains("invalid_ciphertext"));
        // the service is still fine
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/")).StatusCode);
    }

    [Fact]
    public async Task Security_Headers_Present()
    {
        using var c = Client();
        var resp = await c.GetAsync("/");
        Assert.Contains("script-src 'self'", resp.Headers.GetValues("Content-Security-Policy").Single());
        Assert.DoesNotContain("unsafe-inline", resp.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("DENY", resp.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", resp.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("nosniff", resp.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.DoesNotContain("<script>", await resp.Content.ReadAsStringAsync()); // no inline script
    }

    [Fact]
    public void Oidc_Options_Only_Allow_RS256()
    {
        var o = factory.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        Assert.Equal(["RS256"], o.TokenValidationParameters.ValidAlgorithms);
        Assert.True(o.UsePkce);
        Assert.Equal("code", o.ResponseType);
        Assert.False(o.SaveTokens);
        Assert.False(o.MapInboundClaims);
    }
}

public class AuthUnitTests
{
    [Fact]
    public void ConfigureOidc_Sets_RS256_Only()
    {
        var o = new OpenIdConnectOptions();
        AuthSetup.ConfigureOidc(o, new OidcOptions { Authority = "https://auth.example.invalid", ClientId = "x", ClientSecret = "y", Scopes = ["openid"] });
        Assert.Equal(["RS256"], o.TokenValidationParameters.ValidAlgorithms);
    }

    [Fact]
    public void Session_Absolute_Lifetime()
    {
        var now = DateTimeOffset.Parse("2026-09-17T12:00:00Z");
        var props = new AuthenticationProperties();
        Assert.True(SessionPolicy.IsExpired(props, now, TimeSpan.FromHours(8))); // no login time → reject
        props.Items[SessionPolicy.LoginUtcKey] = now.AddHours(-7).ToString("O");
        Assert.False(SessionPolicy.IsExpired(props, now, TimeSpan.FromHours(8)));
        props.Items[SessionPolicy.LoginUtcKey] = now.AddHours(-8).AddMinutes(-1).ToString("O");
        Assert.True(SessionPolicy.IsExpired(props, now, TimeSpan.FromHours(8)));
    }

    [Fact]
    public void Allowed_Subjects_Are_Exact_And_Fail_Closed()
    {
        Assert.True(new OidcOptions { AllowedSubjects = ["alice"] }.IsAllowed("alice"));
        Assert.False(new OidcOptions { AllowedSubjects = ["alice"] }.IsAllowed("ALICE"));
        Assert.False(new OidcOptions { AllowedSubjects = ["alice"] }.IsAllowed((string?)null));
        Assert.False(new OidcOptions().IsAllowed("alice"));
    }

    [Fact]
    public void Allowed_Emails_Are_Trimmed_And_Case_Insensitive()
    {
        var o = new OidcOptions { AllowedEmails = [" Alice@Example.com "] };
        Assert.True(o.IsAllowed("some-sub", "alice@example.com"));
        Assert.True(o.IsAllowed(null, "  ALICE@EXAMPLE.COM"));
        Assert.False(o.IsAllowed("some-sub", "bob@example.com"));
        Assert.False(o.IsAllowed("some-sub", null));
        Assert.False(o.IsAllowed("some-sub", ""));
        Assert.False(o.IsAllowed("alice@example.com")); // an email is not a subject
        Assert.False(new OidcOptions().IsAllowed(null, "alice@example.com"));
    }

    [Fact]
    public void Session_Principal_Only_Matches_Emails_Through_The_Verified_Claim()
    {
        var o = new OidcOptions { AllowedEmails = ["alice@example.com"] };
        ClaimsPrincipal P(params Claim[] c) => new(new ClaimsIdentity(c, "test"));
        Assert.True(o.IsAllowed(P(new("sub", "x"), new(OidcOptions.VerifiedEmailClaim, "alice@example.com"))));
        Assert.False(o.IsAllowed(P(new("sub", "x"), new("email", "alice@example.com"))));
        Assert.False(o.IsAllowed((ClaimsPrincipal?)null));
    }

    [Theory]
    [InlineData("true", ClaimValueTypes.Boolean, true)]
    [InlineData("True", ClaimValueTypes.Boolean, true)]
    [InlineData("true", ClaimValueTypes.String, true)]
    [InlineData("True", ClaimValueTypes.String, false)]
    [InlineData("false", ClaimValueTypes.Boolean, false)]
    [InlineData("1", ClaimValueTypes.String, false)]
    [InlineData("yes", ClaimValueTypes.String, false)]
    public void Email_Verified_Accepts_Only_Boolean_True_Or_String_True(string value, string type, bool expected)
    {
        var p = new ClaimsPrincipal(new ClaimsIdentity([new Claim("email_verified", value, type)], "test"));
        Assert.Equal(expected, AuthSetup.IsEmailVerified(p));
        Assert.False(AuthSetup.IsEmailVerified(new ClaimsPrincipal(new ClaimsIdentity())));
    }

    [Fact]
    public void Default_Scopes_Are_Used_When_None_Configured()
    {
        var o = new OpenIdConnectOptions();
        AuthSetup.ConfigureOidc(o, new OidcOptions { Authority = "https://auth.example.invalid", ClientId = "x", ClientSecret = "y" });
        Assert.Equal(["openid", "email", "profile"], o.Scope.ToArray());
        Assert.Equal("query", o.ResponseMode);
    }
}

/// <summary>Real authentication (not replaced): challenge behavior of the cookie scheme (pages 302 to /login, API 401), and /login starting the OIDC challenge.</summary>
public sealed class RealAuthFactory : WebApplicationFactory<Program>
{
    public TestRepoFixture Repo { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Auth:Authority", "https://auth.example.invalid");
        builder.UseSetting("Auth:ClientId", "secrets-web-test");
        builder.UseSetting("Auth:ClientSecret", "test-only-placeholder");
        builder.UseSetting("Auth:AllowedSubjects:0", "alice");
        builder.UseSetting("PublicOrigin", "https://secrets.example.com");
        builder.UseSetting("Repo:GitDir", Repo.BareDir);
        builder.UseSetting("Repo:Identity", Repo.IdentityPath);
        builder.UseSetting("Audit:Path", Repo.AuditPath);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) Repo.Dispose();
    }
}

public sealed class RealAuthTests(RealAuthFactory factory) : IClassFixture<RealAuthFactory>
{
    private HttpClient Client() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("http://127.0.0.1"),
        AllowAutoRedirect = false,
    });

    [Fact]
    public async Task Anonymous_Page_Redirects_To_Login_On_Public_Origin()
    {
        using var c = Client();
        var resp = await c.GetAsync("/entry/personal/test/api");
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var loc = resp.Headers.Location!.ToString();
        Assert.StartsWith("https://secrets.example.com/login", loc);
    }

    [Fact]
    public async Task Anonymous_Api_Gets_401()
    {
        using var c = Client();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/field") { Content = new FormUrlEncodedContent([]) };
        req.Headers.Add(CsrfHeader.Name, "1");
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.SendAsync(req)).StatusCode);
    }

    [Fact]
    public async Task Health_Is_Anonymous()
    {
        using var c = Client();
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/health")).StatusCode);
    }

    [Fact]
    public void Missing_Client_Secret_Fails_Fast()
    {
        using var f = factory.WithWebHostBuilder(b => b.UseSetting("Auth:ClientSecret", ""));
        Assert.Throws<InvalidOperationException>(() => f.CreateClient());
    }

    [Fact]
    public void Missing_Authority_Fails_Fast()
    {
        using var f = factory.WithWebHostBuilder(b => b.UseSetting("Auth:Authority", ""));
        Assert.Throws<InvalidOperationException>(() => f.CreateClient());
    }

    [Fact]
    public void Empty_Allowlists_Fail_Fast()
    {
        using var f = factory.WithWebHostBuilder(b => b.UseSetting("Auth:AllowedSubjects:0", ""));
        var ex = Assert.Throws<InvalidOperationException>(() => f.CreateClient());
        Assert.Contains("AllowedEmails", ex.Message);
    }

    [Fact]
    public void Email_Allowlist_Alone_Is_Enough_To_Start()
    {
        using var f = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Auth:AllowedSubjects:0", "");
            b.UseSetting("Auth:AllowedEmails:0", "alice@example.com");
        });
        using var c = f.CreateClient();
    }
}
