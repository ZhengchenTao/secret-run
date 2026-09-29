using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecretsWeb.Audit;
using SecretsWeb.Format;
using SecretsWeb.Security;

namespace SecretsWeb.Tests;

/// <summary>The rate-limit key must not follow the cookie (SlidingExpiration re-issues the cookie; if the key changed, the hourly cap would be meaningless).</summary>
public class RateLimitKeyTests
{
    private static HttpContext Ctx(string? sub, string? sid, string? cookie)
    {
        var ctx = new DefaultHttpContext();
        var claims = new List<Claim>();
        if (sub is not null) claims.Add(new Claim("sub", sub));
        if (sid is not null) claims.Add(new Claim(DecryptRateLimiter.SessionIdClaim, sid));
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        if (cookie is not null) ctx.Request.Headers.Cookie = $"{DecryptRateLimiter.SessionCookieName}={cookie}";
        return ctx;
    }

    [Fact]
    public void Key_Is_Stable_Across_Cookie_Resign()
    {
        var before = DecryptRateLimiter.KeyFor(Ctx("alice", "sid-abc", "cookie-value-1"));
        var after = DecryptRateLimiter.KeyFor(Ctx("alice", "sid-abc", "cookie-value-2-after-sliding-resign"));
        Assert.Equal(before, after);
        Assert.Contains("alice", before);
        Assert.Contains("sid-abc", before);
    }

    [Fact]
    public void Different_Sessions_And_Fallbacks()
    {
        Assert.NotEqual(DecryptRateLimiter.KeyFor(Ctx("alice", "sid-a", null)), DecryptRateLimiter.KeyFor(Ctx("alice", "sid-b", null)));
        // only without a sid (an older ticket) fall back to a cookie hash
        var c1 = DecryptRateLimiter.KeyFor(Ctx("alice", null, "cookie-1"));
        Assert.StartsWith("s:", c1);
        Assert.NotEqual(c1, DecryptRateLimiter.KeyFor(Ctx("alice", null, "cookie-2")));
        Assert.Equal("u:alice", DecryptRateLimiter.KeyFor(Ctx("alice", null, null)));
    }

    [Fact]
    public async Task Per_Hour_Limit_Holds_When_Cookie_Changes()
    {
        using var f = new RateLimitPerHourFactory();
        using var c = f.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false,
        });
        c.DefaultRequestHeaders.Add(TestAuthHandler.Header, "alice");
        c.DefaultRequestHeaders.Add("X-Test-Sid", "stable-sid");

        var first = await c.GetAsync("/entry/personal/test/api");
        var html = await first.Content.ReadAsStringAsync();
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;
        var afCookie = first.Headers.GetValues("Set-Cookie")
            .First(x => x.StartsWith("__Host-secrets-web-af=", StringComparison.Ordinal)).Split(';')[0];

        HttpRequestMessage Req(int i)
        {
            var m = new HttpRequestMessage(HttpMethod.Post, "/api/field")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                    { ["path"] = "personal/test/api", ["field"] = "API_KEY", ["mode"] = "show" }),
            };
            m.Headers.Add("RequestVerificationToken", token);
            m.Headers.Add(CsrfHeader.Name, "1");
            // a new session cookie value every time: simulates sliding-renewal re-issue
            m.Headers.Add("Cookie", $"{afCookie}; {DecryptRateLimiter.SessionCookieName}=resigned-{i}");
            return m;
        }

        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Req(1))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Req(2))).StatusCode);
        var third = await c.SendAsync(Req(3));
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
    }
}

/// <summary>An instance that allows only 2 decryptions per hour.</summary>
public sealed class RateLimitPerHourFactory : WriteFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder b)
    {
        base.ConfigureWebHost(b);
        b.UseSetting("DecryptLimits:PerHour", "2");
    }
}

/// <summary>Value constraints aligned with the CLI + the priority / linked keys.</summary>
public class CatalogValueConstraintTests
{
    private const string Meta = "[[meta]]\nformat = \"1\"\n\n";
    private const string Base = "path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\nupdated = \"2026-09-18\"\n";

    private static Catalog Parse(string entryBody) =>
        Catalog.Parse(Meta + "[[entry]]\n" + entryBody, Recipients.Empty);

    [Theory]
    [InlineData("rotate = \"\"\n")]
    [InlineData("rotate = \"  \"\n")]
    [InlineData("readers = [\"\", \"x\"]\n")]
    [InlineData("readers = [\"  \"]\n")]
    [InlineData("tags = [\"\"]\n")]
    [InlineData("linked = [\"\"]\n")]
    [InlineData("priority = \"urgent\"\n")]
    [InlineData("priority = \"\"\n")]
    [InlineData("linked = [\"personal/app/missing\"]\n")]
    [InlineData("linked = [\"not-a-path\"]\n")]
    public void Empty_Or_Invalid_Optional_Values_Invalidate_The_Entry(string extra)
    {
        var c = Parse(Base + extra);
        Assert.False(c.Entries.Single().IsValid);
    }

    [Theory]
    [InlineData("rotate = \"Some console → reset\"\n")]
    [InlineData("readers = [\"Zoë (ops)\", \"backup-script\"]\n")]
    [InlineData("priority = \"high\"\n")]
    [InlineData("priority = \"low\"\n")]
    public void Valid_Optional_Values_Are_Accepted(string extra) =>
        Assert.True(Parse(Base + extra).Entries.Single().IsValid);

    [Fact]
    public void Linked_Must_Point_At_An_Existing_Entry()
    {
        var c = Catalog.Parse(
            Meta + "[[entry]]\n" + Base + "linked = [\"personal/app/b\"]\npriority = \"high\"\n\n" +
            "[[entry]]\npath = \"personal/app/b\"\ntype = \"doc\"\ntitle = \"B\"\nupdated = \"2026-09-18\"\n",
            Recipients.Empty);
        Assert.All(c.Entries, e => Assert.True(e.IsValid));
        var a = c.Find("personal/app/a")!;
        Assert.Equal("high", a.Priority);
        Assert.Equal(["personal/app/b"], a.Linked);
    }
}

/// <summary>On a write failure, rotate and retry once (with a full /data, rotating is exactly what helps).</summary>
public class AuditRotateOnFailureTests
{
    private static AuditRecord Rec() => new() { Timestamp = DateTimeOffset.UtcNow.ToString("O"), Event = "decrypt" };

    private static (AuditLog Log, string Path, string Dir) Make(long maxBytes = 8 * 1024 * 1024)
    {
        var dir = Path.Combine(Path.GetTempPath(), "sw-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "audit.log");
        return (new AuditLog(Options.Create(new AuditOptions { Path = path, MaxBytes = maxBytes, KeepFiles = 3 }),
            NullLogger<AuditLog>.Instance), path, dir);
    }

    [Fact]
    public void Unwritable_File_Is_Rotated_Away_And_The_Line_Still_Lands()
    {
        var (log, path, dir) = Make();
        try
        {
            File.WriteAllText(path, "old\n");
            File.SetAttributes(path, FileAttributes.ReadOnly); // appending will fail
            log.Write(Rec());                                   // no throw: rotation moves it away, the retry succeeds
            Assert.Single(File.ReadAllLines(path));
            Assert.True(File.Exists(path + ".1"));
        }
        finally
        {
            foreach (var f in Directory.GetFiles(dir)) File.SetAttributes(f, FileAttributes.Normal);
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Still_Fail_Closed_When_Rotation_Cannot_Help()
    {
        var (log, path, dir) = Make();
        FileStream? blocker = null;
        try
        {
            log.Write(Rec());
            blocker = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None); // not even a rename is possible
            Assert.Throws<AuditWriteException>(() => log.Write(Rec()));
        }
        finally
        {
            blocker?.Dispose();
            Directory.Delete(dir, true);
        }
    }
}

/// <summary>When the web UI writes the catalog, unknown keys and priority / linked must all survive.</summary>
public class CatalogWritePreservationTests
{
    [Fact]
    public void Writer_Keeps_Unknown_Keys_And_Field_Order()
    {
        var blocks = RestrictedToml.Parse(
            "# header comment (café)\n\n[[meta]]\nformat = \"1\"\n\n[[entry]]\nupdated = \"2026-09-18\"\npath = \"personal/app/a\"\n" +
            "type = \"doc\"\ntitle = \"T\"\npriority = \"high\"\nlinked = [\"personal/app/b\"]\nfuture_key = \"x\"\n");
        var text = TomlWriter.Write(blocks, "# header comment (café)\n");

        Assert.StartsWith("# header comment (café)\n", text);
        Assert.Contains("priority = \"high\"", text);
        Assert.Contains("linked = [\"personal/app/b\"]", text);
        Assert.Contains("future_key = \"x\"", text);
        // canonical key order: path before type, updated last among known keys, unknown keys after updated
        var entry = text[text.IndexOf("[[entry]]", StringComparison.Ordinal)..];
        Assert.True(entry.IndexOf("path =", StringComparison.Ordinal) < entry.IndexOf("type =", StringComparison.Ordinal));
        Assert.True(entry.IndexOf("priority =", StringComparison.Ordinal) < entry.IndexOf("updated =", StringComparison.Ordinal));
        Assert.True(entry.IndexOf("updated =", StringComparison.Ordinal) < entry.IndexOf("future_key =", StringComparison.Ordinal));

        // parsing it again still works
        var again = RestrictedToml.Parse(text);
        Assert.Equal(2, again.Count);
    }
}

/// <summary>Google id_tokens may carry either issuer spelling; every other provider is matched exactly.</summary>
public class IssuerVariantTests
{
    [Theory]
    [InlineData("https://accounts.google.com")]
    [InlineData("https://accounts.google.com/")]
    public void Google_accepts_both_spellings(string authority) =>
        Assert.Equal(["https://accounts.google.com", "accounts.google.com"], IdTokenVerifier.IssuerVariants(authority));

    [Fact]
    public void Other_providers_are_exact() =>
        Assert.Equal(["https://login.example.com/realms/x"], IdTokenVerifier.IssuerVariants("https://login.example.com/realms/x"));
}
