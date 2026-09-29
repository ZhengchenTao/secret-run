using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SecretsWeb.Security;

namespace SecretsWeb.Tests;

[CollectionDefinition("writes", DisableParallelization = true)]
public sealed class WriteCollection;

/// <summary>Factory for writes: the push target is the test bare repo (a local path, no real ssh needed); the working clone lives in a temp directory.</summary>
public class WriteFactory : WebApplicationFactory<Program>
{
    public TestRepoFixture Repo { get; }
    public string WorkDir { get; } = Path.Combine(Path.GetTempPath(), "sw-work-" + Guid.NewGuid().ToString("N"));
    public int WritePerMinute { get; protected init; } = 100;

    public WriteFactory() : this(includeInvalidEntry: false) { }

    /// <summary>includeInvalidEntry = true puts an entry with invalid metadata in the repo (to prove the pre-write check refuses).</summary>
    protected WriteFactory(bool includeInvalidEntry) => Repo = new TestRepoFixture(includeInvalidEntry);

    protected override void ConfigureWebHost(IWebHostBuilder b)
    {
        b.UseEnvironment("Testing");
        b.UseSetting("Auth:Authority", "https://auth.example.invalid");
        b.UseSetting("Auth:ClientId", "secrets-web-test");
        b.UseSetting("Auth:ClientSecret", "test-only-placeholder");
        b.UseSetting("Auth:AllowedSubjects:0", "alice");
        b.UseSetting("Repo:GitDir", Repo.BareDir);
        b.UseSetting("Repo:Identity", Repo.IdentityPath);
        b.UseSetting("Repo:PushUrl", Repo.BareDir);
        b.UseSetting("Repo:WorkDir", WorkDir);
        b.UseSetting("Audit:Path", Repo.AuditPath);
        b.UseSetting("DecryptLimits:WritePerMinute", WritePerMinute.ToString());
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

    public HttpClient Client(string? sub = "alice")
    {
        var c = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        if (sub is not null) c.DefaultRequestHeaders.Add(TestAuthHandler.Header, sub);
        return c;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        Repo.Dispose();
        try { if (Directory.Exists(WorkDir)) TestRepoFixture.ForceDelete(WorkDir); } catch (IOException) { }
    }
}

[Collection("writes")]
public sealed class WriteTests(WriteFactory f) : IClassFixture<WriteFactory>
{
    private TestRepoFixture R => f.Repo;

    private static async Task<string> Token(HttpClient c, string page)
    {
        var html = await c.GetStringAsync(page);
        return Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;
    }

    private static HttpRequestMessage Post(string url, string token, IEnumerable<KeyValuePair<string, string>> fields,
        bool withToken = true, bool withHeader = true, (string Name, byte[] Bytes)? upload = null)
    {
        var content = new MultipartFormDataContent();
        foreach (var kv in fields) content.Add(new StringContent(kv.Value, Encoding.UTF8), kv.Key);
        if (upload is { } u)
        {
            var part = new ByteArrayContent(u.Bytes);
            part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(part, "upload", u.Name);
        }
        var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        if (withToken) req.Headers.Add("RequestVerificationToken", token);
        if (withHeader) req.Headers.Add(CsrfHeader.Name, "1");
        return req;
    }

    private async Task<string?> FieldValue(HttpClient c, string path, string field)
    {
        var token = await Token(c, "/entry/" + path);
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/field")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["path"] = path, ["field"] = field, ["mode"] = "show" }),
        };
        req.Headers.Add("RequestVerificationToken", token);
        req.Headers.Add(CsrfHeader.Name, "1");
        var resp = await c.SendAsync(req);
        if (!resp.IsSuccessStatusCode) return null;
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.GetProperty("value").GetString();
    }

    private static async Task<string> Fingerprint(HttpClient c, string path) =>
        Regex.Match(await c.GetStringAsync($"/entry/{path}/edit"), "name=\"expected\" value=\"([^\"]+)\"").Groups[1].Value;

    private async Task<JsonElement> Health(HttpClient c) =>
        JsonDocument.Parse(await c.GetStringAsync("/health")).RootElement.Clone();

    private string BareHead() => R.GitOutput("--git-dir", R.BareDir, "rev-parse", "HEAD").Trim();

    private string[] AuditLines() => File.Exists(R.AuditPath) ? File.ReadAllLines(R.AuditPath) : [];

    [Fact]
    public async Task Create_Edit_Delete_Round_Trip()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        var value = "created-" + Guid.NewGuid().ToString("N")[..10];
        var path = "personal/test/created";

        // create
        var create = await c.SendAsync(Post("/api/entry/create", token,
        [
            new("path", path), new("type", "kv"), new("title", "Created entry"), new("description", "integration test"),
            new("tags", "t1, t2"), new("rotate", "Some console → reset"), new("readers", "Zoë"),
            new("content", $"# c\nAPI_KEY={value}\n"),
        ]));
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        var created = JsonDocument.Parse(await create.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("/entry/" + path, created.GetProperty("redirect").GetString());
        Assert.Equal(BareHead(), created.GetProperty("commit").GetString()); // already pushed to the bare repo

        // read it back (through the bare-repo read path)
        Assert.Equal(value, await FieldValue(c, path, "API_KEY"));
        var page = await c.GetStringAsync("/entry/" + path);
        Assert.Contains("Created entry", page);
        Assert.Contains("Some console", page);
        Assert.DoesNotContain(value, page);
        var health = await Health(c);
        Assert.Equal(R.Paths.Count + 1, health.GetProperty("entries").GetInt32());
        Assert.True(health.GetProperty("consistency").GetProperty("consistent").GetBoolean());

        // edit: metadata only (content left empty). expected = the fingerprint from the edit page (mandatory optimistic concurrency)
        var expected1 = await Fingerprint(c, path);
        var upd = await c.SendAsync(Post("/api/entry/update", token,
        [
            new("path", path), new("type", "kv"), new("title", "Changed title"), new("tags", "t3"),
            new("content", ""), new("expected", expected1),
        ]));
        Assert.Equal(HttpStatusCode.OK, upd.StatusCode);
        Assert.Contains("Changed title", await c.GetStringAsync("/entry/" + path));
        Assert.Equal(value, await FieldValue(c, path, "API_KEY")); // content untouched

        // edit: change content and fields
        var value2 = "rotated-" + Guid.NewGuid().ToString("N")[..10];
        var upd2 = await c.SendAsync(Post("/api/entry/update", token,
        [
            new("path", path), new("type", "kv"), new("title", "Changed title"),
            new("content", $"API_KEY={value2}\nEXTRA=x\n"), new("expected", await Fingerprint(c, path)),
        ]));
        Assert.Equal(HttpStatusCode.OK, upd2.StatusCode);
        Assert.Equal(value2, await FieldValue(c, path, "API_KEY"));
        Assert.Equal("x", await FieldValue(c, path, "EXTRA"));

        // delete (needs the confirmation token)
        var deletePage = await c.GetStringAsync($"/entry/{path}/delete");
        var confirm = Regex.Match(deletePage, "name=\"confirm\" value=\"([^\"]+)\"").Groups[1].Value;
        Assert.NotEmpty(confirm);
        var noConfirm = await c.SendAsync(Post("/api/entry/delete", token, [new("path", path), new("confirm", "bogus")]));
        Assert.Equal(HttpStatusCode.BadRequest, noConfirm.StatusCode);
        var del = await c.SendAsync(Post("/api/entry/delete", token, [new("path", path), new("confirm", confirm)]));
        Assert.Equal(HttpStatusCode.OK, del.StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/entry/" + path)).StatusCode);
        var health2 = await Health(c);
        Assert.Equal(R.Paths.Count, health2.GetProperty("entries").GetInt32());
        var cons = health2.GetProperty("consistency");
        Assert.True(cons.GetProperty("consistent").GetBoolean());
        Assert.Equal(R.Paths.Count, cons.GetProperty("storeFiles").GetInt32());
        Assert.Equal(R.Paths.Count, cons.GetProperty("lockLines").GetInt32());

        // audit: write lines present, commit recorded, no values
        var lines = AuditLines();
        Assert.Contains(lines, l => l.Contains("\"event\":\"write\"") && l.Contains("\"action\":\"create\""));
        Assert.Contains(lines, l => l.Contains("\"action\":\"update-meta\""));
        Assert.Contains(lines, l => l.Contains("\"action\":\"delete\"") && l.Contains(path));
        var all = string.Join("\n", lines);
        Assert.DoesNotContain(value, all);
        Assert.DoesNotContain(value2, all);
    }

    [Fact]
    public async Task Doc_And_File_Upload_Round_Trip()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        var marker = "doc-" + Guid.NewGuid().ToString("N")[..8];

        var doc = await c.SendAsync(Post("/api/entry/create", token,
        [
            new("path", "personal/test/newdoc"), new("type", "doc"), new("title", "New document"),
            new("content", $"# Title\n\n{marker}\n"),
        ]));
        Assert.Equal(HttpStatusCode.OK, doc.StatusCode);
        var req = new HttpRequestMessage(HttpMethod.Get, "/entry/personal/test/newdoc");
        req.Headers.Add("Sec-Fetch-Site", "same-origin");
        Assert.Contains(marker, await (await c.SendAsync(req)).Content.ReadAsStringAsync());

        var bytes = new byte[] { 0x00, 0x01, 0x02, 0xFF, 0x42 };
        var file = await c.SendAsync(Post("/api/entry/create", token,
        [
            new("path", "personal/test/newblob"), new("type", "file"), new("title", "Uploaded binary"),
            new("target", "{workspace}/x/blob.bin"), new("content", ""),
        ], upload: ("blob.bin", bytes)));
        Assert.Equal(HttpStatusCode.OK, file.StatusCode);

        var dlToken = await Token(c, "/entry/personal/test/newblob");
        var dl = new HttpRequestMessage(HttpMethod.Post, "/api/download")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
                { ["path"] = "personal/test/newblob", ["__RequestVerificationToken"] = dlToken }),
        };
        var dlResp = await c.SendAsync(dl);
        Assert.Equal(bytes, await dlResp.Content.ReadAsByteArrayAsync());

        // clean up so other tests' counts aren't affected
        foreach (var p in new[] { "personal/test/newdoc", "personal/test/newblob" })
        {
            var page = await c.GetStringAsync($"/entry/{p}/delete");
            var confirm = Regex.Match(page, "name=\"confirm\" value=\"([^\"]+)\"").Groups[1].Value;
            Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Post("/api/entry/delete", token, [new("path", p), new("confirm", confirm)]))).StatusCode);
        }
    }

    [Fact]
    public async Task Plaintext_Never_Touches_The_Workspace()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        var value = "ondisk-" + Guid.NewGuid().ToString("N")[..10];
        var path = "personal/test/ondisk";
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Post("/api/entry/create", token,
        [
            new("path", path), new("type", "kv"), new("title", "On-disk check"), new("content", $"K={value}\n"),
        ]))).StatusCode);

        var needle = Encoding.UTF8.GetBytes(value);
        foreach (var file in Directory.EnumerateFiles(f.WorkDir, "*", SearchOption.AllDirectories))
        {
            var bytes = File.ReadAllBytes(file);
            Assert.False(Contains(bytes, needle), $"plaintext found in {file}");
        }

        var page = await c.GetStringAsync($"/entry/{path}/delete");
        var confirm = Regex.Match(page, "name=\"confirm\" value=\"([^\"]+)\"").Groups[1].Value;
        await c.SendAsync(Post("/api/entry/delete", token, [new("path", path), new("confirm", confirm)]));
    }

    private static bool Contains(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i + needle.Length <= haystack.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length && ok; j++) ok = haystack[i + j] == needle[j];
            if (ok) return true;
        }
        return false;
    }

    [Theory]
    [InlineData("api_key=x", "Invalid kv content")]
    [InlineData(" API_KEY=x", "Invalid kv content")]
    [InlineData("NOEQUALS", "Invalid kv content")]
    public async Task Invalid_Kv_Input_Is_Rejected_Without_Committing(string content, string expected)
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        var head = BareHead();
        var resp = await c.SendAsync(Post("/api/entry/create", token,
        [
            new("path", "personal/test/badkv"), new("type", "kv"), new("title", "Bad input"), new("content", content),
        ]));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains(expected, await resp.Content.ReadAsStringAsync());
        Assert.Equal(head, BareHead());
    }

    [Theory]
    [InlineData("personal/test", "path must be")]
    [InlineData("Work/test/x", "path must be")]
    [InlineData("con/test/x", "path must be")]
    [InlineData("personal/test/CON", "path must be")]
    public async Task Invalid_Path_Is_Rejected(string path, string expected)
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        var resp = await c.SendAsync(Post("/api/entry/create", token,
            [new("path", path), new("type", "kv"), new("title", "Bad path"), new("content", "K=v\n")]));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains(expected, await resp.Content.ReadAsStringAsync());
    }

    /// <summary>Domains are generic: an entry under any valid domain (here work/) can be created, read and deleted.</summary>
    [Fact]
    public async Task Generic_Domain_Round_Trip()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        const string path = "work/app/key";
        var value = "work-" + Guid.NewGuid().ToString("N")[..10];
        var create = await c.SendAsync(Post("/api/entry/create", token,
            [new("path", path), new("type", "kv"), new("title", "Work key"), new("content", $"API_KEY={value}\n")]));
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        Assert.Contains("store/work/app/key.kv.age", R.GitOutput("--git-dir", R.BareDir, "ls-tree", "-r", "--name-only", "HEAD"));
        Assert.Equal(value, await FieldValue(c, path, "API_KEY"));

        var page = await c.GetStringAsync($"/entry/{path}/delete");
        var confirm = Regex.Match(page, "name=\"confirm\" value=\"([^\"]+)\"").Groups[1].Value;
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Post("/api/entry/delete", token, [new("path", path), new("confirm", confirm)]))).StatusCode);
    }

    [Fact]
    public async Task Bad_Metadata_Is_Rejected_By_Catalog_Rules()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        var head = BareHead();
        var resp = await c.SendAsync(Post("/api/entry/create", token,
        [
            new("path", "personal/test/badtarget"), new("type", "file"), new("title", "Bad target"),
            new("target", "~/somewhere/x"), new("content", "hi\n"),
        ]));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains("target", await resp.Content.ReadAsStringAsync());
        Assert.Equal(head, BareHead());
    }

    [Fact]
    public async Task Duplicate_Create_Is_409()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        var resp = await c.SendAsync(Post("/api/entry/create", token,
        [
            new("path", "personal/test/api"), new("type", "kv"), new("title", "Duplicate"), new("content", "K=v\n"),
        ]));
        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
    }

    [Fact]
    public async Task Write_Requires_Antiforgery_And_Custom_Header()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        var fields = new KeyValuePair<string, string>[]
            { new("path", "personal/test/csrf"), new("type", "kv"), new("title", "t"), new("content", "K=v\n") };

        Assert.Equal(HttpStatusCode.BadRequest, (await c.SendAsync(Post("/api/entry/create", token, fields, withToken: false))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.SendAsync(Post("/api/entry/create", token, fields, withHeader: false))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.SendAsync(Post("/api/entry/delete", token,
            [new("path", "personal/test/api"), new("confirm", "x")], withHeader: false))).StatusCode);
    }

    [Fact]
    public async Task Non_Allowed_Subject_Cannot_Write()
    {
        using var good = f.Client();
        var token = await Token(good, "/new");
        using var bad = f.Client("mallory");
        var resp = await bad.SendAsync(Post("/api/entry/create", token,
            [new("path", "personal/test/mallory"), new("type", "kv"), new("title", "t"), new("content", "K=v\n")]));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Edit_Page_Does_Not_Decrypt_On_Get_But_Load_Does()
    {
        using var c = f.Client();
        var page = await c.GetStringAsync("/entry/personal/test/api/edit");
        Assert.DoesNotContain(R.ApiKey, page);
        Assert.Contains("Load current content", page);

        var token = Regex.Match(page, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;
        var load = new HttpRequestMessage(HttpMethod.Post, "/entry/personal/test/api/edit?handler=Load")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }),
        };
        var loaded = await (await c.SendAsync(load)).Content.ReadAsStringAsync();
        Assert.Contains(R.ApiKey, loaded); // plaintext only appears after this explicit action
        Assert.Contains(AuditLines(), l => l.Contains("\"path\":\"personal/test/api\"") && l.Contains("\"action\":\"view\""));
    }
}

/// <summary>Write rate limiting uses a separate factory (a few writes per minute).</summary>
[Collection("writes")]
public sealed class WriteRateLimitTests : IClassFixture<WriteRateLimitTests.Factory>
{
    public sealed class Factory : WriteFactory
    {
        public Factory() => WritePerMinute = 3;
    }

    private readonly Factory _f;
    public WriteRateLimitTests(Factory f) => _f = f;

    [Fact]
    public async Task Writes_Are_Rate_Limited()
    {
        using var c = _f.Client();
        var html = await c.GetStringAsync("/new");
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;

        var seen429 = false;
        for (var i = 0; i < 12 && !seen429; i++)
        {
            var content = new MultipartFormDataContent
            {
                { new StringContent($"personal/test/rl{i}", Encoding.UTF8), "path" },
                { new StringContent("kv", Encoding.UTF8), "type" },
                { new StringContent("rate limit", Encoding.UTF8), "title" },
                { new StringContent("K=v\n", Encoding.UTF8), "content" },
            };
            var req = new HttpRequestMessage(HttpMethod.Post, "/api/entry/create") { Content = content };
            req.Headers.Add("RequestVerificationToken", token);
            req.Headers.Add(CsrfHeader.Name, "1");
            var resp = await c.SendAsync(req);
            if (resp.StatusCode == HttpStatusCode.TooManyRequests) seen429 = true;
        }
        Assert.True(seen429, "writes should be rate limited after a few attempts");
    }
}
