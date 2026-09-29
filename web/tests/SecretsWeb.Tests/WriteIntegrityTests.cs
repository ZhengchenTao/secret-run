using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using SecretsWeb.Format;
using SecretsWeb.Security;

namespace SecretsWeb.Tests;

/// <summary>Key order, the lock integrity gate, alias normalization, optimistic concurrency.</summary>
public class CatalogKeyOrderTests
{
    /// <summary>The key order fixed by FORMAT (CLI and web UI must agree, otherwise alternating writes produce full-file diffs).</summary>
    [Fact]
    public void Entry_Key_Order_Matches_Format()
    {
        Assert.Equal(
            ["path", "type", "title", "description", "fields", "target", "acl", "machines", "tags",
             "rotate", "readers", "priority", "linked", "aliases", "updated"],
            TomlWriter.EntryKeyOrder);
    }

    [Fact]
    public void Same_Entry_Data_Always_Writes_The_Same_Bytes()
    {
        // keys are shuffled in the source; the output must be in canonical order
        var text = "[[entry]]\nupdated = \"2026-09-18\"\naliases = [\"vault:x#A\"]\nlinked = [\"personal/app/b\"]\n" +
                   "priority = \"high\"\nreaders = [\"Zoë\"]\nrotate = \"Some console\"\ntags = [\"t\"]\nmachines = [\"laptop\"]\n" +
                   "acl = \"private\"\ntarget = \"~/.ssh/x\"\nfields = [\"A\"]\ntitle = \"T\"\ntype = \"file\"\n" +
                   "path = \"personal/app/a\"\nfuture_key = \"keep-me\"\n";
        var written = TomlWriter.Write(RestrictedToml.Parse(text));

        Assert.Equal(
            "[[entry]]\n" +
            "path = \"personal/app/a\"\n" +
            "type = \"file\"\n" +
            "title = \"T\"\n" +
            "fields = [\"A\"]\n" +
            "target = \"~/.ssh/x\"\n" +
            "acl = \"private\"\n" +
            "machines = [\"laptop\"]\n" +
            "tags = [\"t\"]\n" +
            "rotate = \"Some console\"\n" +
            "readers = [\"Zoë\"]\n" +
            "priority = \"high\"\n" +
            "linked = [\"personal/app/b\"]\n" +
            "aliases = [\"vault:x#A\"]\n" +
            "updated = \"2026-09-18\"\n" +
            "future_key = \"keep-me\"\n",
            written);

        // idempotent: writing it again gives exactly the same bytes
        Assert.Equal(written, TomlWriter.Write(RestrictedToml.Parse(written)));
    }
}

[Collection("writes")]
public sealed class WriteIntegrityTests(WriteFactory f) : IClassFixture<WriteFactory>
{
    private static async Task<string> Token(HttpClient c, string page)
    {
        var html = await c.GetStringAsync(page);
        return Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;
    }

    private static HttpRequestMessage Form(string url, string token, params (string Key, string Value)[] fields)
    {
        var content = new MultipartFormDataContent();
        foreach (var (k, v) in fields) content.Add(new StringContent(v, Encoding.UTF8), k);
        var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        req.Headers.Add("RequestVerificationToken", token);
        req.Headers.Add(CsrfHeader.Name, "1");
        return req;
    }

    private string Head() => f.Repo.GitOutput("--git-dir", f.Repo.BareDir, "rev-parse", "HEAD").Trim();

    private static async Task<(string Expected, string Token)> EditPage(HttpClient c, string path)
    {
        var html = await c.GetStringAsync($"/entry/{path}/edit");
        return (Regex.Match(html, "name=\"expected\" value=\"([^\"]+)\"").Groups[1].Value,
            Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value);
    }

    [Fact]
    public async Task Aliases_Are_Normalized_Before_Writing()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        const string path = "personal/test/alias";
        var resp = await c.SendAsync(Form("/api/entry/create", token,
            ("path", path), ("type", "doc"), ("title", "alias normalization"),
            ("aliases", " [[notes:Secrets\\Home\\Café Token.md#Main]] , wiki:secrets/x.md"),
            ("content", "hi\n")));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var catalog = f.Repo.GitOutput("--git-dir", f.Repo.BareDir, "show", "HEAD:catalog.toml");
        Assert.Contains("\"notes:Secrets/Home/Café Token#Main\"", catalog);
        Assert.Contains("\"wiki:secrets/x\"", catalog);
        Assert.DoesNotContain("[[notes:", catalog);

        var (expected, editToken) = await EditPage(c, path);
        await c.SendAsync(Form("/api/entry/delete", editToken, ("path", path), ("confirm", await Confirm(c, path))));
        _ = expected;
    }

    private static async Task<string> Confirm(HttpClient c, string path) =>
        Regex.Match(await c.GetStringAsync($"/entry/{path}/delete"), "name=\"confirm\" value=\"([^\"]+)\"").Groups[1].Value;

    [Fact]
    public async Task Ciphertext_Not_Matching_Lock_Blocks_The_Write()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        const string path = "personal/test/tampered";
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Form("/api/entry/create", token,
            ("path", path), ("type", "kv"), ("title", "lock gate"), ("content", "K=v\n")))).StatusCode);

        // replace the ciphertext directly, bypassing CLI / web UI (the CHash in the lock no longer matches)
        var work = Path.Combine(f.Repo.Root, "tamper");
        f.Repo.GitOutput("clone", "--quiet", f.Repo.BareDir, work);
        var store = Path.Combine(work, "store", "personal", "test", "tampered.kv.age");
        var bytes = File.ReadAllBytes(store);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(store, bytes);
        f.Repo.GitOutput("-C", work, "add", "-A");
        f.Repo.GitOutput("-C", work, "-c", "user.name=t", "-c", "user.email=t@e.invalid", "commit", "-q", "-m", "tamper");
        f.Repo.GitOutput("-C", work, "push", "-q", "origin", "HEAD:refs/heads/main");
        var head = Head();

        var (expected, editToken) = await EditPage(c, path);
        var resp = await c.SendAsync(Form("/api/entry/update", editToken,
            ("path", path), ("type", "kv"), ("title", "changed"), ("expected", expected), ("content", "K=v2\n")));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.Contains("lock", await resp.Content.ReadAsStringAsync());
        Assert.Equal(head, Head()); // the evidence was not overwritten

        // deleting is blocked just the same
        var del = await c.SendAsync(Form("/api/entry/delete", editToken, ("path", path), ("confirm", await Confirm(c, path))));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, del.StatusCode);
        Assert.Equal(head, Head());
    }

    [Fact]
    public async Task Stale_Edit_Is_Rejected_With_409()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        const string path = "personal/test/concurrent";
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Form("/api/entry/create", token,
            ("path", path), ("type", "doc"), ("title", "concurrency"), ("content", "a\n")))).StatusCode);

        // two people open the edit page at the same time and get the same fingerprint
        var (expectedA, tokenA) = await EditPage(c, path);
        var (expectedB, tokenB) = await EditPage(c, path);
        Assert.Equal(expectedA, expectedB);

        var first = await c.SendAsync(Form("/api/entry/update", tokenA,
            ("path", path), ("type", "doc"), ("title", "changed by A"), ("expected", expectedA), ("content", "")));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var second = await c.SendAsync(Form("/api/entry/update", tokenB,
            ("path", path), ("type", "doc"), ("title", "changed by B"), ("expected", expectedB), ("content", "")));
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Contains("reload", await second.Content.ReadAsStringAsync());
        Assert.Contains("changed by A", await c.GetStringAsync("/entry/" + path));

        // after reloading, the same edit goes through
        var (fresh, tokenC) = await EditPage(c, path);
        Assert.NotEqual(expectedA, fresh);
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Form("/api/entry/update", tokenC,
            ("path", path), ("type", "doc"), ("title", "changed by B"), ("expected", fresh), ("content", "")))).StatusCode);

        await c.SendAsync(Form("/api/entry/delete", tokenC, ("path", path), ("confirm", await Confirm(c, path))));
    }
}
