using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using SecretsWeb.Repo;
using SecretsWeb.Security;

namespace SecretsWeb.Tests;

/// <summary>When the repo itself is inconsistent (the catalog has an unavailable entry), writes must be refused and nothing pushed.</summary>
public sealed class InconsistentRepoFactory : WriteFactory
{
    public InconsistentRepoFactory() : base(includeInvalidEntry: true) { }
}

[Collection("writes")]
public sealed class WriteOnInconsistentRepoTests(InconsistentRepoFactory f) : IClassFixture<InconsistentRepoFactory>
{
    [Fact]
    public async Task Pre_Check_Refuses_And_Does_Not_Push()
    {
        using var c = f.Client();
        var html = await c.GetStringAsync("/new");
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;
        var head = f.Repo.GitOutput("--git-dir", f.Repo.BareDir, "rev-parse", "HEAD").Trim();

        var content = new MultipartFormDataContent
        {
            { new StringContent("personal/test/blocked", Encoding.UTF8), "path" },
            { new StringContent("kv", Encoding.UTF8), "type" },
            { new StringContent("must be refused", Encoding.UTF8), "title" },
            { new StringContent("K=v\n", Encoding.UTF8), "content" },
        };
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/entry/create") { Content = content };
        req.Headers.Add("RequestVerificationToken", token);
        req.Headers.Add(CsrfHeader.Name, "1");
        var resp = await c.SendAsync(req);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.Contains("fix the repo with the CLI first", await resp.Content.ReadAsStringAsync());
        Assert.Equal(head, f.Repo.GitOutput("--git-dir", f.Repo.BareDir, "rev-parse", "HEAD").Trim());
        Assert.Contains(File.ReadAllLines(f.Repo.AuditPath),
            l => l.Contains("\"event\":\"write\"") && l.Contains("RepoInconsistent"));
    }
}

/// <summary>Post-write check failure / push conflict: both must roll back and leave no half-done state.</summary>
[Collection("writes")]
public sealed class WriteRollbackTests(WriteFactory f) : IClassFixture<WriteFactory>, IDisposable
{
    public void Dispose() => RepoWriter.AfterApplyForTests = null;

    private async Task<(HttpClient Client, string Token)> Session()
    {
        var c = f.Client();
        var html = await c.GetStringAsync("/new");
        return (c, Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value);
    }

    private static HttpRequestMessage Create(string token, string path)
    {
        var content = new MultipartFormDataContent
        {
            { new StringContent(path, Encoding.UTF8), "path" },
            { new StringContent("kv", Encoding.UTF8), "type" },
            { new StringContent("rollback case", Encoding.UTF8), "title" },
            { new StringContent("K=v\n", Encoding.UTF8), "content" },
        };
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/entry/create") { Content = content };
        req.Headers.Add("RequestVerificationToken", token);
        req.Headers.Add(CsrfHeader.Name, "1");
        return req;
    }

    private string Head() => f.Repo.GitOutput("--git-dir", f.Repo.BareDir, "rev-parse", "HEAD").Trim();

    [Fact]
    public async Task Post_Check_Failure_Rolls_Back_And_Does_Not_Push()
    {
        var (c, token) = await Session();
        using var _ = c;
        var head = Head();

        // delete some other ciphertext right before the post-write check → catalog and store disagree
        RepoWriter.AfterApplyForTests = ws =>
        {
            var victim = Path.Combine(ws, "store", "personal", "test", "notes.doc.age");
            if (File.Exists(victim)) File.Delete(victim);
        };
        var resp = await c.SendAsync(Create(token, "personal/test/rollback"));
        RepoWriter.AfterApplyForTests = null;

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.Contains("Post-write check failed", await resp.Content.ReadAsStringAsync());
        Assert.Equal(head, Head()); // nothing was pushed

        // rolled back cleanly: the next write succeeds as usual
        var ok = await c.SendAsync(Create(token, "personal/test/afterrollback"));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.NotEqual(head, Head());
    }

    [Fact]
    public async Task Push_Conflict_Is_Retried_Then_Gives_409()
    {
        var (c, token) = await Session();
        using var _ = c;

        // install a pre-receive hook in the bare repo: reject once while reject-once exists (it deletes the file)
        var hooks = Path.Combine(f.Repo.BareDir, "hooks");
        Directory.CreateDirectory(hooks);
        File.WriteAllText(Path.Combine(hooks, "pre-receive"),
            "#!/bin/sh\nif [ -f ./reject-always ]; then echo 'always rejecting' >&2; exit 1; fi\n" +
            "if [ -f ./reject-once ]; then rm -f ./reject-once; echo 'rejected once' >&2; exit 1; fi\nexit 0\n".Replace("\r\n", "\n"));

        // (1) rejected once → the replay should succeed
        File.WriteAllText(Path.Combine(f.Repo.BareDir, "reject-once"), "");
        var retried = await c.SendAsync(Create(token, "personal/test/retried"));
        Assert.Equal(HttpStatusCode.OK, retried.StatusCode);
        Assert.False(File.Exists(Path.Combine(f.Repo.BareDir, "reject-once")), "the hook should have fired (proving there really was a retry)");
        Assert.Contains("personal/test/retried", await c.GetStringAsync("/"));

        // (2) always rejected → 409
        var head = Head();
        File.WriteAllText(Path.Combine(f.Repo.BareDir, "reject-always"), "");
        try
        {
            var conflict = await c.SendAsync(Create(token, "personal/test/conflict"));
            Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
            Assert.Contains("try again later", await conflict.Content.ReadAsStringAsync());
            Assert.Equal(head, Head());
            Assert.Contains(File.ReadAllLines(f.Repo.AuditPath), l => l.Contains("PushConflict"));
        }
        finally
        {
            File.Delete(Path.Combine(f.Repo.BareDir, "reject-always"));
            File.Delete(Path.Combine(hooks, "pre-receive"));
        }
    }
}
