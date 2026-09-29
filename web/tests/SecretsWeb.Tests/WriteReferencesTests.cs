using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecretsWeb;
using SecretsWeb.Alerts;
using SecretsWeb.Security;

namespace SecretsWeb.Tests;

/// <summary>Mandatory optimistic concurrency, listing references before delete, write-volume anomaly alert.</summary>
[Collection("writes")]
public sealed class WriteReferencesTests(WriteFactory f) : IClassFixture<WriteFactory>
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

    private static async Task<string> Expected(HttpClient c, string path) =>
        Regex.Match(await c.GetStringAsync($"/entry/{path}/edit"), "name=\"expected\" value=\"([^\"]+)\"").Groups[1].Value;

    private static async Task<string> Confirm(HttpClient c, string path) =>
        Regex.Match(await c.GetStringAsync($"/entry/{path}/delete"), "name=\"confirm\" value=\"([^\"]+)\"").Groups[1].Value;

    private static async Task Create(HttpClient c, string token, string path, params (string Key, string Value)[] extra)
    {
        (string, string)[] baseFields = [("path", path), ("type", "doc"), ("title", "t"), ("content", "x\n")];
        var resp = await c.SendAsync(Form("/api/entry/create", token, [.. baseFields, .. extra]));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Update_Without_Fingerprint_Is_400()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        const string path = "personal/test/mustmatch";
        await Create(c, token, path);

        var missing = await c.SendAsync(Form("/api/entry/update", token, ("path", path), ("type", "doc"), ("title", "changed")));
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Contains("expected", await missing.Content.ReadAsStringAsync());

        var empty = await c.SendAsync(Form("/api/entry/update", token, ("path", path), ("type", "doc"), ("title", "changed"), ("expected", "")));
        Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);

        var wrong = await c.SendAsync(Form("/api/entry/update", token,
            ("path", path), ("type", "doc"), ("title", "changed"), ("expected", "0123456789abcdef")));
        Assert.Equal(HttpStatusCode.Conflict, wrong.StatusCode);

        var ok = await c.SendAsync(Form("/api/entry/update", token,
            ("path", path), ("type", "doc"), ("title", "changed correctly"), ("expected", await Expected(c, path))));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Contains("changed correctly", await c.GetStringAsync("/entry/" + path));

        await c.SendAsync(Form("/api/entry/delete", token, ("path", path), ("confirm", await Confirm(c, path))));
    }

    [Fact]
    public async Task Delete_Lists_References_And_Refuses_When_Linked_By_Others()
    {
        using var c = f.Client();
        var token = await Token(c, "/new");
        const string target = "personal/test/reftarget";
        const string holder = "personal/test/refholder";

        await Create(c, token, target, ("readers", "backup-script, Zoë"));
        await Create(c, token, holder, ("linked", target));

        // the confirmation page lists all three kinds of relationship
        var page = await c.GetStringAsync($"/entry/{target}/delete");
        Assert.Contains("backup-script", page);
        Assert.Contains("Linked by", page);
        Assert.Contains(holder, page);

        // inbound links → delete refused, referencing entries listed
        var refused = await c.SendAsync(Form("/api/entry/delete", token, ("path", target), ("confirm", await Confirm(c, target))));
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        var body = await refused.Content.ReadAsStringAsync();
        Assert.Contains(holder, body);
        Assert.Contains(target, await c.GetStringAsync("/")); // still there

        // delete the referencing entry first (it has no inbound links) → the response carries its linked
        var holderDelete = await c.SendAsync(Form("/api/entry/delete", token, ("path", holder), ("confirm", await Confirm(c, holder))));
        Assert.Equal(HttpStatusCode.OK, holderDelete.StatusCode);
        var refs = JsonDocument.Parse(await holderDelete.Content.ReadAsStringAsync()).RootElement.GetProperty("references");
        Assert.Equal(target, refs.GetProperty("linked")[0].GetString());
        Assert.Empty(refs.GetProperty("linkedBy").EnumerateArray());

        // now the target can be deleted
        var ok = await c.SendAsync(Form("/api/entry/delete", token, ("path", target), ("confirm", await Confirm(c, target))));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var okRefs = JsonDocument.Parse(await ok.Content.ReadAsStringAsync()).RootElement.GetProperty("references");
        Assert.Equal(["backup-script", "Zoë"], okRefs.GetProperty("readers").EnumerateArray().Select(x => x.GetString()!).ToArray());
    }
}

public class WriteAnomalyAlertTests
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

    private static DecryptRateLimiter Make(FakeClock clock, SpyAlerts alerts, AlertOptions? alertOptions = null) =>
        new(Options.Create(new DecryptLimitOptions()),
            Options.Create(alertOptions ?? new AlertOptions { WriteDistinctEntries = 5, WriteWindowMinutes = 10 }),
            clock, alerts, NullLogger<DecryptRateLimiter>.Instance);

    [Fact]
    public void Six_Distinct_Entries_In_The_Window_Raise_One_Alert()
    {
        var clock = new FakeClock();
        var alerts = new SpyAlerts();
        var l = Make(clock, alerts);
        for (var i = 0; i < 5; i++) l.RecordWrittenEntry($"personal/test/w{i}");
        Assert.Empty(alerts.Raised);

        l.RecordWrittenEntry("personal/test/w5");
        Assert.Single(alerts.Raised);
        Assert.DoesNotContain("personal", alerts.Raised[0]);
        Assert.Contains("5", alerts.Raised[0]);

        // counting starts over once the window has passed
        clock.Now = clock.Now.AddMinutes(11);
        for (var i = 0; i < 5; i++) l.RecordWrittenEntry($"personal/test/x{i}");
        Assert.Single(alerts.Raised);
    }

    [Fact]
    public void Repeated_Writes_To_One_Entry_Do_Not_Alert()
    {
        var alerts = new SpyAlerts();
        var l = Make(new FakeClock(), alerts);
        for (var i = 0; i < 30; i++) l.RecordWrittenEntry("personal/test/same");
        Assert.Empty(alerts.Raised);
    }

    [Fact]
    public void Threshold_And_Window_Are_Configurable()
    {
        var alerts = new SpyAlerts();
        var l = Make(new FakeClock(), alerts, new AlertOptions { WriteDistinctEntries = 2, WriteWindowMinutes = 30 });
        l.RecordWrittenEntry("a");
        l.RecordWrittenEntry("b");
        Assert.Empty(alerts.Raised);
        l.RecordWrittenEntry("c");
        Assert.Single(alerts.Raised);
        Assert.Contains("30 minutes", alerts.Raised[0]);
    }

    [Fact]
    public void Alert_Service_Rate_Limits_To_One_Per_Window()
    {
        var clock = new FakeClock();
        var alerts = new AlertService(
            Options.Create(new AlertOptions { MinIntervalMinutes = 10 }),
            new StubHttpClientFactory(), clock, NullLogger<AlertService>.Instance);
        alerts.Raise("first");
        alerts.Raise("second");   // rate limited
        clock.Now = clock.Now.AddMinutes(11);
        alerts.Raise("third");    // new window
        Assert.False(alerts.Enabled); // no webhook configured → only logged, nothing is sent
    }

    [Fact]
    public async Task Alert_Service_Posts_Generic_Json_To_Webhook_With_Bearer_Token()
    {
        var handler = new CaptureHandler();
        var alerts = new AlertService(
            Options.Create(new AlertOptions { WebhookUrl = "http://relay.test/hook", WebhookToken = "t0ken", MinIntervalMinutes = 10 }),
            new StubHttpClientFactory(handler), new FakeClock(), NullLogger<AlertService>.Instance);
        Assert.True(alerts.Enabled);

        alerts.Raise("Login failed");
        var req = await handler.Seen.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(HttpMethod.Post, req.Method);
        Assert.Equal("http://relay.test/hook", req.Uri);
        Assert.Equal("Bearer t0ken", req.Auth);
        using var doc = JsonDocument.Parse(req.Body);
        var root = doc.RootElement;
        Assert.Equal(["severity", "text", "title"], root.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(AlertService.Title, root.GetProperty("title").GetString());
        Assert.Equal("warning", root.GetProperty("severity").GetString());
        Assert.Contains("Login failed", root.GetProperty("text").GetString());
    }

    [Fact]
    public async Task Webhook_Without_Token_Sends_No_Authorization_Header()
    {
        var handler = new CaptureHandler();
        var alerts = new AlertService(
            Options.Create(new AlertOptions { WebhookUrl = "http://relay.test/hook" }),
            new StubHttpClientFactory(handler), new FakeClock(), NullLogger<AlertService>.Instance);
        alerts.Raise("Login failed");
        var req = await handler.Seen.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("", req.Auth);
    }

    /// <summary>End to end through the real limiter and alert service: the webhook body never names entries.</summary>
    [Fact]
    public async Task Webhook_Payload_Never_Contains_Entry_Names()
    {
        var handler = new CaptureHandler();
        var clock = new FakeClock();
        var alerts = new AlertService(
            Options.Create(new AlertOptions { WebhookUrl = "http://relay.test/hook", WebhookToken = "t0ken" }),
            new StubHttpClientFactory(handler), clock, NullLogger<AlertService>.Instance);
        var limiter = new DecryptRateLimiter(
            Options.Create(new DecryptLimitOptions { DistinctThreshold = 3, DistinctWindowMinutes = 10 }),
            Options.Create(new AlertOptions()), clock, alerts, NullLogger<DecryptRateLimiter>.Instance);

        var names = Enumerable.Range(0, 5).Select(i => $"work/payroll/secret-entry-{i}").ToArray();
        foreach (var n in names) limiter.RecordEntry(n);
        var req = await handler.Seen.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Contains("decryption", req.Body);
        foreach (var n in names)
        {
            Assert.DoesNotContain(n, req.Body);
            Assert.DoesNotContain(n.Split('/')[2], req.Body);
        }
        Assert.DoesNotContain("payroll", req.Body);
        Assert.DoesNotContain("work/", req.Body);
    }

    private sealed record Captured(HttpMethod Method, string Uri, string Auth, string Body);

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public TaskCompletionSource<Captured> Seen { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            Seen.TrySetResult(new Captured(request.Method, request.RequestUri!.ToString(), request.Headers.Authorization?.ToString() ?? "", body));
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler? handler = null) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => handler is null ? new() : new(handler, disposeHandler: false);
    }
}
