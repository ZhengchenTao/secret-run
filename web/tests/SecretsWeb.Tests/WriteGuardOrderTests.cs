using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecretsWeb;
using SecretsWeb.Alerts;
using SecretsWeb.Audit;
using SecretsWeb.Format;
using SecretsWeb.Repo;
using SecretsWeb.Security;
using SecretsWeb.Services;

namespace SecretsWeb.Tests;

/// <summary>Check order (read-only → business validation → quota) and "failed writes don't count towards the anomaly alert".</summary>
public class WriteGuardOrderTests
{
    private sealed class FakeWriter : IRepoWriter
    {
        public bool Enabled { get; init; } = true;
        public bool Fail { get; set; }
        public int Calls { get; private set; }

        private Task<WriteResult> Run()
        {
            Calls++;
            if (Fail) throw new WriteRejectedException(WriteError.PushConflict, "push keeps being rejected");
            return Task.FromResult(new WriteResult("deadbeef", "ok"));
        }

        public Task<WriteResult> CreateAsync(EntrySpec spec, byte[] plaintext, CancellationToken ct) => Run();
        public Task<WriteResult> UpdateAsync(string path, EntrySpec spec, byte[]? plaintext, string? expected, CancellationToken ct) => Run();
        public Task<WriteResult> DeleteAsync(string path, CancellationToken ct) => Run();
    }

    private sealed class FakeRepo : ISecretRepository
    {
        public Task<RepoSnapshot> GetSnapshotAsync(CancellationToken ct = default) =>
            Task.FromResult(new RepoSnapshot("0".PadLeft(40, '0'),
                new Catalog("1", [], []), Recipients.Empty, new StoreConsistency(0, 0, 0, true)));

        public Task<byte[]> DecryptAsync(RepoSnapshot snapshot, CatalogEntry entry, int maxPlaintext, CancellationToken ct = default) =>
            throw new NotSupportedException();
    }

    private sealed class SpyAudit : IAuditLog
    {
        public List<AuditRecord> Records { get; } = [];
        public void Write(AuditRecord record) => Records.Add(record);
    }

    private sealed class SpyAlerts : IAlertService
    {
        public List<string> Raised { get; } = [];
        public void Raise(string kind) => Raised.Add(kind);
    }

    private static (EntryWriteService Svc, FakeWriter Writer, SpyAlerts Alerts, SpyAudit Audit) Build(
        bool enabled = true, int writePerMinute = 100)
    {
        var writer = new FakeWriter { Enabled = enabled };
        var alerts = new SpyAlerts();
        var audit = new SpyAudit();
        var repo = new FakeRepo();
        var limiter = new DecryptRateLimiter(
            Options.Create(new DecryptLimitOptions { WritePerMinute = writePerMinute }),
            Options.Create(new AlertOptions { WriteDistinctEntries = 1, WriteWindowMinutes = 10 }),
            TimeProvider.System, alerts, NullLogger<DecryptRateLimiter>.Instance);
        var health = new HealthService(repo, TimeProvider.System, NullLogger<HealthService>.Instance);
        var svc = new EntryWriteService(writer, repo, audit, limiter, health,
            Options.Create(new RepoOptions()), NullLogger<EntryWriteService>.Instance);
        return (svc, writer, alerts, audit);
    }

    private static HttpContext Http()
    {
        var ctx = new DefaultHttpContext();
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "alice"), new Claim(DecryptRateLimiter.SessionIdClaim, "sid-test")], "test"));
        return ctx;
    }

    private static WriteRequest Req(string path, string? expected = "fp") =>
        new(path, "doc",
            new EntrySpec(path, "doc", "t", null, null, null, null, null, null, null, null, null, null, null),
            "x\n"u8.ToArray(), expected);

    [Fact]
    public async Task Read_Only_Instance_Says_Read_Only_Even_Without_Fingerprint()
    {
        var (svc, writer, _, _) = Build(enabled: false);
        var ex = await Assert.ThrowsAsync<EntryException>(() => svc.UpdateAsync(Http(), Req("personal/a/b", expected: null), default));
        Assert.Contains("read-only", ex.Message);      // not "missing fingerprint"
        Assert.Equal(0, writer.Calls);
    }

    [Fact]
    public async Task Rejected_Requests_Do_Not_Consume_The_Write_Quota()
    {
        var (svc, writer, _, _) = Build(writePerMinute: 2);
        var http = Http();

        // three refusals for a missing fingerprint — none of them may consume quota
        for (var i = 0; i < 3; i++)
            await Assert.ThrowsAsync<EntryException>(() => svc.UpdateAsync(http, Req("personal/a/b", expected: null), default));

        // quota is still full: two successful writes, only the third is rate limited
        await svc.CreateAsync(http, Req("personal/a/c"), default);
        await svc.CreateAsync(http, Req("personal/a/d"), default);
        var limited = await Assert.ThrowsAsync<EntryException>(() => svc.CreateAsync(http, Req("personal/a/e"), default));
        Assert.Equal(EntryError.RateLimited, limited.Error);
        Assert.Equal(2, writer.Calls);
    }

    [Fact]
    public async Task Failed_Writes_Are_Not_Counted_For_The_Anomaly_Alert()
    {
        var (svc, writer, alerts, audit) = Build();
        var http = Http();
        writer.Fail = true;

        // the threshold is "more than 1 distinct entry in the window": 3 failed writes to distinct entries must not trigger it
        foreach (var p in new[] { "personal/a/f1", "personal/a/f2", "personal/a/f3" })
            await Assert.ThrowsAsync<EntryException>(() => svc.CreateAsync(http, Req(p), default));
        Assert.Empty(alerts.Raised);
        Assert.All(audit.Records, r => Assert.Equal("error", r.Result));

        // only successful writes count: two distinct entries cross the threshold, one alert
        writer.Fail = false;
        await svc.CreateAsync(http, Req("personal/a/s1"), default);
        Assert.Empty(alerts.Raised);
        await svc.CreateAsync(http, Req("personal/a/s2"), default);
        Assert.Single(alerts.Raised);
        Assert.DoesNotContain("personal", alerts.Raised[0]);
    }
}
