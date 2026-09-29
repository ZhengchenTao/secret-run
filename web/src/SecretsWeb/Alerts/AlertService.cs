using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace SecretsWeb.Alerts;

public interface IAlertService
{
    /// <summary>Security alert. <paramref name="kind"/> must be a fixed descriptive phrase; callers never pass entry names.</summary>
    void Raise(string kind);
}

/// <summary>
/// Login failures / non-allowlisted accounts / unusual decryption or write volume. Rate limited: at most one alert per
/// MinIntervalMinutes; the number suppressed in a window is carried in the next alert.
/// Delivery is a generic webhook: POST JSON <c>{"title", "text", "severity"}</c> to <c>Alerts:WebhookUrl</c>, with
/// <c>Authorization: Bearer &lt;Alerts:WebhookToken&gt;</c> when a token is configured. This service therefore holds no chat
/// or pager credentials of its own — put a small relay in front of whatever you use.
/// No URL configured → alerts are only logged. Sending happens in the background; failures are only logged and never
/// affect the request.
/// </summary>
public sealed class AlertService(
    IOptions<AlertOptions> options,
    IHttpClientFactory httpFactory,
    TimeProvider time,
    ILogger<AlertService> logger) : IAlertService
{
    public const string HttpClientName = "alerts";
    public const string Title = "secrets-web security alert";

    private readonly AlertOptions _o = options.Value;
    private readonly object _gate = new();
    private DateTimeOffset _lastSent = DateTimeOffset.MinValue;
    private int _suppressed;

    public bool Enabled => !string.IsNullOrWhiteSpace(_o.WebhookUrl);

    public void Raise(string kind)
    {
        logger.LogWarning("Security alert: {Kind}", kind);
        string message;
        lock (_gate)
        {
            var now = time.GetUtcNow();
            if (now - _lastSent < TimeSpan.FromMinutes(_o.MinIntervalMinutes))
            {
                _suppressed++;
                return;
            }
            var extra = _suppressed > 0 ? $" ({_suppressed} more were rate limited in the previous window)" : "";
            message = $"{kind}{extra}. Time: {now:yyyy-MM-dd HH:mm:ss}Z. See the audit log on the server for details.";
            _lastSent = now;
            _suppressed = 0;
        }
        if (!Enabled) return;
        _ = SendAsync(message);
    }

    /// <summary>Webhook request body. Only a fixed phrase, counts and a timestamp — never entry names.</summary>
    public static object BuildPayload(string message) => new
    {
        title = Title,
        text = message,
        severity = "warning",
    };

    private async Task SendAsync(string content)
    {
        try
        {
            var client = httpFactory.CreateClient(HttpClientName);
            using var req = new HttpRequestMessage(HttpMethod.Post, _o.WebhookUrl);
            if (!string.IsNullOrWhiteSpace(_o.WebhookToken))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _o.WebhookToken);
            req.Content = JsonContent.Create(BuildPayload(content));
            using var resp = await client.SendAsync(req);
            if (!resp.IsSuccessStatusCode)
                logger.LogWarning("Alert webhook failed: HTTP {Status}", (int)resp.StatusCode);
        }
        catch (Exception ex)
        {
            logger.LogWarning("Alert webhook error: {Type}", ex.GetType().Name);
        }
    }
}
