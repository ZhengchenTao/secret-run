using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace SecretsWeb.Security;

public enum AccessLayerStatus
{
    /// <summary>An access layer is declared.</summary>
    Declared,
    /// <summary>Explicitly <c>none</c>: start, but warn loudly.</summary>
    ExplicitlyNone,
    /// <summary>Not enforced outside Production and nothing declared.</summary>
    NotEnforced,
}

/// <summary>Startup-time guards that turn dangerous deployments into a refusal to start instead of a silent exposure.</summary>
public static class StartupChecks
{
    public const string AccessLayerMissingMessage =
        "Deployment:AccessLayer is not set. This service decrypts every secret that is encrypted to its age identity, " +
        "so it must sit behind a network access layer (for example a mesh VPN, an identity-aware proxy such as " +
        "Cloudflare Access, a classic VPN, or an authenticating reverse proxy) — OIDC login alone is not enough. Set Deployment:AccessLayer " +
        "(environment variable Deployment__AccessLayer) to describe what protects it, or to 'none' to start anyway " +
        "with a warning.";

    public const string AccessLayerNoneWarning =
        "SECURITY WARNING: Deployment:AccessLayer is 'none'. This service decrypts every secret encrypted to its " +
        "identity and is protected only by OIDC login. Put it behind a network access layer (VPN, mesh VPN, " +
        "identity-aware proxy, authenticating reverse proxy) before exposing it.";

    /// <summary>
    /// Production: empty → throw (refuse to start); <c>none</c> → start with a warning (logged by the caller).
    /// Other environments (Development, test hosts): not enforced.
    /// </summary>
    public static AccessLayerStatus CheckAccessLayer(IHostEnvironment env, DeploymentOptions o)
    {
        var value = o.AccessLayer?.Trim() ?? "";
        if (string.Equals(value, "none", StringComparison.OrdinalIgnoreCase)) return AccessLayerStatus.ExplicitlyNone;
        if (value.Length > 0) return AccessLayerStatus.Declared;
        if (env.IsProduction()) throw new InvalidOperationException(AccessLayerMissingMessage);
        return AccessLayerStatus.NotEnforced;
    }

    /// <summary>
    /// Forwarded-header options for a trusted reverse proxy, or null when neither <c>Network:KnownProxies</c> nor
    /// <c>Network:KnownNetworks</c> is configured (then X-Forwarded-* is ignored entirely).
    /// The framework's default trust list (loopback) is cleared on purpose: only what the operator configured is trusted,
    /// and only one hop, so a client can never inject its own X-Forwarded-For in front of the proxy's value.
    /// </summary>
    public static ForwardedHeadersOptions? BuildForwardedHeaders(NetworkOptions o)
    {
        var proxies = (o.KnownProxies ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
        var networks = (o.KnownNetworks ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
        if (proxies.Count == 0 && networks.Count == 0) return null;

        var f = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            ForwardLimit = 1,
        };
        f.KnownProxies.Clear();
        f.KnownIPNetworks.Clear();
        foreach (var p in proxies)
        {
            if (!IPAddress.TryParse(p, out var ip))
                throw new InvalidOperationException($"Network:KnownProxies contains an invalid IP address: '{p}'");
            f.KnownProxies.Add(ip);
        }
        foreach (var n in networks)
        {
            if (!System.Net.IPNetwork.TryParse(n, out var net))
                throw new InvalidOperationException($"Network:KnownNetworks contains an invalid CIDR range: '{n}'");
            f.KnownIPNetworks.Add(net);
        }
        return f;
    }
}
