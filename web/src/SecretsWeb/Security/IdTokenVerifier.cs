using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SecretsWeb.Security;

/// <summary>
/// Independently re-verifies the raw id_token (defense in depth): for an id_token returned by the token endpoint, the OIDC
/// handler does not enforce a signature in some shapes (alg=none, RS256 header + empty signature). Here only RSA public keys
/// from the JWKS are used, only RS256 is accepted, the signature segment must be non-empty, and iss / aud / lifetime are checked.
/// A signature-type failure forces one JWKS refresh and a retry (so a legitimate login isn't refused right after the IdP
/// rotates its signing key); refreshes have a minimum interval and can't be hammered. After a refresh the new key set is
/// authoritative — a key that was removed is no longer accepted.
/// </summary>
public sealed class IdTokenVerifier(TimeProvider time, ILogger<IdTokenVerifier> logger)
{
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan MinRefreshInterval = TimeSpan.FromSeconds(60);

    private readonly object _gate = new();
    private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;

    /// <summary>Returns null on success, otherwise a failure reason (a short phrase, never token content).</summary>
    public async Task<string?> VerifyAsync(
        string? rawIdToken, IConfigurationManager<OpenIdConnectConfiguration> manager, string clientId, CancellationToken ct = default)
    {
        var config = await manager.GetConfigurationAsync(ct);
        var error = await VerifyAsync(rawIdToken, config, clientId);
        if (error is null || !IsSignatureRelated(error) || !TryTakeRefreshSlot()) return error;

        logger.LogInformation("id_token signature check failed ({Reason}); forcing one JWKS refresh and retrying", error);
        manager.RequestRefresh();
        var refreshed = await manager.GetConfigurationAsync(ct);
        if (ReferenceEquals(refreshed, config)) return error;
        var retry = await VerifyAsync(rawIdToken, refreshed, clientId);
        if (retry is null) logger.LogInformation("id_token signature check passed after the JWKS refresh");
        return retry;
    }

    private bool TryTakeRefreshSlot()
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (now - _lastRefresh < MinRefreshInterval) return false;
            _lastRefresh = now;
            return true;
        }
    }

    /// <summary>Only signature / key failures are worth a JWKS refresh; for aud, iss or expiry a refresh would not help.</summary>
    public static bool IsSignatureRelated(string error) =>
        error.Contains("SecurityTokenSignatureKeyNotFound", StringComparison.Ordinal)
        || error.Contains("SecurityTokenInvalidSignature", StringComparison.Ordinal)
        || error == "jwks_no_rsa_key";

    /// <summary>Verify against one given configuration (no refresh).</summary>
    public static async Task<string?> VerifyAsync(string? rawIdToken, OpenIdConnectConfiguration config, string clientId)
    {
        if (string.IsNullOrEmpty(rawIdToken)) return "id_token_missing";
        var parts = rawIdToken.Split('.');
        if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0) return "id_token_unsigned";

        string? alg;
        try { alg = new JsonWebToken(rawIdToken).Alg; }
        catch (ArgumentException) { return "id_token_malformed"; }
        if (alg != SecurityAlgorithms.RsaSha256) return "id_token_alg_not_rs256";

        var rsaKeys = config.SigningKeys
            .Where(k => k is RsaSecurityKey || k is X509SecurityKey || (k is JsonWebKey j && j.Kty == JsonWebAlgorithmsKeyTypes.RSA))
            .ToList();
        foreach (var jwk in config.JsonWebKeySet?.Keys ?? [])
            if (jwk.Kty == JsonWebAlgorithmsKeyTypes.RSA && !rsaKeys.Contains(jwk)) rsaKeys.Add(jwk);
        if (rsaKeys.Count == 0) return "jwks_no_rsa_key";
        if (string.IsNullOrEmpty(config.Issuer)) return "issuer_unknown";

        var tvp = new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            IssuerSigningKeys = rsaKeys,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidIssuers = IssuerVariants(config.Issuer),
            ValidateAudience = true,
            ValidAudience = clientId,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = ClockSkew,
        };
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(rawIdToken, tvp);
        if (!result.IsValid) return "id_token_invalid:" + (result.Exception?.GetType().Name ?? "unknown");
        if (result.SecurityToken is not JsonWebToken { Alg: SecurityAlgorithms.RsaSha256 }) return "id_token_alg_not_rs256";
        return null;
    }

    /// <summary>
    /// Issuers accepted for an id_token. Google documents that its id_tokens may carry either
    /// <c>https://accounts.google.com</c> (what discovery advertises) or the bare <c>accounts.google.com</c>;
    /// both name the same issuer and are signed by the same JWKS, so both are accepted. Any other provider: exact match only.
    /// </summary>
    public static string[] IssuerVariants(string issuer) =>
        string.Equals(issuer?.TrimEnd('/'), "https://accounts.google.com", StringComparison.Ordinal)
            ? ["https://accounts.google.com", "accounts.google.com"]
            : [issuer ?? ""];
}
