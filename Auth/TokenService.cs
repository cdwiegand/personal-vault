using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using PersonalMcpVault.Configuration;

namespace PersonalMcpVault.Auth;

/// <summary>
/// Mints and describes access tokens, and provides the crypto primitives used across the OAuth
/// endpoints (random secret generation and PKCE S256 verification).
/// </summary>
public sealed class TokenService
{
    private readonly AuthOptions _options;
    private readonly SymmetricSecurityKey _signingKey;

    public TokenService(AuthOptions options)
    {
        _options = options;
        _signingKey = new SymmetricSecurityKey(DeriveKeyBytes(options.JwtSigningKey));
    }

    /// <summary>Token issuer identifier (matches AS metadata and PRM's authorization_servers).</summary>
    public string Issuer => _options.Issuer;

    /// <summary>Token audience — the canonical MCP resource URL (RFC 8707).</summary>
    public string Audience => _options.ResourceUrl;

    /// <summary>The symmetric key the resource server uses to validate incoming access tokens.</summary>
    public SymmetricSecurityKey SigningKey => _signingKey;

    /// <summary>Create a signed HS256 access token for the given subject and scope.</summary>
    public string CreateAccessToken(string subject, string scope)
    {
        var now = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.AddMinutes(_options.AccessTokenLifetimeMinutes).UtcDateTime,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = subject,
                ["scope"] = scope,
                ["jti"] = Guid.NewGuid().ToString("N"),
            },
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    /// <summary>A URL-safe random opaque secret (for authorization codes and refresh tokens).</summary>
    public static string NewOpaqueToken() =>
        Base64Url(RandomNumberGenerator.GetBytes(32));

    /// <summary>Verify an RFC 7636 S256 PKCE challenge: BASE64URL(SHA256(verifier)) == challenge.</summary>
    public static bool VerifyPkceS256(string codeVerifier, string codeChallenge)
    {
        if (string.IsNullOrEmpty(codeVerifier) || string.IsNullOrEmpty(codeChallenge)) return false;

        var computed = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
        var a = Encoding.ASCII.GetBytes(computed);
        var b = Encoding.ASCII.GetBytes(codeChallenge);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DeriveKeyBytes(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
            throw new InvalidOperationException("Auth:JwtSigningKey is not configured.");

        // Accept either base64 or raw text; require at least 256 bits of key material for HS256.
        byte[] bytes;
        try { bytes = Convert.FromBase64String(key); }
        catch (FormatException) { bytes = Encoding.UTF8.GetBytes(key); }

        if (bytes.Length < 32)
            throw new InvalidOperationException("Auth:JwtSigningKey must be at least 32 bytes (256 bits).");

        return bytes;
    }
}
