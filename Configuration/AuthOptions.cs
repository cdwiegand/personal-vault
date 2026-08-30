namespace PersonalMcpVault.Configuration;

/// <summary>
/// Options for the built-in OAuth 2.1 authorization server + resource server.
/// Bound from the "Auth" configuration section.
/// </summary>
public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>
    /// Public HTTPS base URL of this server — the OAuth issuer and the origin of the protected
    /// resource, e.g. "https://vault.example.com". No trailing slash. This MUST be the URL Claude
    /// actually reaches (after any proxy), or discovery/audience validation will fail.
    /// </summary>
    public string PublicBaseUrl { get; set; } = "";

    /// <summary>The single permitted login username.</summary>
    public string Username { get; set; } = "";

    /// <summary>
    /// PBKDF2 password hash: "pbkdf2.{iterations}.{saltBase64}.{hashBase64}".
    /// Generate one with: <c>dotnet run -- hash-password</c>.
    /// </summary>
    public string PasswordHash { get; set; } = "";

    /// <summary>
    /// Convenience for first-run/dev: a plaintext password. If set while <see cref="PasswordHash"/>
    /// is empty, it is hashed in memory at startup. Prefer <see cref="PasswordHash"/> in production.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>Symmetric key used to sign access tokens (HS256). At least 32 bytes; base64 or raw text.</summary>
    public string JwtSigningKey { get; set; } = "";

    /// <summary>Scope granted to the connector (single logical scope is fine for a personal server).</summary>
    public string Scope { get; set; } = "vault";

    public int AccessTokenLifetimeMinutes { get; set; } = 60;
    public int RefreshTokenLifetimeDays { get; set; } = 30;
    public int AuthCodeLifetimeSeconds { get; set; } = 120;

    /// <summary>Path to the SQLite file storing client registrations, auth codes, and refresh tokens.</summary>
    public string StorePath { get; set; } = "oauth-store.db";

    /// <summary>The canonical resource identifier (audience) = PublicBaseUrl + "/mcp".</summary>
    public string ResourceUrl => PublicBaseUrl.TrimEnd('/') + "/mcp";

    /// <summary>The issuer identifier = PublicBaseUrl with no trailing slash.</summary>
    public string Issuer => PublicBaseUrl.TrimEnd('/');
}
