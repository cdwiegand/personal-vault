namespace PersonalMcpVault.Auth;

/// <summary>A dynamically-registered OAuth client (RFC 7591).</summary>
public sealed record OAuthClient(
    string ClientId,
    IReadOnlyList<string> RedirectUris,
    string? ClientName,
    long CreatedAtUnix);

/// <summary>State bound to an issued authorization code, verified at the token endpoint.</summary>
public sealed record AuthCodeData(
    string ClientId,
    string RedirectUri,
    string CodeChallenge,
    string Scope,
    string? Resource,
    string Subject,
    long ExpiresAtUnix);

/// <summary>State bound to an issued refresh token.</summary>
public sealed record RefreshTokenData(
    string ClientId,
    string Subject,
    string Scope,
    string? Resource,
    long ExpiresAtUnix);
