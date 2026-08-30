using System.Collections.Concurrent;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using PersonalMcpVault.Configuration;

namespace PersonalMcpVault.Auth;

/// <summary>
/// Maps the built-in OAuth 2.1 authorization-server + discovery endpoints:
/// protected-resource metadata, authorization-server metadata, dynamic client registration,
/// the local login page (/authorize), and the token endpoint. All are anonymous; only /mcp
/// requires a validated token.
/// </summary>
public static class OAuthEndpoints
{
    // Literal JSON keys (no camelCase transform) — OAuth metadata field names are fixed by the RFCs.
    private static readonly JsonSerializerOptions Raw = new()
    {
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    // Very small in-memory brute-force throttle for the login form, keyed by client IP.
    private static readonly ConcurrentDictionary<string, (int Failures, DateTime WindowStart)> LoginFailures = new();
    private const int MaxFailuresPerWindow = 10;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public static void MapOAuthServer(this IEndpointRouteBuilder app)
    {
        // --- Protected Resource Metadata (RFC 9728). Claude probes the /mcp-suffixed path first. ---
        var prm = (AuthOptions o) => Results.Json(new
        {
            resource = o.ResourceUrl,
            authorization_servers = new[] { o.Issuer },
            bearer_methods_supported = new[] { "header" },
            scopes_supported = new[] { o.Scope, "offline_access" },
        }, Raw);

        app.MapGet("/.well-known/oauth-protected-resource", prm);
        app.MapGet("/.well-known/oauth-protected-resource/mcp", prm);

        // --- Authorization Server Metadata (RFC 8414) ---
        app.MapGet("/.well-known/oauth-authorization-server", (AuthOptions o) => Results.Json(new
        {
            issuer = o.Issuer,
            authorization_endpoint = o.Issuer + "/authorize",
            token_endpoint = o.Issuer + "/token",
            registration_endpoint = o.Issuer + "/register",
            scopes_supported = new[] { o.Scope, "offline_access" },
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "authorization_code", "refresh_token" },
            token_endpoint_auth_methods_supported = new[] { "none" },
            code_challenge_methods_supported = new[] { "S256" },
        }, Raw));

        // --- Dynamic Client Registration (RFC 7591) — JSON in, 201 out, no client secret ---
        app.MapPost("/register", RegisterAsync);

        // --- Authorization endpoint: local username/password login page ---
        app.MapGet("/authorize", AuthorizeGet);
        app.MapPost("/authorize", AuthorizePostAsync);

        // --- Token endpoint: form-urlencoded in, JSON out ---
        app.MapPost("/token", TokenAsync);
    }

    // ---------------------------------------------------------------- /register

    private static async Task<IResult> RegisterAsync(HttpContext ctx, OAuthStore store)
    {
        JsonElement body;
        try { body = await ctx.Request.ReadFromJsonAsync<JsonElement>(); }
        catch { return Error(400, "invalid_client_metadata", "Body must be JSON."); }

        var redirectUris = new List<string>();
        if (body.ValueKind == JsonValueKind.Object &&
            body.TryGetProperty("redirect_uris", out var uris) && uris.ValueKind == JsonValueKind.Array)
        {
            foreach (var u in uris.EnumerateArray())
                if (u.ValueKind == JsonValueKind.String) redirectUris.Add(u.GetString()!);
        }

        redirectUris = redirectUris.Where(IsAcceptableRedirectUri).Distinct().ToList();
        if (redirectUris.Count == 0)
            return Error(400, "invalid_redirect_uri", "At least one https or loopback redirect_uri is required.");

        string? clientName = null;
        if (body.ValueKind == JsonValueKind.Object &&
            body.TryGetProperty("client_name", out var n) && n.ValueKind == JsonValueKind.String)
            clientName = n.GetString();

        var clientId = "mcp_" + TokenService.NewOpaqueToken();
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        store.SaveClient(new OAuthClient(clientId, redirectUris, clientName, issuedAt));

        return Results.Json(new
        {
            client_id = clientId,
            client_id_issued_at = issuedAt,
            redirect_uris = redirectUris,
            grant_types = new[] { "authorization_code", "refresh_token" },
            response_types = new[] { "code" },
            token_endpoint_auth_method = "none",
            client_name = clientName,
        }, Raw, statusCode: 201);
    }

    // ---------------------------------------------------------------- /authorize

    private static IResult AuthorizeGet(HttpContext ctx, AuthOptions o, OAuthStore store)
    {
        var req = AuthRequest.FromQuery(ctx.Request.Query);

        // Validate client + redirect first; on failure show an error page (never redirect to an unvalidated URI).
        var client = string.IsNullOrEmpty(req.ClientId) ? null : store.GetClient(req.ClientId);
        if (client is null)
            return HtmlError(400, "Unknown or missing client_id. Reconnect the connector so it can re-register.");
        if (string.IsNullOrEmpty(req.RedirectUri) || !RedirectUriAllowed(client.RedirectUris, req.RedirectUri))
            return HtmlError(400, "The redirect_uri does not match this client's registration.");

        // Protocol errors past this point can safely be reported back to the (validated) redirect_uri.
        if (req.ResponseType != "code")
            return RedirectError(req.RedirectUri, req.State, "unsupported_response_type");
        if (string.IsNullOrEmpty(req.CodeChallenge) || req.CodeChallengeMethod != "S256")
            return RedirectError(req.RedirectUri, req.State, "invalid_request", "PKCE S256 is required.");

        return Results.Content(LoginPage(o, req, error: null), "text/html; charset=utf-8");
    }

    private static async Task<IResult> AuthorizePostAsync(HttpContext ctx, AuthOptions o, OAuthStore store)
    {
        if (!ctx.Request.HasFormContentType) return HtmlError(400, "Expected a form submission.");
        var form = await ctx.Request.ReadFormAsync();
        var req = AuthRequest.FromForm(form);

        var client = string.IsNullOrEmpty(req.ClientId) ? null : store.GetClient(req.ClientId);
        if (client is null)
            return HtmlError(400, "Unknown client. Reconnect the connector.");
        if (string.IsNullOrEmpty(req.RedirectUri) || !RedirectUriAllowed(client.RedirectUris, req.RedirectUri))
            return HtmlError(400, "The redirect_uri does not match this client's registration.");

        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (IsThrottled(ip))
            return Results.Content(LoginPage(o, req, "Too many attempts. Wait a few minutes and try again."),
                "text/html; charset=utf-8", Encoding.UTF8, statusCode: 429);

        var username = form["username"].ToString();
        var password = form["password"].ToString();
        var userOk = string.Equals(username, o.Username, StringComparison.Ordinal);
        var passOk = PasswordHasher.Verify(password, o.PasswordHash);
        if (!userOk || !passOk)
        {
            RecordFailure(ip);
            return Results.Content(LoginPage(o, req, "Incorrect username or password."),
                "text/html; charset=utf-8", Encoding.UTF8, statusCode: 401);
        }
        ResetFailures(ip);

        // Grant offline_access (→ a refresh token) only when the client asked for it.
        var scope = o.Scope;
        if (SplitScope(req.Scope).Contains("offline_access")) scope += " offline_access";

        var code = TokenService.NewOpaqueToken();
        store.SaveAuthCode(code, new AuthCodeData(
            client.ClientId, req.RedirectUri, req.CodeChallenge, scope, req.Resource, o.Username,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() + o.AuthCodeLifetimeSeconds));

        var sep = req.RedirectUri.Contains('?') ? '&' : '?';
        var location = $"{req.RedirectUri}{sep}code={Uri.EscapeDataString(code)}";
        if (!string.IsNullOrEmpty(req.State)) location += $"&state={Uri.EscapeDataString(req.State)}";
        return Results.Redirect(location);
    }

    // ---------------------------------------------------------------- /token

    private static async Task<IResult> TokenAsync(HttpContext ctx, AuthOptions o, OAuthStore store, TokenService tokens)
    {
        if (!ctx.Request.HasFormContentType)
            return Error(400, "invalid_request", "Token requests must be application/x-www-form-urlencoded.");

        store.PurgeExpired(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var form = await ctx.Request.ReadFormAsync();
        var grantType = form["grant_type"].ToString();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        if (grantType == "authorization_code")
        {
            var code = form["code"].ToString();
            var data = string.IsNullOrEmpty(code) ? null : store.ConsumeAuthCode(code);
            if (data is null || data.ExpiresAtUnix < now)
                return Error(400, "invalid_grant", "Authorization code is invalid or expired.");

            if (form["client_id"].ToString() is { Length: > 0 } cid && cid != data.ClientId)
                return Error(400, "invalid_grant", "client_id mismatch.");
            if (form["redirect_uri"].ToString() != data.RedirectUri)
                return Error(400, "invalid_grant", "redirect_uri mismatch.");
            if (!TokenService.VerifyPkceS256(form["code_verifier"].ToString(), data.CodeChallenge))
                return Error(400, "invalid_grant", "PKCE verification failed.");

            return IssueTokens(o, store, tokens, data.ClientId, data.Subject, data.Scope, data.Resource);
        }

        if (grantType == "refresh_token")
        {
            var refresh = form["refresh_token"].ToString();
            var data = string.IsNullOrEmpty(refresh) ? null : store.ConsumeRefreshToken(refresh);
            if (data is null || data.ExpiresAtUnix < now)
                return Error(400, "invalid_grant", "Refresh token is invalid or expired.");

            // Rotation: the old token was consumed (deleted) above; issue a fresh pair.
            return IssueTokens(o, store, tokens, data.ClientId, data.Subject, data.Scope, data.Resource);
        }

        return Error(400, "unsupported_grant_type", $"Unsupported grant_type '{grantType}'.");
    }

    private static IResult IssueTokens(
        AuthOptions o, OAuthStore store, TokenService tokens,
        string clientId, string subject, string scope, string? resource)
    {
        var accessToken = tokens.CreateAccessToken(subject, scope);

        string? refreshToken = null;
        if (SplitScope(scope).Contains("offline_access"))
        {
            refreshToken = TokenService.NewOpaqueToken();
            store.SaveRefreshToken(refreshToken, new RefreshTokenData(
                clientId, subject, scope, resource,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds() + (long)o.RefreshTokenLifetimeDays * 86_400));
        }

        return Results.Json(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = o.AccessTokenLifetimeMinutes * 60,
            refresh_token = refreshToken,
            scope,
        }, Raw);
    }

    // ---------------------------------------------------------------- helpers

    private static IResult Error(int status, string error, string description) =>
        Results.Json(new { error, error_description = description }, Raw, statusCode: status);

    private static IResult RedirectError(string redirectUri, string? state, string error, string? description = null)
    {
        var sep = redirectUri.Contains('?') ? '&' : '?';
        var url = $"{redirectUri}{sep}error={Uri.EscapeDataString(error)}";
        if (!string.IsNullOrEmpty(description)) url += $"&error_description={Uri.EscapeDataString(description)}";
        if (!string.IsNullOrEmpty(state)) url += $"&state={Uri.EscapeDataString(state)}";
        return Results.Redirect(url);
    }

    private static bool IsAcceptableRedirectUri(string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var u)) return false;
        if (u.Scheme == "https") return true;
        if (u.Scheme == "http" && (u.IsLoopback || u.Host is "localhost")) return true; // native/CLI clients
        return false;
    }

    private static bool RedirectUriAllowed(IReadOnlyList<string> registered, string provided)
    {
        foreach (var r in registered)
            if (string.Equals(r, provided, StringComparison.Ordinal)) return true;

        // Loopback redirect URIs match ignoring the (ephemeral) port — RFC 8252 §7.3.
        if (Uri.TryCreate(provided, UriKind.Absolute, out var p) && (p.IsLoopback || p.Host is "localhost"))
        {
            foreach (var r in registered)
                if (Uri.TryCreate(r, UriKind.Absolute, out var ru) &&
                    ru.Scheme == p.Scheme && ru.Host == p.Host &&
                    string.Equals(ru.AbsolutePath, p.AbsolutePath, StringComparison.Ordinal))
                    return true;
        }
        return false;
    }

    private static string[] SplitScope(string? scope) =>
        (scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool IsThrottled(string ip)
    {
        if (!LoginFailures.TryGetValue(ip, out var e)) return false;
        if (DateTime.UtcNow - e.WindowStart > Window) { LoginFailures.TryRemove(ip, out _); return false; }
        return e.Failures >= MaxFailuresPerWindow;
    }

    private static void RecordFailure(string ip) =>
        LoginFailures.AddOrUpdate(ip,
            _ => (1, DateTime.UtcNow),
            (_, e) => DateTime.UtcNow - e.WindowStart > Window ? (1, DateTime.UtcNow) : (e.Failures + 1, e.WindowStart));

    private static void ResetFailures(string ip) => LoginFailures.TryRemove(ip, out _);

    private static IResult HtmlError(int status, string message) =>
        Results.Content($"<!doctype html><meta charset=utf-8><title>Sign-in error</title>" +
            $"<body style='font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem'>" +
            $"<h1 style='font-size:1.25rem'>Can't sign in</h1><p>{HtmlEncoder.Default.Encode(message)}</p></body>",
            "text/html; charset=utf-8", Encoding.UTF8, statusCode: status);

    private static string LoginPage(AuthOptions o, AuthRequest req, string? error)
    {
        string H(string? s) => HtmlEncoder.Default.Encode(s ?? "");
        var vaultName = string.IsNullOrEmpty(o.PublicBaseUrl) ? "vault" : new Uri(o.PublicBaseUrl).Host;
        var errorBlock = error is null ? "" :
            $"<p class='err' role='alert'>{H(error)}</p>";

        return $$"""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Sign in — {{H(vaultName)}}</title>
              <style>
                :root { color-scheme: light dark; }
                body { font-family: system-ui, sans-serif; margin: 0; min-height: 100dvh;
                       display: grid; place-items: center; background: Canvas; color: CanvasText; }
                .card { width: min(22rem, 92vw); padding: 2rem; border: 1px solid color-mix(in srgb, CanvasText 15%, transparent);
                        border-radius: 14px; }
                h1 { font-size: 1.15rem; margin: 0 0 .25rem; }
                p.sub { margin: 0 0 1.25rem; opacity: .7; font-size: .9rem; }
                label { display: block; font-size: .82rem; margin: .75rem 0 .25rem; opacity: .85; }
                input { width: 100%; box-sizing: border-box; padding: .6rem .7rem; border-radius: 8px;
                        border: 1px solid color-mix(in srgb, CanvasText 25%, transparent); background: Field; color: FieldText; }
                button { width: 100%; margin-top: 1.25rem; padding: .65rem; border: 0; border-radius: 8px;
                         font-weight: 600; cursor: pointer; background: AccentColor; color: AccentColorText; }
                .err { color: #d33; font-size: .85rem; margin: .5rem 0 0; }
              </style>
            </head>
            <body>
              <form class="card" method="post" action="/authorize" autocomplete="off">
                <h1>Sign in to your vault</h1>
                <p class="sub">{{H(vaultName)}} · personal knowledge base</p>
                {{errorBlock}}
                <label for="u">Username</label>
                <input id="u" name="username" autocapitalize="off" autocomplete="username" autofocus required>
                <label for="p">Password</label>
                <input id="p" name="password" type="password" autocomplete="current-password" required>
                <input type="hidden" name="response_type" value="{{H(req.ResponseType)}}">
                <input type="hidden" name="client_id" value="{{H(req.ClientId)}}">
                <input type="hidden" name="redirect_uri" value="{{H(req.RedirectUri)}}">
                <input type="hidden" name="code_challenge" value="{{H(req.CodeChallenge)}}">
                <input type="hidden" name="code_challenge_method" value="{{H(req.CodeChallengeMethod)}}">
                <input type="hidden" name="state" value="{{H(req.State)}}">
                <input type="hidden" name="scope" value="{{H(req.Scope)}}">
                <input type="hidden" name="resource" value="{{H(req.Resource)}}">
                <button type="submit">Sign in</button>
              </form>
            </body>
            </html>
            """;
    }

    /// <summary>The OAuth authorization-request parameters, from either query string or form body.</summary>
    private sealed record AuthRequest(
        string ResponseType, string ClientId, string RedirectUri, string CodeChallenge,
        string CodeChallengeMethod, string? State, string? Scope, string? Resource)
    {
        public static AuthRequest FromQuery(IQueryCollection q) => new(
            q["response_type"].ToString(), q["client_id"].ToString(), q["redirect_uri"].ToString(),
            q["code_challenge"].ToString(), q["code_challenge_method"].ToString(),
            q["state"], q["scope"], q["resource"]);

        public static AuthRequest FromForm(IFormCollection f) => new(
            f["response_type"].ToString(), f["client_id"].ToString(), f["redirect_uri"].ToString(),
            f["code_challenge"].ToString(), f["code_challenge_method"].ToString(),
            f["state"], f["scope"], f["resource"]);
    }
}
