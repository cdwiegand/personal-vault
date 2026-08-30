using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.AspNetCore;
using PersonalMcpVault.Auth;
using PersonalMcpVault.Configuration;
using PersonalMcpVault.Security;
using PersonalMcpVault.Tools;

// ── CLI helper: `dotnet run -- hash-password [password]` prints a PBKDF2 hash for appsettings. ──
if (args.Length > 0 && args[0] is "hash-password")
{
    var pw = args.Length > 1 ? args[1] : ReadHidden("Password: ");
    if (string.IsNullOrEmpty(pw)) { Console.Error.WriteLine("No password provided."); return 1; }
    Console.WriteLine(PasswordHasher.Hash(pw));
    return 0;
}

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables("VAULTMCP_"); // e.g. VAULTMCP_Auth__JwtSigningKey

// ── Bind + validate configuration ──
var vaultOptions = builder.Configuration.GetSection(VaultServerOptions.SectionName).Get<VaultServerOptions>() ?? new();
var authOptions = builder.Configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>() ?? new();

// Convenience: hash a plaintext password at startup if no hash was supplied.
if (string.IsNullOrEmpty(authOptions.PasswordHash) && !string.IsNullOrEmpty(authOptions.Password))
    authOptions.PasswordHash = PasswordHasher.Hash(authOptions.Password);

foreach (var problem in Validate(vaultOptions, authOptions))
    Console.Error.WriteLine($"[config] {problem}");
if (Validate(vaultOptions, authOptions).Any())
{
    Console.Error.WriteLine("Fix the configuration above and restart. See README.md for details.");
    return 1;
}

var tokenService = new TokenService(authOptions);
var oauthStore = new OAuthStore(authOptions.StorePath);

// ── Services ──
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    // Trust the co-located reverse proxy (Caddy/nginx) to set the real scheme/host.
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});

builder.Services.AddSingleton(vaultOptions);
builder.Services.AddSingleton(authOptions);
builder.Services.AddSingleton(tokenService);
builder.Services.AddSingleton(oauthStore);
builder.Services.AddSingleton<VaultPathResolver>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = tokenService.Issuer,
            ValidateAudience = true,
            ValidAudience = tokenService.Audience,      // RFC 8707: token must be bound to this resource
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = tokenService.SigningKey, // HS256; validated locally, no Authority round-trip
            ValidateLifetime = true,
            NameClaimType = "sub",
            RoleClaimType = "roles",
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        // A 401 MUST carry WWW-Authenticate pointing at the protected-resource metadata,
        // or Claude never starts the OAuth flow.
        options.Events = new JwtBearerEvents
        {
            OnChallenge = async context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                var prm = $"{authOptions.Issuer}/.well-known/oauth-protected-resource";
                context.Response.Headers.Append("WWW-Authenticate",
                    $"Bearer error=\"invalid_token\", resource_metadata=\"{prm}\", scope=\"{authOptions.Scope}\"");
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    "{\"error\":\"invalid_token\",\"error_description\":\"Authentication required\"}");
            },
        };
    });
builder.Services.AddAuthorization();

builder.Services.AddMcpServer()
    .WithHttpTransport(o => o.SessionMode = HttpServerSessionMode.Stateless)
    .WithTools<FileSystemTools>();

var app = builder.Build();

app.UseForwardedHeaders();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Text(
    $"Obsidian Vault MCP server is running.\nMCP endpoint: {authOptions.ResourceUrl}\n", "text/plain"));

app.MapOAuthServer();
app.MapMcp("/mcp").RequireAuthorization();

app.Logger.LogInformation("Vault MCP ready. Issuer={Issuer}, Resource={Resource}, Vault={Vault}, ReadOnly={ReadOnly}",
    authOptions.Issuer, authOptions.ResourceUrl, vaultOptions.Root, vaultOptions.ReadOnly);

app.Run();
return 0;

// ── local functions ──

static IEnumerable<string> Validate(VaultServerOptions vault, AuthOptions auth)
{
    if (string.IsNullOrWhiteSpace(vault.Root))
        yield return "Vault:Root is required (absolute path to your Obsidian vault).";
    else if (!Directory.Exists(vault.Root))
        yield return $"Vault:Root does not exist: {vault.Root}";

    if (string.IsNullOrWhiteSpace(auth.PublicBaseUrl))
        yield return "Auth:PublicBaseUrl is required (e.g. https://vault.example.com).";
    else if (!Uri.TryCreate(auth.PublicBaseUrl, UriKind.Absolute, out var u) || u.Scheme != "https")
        yield return "Auth:PublicBaseUrl must be an absolute https:// URL.";

    if (string.IsNullOrWhiteSpace(auth.Username))
        yield return "Auth:Username is required.";
    if (string.IsNullOrWhiteSpace(auth.PasswordHash))
        yield return "Auth:PasswordHash (or Auth:Password) is required. Generate one with: dotnet run -- hash-password";
    if (string.IsNullOrWhiteSpace(auth.JwtSigningKey))
        yield return "Auth:JwtSigningKey is required (>= 32 bytes; base64 or raw).";
}

static string ReadHidden(string prompt)
{
    Console.Error.Write(prompt);
    var sb = new StringBuilder();
    if (Console.IsInputRedirected) return Console.ReadLine() ?? "";
    ConsoleKeyInfo key;
    while ((key = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
    {
        if (key.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; }
        else if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
    }
    Console.Error.WriteLine();
    return sb.ToString();
}
