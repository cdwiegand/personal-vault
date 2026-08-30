# Personal Vault MCP Server

A single-user [Model Context Protocol](https://modelcontextprotocol.io) server that exposes your
Personal vault as a set of filesystem tools, protected by a **self-contained OAuth 2.1 login**
(local username/password — no Google, no third-party IdP). Built for Claude's remote **custom
connectors** (claude.ai / Claude Desktop).

It is both the OAuth **authorization server** (discovery, dynamic client registration, a login
page, token issuance) and the **resource server** (validates the token, serves the tools). Only the
one username/password you configure can connect — teammates with the URL but no credentials get a
`401`.

## Tools

All paths are relative to the vault root and validated so nothing can escape it.

| Tool | Description |
|------|-------------|
| `read_file` | Read a file's text |
| `read_multiple_files` | Read several files, errors reported inline |
| `write_file` | Create/overwrite a file (creates parent dirs) |
| `edit_file` | Exact find-and-replace edits (each `oldText` must be unique) |
| `create_directory` | `mkdir -p` |
| `list_directory` | Immediate children, `[DIR]`/`[FILE]` prefixed |
| `directory_tree` | Recursive JSON tree (bounded) |
| `move_file` | Move/rename within the vault |
| `search_files` | Recursive filename glob (`*.md`, `meeting-*`) |
| `search_content` | Full-text search across notes (great for a KB) |
| `get_file_info` | Size + timestamps + type |
| `list_allowed_directories` | Returns the vault root |
| `delete_file` | Permanent delete — **off unless `Vault:AllowDelete=true`** |

Mutating tools are all disabled if `Vault:ReadOnly=true`.

## Requirements

- .NET SDK 10 (`dotnet --version`)
- A VPS with a **public domain**, valid **HTTPS**, and public **IPv4** DNS (see Deploy)

## Configure

Settings come from `appsettings.json`, overridable by `Section__Key` environment variables. Keep
**secrets out of `appsettings.json`** — put them in env vars / the systemd `EnvironmentFile`.

Generate the two secrets:

```bash
# 1) a password hash (interactive prompt, or pass the password as an argument)
dotnet run -- hash-password

# 2) a token signing key (>= 32 bytes)
openssl rand -base64 32
```

Minimum config:

| Key | Example | Notes |
|-----|---------|-------|
| `Vault__Root` | `/opt/personal-vault-mcp/vault` | Absolute path to your Personal vault |
| `Auth__PublicBaseUrl` | `https://vault.example.com` | Exact HTTPS origin Claude reaches. No trailing slash/path. |
| `Auth__Username` | `chris` | |
| `Auth__PasswordHash` | `pbkdf2$210000$…` | From `hash-password` (or set `Auth__Password` for a plaintext dev shortcut) |
| `Auth__JwtSigningKey` | base64, 32+ bytes | From `openssl rand`. Rotating it invalidates all sessions. |

## Run locally

```bash
Vault__Root="$HOME/vault" \
Auth__PublicBaseUrl="https://localhost:5099" \
Auth__Username="chris" Auth__Password="dev-only-pass" \
Auth__JwtSigningKey="$(openssl rand -base64 32)" \
ASPNETCORE_URLS="http://127.0.0.1:5099" \
dotnet run
```

An end-to-end test of the whole OAuth + MCP flow lives in
[`test/e2e.sh`](test/e2e.sh) — run it against a local build to verify everything.

## Deploy on a VPS

1. **Publish** and copy to the server:
   ```bash
   dotnet publish -c Release -o ./publish
   # scp ./publish/* to /opt/personal-vault-mcp/ on the VPS
   ```
2. **DNS**: point `vault.example.com`'s A record at the VPS (public IPv4).
3. **Secrets**: `sudo cp deploy/personal-vault-mcp.env.example /opt/personal-vault-mcp/personal-vault-mcp.env`,
   fill it in, `sudo chmod 600 /opt/personal-vault-mcp/personal-vault-mcp.env`.
4. **Service**: install [`deploy/personal-vault-mcp.service`](deploy/personal-vault-mcp.service),
   then `sudo systemctl enable --now personal-vault-mcp`.
5. **TLS**: put [`deploy/Caddyfile`](deploy/Caddyfile) in front — Caddy reverse-proxies
   `127.0.0.1:5090` and gets an automatic Let's Encrypt cert, or if using Nginx adapt
   the `nginx.site.conf` file as desired.

## Connect Claude

In claude.ai or Claude Desktop → **Settings → Connectors → Add custom connector**, enter:

```
https://vault.example.com/mcp
```

Claude discovers the OAuth server, registers itself, and opens your login page. Sign in with your
username/password once; it stores a rotating refresh token so you stay connected.

## Security notes

- **Path confinement** — every tool routes through a resolver that normalizes `..`, resolves
  symlinks, and rejects anything outside `Vault__Root`.
- **Single user** — only the configured username can authenticate; there is no signup.
- **Tokens** — HS256, ~1h access tokens bound to this resource (`aud`), rotating refresh tokens,
  single-use PKCE-bound auth codes. Codes/refresh tokens are stored only as SHA-256 hashes.
- **Login throttling** — repeated bad passwords from one IP are rate-limited.
- **Least privilege** — run as a dedicated user; start with `ReadOnly=true` / `AllowDelete=false`
  and open up only what you need.

## Troubleshooting connectors

Claude connects from **Anthropic's servers**, not your machine — so the endpoint must be publicly
reachable, not just reachable from your laptop.

- **"Couldn't reach the server"** — check public DNS (`dig +short vault.example.com`), that the IP
  is globally routable (not private/CGNAT), and IPv4 exists. `curl -sI https://vault.example.com/mcp`
  should return `401` with a `WWW-Authenticate` header.
- **"Authorization failed"** — usually a redirect that drops the `Authorization` header (e.g.
  apex→www). Register the exact host the server listens on. Also confirm `Auth__PublicBaseUrl`
  matches the URL you typed into Claude (this drives the token `iss`/`aud`).
- **WAF/CDN in front?** Allowlist Anthropic's egress range `160.79.104.0/21`.
- Metadata is cached ~5 min; after changing config, give it a few minutes.
