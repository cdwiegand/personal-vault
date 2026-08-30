using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace PersonalMcpVault.Auth;

/// <summary>
/// Durable storage (SQLite) for OAuth client registrations, authorization codes, and refresh
/// tokens. Codes and refresh tokens are stored as SHA-256 hashes so a leak of the DB does not
/// expose usable secrets. Everything is single-user, but the schema is generic.
/// </summary>
public sealed class OAuthStore
{
    private readonly string _connectionString;

    public OAuthStore(string dbPath)
    {
        var fullPath = Path.GetFullPath(dbPath);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        _connectionString = new SqliteConnectionStringBuilder { DataSource = fullPath }.ToString();

        using var conn = Open();
        Execute(conn, """
            CREATE TABLE IF NOT EXISTS clients (
                client_id      TEXT PRIMARY KEY,
                redirect_uris  TEXT NOT NULL,
                client_name    TEXT,
                created_at     INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_codes (
                code_hash      TEXT PRIMARY KEY,
                client_id      TEXT NOT NULL,
                redirect_uri   TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                scope          TEXT NOT NULL,
                resource       TEXT,
                subject        TEXT NOT NULL,
                expires_at     INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash     TEXT PRIMARY KEY,
                client_id      TEXT NOT NULL,
                subject        TEXT NOT NULL,
                scope          TEXT NOT NULL,
                resource       TEXT,
                expires_at     INTEGER NOT NULL
            );
            """);
    }

    // ------------------------------------------------------------- clients

    public void SaveClient(OAuthClient client)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT OR REPLACE INTO clients (client_id, redirect_uris, client_name, created_at)
            VALUES ($id, $uris, $name, $created);
            """;
        cmd.Parameters.AddWithValue("$id", client.ClientId);
        cmd.Parameters.AddWithValue("$uris", JsonSerializer.Serialize(client.RedirectUris));
        cmd.Parameters.AddWithValue("$name", (object?)client.ClientName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$created", client.CreatedAtUnix);
        cmd.ExecuteNonQuery();
    }

    public OAuthClient? GetClient(string clientId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT redirect_uris, client_name, created_at FROM clients WHERE client_id = $id;";
        cmd.Parameters.AddWithValue("$id", clientId);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;

        var uris = JsonSerializer.Deserialize<List<string>>(r.GetString(0)) ?? [];
        var name = r.IsDBNull(1) ? null : r.GetString(1);
        return new OAuthClient(clientId, uris, name, r.GetInt64(2));
    }

    // --------------------------------------------------------- auth codes

    public void SaveAuthCode(string code, AuthCodeData data)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO auth_codes (code_hash, client_id, redirect_uri, code_challenge, scope, resource, subject, expires_at)
            VALUES ($h, $c, $r, $cc, $s, $res, $sub, $exp);
            """;
        cmd.Parameters.AddWithValue("$h", Sha256(code));
        cmd.Parameters.AddWithValue("$c", data.ClientId);
        cmd.Parameters.AddWithValue("$r", data.RedirectUri);
        cmd.Parameters.AddWithValue("$cc", data.CodeChallenge);
        cmd.Parameters.AddWithValue("$s", data.Scope);
        cmd.Parameters.AddWithValue("$res", (object?)data.Resource ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$sub", data.Subject);
        cmd.Parameters.AddWithValue("$exp", data.ExpiresAtUnix);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Atomically fetch-and-delete an authorization code (single use). Returns null if absent.</summary>
    public AuthCodeData? ConsumeAuthCode(string code)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();

        AuthCodeData? data = null;
        using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = """
                SELECT client_id, redirect_uri, code_challenge, scope, resource, subject, expires_at
                FROM auth_codes WHERE code_hash = $h;
                """;
            sel.Parameters.AddWithValue("$h", Sha256(code));
            using var r = sel.ExecuteReader();
            if (r.Read())
            {
                data = new AuthCodeData(
                    r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3),
                    r.IsDBNull(4) ? null : r.GetString(4), r.GetString(5), r.GetInt64(6));
            }
        }

        if (data is not null)
        {
            using var del = conn.CreateCommand();
            del.Transaction = tx;
            del.CommandText = "DELETE FROM auth_codes WHERE code_hash = $h;";
            del.Parameters.AddWithValue("$h", Sha256(code));
            del.ExecuteNonQuery();
        }

        tx.Commit();
        return data;
    }

    // ----------------------------------------------------- refresh tokens

    public void SaveRefreshToken(string token, RefreshTokenData data)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO refresh_tokens (token_hash, client_id, subject, scope, resource, expires_at)
            VALUES ($h, $c, $sub, $s, $res, $exp);
            """;
        cmd.Parameters.AddWithValue("$h", Sha256(token));
        cmd.Parameters.AddWithValue("$c", data.ClientId);
        cmd.Parameters.AddWithValue("$sub", data.Subject);
        cmd.Parameters.AddWithValue("$s", data.Scope);
        cmd.Parameters.AddWithValue("$res", (object?)data.Resource ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$exp", data.ExpiresAtUnix);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Atomically fetch-and-delete a refresh token (rotation). Returns null if absent.</summary>
    public RefreshTokenData? ConsumeRefreshToken(string token)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();

        RefreshTokenData? data = null;
        using (var sel = conn.CreateCommand())
        {
            sel.Transaction = tx;
            sel.CommandText = "SELECT client_id, subject, scope, resource, expires_at FROM refresh_tokens WHERE token_hash = $h;";
            sel.Parameters.AddWithValue("$h", Sha256(token));
            using var r = sel.ExecuteReader();
            if (r.Read())
            {
                data = new RefreshTokenData(
                    r.GetString(0), r.GetString(1), r.GetString(2),
                    r.IsDBNull(3) ? null : r.GetString(3), r.GetInt64(4));
            }
        }

        if (data is not null)
        {
            using var del = conn.CreateCommand();
            del.Transaction = tx;
            del.CommandText = "DELETE FROM refresh_tokens WHERE token_hash = $h;";
            del.Parameters.AddWithValue("$h", Sha256(token));
            del.ExecuteNonQuery();
        }

        tx.Commit();
        return data;
    }

    /// <summary>Remove expired codes and refresh tokens. Cheap; call opportunistically.</summary>
    public void PurgeExpired(long nowUnix)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM auth_codes WHERE expires_at < $n; DELETE FROM refresh_tokens WHERE expires_at < $n;";
        cmd.Parameters.AddWithValue("$n", nowUnix);
        cmd.ExecuteNonQuery();
    }

    // ------------------------------------------------------------ helpers

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=3000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    private static void Execute(SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
