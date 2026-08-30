using PersonalMcpVault.Configuration;

namespace PersonalMcpVault.Security;

/// <summary>
/// Resolves caller-supplied paths against the vault root and guarantees the result
/// stays inside it. Every filesystem tool MUST route its paths through <see cref="Resolve"/>.
///
/// Two layers of defense:
///   1. Lexical: <see cref="Path.GetFullPath(string)"/> normalizes "." and ".." so a
///      relative path like "../../etc/passwd" collapses to a real absolute path that
///      is then checked against the root prefix.
///   2. Symlink: the nearest existing ancestor is resolved through any symlinks and
///      re-checked, so a link inside the vault pointing outside it is also rejected.
/// </summary>
public sealed class VaultPathResolver
{
    private readonly string _root;

    public VaultPathResolver(VaultServerOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Root))
            throw new InvalidOperationException("Vault:Root is not configured.");

        _root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(options.Root));

        if (!Directory.Exists(_root))
            throw new DirectoryNotFoundException($"Configured vault root does not exist: {_root}");
    }

    /// <summary>The validated, fully-qualified vault root.</summary>
    public string Root => _root;

    /// <summary>
    /// Resolve a vault-relative (or absolute-but-inside-vault) path to a full path.
    /// Throws <see cref="UnauthorizedAccessException"/> if it would escape the vault.
    /// Does not require the path to already exist (so it works for write/create).
    /// </summary>
    public string Resolve(string? requested)
    {
        requested = string.IsNullOrWhiteSpace(requested) ? "." : requested.Trim();

        // Normalize leading slashes so "/Daily/x.md" is treated as vault-relative, not OS-absolute.
        var normalized = requested.Replace('\\', '/').TrimStart('/');
        if (normalized.Length == 0) normalized = ".";

        var combined = Path.Combine(_root, normalized);
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(combined));

        if (!IsInside(full))
            throw new UnauthorizedAccessException($"Access denied: '{requested}' resolves outside the vault.");

        var real = ResolveRealPath(full);
        if (real is not null && !IsInside(real))
            throw new UnauthorizedAccessException($"Access denied: '{requested}' resolves (via a link) outside the vault.");

        return full;
    }

    private bool IsInside(string fullPath)
    {
        if (string.Equals(fullPath, _root, StringComparison.Ordinal)) return true;
        return fullPath.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    /// <summary>
    /// Walk up to the nearest path component that exists on disk, follow any symlink
    /// chain to its final target, and return the resolved location (null if nothing
    /// in the chain exists yet, e.g. writing a brand-new file into a new folder).
    /// </summary>
    private static string? ResolveRealPath(string path)
    {
        var current = path;
        while (!File.Exists(current) && !Directory.Exists(current))
        {
            var parent = Path.GetDirectoryName(current);
            if (string.IsNullOrEmpty(parent) || parent == current) return null;
            current = parent;
        }

        try
        {
            FileSystemInfo fsi = Directory.Exists(current)
                ? new DirectoryInfo(current)
                : new FileInfo(current);

            var resolved = fsi.ResolveLinkTarget(returnFinalTarget: true);
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(resolved?.FullName ?? current));
        }
        catch
        {
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(current));
        }
    }

    /// <summary>Render a full path as a vault-relative, POSIX-style display path.</summary>
    public string ToRelative(string fullPath)
    {
        var rel = Path.GetRelativePath(_root, fullPath);
        return rel == "." ? "/" : "/" + rel.Replace(Path.DirectorySeparatorChar, '/');
    }
}
