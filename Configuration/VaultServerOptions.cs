namespace PersonalMcpVault.Configuration;

/// <summary>
/// Options controlling the vault the filesystem tools operate on.
/// Bound from the "Vault" configuration section.
/// </summary>
public sealed class VaultServerOptions
{
    public const string SectionName = "Vault";

    /// <summary>Absolute path to the Personal vault root. All tools are confined to this directory.</summary>
    public string Root { get; set; } = "";

    /// <summary>When true, every mutating tool (write/edit/move/create/delete) is disabled.</summary>
    public bool ReadOnly { get; set; }

    /// <summary>When true, the delete_file tool is enabled. Off by default because deletion is destructive.</summary>
    public bool AllowDelete { get; set; }

    /// <summary>Upper bound (bytes) for a single read_file / write_file, to guard against huge files.</summary>
    public long MaxFileBytes { get; set; } = 10 * 1024 * 1024; // 10 MiB

    /// <summary>Max entries returned by directory_tree / search tools, to keep responses bounded.</summary>
    public int MaxResults { get; set; } = 1000;
}
