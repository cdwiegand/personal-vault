using System.ComponentModel;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ModelContextProtocol.Server;
using PersonalMcpVault.Configuration;
using PersonalMcpVault.Security;

namespace PersonalMcpVault.Tools;

/// <summary>A single exact find/replace edit used by <c>edit_file</c>.</summary>
public sealed record TextEdit(
    [property: JsonPropertyName("oldText")]
    [property: Description("Exact text to find. Must occur exactly once in the file.")]
    string OldText,
    [property: JsonPropertyName("newText")]
    [property: Description("Replacement text.")]
    string NewText);

/// <summary>
/// Filesystem tools scoped to a single Obsidian vault. Every path is validated by
/// <see cref="VaultPathResolver"/> before any I/O happens, so nothing can read or
/// write outside the configured vault root.
/// </summary>
[McpServerToolType]
public sealed class FileSystemTools
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private readonly VaultPathResolver _paths;
    private readonly VaultServerOptions _options;

    public FileSystemTools(VaultPathResolver paths, VaultServerOptions options)
    {
        _paths = paths;
        _options = options;
    }

    // ---------------------------------------------------------------- reads

    [McpServerTool(Name = "read_file"), Description(
        "Read the full text contents of a file in the vault. The path is relative to the vault root.")]
    public async Task<string> ReadFile(
        [Description("File path relative to the vault root, e.g. 'Projects/roadmap.md'.")] string path,
        CancellationToken ct = default)
    {
        var full = _paths.Resolve(path);
        if (!File.Exists(full)) throw new FileNotFoundException($"File not found: {path}");

        var info = new FileInfo(full);
        if (info.Length > _options.MaxFileBytes)
            throw new InvalidOperationException(
                $"File is {info.Length} bytes, which exceeds the {_options.MaxFileBytes}-byte limit.");

        return await File.ReadAllTextAsync(full, ct);
    }

    [McpServerTool(Name = "read_multiple_files"), Description(
        "Read several files at once. Each file's contents are returned prefixed by its path; " +
        "an error on one file is reported inline and does not abort the rest.")]
    public async Task<string> ReadMultipleFiles(
        [Description("Vault-relative file paths to read.")] string[] paths,
        CancellationToken ct = default)
    {
        var sb = new StringBuilder();
        foreach (var p in paths)
        {
            try
            {
                var content = await ReadFile(p, ct);
                sb.Append("==> ").Append(p).AppendLine(" <==").AppendLine(content).AppendLine();
            }
            catch (Exception ex)
            {
                sb.Append("==> ").Append(p).Append(" <== [ERROR] ").AppendLine(ex.Message).AppendLine();
            }
        }
        return sb.ToString();
    }

    [McpServerTool(Name = "get_file_info"), Description(
        "Return metadata for a file or directory: type, size, and created/modified timestamps (UTC).")]
    public string GetFileInfo(
        [Description("Vault-relative path to inspect.")] string path)
    {
        var full = _paths.Resolve(path);
        if (Directory.Exists(full))
        {
            var d = new DirectoryInfo(full);
            return JsonSerializer.Serialize(new
            {
                path = _paths.ToRelative(full),
                type = "directory",
                entries = d.EnumerateFileSystemInfos().Count(),
                created = d.CreationTimeUtc,
                modified = d.LastWriteTimeUtc
            }, Json);
        }
        if (File.Exists(full))
        {
            var f = new FileInfo(full);
            return JsonSerializer.Serialize(new
            {
                path = _paths.ToRelative(full),
                type = "file",
                size = f.Length,
                created = f.CreationTimeUtc,
                modified = f.LastWriteTimeUtc
            }, Json);
        }
        throw new FileNotFoundException($"No file or directory at: {path}");
    }

    [McpServerTool(Name = "list_directory"), Description(
        "List the immediate contents of a directory. Each entry is prefixed with [DIR] or [FILE].")]
    public string ListDirectory(
        [Description("Vault-relative directory path. Use '.' or '/' for the vault root.")] string path = ".")
    {
        var full = _paths.Resolve(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Directory not found: {path}");

        var entries = new DirectoryInfo(full)
            .EnumerateFileSystemInfos()
            .OrderBy(e => e is FileInfo)          // directories first
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .Select(e => (e is DirectoryInfo ? "[DIR]  " : "[FILE] ") + e.Name);

        var text = string.Join('\n', entries);
        return text.Length == 0 ? "(empty)" : text;
    }

    [McpServerTool(Name = "directory_tree"), Description(
        "Return a recursive JSON tree of a directory's contents. Bounded by the server's max-results setting.")]
    public string DirectoryTree(
        [Description("Vault-relative directory to walk. Use '.' or '/' for the vault root.")] string path = ".")
    {
        var full = _paths.Resolve(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Directory not found: {path}");

        var remaining = _options.MaxResults;
        var tree = BuildTree(new DirectoryInfo(full), ref remaining);
        return JsonSerializer.Serialize(tree, Json);
    }

    private static object BuildTree(DirectoryInfo dir, ref int remaining)
    {
        var children = new List<object>();
        foreach (var entry in dir.EnumerateFileSystemInfos()
                     .OrderBy(e => e is FileInfo)
                     .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            if (remaining-- <= 0) { children.Add(new { name = "…", type = "truncated" }); break; }

            if (entry is DirectoryInfo sub)
                children.Add(new { name = sub.Name, type = "directory", children = BuildTree(sub, ref remaining) });
            else
                children.Add(new { name = entry.Name, type = "file" });
        }
        return children;
    }

    [McpServerTool(Name = "search_files"), Description(
        "Recursively find files and folders whose name matches a glob pattern (case-insensitive), " +
        "e.g. '*.md' or 'meeting-*'. Returns matching vault-relative paths.")]
    public string SearchFiles(
        [Description("Vault-relative directory to search under. Use '.' or '/' for the whole vault.")] string path,
        [Description("Filename glob, e.g. '*.md'.")] string pattern,
        CancellationToken ct = default)
    {
        var full = _paths.Resolve(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Directory not found: {path}");

        var matches = new List<string>();
        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
        foreach (var hit in Directory.EnumerateFileSystemEntries(full, pattern, opts))
        {
            ct.ThrowIfCancellationRequested();
            matches.Add(_paths.ToRelative(hit));
            if (matches.Count >= _options.MaxResults) { matches.Add("… (truncated)"); break; }
        }
        return matches.Count == 0 ? "(no matches)" : string.Join('\n', matches);
    }

    [McpServerTool(Name = "search_content"), Description(
        "Full-text search across the vault: return files containing the query string, with matching line " +
        "numbers and a snippet. Case-insensitive. Ideal for finding notes by their content.")]
    public async Task<string> SearchContent(
        [Description("Text to search for.")] string query,
        [Description("Vault-relative directory to search under. Defaults to the whole vault.")] string path = ".",
        [Description("Only search files with this extension, e.g. '.md'. Empty = all text files.")] string extension = ".md",
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(query)) throw new ArgumentException("query must not be empty.");
        var full = _paths.Resolve(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Directory not found: {path}");

        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
        var pattern = string.IsNullOrWhiteSpace(extension) ? "*" : "*" + (extension.StartsWith('.') ? extension : "." + extension);

        var sb = new StringBuilder();
        var hits = 0;
        foreach (var file in Directory.EnumerateFiles(full, pattern, opts))
        {
            ct.ThrowIfCancellationRequested();
            var info = new FileInfo(file);
            if (info.Length > _options.MaxFileBytes) continue;

            var lineNo = 0;
            foreach (var line in await File.ReadAllLinesAsync(file, ct))
            {
                lineNo++;
                if (line.Contains(query, StringComparison.OrdinalIgnoreCase))
                {
                    sb.Append(_paths.ToRelative(file)).Append(':').Append(lineNo).Append(": ")
                      .AppendLine(line.Trim());
                    if (++hits >= _options.MaxResults) { sb.AppendLine("… (truncated)"); return sb.ToString(); }
                }
            }
        }
        return hits == 0 ? "(no matches)" : sb.ToString();
    }

    [McpServerTool(Name = "list_allowed_directories"), Description(
        "Return the directories these tools are permitted to access. Everything is confined to the vault root.")]
    public string ListAllowedDirectories() => _paths.Root;

    // --------------------------------------------------------------- writes

    [McpServerTool(Name = "write_file"), Description(
        "Create a new file or overwrite an existing one with UTF-8 text. Parent directories are created as needed.")]
    public async Task<string> WriteFile(
        [Description("Vault-relative destination path.")] string path,
        [Description("Full text content to write.")] string content,
        CancellationToken ct = default)
    {
        EnsureWritable();
        if (Encoding.UTF8.GetByteCount(content) > _options.MaxFileBytes)
            throw new InvalidOperationException($"Content exceeds the {_options.MaxFileBytes}-byte limit.");

        var full = _paths.Resolve(path);
        var dir = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        await File.WriteAllTextAsync(full, content, ct);
        return $"Wrote {Encoding.UTF8.GetByteCount(content)} bytes to {_paths.ToRelative(full)}";
    }

    [McpServerTool(Name = "edit_file"), Description(
        "Apply one or more exact find-and-replace edits to a text file. Each edit's oldText must appear exactly once.")]
    public async Task<string> EditFile(
        [Description("Vault-relative file path to edit.")] string path,
        [Description("Edits to apply in order.")] TextEdit[] edits,
        CancellationToken ct = default)
    {
        EnsureWritable();
        var full = _paths.Resolve(path);
        if (!File.Exists(full)) throw new FileNotFoundException($"File not found: {path}");

        var text = await File.ReadAllTextAsync(full, ct);
        foreach (var edit in edits)
        {
            if (string.IsNullOrEmpty(edit.OldText))
                throw new ArgumentException("oldText must not be empty.");

            var idx = text.IndexOf(edit.OldText, StringComparison.Ordinal);
            if (idx < 0)
                throw new InvalidOperationException($"oldText not found: \"{Truncate(edit.OldText)}\"");
            if (text.IndexOf(edit.OldText, idx + edit.OldText.Length, StringComparison.Ordinal) >= 0)
                throw new InvalidOperationException($"oldText is not unique: \"{Truncate(edit.OldText)}\"");

            text = string.Concat(text.AsSpan(0, idx), edit.NewText, text.AsSpan(idx + edit.OldText.Length));
        }

        await File.WriteAllTextAsync(full, text, ct);
        return $"Applied {edits.Length} edit(s) to {_paths.ToRelative(full)}";
    }

    [McpServerTool(Name = "create_directory"), Description(
        "Create a directory (and any missing parents). No error if it already exists.")]
    public string CreateDirectory(
        [Description("Vault-relative directory path to create.")] string path)
    {
        EnsureWritable();
        var full = _paths.Resolve(path);
        Directory.CreateDirectory(full);
        return $"Created {_paths.ToRelative(full)}";
    }

    [McpServerTool(Name = "move_file"), Description(
        "Move or rename a file or directory within the vault. Fails if the destination already exists.")]
    public string MoveFile(
        [Description("Vault-relative source path.")] string source,
        [Description("Vault-relative destination path.")] string destination)
    {
        EnsureWritable();
        var from = _paths.Resolve(source);
        var to = _paths.Resolve(destination);

        if (File.Exists(to) || Directory.Exists(to))
            throw new IOException($"Destination already exists: {destination}");

        var destDir = Path.GetDirectoryName(to);
        if (!string.IsNullOrEmpty(destDir)) Directory.CreateDirectory(destDir);

        if (Directory.Exists(from)) Directory.Move(from, to);
        else if (File.Exists(from)) File.Move(from, to);
        else throw new FileNotFoundException($"Source not found: {source}");

        return $"Moved {_paths.ToRelative(from)} -> {_paths.ToRelative(to)}";
    }

    [McpServerTool(Name = "delete_file"), Description(
        "Permanently delete a file. Disabled unless the server is configured with Vault:AllowDelete=true.")]
    public string DeleteFile(
        [Description("Vault-relative file path to delete.")] string path)
    {
        EnsureWritable();
        if (!_options.AllowDelete)
            throw new InvalidOperationException("Deletion is disabled (set Vault:AllowDelete=true to enable).");

        var full = _paths.Resolve(path);
        if (!File.Exists(full)) throw new FileNotFoundException($"File not found: {path}");

        File.Delete(full);
        return $"Deleted {_paths.ToRelative(full)}";
    }

    // --------------------------------------------------------------- helpers

    private void EnsureWritable()
    {
        if (_options.ReadOnly)
            throw new InvalidOperationException("Server is in read-only mode; this operation is disabled.");
    }

    private static string Truncate(string s, int max = 60) =>
        s.Length <= max ? s : s[..max] + "…";
}
