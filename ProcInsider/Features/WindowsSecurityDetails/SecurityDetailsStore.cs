using System.Text.Json;
using System.IO;
using System.Text.Json.Serialization;

namespace ProcInsider.Features.WindowsSecurityDetails;

public sealed record SecurityDetailsFile(int FormatVersion, string Provider, string Channel, SecurityDetailsDefinition[] Definitions);

/// <summary>One atomic current-user configuration file, independent of any capture workspace.</summary>
public sealed class SecurityDetailsStore
{
    public const int MaxFileBytes = 2097152, MaxDefinitions = 2048;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 12,
        RespectRequiredConstructorParameters = true
    };
    private readonly string _path;
    private readonly object _gate = new();
    private readonly Dictionary<int, SecurityDetailsDefinition> _defaults;
    private Dictionary<int, SecurityDetailsDefinition> _definitions;
    public string LoadError { get; private set; } = "";
    public long Revision { get; private set; }
    public event EventHandler? Changed;

    public SecurityDetailsStore(string path, IEnumerable<SecurityDetailsDefinition>? defaults = null)
    {
        _path = Path.GetFullPath(path);
        _definitions = Validate((defaults ?? SecurityDetailsDefaults.All).ToArray());
        _defaults = _definitions.ToDictionary(p => p.Key, p => Clone(p.Value));
        try
        {
            if (File.Exists(_path)) foreach (var pair in ReadFile(_path)) _definitions[pair.Key] = pair.Value;
        }
        catch (Exception ex) when (IsExpected(ex)) { LoadError = $"Saved details definitions could not be loaded: {ex.Message}"; }
    }

    public SecurityDetailsDefinition[] Snapshot()
    {
        lock (_gate) return _definitions.Values.OrderBy(d => d.EventId).Select(Clone).ToArray();
    }
    private static SecurityDetailsDefinition Clone(SecurityDetailsDefinition d) =>
        d with { Layouts = d.Layouts.Select(l => l with { Fields = l.Fields.ToArray() }).ToArray() };

    public void Save(SecurityDetailsDefinition definition) => Merge(Validate([definition]));
    public void Import(string path) => Merge(ReadFile(path));
    public void Export(string path) => WriteAtomic(path, Snapshot());

    private void Merge(Dictionary<int, SecurityDetailsDefinition> incoming)
    {
        if (incoming.Count == 0) return;
        lock (_gate)
        {
            // Never silently overwrite an unreadable last-good file with defaults.
            if (LoadError.Length > 0) throw new IOException(LoadError + " Recover the saved file before saving changes.");
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            // An exclusive sidecar lease serializes different Viewer processes. A busy writer
            // produces a visible retryable I/O error; never overwrite from a stale instance cache.
            using var lease = new FileStream(_path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var merged = new Dictionary<int, SecurityDetailsDefinition>(_defaults);
            if (File.Exists(_path)) foreach (var pair in ReadFile(_path)) merged[pair.Key] = pair.Value;
            foreach (var pair in incoming) merged[pair.Key] = Clone(pair.Value);
            if (merged.Count > MaxDefinitions) throw new FormatException($"At most {MaxDefinitions} definitions are supported.");
            WriteAtomic(_path, merged.Values.OrderBy(d => d.EventId).ToArray());
            _definitions = merged;
            Revision++;
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public static Dictionary<int, SecurityDetailsDefinition> ReadFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxFileBytes) throw new FormatException("Definition files must be at most 2 MiB.");
        var file = JsonSerializer.Deserialize<SecurityDetailsFile>(stream, JsonOptions);
        if (file is null || file.FormatVersion != 1 || file.Provider != SecurityDetailsTemplate.Provider || file.Channel != "Security")
            throw new FormatException("Expected formatVersion 1 for Microsoft-Windows-Security-Auditing / Security.");
        return Validate(file.Definitions);
    }

    public static Dictionary<int, SecurityDetailsDefinition> Validate(SecurityDetailsDefinition[] definitions)
    {
        if (definitions is null || definitions.Length > MaxDefinitions) throw new FormatException("Invalid definition table size.");
        var result = new Dictionary<int, SecurityDetailsDefinition>();
        foreach (var d in definitions)
        {
            if (d is null || d.EventId is < 0 or > 65535 || !result.TryAdd(d.EventId, d))
                throw new FormatException("Event IDs must be unique integers between 0 and 65535.");
            SecurityDetailsTemplate.Compile(d.Template);
            if (d.Layouts is null || d.Layouts.Length > 32 || d.Layouts.Any(l => l is null || l.Version is < 0 or > 255 || l.Fields is null || l.Fields.Length > SecurityDetailsTemplate.MaxFields || l.Fields.Any(f => f is null || f.Length > 256)))
                throw new FormatException("Invalid positional field layout.");
        }
        return result;
    }

    private static void WriteAtomic(string path, SecurityDetailsDefinition[] definitions)
    {
        path = Path.GetFullPath(path);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new SecurityDetailsFile(1, SecurityDetailsTemplate.Provider, "Security", definitions), JsonOptions);
        if (bytes.Length > MaxFileBytes) throw new FormatException("Definition files must be at most 2 MiB.");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(bytes); stream.Flush(true); }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static bool IsExpected(Exception ex) => ex is IOException or UnauthorizedAccessException or FormatException or JsonException or ArgumentException or NotSupportedException;
}
