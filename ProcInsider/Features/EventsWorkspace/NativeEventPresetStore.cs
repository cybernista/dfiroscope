using ProcInsider.Features.NativeEventProfiles;
using System.Collections.Immutable;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class NativeEventPresetStore
{
    internal sealed record PresetData(string Id, Guid Revision, string Name, NativeEventPresetProfile[] Profiles,
        NativeEventPresetColumn[] Columns, NativeEventPresetAssociation? Association)
    {
        internal NativeEventPreset ToPreset() => new(Id, Revision, Name, Profiles, Columns, Association);
        internal static PresetData From(NativeEventPreset p) => new(p.Id, p.Revision, p.Name, p.Profiles.ToArray(), p.Columns.ToArray(), p.Association);
    }
    internal sealed record PresetFile(int FormatVersion, PresetData[] Presets);
    internal const int MaximumFileBytes = 2097152;
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 16,
        RespectRequiredConstructorParameters = true,
        Converters = { new JsonStringEnumConverter<NativeEventFieldPriority>(allowIntegerValues: false), new JsonStringEnumConverter<EventSort>(allowIntegerValues: false) }
    };
    private readonly string _path;
    private readonly object _gate = new();
    private ImmutableArray<NativeEventPreset> _presets = [];
    public string LoadError { get; private set; } = "";
    public NativeEventPresetStore(string path) { _path = Path.GetFullPath(path); Reload(); }
    public ImmutableArray<NativeEventPreset> Snapshot() { lock (_gate) return _presets; }
    public void Reload()
    {
        lock (_gate)
        {
            try { _presets = Read(); LoadError = ""; }
            catch (Exception ex) when (NativeEventProfileStore.IsExpected(ex))
            { LoadError = "Saved presets unavailable. File preserved; recover externally and reload before saving. " + ex.Message; }
        }
    }
    private ImmutableArray<NativeEventPreset> Read()
    {
        FileStream stream;
        try { stream = new(_path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (FileNotFoundException) { return []; }
        catch (DirectoryNotFoundException) { return []; }
        using (stream)
        {
            if (stream.Length > MaximumFileBytes) throw new FormatException("Presets file exceeds 2 MiB.");
            var file = JsonSerializer.Deserialize<PresetFile>(stream, Options);
            if (file?.FormatVersion != 1 || file.Presets == null || file.Presets.Any(p => p == null)) throw new FormatException("Expected preset formatVersion 1.");
            var result = file.Presets.Select(p => p.ToPreset()).ToImmutableArray();
            if (result.Select(p => p.Id).Distinct(StringComparer.Ordinal).Count() != result.Length) throw new FormatException("Duplicate preset ID.");
            return result;
        }
    }
    public NativeEventPreset Save(NativeEventPreset draft, Guid? expectedRevision, CancellationToken token = default)
    {
        lock (_gate)
        {
            token.ThrowIfCancellationRequested();
            if (LoadError.Length > 0) throw new IOException(LoadError);
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            using var lease = new FileStream(_path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var current = Read().ToDictionary(p => p.Id, StringComparer.Ordinal);
            if (current.GetValueOrDefault(draft.Id)?.Revision != expectedRevision)
                throw new InvalidOperationException("This preset changed since editing began. Reload and reapply the draft deliberately.");
            var saved = new NativeEventPreset(draft.Id, Guid.NewGuid(), draft.Name, draft.Profiles, draft.Columns, draft.Association);
            current[saved.Id] = saved;
            var merged = current.Values.OrderBy(p => p.Name, StringComparer.Ordinal).ThenBy(p => p.Id, StringComparer.Ordinal).ToImmutableArray();
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new PresetFile(1, merged.Select(PresetData.From).ToArray()), Options);
            if (bytes.Length > MaximumFileBytes) throw new FormatException("Presets file exceeds 2 MiB.");
            var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { stream.Write(bytes); stream.Flush(true); }
                token.ThrowIfCancellationRequested();
                File.Move(temporary, _path, overwrite: true);
                _presets = merged;
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            return saved;
        }
    }
}
