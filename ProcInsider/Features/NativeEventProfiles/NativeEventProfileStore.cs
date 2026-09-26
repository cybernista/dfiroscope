using System.Collections.Immutable;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.NativeEventProfiles;

/// <summary>Shared current-user presentation configuration. Writes merge under an exclusive process lease.</summary>
internal sealed class NativeEventProfileStore
{
    internal sealed record ProfileFile(int FormatVersion, ProfileData[] Profiles);
    internal sealed record ProfileData(string Id, Guid Revision, string Name, NativeEventType EventType, NativeEventProfileField[] Fields)
    {
        internal NativeEventProfile ToProfile() => new(Id, Revision, Name, EventType, Fields);
        internal static ProfileData From(NativeEventProfile p) => new(p.Id, p.Revision, p.Name, p.EventType, p.Fields.ToArray());
    }
    internal const int MaximumFileBytes = 2097152, MaximumProfiles = 2048;
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 12,
        RespectRequiredConstructorParameters = true,
        Converters = { new JsonStringEnumConverter<NativeEventFieldPriority>(allowIntegerValues: false) }
    };
    private readonly string _path;
    private readonly object _gate = new();
    private readonly ImmutableArray<NativeEventProfile> _defaults;
    private ImmutableArray<NativeEventProfile> _profiles;
    public string LoadError { get; private set; } = "";
    public long Revision { get; private set; }
    public event EventHandler? Changed;
    public NativeEventProfileStore(string path, IEnumerable<NativeEventProfile>? defaults = null)
    {
        _path = Path.GetFullPath(path);
        _defaults = (defaults ?? NativeEventProfileDefaults.All).ToImmutableArray();
        _profiles = _defaults;
        Reload();
    }
    public ImmutableArray<NativeEventProfile> Snapshot() { lock (_gate) return _profiles; }
    public bool IsBundled(NativeEventProfile profile) => _defaults.Any(p => p.Id == profile.Id && p.Revision == profile.Revision);
    public void Reload()
    {
        lock (_gate)
        {
            try { _profiles = Merge(ReadUsers()); LoadError = ""; }
            catch (Exception ex) when (IsExpected(ex))
            { LoadError = "Saved profiles could not be loaded. File preserved; recover it externally and reload before saving. " + ex.Message; }
            Revision++;
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }
    private Dictionary<string, NativeEventProfile> ReadUsers()
    {
        var users = new Dictionary<string, NativeEventProfile>(StringComparer.Ordinal);
        // Opening directly distinguishes absence from access failure (File.Exists would hide that failure).
        FileStream stream;
        try { stream = new(_path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (FileNotFoundException) { return users; }
        catch (DirectoryNotFoundException) { return users; }
        using (stream)
        {
            if (stream.Length > MaximumFileBytes) throw new FormatException("Profiles file exceeds 2 MiB.");
            var file = JsonSerializer.Deserialize<ProfileFile>(stream, Options);
            if (file is null || file.FormatVersion != NativeEventProfile.ContractVersion || file.Profiles is null || file.Profiles.Length > MaximumProfiles)
                throw new FormatException("Expected formatVersion 1 and at most 2048 profiles.");
            foreach (var data in file.Profiles)
            {
                if (data is null) throw new FormatException("Null profile.");
                var profile = data.ToProfile();
                if (!users.TryAdd(profile.Id, profile)) throw new FormatException("Duplicate profile ID.");
            }
        }
        return users;
    }
    private ImmutableArray<NativeEventProfile> Merge(Dictionary<string, NativeEventProfile> users)
    {
        var merged = _defaults.ToDictionary(p => p.Id, StringComparer.Ordinal);
        foreach (var pair in users) merged[pair.Key] = pair.Value;
        if (merged.Count > MaximumProfiles) throw new FormatException("At most 2048 profiles are supported.");
        return merged.Values.OrderBy(p => p.Name, StringComparer.Ordinal).ThenBy(p => p.Id, StringComparer.Ordinal).ToImmutableArray();
    }
    public NativeEventProfile Save(NativeEventProfile draft, Guid? expectedRevision, CancellationToken token = default)
    {
        NativeEventProfile saved;
        lock (_gate)
        {
            token.ThrowIfCancellationRequested();
            if (LoadError.Length > 0) throw new IOException(LoadError);
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            using var lease = new FileStream(_path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var users = ReadUsers();
            var current = Merge(users).FirstOrDefault(p => p.Id == draft.Id);
            if (current?.Revision != expectedRevision)
                throw new InvalidOperationException("This profile changed since editing began. Reload saved profiles and reapply the draft deliberately.");
            saved = new(draft.Id, Guid.NewGuid(), draft.Name, draft.EventType, draft.Fields);
            users[saved.Id] = saved;
            var merged = Merge(users);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new ProfileFile(1, users.Values.OrderBy(p => p.Id, StringComparer.Ordinal).Select(ProfileData.From).ToArray()), Options);
            if (bytes.Length > MaximumFileBytes) throw new FormatException("Profiles file exceeds 2 MiB.");
            var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { stream.Write(bytes); stream.Flush(true); }
                token.ThrowIfCancellationRequested();
                File.Move(temporary, _path, overwrite: true);
                // Cancellation after the atomic commit cannot report the durable save as canceled.
                _profiles = merged; Revision++;
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        Changed?.Invoke(this, EventArgs.Empty);
        return saved;
    }
    internal static bool IsExpected(Exception ex) => ex is IOException or UnauthorizedAccessException or FormatException or JsonException or ArgumentException or NotSupportedException or InvalidOperationException;
}
