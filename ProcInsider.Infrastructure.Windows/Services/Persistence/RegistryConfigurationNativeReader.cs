using System.Globalization;
using System.Text;
using System.Text.Json;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

internal sealed class RegistryConfigurationNativeReader(RegistryPersistenceFamily family, IRegistryConfigurationSource? source = null) : IRegistryConfigurationNativeReader
{
    internal const string Nt = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    internal const string Winlogon = Nt + @"\Winlogon";
    internal const string Ifeo = Nt + @"\Image File Execution Options";
    internal const string SilentExit = Nt + @"\SilentProcessExit";
    internal const string AppInit = Nt + @"\Windows";
    internal const string Lsa = @"SYSTEM\CurrentControlSet\Control\Lsa";
    internal const int MaxBytes = 32 * 1024 * 1024;
    internal const int MaxEntries = 20000;
    private readonly IRegistryConfigurationSource _source = source ?? new RegistryConfigurationSource();
    internal sealed record Rule(string Name, params uint[] Types);
    internal static readonly Rule[] NotifyFields = [new("DllName", 2), new("Asynchronous", 4), new("Impersonate", 4), new("SmartCardLogonNotify", 4),
        new("Lock", 1), new("Logoff", 1), new("Logon", 1), new("Shutdown", 1), new("StartScreenSaver", 1), new("StartShell", 1), new("Startup", 1), new("StopScreenSaver", 1), new("Unlock", 1)];
    internal static readonly Rule[] IfeoFields = [new("Debugger", 1, 2), new("GlobalFlag", 1, 4), new("UseFilter", 4)];
    internal static readonly Rule[] FilterFields = [new("FilterFullPath", 1, 2), new("Debugger", 1, 2), new("GlobalFlag", 1, 4)];
    internal static readonly Rule[] SilentDefaults = [new("MonitorProcess", 1, 2), new("ModuleIgnoreList", 1, 2)];
    internal static readonly Rule[] SilentFields = [new("MonitorProcess", 1, 2), new("ReportingMode", 4), new("IgnoreSelfExits", 4), new("ModuleIgnoreList", 1, 2)];
    internal static readonly Rule[] AppInitFields = [new("AppInit_DLLs", 1), new("LoadAppInit_DLLs", 4), new("RequireSignedAppInit_DLLs", 4)];

    public IReadOnlyList<RegistryConfigurationPartition> Read(CancellationToken token)
    {
        var partitions = new List<RegistryConfigurationPartition>(); var bytes = MaxBytes; var entries = MaxEntries;
        var views = _source.Is64Bit ? new[] { "32", "64" } : ["32"];
        string hive = "HKEY_LOCAL_MACHINE", sid = "", viewName = "Shared";
        uint? controlSetSelector = null;
        List<RegistryConfigurationEntry> observed = [];
        var verifiedKeys = new List<(string Hive, string Sid, string View, string Path, PersistenceRegistryMetadata? Stamp)>();
        try
        {
            if (family == RegistryPersistenceFamily.Winlogon)
            {
                foreach (var view in views)
                {
                    Visit("HKEY_LOCAL_MACHINE", "", view, Winlogon, key =>
                    {
                        ValueRows(key, Winlogon, [new("Shell", 1, 2), new("Userinit", 1, 2)]);
                    });
                    Visit("HKEY_LOCAL_MACHINE", "", view, Winlogon + @"\Notify", key =>
                    {
                        foreach (var name in Children(key)) Registration(Winlogon + @"\Notify\" + name, name, NotifyFields, "DllName", enabled: false,
                            qualification: "Legacy notification packages are ignored since Windows Vista.");
                    });
                }
                var sids = _source.LoadedSids(token);
                if (sids.Count > 512) throw new InvalidDataException("Loaded-user SID bound reached.");
                foreach (var loadedSid in sids)
                {
                    if (!System.Text.RegularExpressions.Regex.IsMatch(loadedSid, @"^S-\d+(?:-\d+)+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)) throw new InvalidDataException("Malformed loaded SID declaration.");
                    Visit("HKEY_USERS", loadedSid, "Shared", Winlogon, key => ValueRows(key, Winlogon, [new("Shell", 1, 2)]));
                }
                if (!sids.Order(StringComparer.OrdinalIgnoreCase).SequenceEqual(_source.LoadedSids(token).Order(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase))
                    throw new IOException("Loaded-user scope changed; no authoritative empty user scopes.");
            }
            else if (family == RegistryPersistenceFamily.AppInit)
                foreach (var view in views) Visit("HKEY_LOCAL_MACHINE", "", view, AppInit, key =>
                {
                    var fields = Fields(key, AppInitFields);
                    if (fields.Count != 0) Add("AppInit_DLLs", AppInit, fields, Text(fields, "AppInit_DLLs"), Flag(fields, "LoadAppInit_DLLs") is uint load ? load != 0 : null,
                        "Configured flags only; Secure Boot/effective DLL loading not observed.");
                });
            else if (family == RegistryPersistenceFamily.LSA)
            {
                using var selector = _source.Open("HKEY_LOCAL_MACHINE", "", "Shared", @"SYSTEM\Select") ?? throw new IOException("Active control-set selector unavailable.");
                var stamp = selector.Stamp(); var selected = Fields(selector, [new("Current", 4)]);
                var current = Flag(selected, "Current") ?? throw new InvalidDataException("Active control-set selector absent.");
                controlSetSelector = current;
                if (current is < 1 or > 999) throw new InvalidDataException("Active control-set selector outside bound.");
                var physical = @"SYSTEM\ControlSet" + current.ToString("D3", CultureInfo.InvariantCulture) + @"\Control\Lsa";
                Visit("HKEY_LOCAL_MACHINE", "", "Shared", Lsa, key => ValueRows(key, Lsa, [new("Authentication Packages", 7), new("Security Packages", 7), new("Notification Packages", 7)]), physical);
                Visit("HKEY_LOCAL_MACHINE", "", "Shared", Lsa + @"\OSConfig", key => ValueRows(key, Lsa + @"\OSConfig", [new("Security Packages", 7)]), physical + @"\OSConfig");
                if (selector.Stamp() != stamp || Flag(Fields(selector, [new("Current", 4)]), "Current") != current) throw new IOException("Active control-set selector changed during read.");
            }
            else ReadIfeo();
            foreach (var observedKey in verifiedKeys)
            {
                token.ThrowIfCancellationRequested();
                using var key = _source.Open(observedKey.Hive, observedKey.Sid, observedKey.View, observedKey.Path);
                if (key?.Stamp() != observedKey.Stamp) throw new IOException("Observed native registry dependency changed before family completion.");
            }
            if (family == RegistryPersistenceFamily.Winlogon) _source.VerifyUserAliases(token);
        }
        catch (Exception error) when (ServicesDriversNativeReader.ExpectedFailure(error))
        { partitions.Add(new("HKEY_LOCAL_MACHINE", "", "Shared", family + "Discovery", PersistenceCollectionStatus.Failed, [], "Declared registry discovery unavailable, unsafe, changed or bounded.")); }
        finally { _source.Dispose(); }
        token.ThrowIfCancellationRequested(); return partitions;

        void Visit(string selectedHive, string selectedSid, string view, string path, Action<IRegistryConfigurationKey> read, string? physical = null)
        {
            hive = selectedHive; sid = selectedSid; viewName = view; observed = [];
            var status = PersistenceCollectionStatus.Complete;
            try
            {
                token.ThrowIfCancellationRequested();
                using var key = _source.Open(hive, sid, view, physical ?? path);
                verifiedKeys.Add((hive, sid, view, physical ?? path, key?.Stamp()));
                if (key != null) { var stamp = key.Stamp(); read(key); if (key.Stamp() != stamp) throw new IOException("Declared registry root changed during read."); }
            }
            catch (Exception error) when (ServicesDriversNativeReader.ExpectedFailure(error)) { status = observed.Count == 0 ? PersistenceCollectionStatus.Failed : PersistenceCollectionStatus.Partial; }
            partitions.Add(new(hive, sid, view, path, status, observed.ToArray(), status == PersistenceCollectionStatus.Complete
                ? "Allowlisted native configuration observed; presence does not establish execution. Unloaded user scopes are excluded." +
                    (sid != "S-1-5-18" ? "" : " Logical SID S-1-5-18 retains identity; exact verified native LocalSystem alias maps only to .DEFAULT and is rechecked at family completion.") +
                    (physical == null ? "" : " Logical CurrentControlSet resolved to " + physical + "; Select.Current=" + controlSetSelector + ". Selector consistency checked for the family.")
                : "Declared native configuration unavailable, unsafe, malformed, changed or bounded."));
        }
        IReadOnlyList<string> Children(IRegistryConfigurationKey key)
        {
            if (entries <= 0) throw new InvalidDataException("Registry registration aggregate count reached.");
            var names = key.Children(Math.Min(4096, entries), token);
            if (names.Count > Math.Min(4096, entries) || names.Distinct(StringComparer.OrdinalIgnoreCase).Count() != names.Count) throw new InvalidDataException("Registry child count or conflicting name bound.");
            entries -= names.Count;
            foreach (var name in names) { PersistenceRegistryNativeReader.ValidateText(name); if (name.Length is 0 or > 256 || name.Contains('\\') || name.Contains('/') || name.Contains('\0')) throw new InvalidDataException("Unsafe registration child."); }
            return names;
        }
        Dictionary<string, PersistenceNativeValue> Fields(IRegistryConfigurationKey key, Rule[] rules)
        {
            var stamp = key.Stamp(); var fields = new Dictionary<string, PersistenceNativeValue>(StringComparer.Ordinal);
            foreach (var rule in rules)
            {
                token.ThrowIfCancellationRequested(); var raw = key.Field(rule.Name, ref bytes); if (raw == null) continue;
                if (!rule.Types.Contains(raw.Type)) throw new InvalidDataException("Unsupported declared registry native type.");
                // Reserve worst-case escaped JSON plus exact base64 native bytes before decoding/serialization.
                var projected = checked(raw.Bytes.Length * 12 + 1024);
                if (projected > bytes) throw new InvalidDataException("Registry retained projection bound reached."); bytes -= projected;
                var data = Decode(raw);
                fields.Add(rule.Name, new("REG_TYPE_" + raw.Type, PersistenceValueState.Known, JsonSerializer.Serialize(data)));
                fields.Add(rule.Name + ".NativeBytes", new("REG_TYPE_" + raw.Type, PersistenceValueState.Known, JsonSerializer.Serialize(raw.Bytes)));
                if (rule.Name == "GlobalFlag") _ = Flag(fields, rule.Name); // Validate the supported hexadecimal native form without replacing it.
            }
            if (key.Stamp() != stamp) throw new IOException("Registry fields changed during read."); return fields;
        }
        void ValueRows(IRegistryConfigurationKey key, string path, Rule[] rules)
        {
            var fields = Fields(key, rules);
            foreach (var rule in rules.Where(rule => fields.ContainsKey(rule.Name)))
                Add(rule.Name, path, fields.Where(pair => pair.Key == rule.Name || pair.Key == rule.Name + ".NativeBytes").ToDictionary(), Text(fields, rule.Name), null);
        }
        void Add(string name, string path, Dictionary<string, PersistenceNativeValue> fields, string? command = null, bool? enabled = null, string? qualification = null)
        {
            if (--entries < 0) throw new InvalidDataException("Registry observed-registration bound reached.");
            var projected = checked((name.Length + path.Length + sid.Length + (qualification?.Length ?? 100)) * 2 + 512 +
                fields.Sum(pair => checked((pair.Key.Length + pair.Value.NativeType.Length + pair.Value.Json.Length) * 2 + 128)));
            if (projected > bytes) throw new InvalidDataException("Registry per-registration retained projection bound reached."); bytes -= projected;
            fields["Effectiveness"] = new("OBSERVATION_QUALIFICATION", PersistenceValueState.Known, JsonSerializer.Serialize(qualification ?? "Configuration presence observed; effective activation/execution not observed."));
            fields["EffectiveActivation"] = new("OBSERVATION_CONTEXT", PersistenceValueState.Unknown, "null");
            observed.Add(new(name, hive + (sid.Length == 0 ? "" : "\\" + sid) + "\\" + path, fields, command, enabled));
        }
        void Registration(string path, string name, Rule[] rules, string commandName, bool? enabled = null, string? qualification = null,
            Dictionary<string, PersistenceNativeValue>? related = null, bool filterRegistration = false)
        {
            token.ThrowIfCancellationRequested(); using var key = _source.Open(hive, sid, viewName, path) ?? throw new IOException("Enumerated registry registration disappeared.");
            verifiedKeys.Add((hive, sid, viewName, path, key.Stamp()));
            var fields = Fields(key, rules); if (fields.Count == 0) return;
            if (related != null) foreach (var pair in related) fields.Add(pair.Key, pair.Value);
            if (filterRegistration)
            {
                var useFilter = Flag(fields, "Parent.UseFilter");
                enabled = useFilter == 0 ? false : useFilter == 1 && Text(fields, "FilterFullPath") != null && Text(fields, "Debugger") != null ? Text(fields, "Debugger")!.Length != 0 : null;
                qualification = "Recorded IFEO UseFilter governs child matching; configured path/debugger retained. Process path matching and debugger execution not observed.";
            }
            Add(name, path, fields, Text(fields, commandName), enabled, qualification);
        }
        void ReadIfeo()
        {
            var imageFlags = new Dictionary<string, Dictionary<string, PersistenceNativeValue>>(StringComparer.OrdinalIgnoreCase);
            Visit("HKEY_LOCAL_MACHINE", "", "Shared", Ifeo, root =>
            {
                foreach (var image in Children(root))
                {
                    var path = Ifeo + "\\" + image;
                    using var key = _source.Open(hive, "", "Shared", path) ?? throw new IOException("Enumerated image registration disappeared.");
                    verifiedKeys.Add((hive, "", "Shared", path, key.Stamp()));
                    var stamp = key.Stamp(); var fields = Fields(key, IfeoFields); imageFlags.Add(image, fields);
                    var useFilter = Flag(fields, "UseFilter"); var debugger = Text(fields, "Debugger");
                    if (fields.Count != 0) Add(image, path, new(fields, StringComparer.Ordinal), debugger,
                        debugger == null ? null : useFilter == 1 ? false : useFilter == 0 ? debugger.Length != 0 : null,
                        "Recorded IFEO UseFilter=1 selects child filters instead of the root debugger. Configured debugger/flags are evidence; matching and execution not observed.");
                    foreach (var child in Children(key)) Registration(path + "\\" + child, image + "\\" + child, FilterFields, "Debugger", related: fields
                        .Where(pair => pair.Key == "UseFilter" || pair.Key == "UseFilter.NativeBytes").ToDictionary(pair => "Parent." + pair.Key, pair => pair.Value), filterRegistration: true);
                    if (key.Stamp() != stamp) throw new IOException("Image filter registration changed during read.");
                }
            });
            var ifeoComplete = partitions[^1].Status == PersistenceCollectionStatus.Complete;
            foreach (var view in views) Visit("HKEY_LOCAL_MACHINE", "", view, SilentExit, root =>
            {
                var defaults = Fields(root, SilentDefaults);
                if (defaults.Count != 0) Add("Root defaults", SilentExit, new(defaults, StringComparer.Ordinal), Text(defaults, "MonitorProcess"), null);
                foreach (var image in Children(root))
                {
                    var path = SilentExit + "\\" + image;
                    using var key = _source.Open(hive, "", view, path) ?? throw new IOException("Enumerated silent-exit registration disappeared.");
                    verifiedKeys.Add((hive, "", view, path, key.Stamp()));
                    var fields = Fields(key, SilentFields); if (fields.Count == 0) continue;
                    var reporting = Flag(fields, "ReportingMode");
                    imageFlags.TryGetValue(image, out var ifeoFields);
                    uint? global = ifeoComplete ? ifeoFields == null ? 0u : Flag(ifeoFields, "GlobalFlag") ?? 0u : null;
                    if (ifeoFields != null) foreach (var pair in ifeoFields.Where(pair => pair.Key is "GlobalFlag" or "GlobalFlag.NativeBytes")) fields.Add("IFEO." + pair.Key, pair.Value);
                    foreach (var pair in defaults) fields.Add("RootDefault." + pair.Key, pair.Value);
                    Add(image, path, fields, Text(fields, "MonitorProcess") ?? Text(defaults, "MonitorProcess"),
                        global is not uint flag ? null : (flag & 0x200) == 0 ? false : reporting is uint mode ? (mode & 1) != 0 : null,
                        "Configured silent-exit monitor prerequisites only; no observed process launch.");
                }
            });
        }
    }
    internal static object Decode(PersistenceRegistryRawField raw)
    {
        if (raw.Type == 4) return raw.Bytes.Length == 4 ? BitConverter.ToUInt32(raw.Bytes) : throw new InvalidDataException("Malformed native DWORD.");
        if (raw.Type is not (1 or 2 or 7) || (raw.Bytes.Length & 1) != 0) throw new InvalidDataException("Unsupported or odd-length registry text.");
        string text;
        try { text = new UnicodeEncoding(false, false, true).GetString(raw.Bytes); }
        catch (DecoderFallbackException error) { throw new InvalidDataException("Malformed native registry Unicode.", error); }
        if (raw.Type == 7)
        {
            if (text == "\0") return Array.Empty<string>();
            if (!text.EndsWith("\0\0", StringComparison.Ordinal)) throw new InvalidDataException("Native MULTI_SZ terminator missing.");
            var body = text[..^2];
            if (body.Length == 0) return Array.Empty<string>();
            if (body.StartsWith('\0') || body.Contains("\0\0", StringComparison.Ordinal) || body.EndsWith('\0')) throw new InvalidDataException("Native MULTI_SZ contains data beyond an early terminator.");
            return body.Split('\0');
        }
        if (!text.EndsWith('\0') || text[..^1].Contains('\0')) throw new InvalidDataException("Native string termination malformed.");
        return text[..^1];
    }
    private static string? Text(IReadOnlyDictionary<string, PersistenceNativeValue> fields, string name)
        => fields.TryGetValue(name, out var value) && value.NativeType is "REG_TYPE_1" or "REG_TYPE_2" ? JsonSerializer.Deserialize<string>(value.Json) : null;
    private static uint? Flag(IReadOnlyDictionary<string, PersistenceNativeValue> fields, string name)
    {
        if (!fields.TryGetValue(name, out var value)) return null;
        if (value.NativeType == "REG_TYPE_4") return JsonSerializer.Deserialize<uint>(value.Json);
        var text = JsonSerializer.Deserialize<string>(value.Json) ?? throw new InvalidDataException("GlobalFlag native string missing.");
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        return uint.TryParse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var parsed) ? parsed : throw new InvalidDataException("Malformed hexadecimal GlobalFlag.");
    }
}
