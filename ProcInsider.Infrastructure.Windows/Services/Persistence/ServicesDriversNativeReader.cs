using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

internal sealed record ServiceConfiguration(uint Type, uint Start, uint Error, string? BinaryPath, string? Group, string? Account, string? DisplayName, string[]? Dependencies, uint TagId);
internal interface IServiceConfigurationNativeSource { bool Query(IntPtr buffer, uint bytes, out uint required, out int error); }

internal sealed class ServicesDriversNativeReader : IServicesDriversNativeReader
{
    internal const int MaxCandidates = 20000;
    internal const int MaxConfigurationBytes = 8192; // QueryServiceConfig's documented maximum.
    private static readonly string[] RegistryFields = ["Type", "Start", "ErrorControl", "ImagePath", "DisplayName", "ObjectName", "Group", "Tag", "DependOnService", "DependOnGroup", "DelayedAutoStart", "ServiceSidType", "RequiredPrivileges", "FailureActions", "FailureActionsOnNonCrashFailures"];
    public ServicesDriversNativeSnapshot Read(CancellationToken token)
    {
        var entries = new List<ServicePersistenceNativeEntry>(); var issues = new List<ServicePersistenceNativeIssue>();
        var incomplete = false; var failures = new List<string>(); var failedCount = 0; var remaining = 32 * 1024 * 1024;
        try
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = machine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false) ?? throw new IOException("Service registry root unavailable.");
            var topology = PersistenceRegistryNativeReader.Metadata(services);
            var names = PersistenceRegistryNativeReader.Children(services, MaxCandidates, token);
            // SCM enumeration silently omits services lacking QUERY_STATUS. Registry names are the bounded
            // candidate directory; only QUERY_CONFIG is requested, so omission cannot become a removal.
            using var manager = OpenSCManager(null, null, 1);
            if (manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            foreach (var name in names)
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using var key = services.OpenSubKey(name, writable: false) ?? throw new IOException("Service configuration disappeared.");
                    var before = PersistenceRegistryNativeReader.Metadata(key);
                    using var service = OpenService(manager, name, 1);
                    ConfigurationSource? source = null;
                    ServiceConfiguration config;
                    if (service.IsInvalid)
                    {
                        var error = Marshal.GetLastWin32Error();
                        // Non-service settings keys exist below Services. A typed service key which
                        // denied query stays incomplete; missing SCM objects retain registry configuration.
                        var type = PersistenceRegistryNativeReader.Field(key, "Type", ref remaining);
                        if (error == 1060 && type == null && PersistenceRegistryNativeReader.Metadata(key) == before) continue;
                        if (error != 1060) throw new Win32Exception(error);
                        // Registry-only registrations (for example Fs_Rec) are configuration
                        // evidence even when SCM has no installed-service object for them.
                        config = ReadRegistryConfiguration(key, ref remaining);
                    }
                    else
                    {
                        source = new ConfigurationSource(service);
                        config = ReadConfiguration(source, ref remaining);
                    }
                    var native = new Dictionary<string, PersistenceNativeValue>(StringComparer.Ordinal);
                    foreach (var field in RegistryFields)
                    {
                        var value = PersistenceRegistryNativeReader.Field(key, field, ref remaining, field is "DependOnService" or "DependOnGroup" or "RequiredPrivileges");
                        if (value != null) native["Registry." + field] = value;
                    }
                    using var parameters = key.OpenSubKey("Parameters", writable: false);
                    var parameterStamp = parameters == null ? null : PersistenceRegistryNativeReader.Metadata(parameters);
                    if (parameters != null)
                    {
                        foreach (var field in new[] { "ServiceDll", "ServiceMain", "ServiceDllUnloadOnStop" })
                        {
                            var value = PersistenceRegistryNativeReader.Field(parameters, field, ref remaining);
                            if (value != null) native["Parameters." + field] = value;
                        }
                        if (PersistenceRegistryNativeReader.Metadata(parameters) != parameterStamp) throw new IOException("Service Parameters changed during read.");
                    }
                    using var triggers = key.OpenSubKey("TriggerInfo", writable: false);
                    var triggerStamp = triggers == null ? null : PersistenceRegistryNativeReader.Metadata(triggers);
                    var triggerChildren = new Dictionary<string, PersistenceRegistryMetadata>(StringComparer.Ordinal);
                    if (triggers != null)
                    {
                        ReadTriggerValues(triggers, "TriggerInfo", native, ref remaining, token);
                        foreach (var triggerName in PersistenceRegistryNativeReader.Children(triggers, 64, token))
                        {
                            using var trigger = triggers.OpenSubKey(triggerName, writable: false) ?? throw new IOException("Service trigger disappeared.");
                            var stamp = PersistenceRegistryNativeReader.Metadata(trigger);
                            if (stamp.SubKeys != 0) throw new IOException("Unsupported nested service trigger configuration; family incomplete.");
                            ReadTriggerValues(trigger, "TriggerInfo." + triggerName, native, ref remaining, token);
                            if (PersistenceRegistryNativeReader.Metadata(trigger) != stamp) throw new IOException("Service trigger changed during read.");
                            triggerChildren.Add(triggerName, stamp);
                        }
                    }
                    var check = source == null ? ReadRegistryConfiguration(key, ref remaining) : ReadConfiguration(source, ref remaining);
                    foreach (var (nameOfTrigger, stamp) in triggerChildren)
                    {
                        using var trigger = triggers!.OpenSubKey(nameOfTrigger, writable: false) ?? throw new IOException("Service trigger disappeared after read.");
                        if (PersistenceRegistryNativeReader.Metadata(trigger) != stamp) throw new IOException("Service trigger changed after read.");
                    }
                    if (PersistenceRegistryNativeReader.Metadata(key) != before || parameters != null && PersistenceRegistryNativeReader.Metadata(parameters) != parameterStamp || triggers != null && PersistenceRegistryNativeReader.Metadata(triggers) != triggerStamp || !Same(config, check)) throw new IOException("Service configuration changed during observation.");
                    var image = native.TryGetValue("Registry.ImagePath", out var rawImage) ? PersistenceRegistryNativeReader.Text(rawImage) : config.BinaryPath;
                    if (source != null)
                    {
                        native["LoadOrderGroup"] = new("SCM_STRING", PersistenceValueState.Known, JsonSerializer.Serialize(config.Group));
                        native["SCM.TagId"] = new("SCM_DWORD", PersistenceValueState.Known, JsonSerializer.Serialize(config.TagId));
                    }
                    entries.Add(new(name, config.Type, config.Start, config.Error, config.DisplayName, image, config.Account, config.Dependencies, native));
                }
                catch (Exception ex) when (ExpectedFailure(ex))
                {
                    incomplete = true; failedCount++;
                    if (failures.Count < 3) failures.Add(name + ": " + ex.Message);
                    var issue = ReadIssue(services, name, ex.Message, ref remaining);
                    if (issue != null) issues.Add(issue);
                }
                if (remaining <= 0) { incomplete = true; break; }
            }
            if (PersistenceRegistryNativeReader.Metadata(services) != topology) incomplete = true;
        }
        catch (Exception ex) when (ExpectedFailure(ex)) { incomplete = true; if (failures.Count < 3) failures.Add(ex.Message); }
        token.ThrowIfCancellationRequested();
        var diagnostic = incomplete
            ? $"Service/driver observation incomplete ({failedCount} candidate failures); observed entries are unconfirmed and no removals inferred. " + string.Join("; ", failures)
            : "Local service/driver configurations read; raw paths remain uninterpreted and no service is started or changed.";
        return new(incomplete ? entries.Count + issues.Count == 0 ? PersistenceCollectionStatus.Failed : PersistenceCollectionStatus.Partial : PersistenceCollectionStatus.Complete,
            entries, diagnostic.Length > 2048 ? diagnostic[..2048] : diagnostic, issues);
    }
    private static ServicePersistenceNativeIssue? ReadIssue(RegistryKey services, string name, string diagnostic, ref int remaining)
    {
        if (remaining <= 0) return null;
        try
        {
            using var key = services.OpenSubKey(name, writable: false);
            if (key == null) return null;
            var before = PersistenceRegistryNativeReader.Metadata(key);
            var rawType = PersistenceRegistryNativeReader.Field(key, "Type", ref remaining);
            if (rawType?.NativeType != "REG_TYPE_4" || rawType.State != PersistenceValueState.Known) return null;
            using var typeJson = JsonDocument.Parse(rawType.Json);
            if (!typeJson.RootElement.TryGetUInt32(out var type) || !ServicesDriversCollector.TryCategory(type, out var category)) return null;
            var native = new Dictionary<string, PersistenceNativeValue>(StringComparer.Ordinal) { ["Registry.Type"] = rawType };
            foreach (var field in RegistryFields.Where(field => field != "Type"))
            {
                if (remaining <= 0) break;
                try
                {
                    var value = PersistenceRegistryNativeReader.Field(key, field, ref remaining, field is "DependOnService" or "DependOnGroup" or "RequiredPrivileges");
                    RetainIssueField(native, field, value);
                }
                catch (Exception ex) when (ExpectedFailure(ex))
                { native["Registry." + field] = new("REGISTRY_UNAVAILABLE", PersistenceValueState.Unknown, "null"); }
            }
            if (PersistenceRegistryNativeReader.Metadata(key) != before) return null;
            return new(name, category, native, diagnostic.Length > 512 ? diagnostic[..512] : diagnostic);
        }
        catch (Exception ex) when (ExpectedFailure(ex) || ex is JsonException) { return null; }
    }
    internal static void RetainIssueField(Dictionary<string, PersistenceNativeValue> native,
        string field, PersistenceNativeValue? value)
    {
        if (value != null) native["Registry." + field] = value;
        else if (field is "Start" or "ErrorControl")
            native["Registry." + field] = new("REGISTRY_ABSENT", PersistenceValueState.Known, "null");
        // An absent optional registry value is a known absence, distinct from a
        // failed read. Keep it absent rather than fabricating an Unknown value.
    }
    private static ServiceConfiguration ReadRegistryConfiguration(RegistryKey key, ref int remaining)
    {
        var fields = new Dictionary<string, PersistenceNativeValue>(StringComparer.Ordinal);
        foreach (var field in RegistryFields)
        {
            var value = PersistenceRegistryNativeReader.Field(key, field, ref remaining, field is "DependOnService" or "DependOnGroup" or "RequiredPrivileges");
            if (value != null) fields.Add(field, value);
        }
        return RegistryConfiguration(fields);
    }
    internal static ServiceConfiguration RegistryConfiguration(IReadOnlyDictionary<string, PersistenceNativeValue> fields)
    {
        uint Dword(string field, bool optional = false)
        {
            if (!fields.TryGetValue(field, out var value) && optional) return 0;
            if (value == null || value.NativeType != "REG_TYPE_4" || value.State != PersistenceValueState.Known)
                throw new InvalidDataException("Registry-only service DWORD unavailable: " + field);
            using var json = JsonDocument.Parse(value.Json);
            if (json.RootElement.ValueKind != JsonValueKind.Number || !json.RootElement.TryGetUInt32(out var number)) throw new InvalidDataException("Registry-only service DWORD malformed: " + field);
            return number;
        }
        string? Text(string field) => fields.TryGetValue(field, out var value) ? PersistenceRegistryNativeReader.Text(value) : null;
        string[]? dependencies = null;
        if (fields.TryGetValue("DependOnService", out var nativeDependencies))
        {
            if (nativeDependencies.NativeType != "REG_TYPE_7" || nativeDependencies.State != PersistenceValueState.Known)
                throw new InvalidDataException("Registry-only service dependencies unavailable.");
            dependencies = JsonSerializer.Deserialize<string[]>(nativeDependencies.Json) ?? throw new InvalidDataException("Registry-only service dependencies malformed.");
        }
        return new(Dword("Type"), Dword("Start"), Dword("ErrorControl"), Text("ImagePath"), Text("Group"), Text("ObjectName"), Text("DisplayName"), dependencies, Dword("Tag", optional: true));
    }
    internal static ServiceConfiguration ReadConfiguration(IServiceConfigurationNativeSource source, ref int remaining)
    {
        var success = source.Query(IntPtr.Zero, 0, out var required, out var error);
        if (success || error != 122 || required < Marshal.SizeOf<NativeConfiguration>() || required > Math.Min(MaxConfigurationBytes, remaining))
            throw new IOException("Service configuration size unavailable or exceeds its allocation bound.");
        var buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            remaining -= (int)required;
            if (!source.Query(buffer, required, out var after, out _) || after > required) throw new IOException("Service configuration grew or became unavailable; no expanding allocation.");
            var value = Marshal.PtrToStructure<NativeConfiguration>(buffer);
            return new(value.Type, value.Start, value.Error, ReadString(value.BinaryPath, buffer, (int)required), ReadString(value.Group, buffer, (int)required),
                ReadString(value.Account, buffer, (int)required), ReadString(value.DisplayName, buffer, (int)required), ReadMultiString(value.Dependencies, buffer, (int)required), value.Tag);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private static void ReadTriggerValues(RegistryKey key, string prefix, Dictionary<string, PersistenceNativeValue> values, ref int remaining, CancellationToken token)
    {
        foreach (var name in PersistenceRegistryNativeReader.ValueNames(key, 128, token))
            AddTriggerValue(values, prefix, name, PersistenceRegistryNativeReader.Field(key, name, ref remaining) ?? throw new IOException("Service trigger value disappeared."));
    }
    internal static void AddTriggerValue(Dictionary<string, PersistenceNativeValue> values, string prefix, string name, PersistenceNativeValue value)
    {
        if (!values.TryAdd(prefix + "." + name, value)) throw new InvalidDataException("Service trigger native fields have a conflicting projected name.");
    }
    private static bool Same(ServiceConfiguration a, ServiceConfiguration b) => a.Type == b.Type && a.Start == b.Start && a.Error == b.Error && a.TagId == b.TagId && a.BinaryPath == b.BinaryPath && a.Group == b.Group && a.Account == b.Account && a.DisplayName == b.DisplayName &&
        (a.Dependencies == null ? b.Dependencies == null : b.Dependencies != null && a.Dependencies.SequenceEqual(b.Dependencies, StringComparer.Ordinal));
    private static string? ReadString(IntPtr pointer, IntPtr buffer, int bytes)
    {
        if (pointer == IntPtr.Zero) return null;
        var offset = pointer.ToInt64() - buffer.ToInt64();
        if (offset < 0 || offset > bytes - 2 || offset % 2 != 0) throw new InvalidDataException("Service configuration pointer outside native buffer.");
        var length = 0;
        while (offset + (length + 1L) * 2 <= bytes)
        {
            if (Marshal.ReadInt16(pointer, length * 2) == 0)
            {
                var value = Marshal.PtrToStringUni(pointer, length)!;
                PersistenceRegistryNativeReader.ValidateText(value); return value;
            }
            length++;
        }
        throw new InvalidDataException("Unterminated service configuration string.");
    }
    private static string[]? ReadMultiString(IntPtr pointer, IntPtr buffer, int bytes)
    {
        if (pointer == IntPtr.Zero) return null;
        var values = new List<string>(); var current = pointer;
        while (true)
        {
            var value = ReadString(current, buffer, bytes)!;
            if (value.Length == 0) return values.ToArray();
            values.Add(value); current += (value.Length + 1) * 2;
        }
    }
    internal static bool ExpectedFailure(Exception ex) => ex is IOException or InvalidDataException or UnauthorizedAccessException or SecurityException or Win32Exception;
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeConfiguration { public uint Type, Start, Error; public IntPtr BinaryPath, Group; public uint Tag; public IntPtr Dependencies, Account, DisplayName; }
    private sealed class ConfigurationSource(ServiceHandle service) : IServiceConfigurationNativeSource
    {
        public bool Query(IntPtr buffer, uint bytes, out uint required, out int error) { var result = QueryServiceConfig(service, buffer, bytes, out required); error = result ? 0 : Marshal.GetLastWin32Error(); return result; }
    }
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig(ServiceHandle service, IntPtr buffer, uint bytes, out uint required);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr handle);
}
