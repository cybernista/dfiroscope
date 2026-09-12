using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

/// <summary>Handle-based SACL-only access. The privilege is scoped to an impersonation token.</summary>
internal sealed class WindowsObjectAuditRuntime : IObjectAuditRuntime
{
    private const uint SaclInformation = 8;
    private readonly Func<ObjectAuditTarget, bool>? _registryFixtureValidator;

    public WindowsObjectAuditRuntime() { }
    public bool RootConfigurationOnly => true;

    internal WindowsObjectAuditRuntime(Func<ObjectAuditTarget, bool> registryFixtureValidator)
    {
        _registryFixtureValidator = registryFixtureValidator ?? throw new ArgumentNullException(nameof(registryFixtureValidator));
    }
    private const uint SecurityAccess = 0x01000000;
    private const uint ReadControl = 0x00020000;

    public T WithPrivilege<T>(Func<T> action)
    {
        using var identity = WindowsIdentity.GetCurrent();
        return WindowsIdentity.RunImpersonated(identity.AccessToken, () =>
        {
            if (!Native.OpenThreadToken(Native.GetCurrentThread(), 0x28, true, out var token)) ThrowLastError();
            using (token)
            {
                if (!Native.LookupPrivilegeValue(null, "SeSecurityPrivilege", out var luid)) ThrowLastError();
                var requested = new TokenPrivileges { Count = 1, Luid = luid, Attributes = 2 };
                if (!Native.AdjustTokenPrivileges(token, false, ref requested, Marshal.SizeOf<TokenPrivileges>(), out var previous, out _))
                    ThrowLastError();
                if (Marshal.GetLastWin32Error() == 1300)
                    throw new UnauthorizedAccessException("SeSecurityPrivilege is unavailable; object SACLs were not accessed.");
                try { return action(); }
                finally
                {
                    // Only this duplicated impersonation token is adjusted; leaving RunImpersonated
                    // restores the original thread context even if privilege restoration fails.
                    Native.AdjustTokenPrivileges(token, false, ref previous, Marshal.SizeOf<TokenPrivileges>(), out _, out _);
                }
            }
        });
    }

    public ObjectAuditDiscovery Discover(AgentSecurityAuditMonitoringIntent intent)
    {
        var roots = WindowsObjectAuditTargets.Discover(intent);
        var discovered = DiscoverRootConfiguration(roots.Targets);
        return discovered with { Gaps = roots.Gaps.Concat(discovered.Gaps).ToArray(),
            Exclusions = roots.Exclusions.Concat(discovered.Exclusions).ToArray() };
    }

    internal ObjectAuditDiscovery DiscoverRootConfiguration(ObjectAuditTarget[] roots)
    {
        var targets = new List<ObjectAuditTarget>();
        var gaps = new List<string>();
        foreach (var root in roots.Take(AgentObjectAccessAuditingService.MaxTargets))
        {
            try
            {
                using var handle = Open(root with { RootConfigurationOnly = true });
                targets.Add(root with { Root = root.Path, RootIdentity = handle.Read().Identity, RootConfigurationOnly = true });
            }
            catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex))
            { gaps.Add($"{root.Path}: root unavailable: {ex.Message}"); }
        }
        if (roots.Length > AgentObjectAccessAuditingService.MaxTargets) gaps.Add("Root inventory exceeds the supported bound.");
        return new(targets.ToArray(), gaps.ToArray());
    }

    public ObjectAuditDiscovery DiscoverLegacy(AgentSecurityAuditMonitoringIntent intent)
    {
        var roots = WindowsObjectAuditTargets.Discover(intent);
        var expanded = DiscoverAvailableTargets(roots.Targets);
        return expanded with { Gaps = roots.Gaps.Concat(expanded.Gaps).ToArray(), Exclusions = roots.Exclusions.Concat(expanded.Exclusions).ToArray() };
    }

    public ObjectAuditDiscovery DiscoverUnderRoots(ObjectAuditTarget[] roots)
        => DiscoverUnderRoots(roots, allowAbsent: false);

    // Recovery scans remain strict. Only discovery for new settings treats absence as
    // an optional target exclusion; unreadable existing objects still block coverage.
    internal ObjectAuditDiscovery DiscoverAvailableTargets(ObjectAuditTarget[] roots)
        => DiscoverUnderRoots(roots, allowAbsent: true);

    internal static bool IsAbsentTarget(Exception error) => error is FileNotFoundException or DirectoryNotFoundException ||
        error is Win32Exception { NativeErrorCode: 2 or 3 };

    private ObjectAuditDiscovery DiscoverUnderRoots(ObjectAuditTarget[] roots, bool allowAbsent)
    {
        var targets = new List<ObjectAuditTarget>();
        var gaps = new List<string>();
        var exclusions = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            if (seen.Count + exclusions.Count >= AgentObjectAccessAuditingService.MaxTargets)
                return new(targets.ToArray(), gaps.Append("Object scan bound reached; remaining descendants are not covered.").ToArray()) { Exclusions = exclusions.ToArray() };
            try
            {
                using var rootHandle = Open(root);
                var boundRoot = root with { Root = root.Path, RootIdentity = rootHandle.Read().Identity };
                var pending = new Stack<(ObjectAuditTarget Target, int Depth)>();
                pending.Push((boundRoot, 0));
                while (pending.TryPop(out var item))
                {
                    if (seen.Count + exclusions.Count >= AgentObjectAccessAuditingService.MaxTargets)
                        return new(targets.ToArray(), gaps.Append("Object scan bound reached; remaining descendants are not covered.").ToArray());
                    if (!seen.Add(item.Target.Path)) continue;
                    try
                    {
                        using var handle = (Handle)Open(item.Target);
                        var state = handle.Read();
                        if (item.Depth > 0 && (new RawSecurityDescriptor(state.Sacl).ControlFlags & ControlFlags.SystemAclProtected) != 0)
                        { gaps.Add($"{item.Target.Path}: protected SACL; subtree not changed."); continue; }
                        targets.Add(item.Target);
                        if (item.Target.Kind == ObjectAuditKind.File || !item.Target.IncludeDescendants) continue;
                        if (item.Depth >= 64) { gaps.Add($"{item.Target.Path}: depth limit reached; descendants not covered."); continue; }
                        foreach (var child in handle.Children(item.Target, allowAbsent ? exclusions : null,
                            AgentObjectAccessAuditingService.MaxTargets - pending.Count - seen.Count - exclusions.Count))
                        {
                            if (pending.Count + seen.Count + exclusions.Count >= AgentObjectAccessAuditingService.MaxTargets)
                                return new(targets.ToArray(), gaps.Append("Object scan bound reached; remaining descendants are not covered.").ToArray());
                            pending.Push((child, item.Depth + 1));
                        }
                    }
                    catch (Exception ex) when (allowAbsent && IsAbsentTarget(ex))
                    { exclusions.Add($"{item.Target.Path}: not present; not created or changed."); }
                    catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex))
                    { gaps.Add($"{item.Target.Path}: {ex.Message}"); }
                }
            }
            catch (Exception ex) when (allowAbsent && IsAbsentTarget(ex))
            { exclusions.Add($"{root.Path}: not present; not created or changed."); }
            catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex)) { gaps.Add($"{root.Path}: {ex.Message}"); }
        }
        return new(targets.ToArray(), gaps.ToArray()) { Exclusions = exclusions.ToArray() };
    }

    public IObjectAuditHandle Open(ObjectAuditTarget target)
    {
        if (target.RootConfigurationOnly && (target.Kind == ObjectAuditKind.File ||
            target.Root.Length > 0 && !target.Path.Equals(target.Root, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Root configuration cannot directly modify descendants.");
        if (target.Kind is ObjectAuditKind.Directory or ObjectAuditKind.File)
        {
            ValidateLocalPath(target.Path);
            WindowsObjectAuditTargets.ValidateDataRoot(string.IsNullOrEmpty(target.Root) ? target.Path : target.Root);
            ValidateRootContainment(target);
            var chain = new List<SafeFileHandle>();
            try
            {
                var paths = new Stack<string>();
                for (var path = target.Path; !string.IsNullOrEmpty(path); path = Path.GetDirectoryName(path)) paths.Push(path);
                var identity = string.Empty;
                while (paths.TryPop(out var path))
                {
                    var leaf = paths.Count == 0;
                    // Pin every ancestor, denying write/delete sharing. A pre-existing writer,
                    // rename or reparse mutation handle makes this object unavailable, not unsafe.
                    // FILE_READ_DATA / FILE_LIST_DIRECTORY makes sharing checks effective;
                    // an attributes-only open would not establish this exclusion.
                    var handle = Native.CreateFile(path, (leaf ? SecurityAccess | ReadControl : 0) | 0x81,
                        target.RootConfigurationOnly ? 3u : 1u, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                    chain.Add(handle);
                    if (handle.IsInvalid) ThrowLastError();
                    if (!Native.GetFileInformationByHandle(handle, out var info)) ThrowLastError();
                    if ((info.Attributes & 0x400) != 0 ||
                        ((info.Attributes & 0x10) != 0) != (!leaf || target.Kind == ObjectAuditKind.Directory) ||
                        (leaf && target.Kind == ObjectAuditKind.File && info.Links != 1))
                        throw new InvalidOperationException("Reparse, hard-linked, or replaced audit objects are unsupported.");
                    var final = new StringBuilder(32768);
                    var length = Native.GetFinalPathNameByHandle(handle, final, final.Capacity, 0);
                    if (length == 0 || length >= final.Capacity) ThrowLastError();
                    if (!string.Equals(final.ToString().Replace(@"\\?\", "").TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Audit target resolved through an unsupported redirect.");
                    identity = FileIdentity(info);
                    if (path.Equals(target.Root, StringComparison.OrdinalIgnoreCase) && target.RootIdentity != identity)
                        throw new InvalidOperationException("Audit root identity changed; target withheld.");
                }
                return new Handle(chain[^1], null, 1, identity, chain.Take(chain.Count - 1).ToArray(),
                    propagate: target.RootConfigurationOnly && target.IncludeDescendants);
            }
            catch { foreach (var handle in chain) handle.Dispose(); throw; }
        }
        if (target.Kind != ObjectAuditKind.RegistryKey) throw new InvalidOperationException("Unknown object-audit kind.");
        var machine = target.Path.StartsWith("HKLM\\", StringComparison.Ordinal);
        if (!machine && !target.Path.StartsWith("HKU\\", StringComparison.Ordinal))
            throw new InvalidOperationException("Object audit registry hive is unsupported.");
        var subkey = target.Path[(machine ? 5 : 4)..];
        ValidateRootContainment(target);
        if (_registryFixtureValidator?.Invoke(target) != true)
            WindowsObjectAuditTargets.ValidateRegistryRoot(string.IsNullOrEmpty(target.Root) ? target.Path : target.Root);
        using var root = RegistryKey.OpenBaseKey(machine ? RegistryHive.LocalMachine : RegistryHive.Users, RegistryView.Registry64);
        var result = Native.RegOpenKeyEx(root.Handle, subkey, 8, SecurityAccess | ReadControl | 0x109, out var registryHandle);
        if (result != 0) { registryHandle?.Dispose(); throw new Win32Exception(result); }
        IObjectAuditHandle? boundRootHandle = null;
        try
        {
            uint size = 0;
            result = Native.RegQueryValueEx(registryHandle, "SymbolicLinkValue", IntPtr.Zero, out var type, IntPtr.Zero, ref size);
            if (result == 0 && type == 6) throw new InvalidOperationException("Registry symbolic links are not audit targets.");
            var actualName = ReadRegistryName(registryHandle);
            var expected = (machine ? @"\REGISTRY\MACHINE\" : @"\REGISTRY\USER\") + subkey;
            if (!string.Equals(actualName, expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Registry target resolved through an unsupported link.");
            if (target.Root.Length > 0 && !target.Path.Equals(target.Root, StringComparison.OrdinalIgnoreCase))
            {
                boundRootHandle = Open(new(ObjectAuditKind.RegistryKey, target.Root));
                if (boundRootHandle.Read().Identity != target.RootIdentity)
                    throw new InvalidOperationException("Registry root changed; descendant auditing withheld.");
            }
            var opened = new Handle(null, registryHandle, 4, actualName,
                rootGuard: boundRootHandle, rootIdentity: target.RootIdentity,
                propagate: target.RootConfigurationOnly && target.IncludeDescendants,
                rootRegistryConfiguration: target.RootConfigurationOnly);
            if (target.Path == target.Root && opened.Read().Identity != target.RootIdentity)
                throw new InvalidOperationException("Registry root changed; object auditing withheld.");
            return opened;
        }
        catch { registryHandle.Dispose(); boundRootHandle?.Dispose(); throw; }
    }

    internal static string ReadRegistryName(SafeRegistryHandle registry)
    {
        var buffer = new byte[32768];
        if (Native.NtQueryKey(registry, 3, buffer, buffer.Length, out _) != 0)
            throw new InvalidOperationException("Registry target identity could not be resolved.");
        var length = BitConverter.ToInt32(buffer, 0);
        if (length < 0 || length > buffer.Length - 4 || (length & 1) != 0)
            throw new InvalidOperationException("Invalid registry target identity.");
        return Encoding.Unicode.GetString(buffer, 4, length);
    }

    private static void ValidateRootContainment(ObjectAuditTarget target)
    {
        if (target.Root.Length == 0) return;
        if (target.RootIdentity.Length == 0 || !(target.Path.Equals(target.Root, StringComparison.OrdinalIgnoreCase) ||
            target.Path.StartsWith(target.Root + "\\", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Object lies outside its bound audit root.");
    }

    private static string FileIdentity(FileInfoNative info) =>
        $"{info.VolumeSerial:X8}:{info.IndexHigh:X8}{info.IndexLow:X8}:{info.Creation.dwHighDateTime:X8}{info.Creation.dwLowDateTime:X8}";

    internal static void ValidateLocalPath(string path, bool allowFile = false)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 4096 || !Path.IsPathFullyQualified(path) ||
            path.StartsWith(@"\\", StringComparison.Ordinal) || path.IndexOf(':', 2) >= 0)
            throw new InvalidOperationException("Object auditing supports fully qualified local paths without device, UNC or stream syntax.");
        var full = Path.GetFullPath(path);
        if (!string.Equals(full.TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Object auditing requires a canonical path.");
        var part = allowFile ? Path.GetDirectoryName(full) : full;
        while (!string.IsNullOrWhiteSpace(part))
        {
            if ((File.GetAttributes(part) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Reparse points in audit/recovery paths are unsupported.");
            part = Path.GetDirectoryName(part);
        }
        if (allowFile)
        {
            try
            {
                if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Recovery journal is a reparse point.");
            }
            catch (FileNotFoundException) { } // Only exact absence is an unused journal, not access denial.
        }
    }

    internal sealed class Handle(SafeFileHandle? file, SafeRegistryHandle? registry, int kind, string identity,
        SafeFileHandle[]? ancestors = null, IObjectAuditHandle? rootGuard = null, string rootIdentity = "", bool propagate = false,
        bool rootRegistryConfiguration = false) : IObjectAuditHandle
    {
        private IntPtr Pointer => file?.DangerousGetHandle() ?? registry!.DangerousGetHandle();

        public bool SupportsRegistryIdentityTransitions => registry != null && !rootRegistryConfiguration;
        public bool IsSameRegistryObject(ObjectAuditSnapshot before, ObjectAuditSnapshot after) => registry != null &&
            before.Identity.StartsWith(identity + "|", StringComparison.OrdinalIgnoreCase) &&
            after.Identity.StartsWith(identity + "|", StringComparison.OrdinalIgnoreCase) &&
            before.Identity.Length == identity.Length + 17 && after.Identity.Length == identity.Length + 17 &&
            ulong.TryParse(before.Identity.AsSpan(identity.Length + 1), System.Globalization.NumberStyles.HexNumber, null, out _) &&
            ulong.TryParse(after.Identity.AsSpan(identity.Length + 1), System.Globalization.NumberStyles.HexNumber, null, out _);

        public ObjectAuditSnapshot Read()
        {
            if (rootGuard != null && rootGuard.Read().Identity != rootIdentity)
                throw new InvalidOperationException("Bound registry root changed; SACL access withheld.");
            if (registry != null && !ReadRegistryName(registry).Equals(identity, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Registry object was renamed; SACL access withheld.");
            if (file != null)
            {
                if (!Native.GetFileInformationByHandle(file, out var info)) ThrowLastError();
                if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) == 0 && info.Links != 1) || FileIdentity(info) != identity)
                    throw new InvalidOperationException("Pinned file identity/link state changed; SACL access withheld.");
            }
            var raw = ReadSaclDescriptor();
            // New root configuration targets the selected native key path, including a
            // recreated key. Legacy per-object recovery retains last-write continuity.
            var objectIdentity = rootRegistryConfiguration ? identity.ToUpperInvariant() : identity;
            if (registry != null && !rootRegistryConfiguration)
            {
                var result = Native.RegQueryInfoKey(registry, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var written);
                if (result != 0) throw new Win32Exception(result);
                objectIdentity += $"|{written:X16}";
            }
            return new(objectIdentity, AgentObjectAccessAuditingService.NormalizeNativeSacl(raw));
        }

        private RawSecurityDescriptor ReadSaclDescriptor()
        {
            if (registry != null)
            {
                // GetSecurityInfo projects inherited ACE flags for legacy registry descriptors.
                // Saved settings and protected originals must describe the stored SACL instead.
                _ = Native.NtQuerySecurityObject(Pointer, SaclInformation, null, 0, out var length);
                if (length <= 0 || length > 131072) throw new InvalidOperationException("Registry SACL exceeds its observation bound.");
                var bytes = new byte[length];
                var status = Native.NtQuerySecurityObject(Pointer, SaclInformation, bytes, bytes.Length, out _);
                if (status < 0) throw new Win32Exception((int)Native.RtlNtStatusToDosError(status));
                return new RawSecurityDescriptor(bytes, 0);
            }
            var result = Native.GetSecurityInfo(Pointer, kind, SaclInformation, out _, out _, out _, out _, out var descriptor);
            if (result != 0) throw new Win32Exception((int)result);
            try
            {
                var bytes = new byte[Native.GetSecurityDescriptorLength(descriptor)];
                Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                return new RawSecurityDescriptor(bytes, 0);
            }
            finally { Native.LocalFree(descriptor); }
        }

        public void WriteSacl(string sacl)
        {
            _ = Read();
            var descriptor = new RawSecurityDescriptor(sacl);
            if (propagate)
            {
                byte[]? acl = null;
                if (descriptor.SystemAcl != null)
                {
                    acl = new byte[descriptor.SystemAcl.BinaryLength];
                    descriptor.SystemAcl.GetBinaryForm(acl, 0);
                }
                var result = Native.SetSecurityInfo(Pointer, kind, SaclInformation, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, acl);
                if (result != 0) throw new Win32Exception((int)result);
                return;
            }
            var bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            // Unlike SetSecurityInfo, this handle-bound native call does not walk a subtree.
            // Every child mutation has its own preflight, journal entry and verification.
            var status = Native.NtSetSecurityObject(Pointer, SaclInformation, bytes);
            if (status < 0) throw new Win32Exception((int)Native.RtlNtStatusToDosError(status));
        }

        internal IEnumerable<ObjectAuditTarget> Children(ObjectAuditTarget target, List<string>? absentTargets = null,
            int remainingTargetBudget = AgentObjectAccessAuditingService.MaxTargets)
        {
            if (registry != null)
            {
                for (uint index = 0; ; index++)
                {
                    var name = new StringBuilder(256);
                    uint length = 256;
                    var result = Native.RegEnumKeyEx(registry, index, name, ref length, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    if (result == 259) yield break;
                    if (result != 0) throw new Win32Exception(result);
                    yield return new(ObjectAuditKind.RegistryKey, target.Path + "\\" + name)
                    { Root = target.Root, RootIdentity = target.RootIdentity };
                }
            }
            else
                foreach (var path in BoundedChildPaths(Directory.EnumerateFileSystemEntries(target.Path), remainingTargetBudget))
                {
                    FileAttributes attributes;
                    try { attributes = File.GetAttributes(path); }
                    catch (Exception ex) when (absentTargets != null && IsAbsentTarget(ex))
                    { absentTargets.Add($"{path}: not present; not created or changed."); continue; }
                    yield return new((attributes & FileAttributes.Directory) != 0 ? ObjectAuditKind.Directory : ObjectAuditKind.File, path)
                    { Root = target.Root, RootIdentity = target.RootIdentity };
                }
        }

        public void Dispose()
        {
            file?.Dispose(); registry?.Dispose(); rootGuard?.Dispose();
            foreach (var handle in ancestors ?? []) handle.Dispose();
        }
    }

    internal static IEnumerable<string> BoundedChildPaths(IEnumerable<string> paths, int remainingTargetBudget)
    {
        foreach (var path in paths)
        {
            if (remainingTargetBudget-- <= 0)
                throw new InvalidOperationException("Object scan bound reached; remaining descendants are not covered.");
            yield return path;
        }
    }

    private static void ThrowLastError() => throw new Win32Exception(Marshal.GetLastWin32Error());

    [StructLayout(LayoutKind.Sequential)] private struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] private struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfoNative
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    private static class Native
    {
        [DllImport("advapi32.dll")]
        internal static extern uint SetSecurityInfo(IntPtr handle, int type, uint information, IntPtr owner,
            IntPtr group, IntPtr dacl, byte[]? sacl);
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentThread();
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, bool disableAll, ref TokenPrivileges state,
            int bufferLength, out TokenPrivileges previous, out int returnLength);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInfoNative info);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, int length, uint flags);
        [DllImport("advapi32.dll")]
        internal static extern uint GetSecurityInfo(IntPtr handle, int kind, uint information,
            out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("ntdll.dll")]
        internal static extern int NtSetSecurityObject(IntPtr handle, uint information, byte[] descriptor);
        [DllImport("ntdll.dll")]
        internal static extern int NtQuerySecurityObject(IntPtr handle, uint information, byte[]? descriptor, int length, out int required);
        [DllImport("ntdll.dll")]
        internal static extern uint RtlNtStatusToDosError(int status);
        [DllImport("advapi32.dll")] internal static extern int GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int RegOpenKeyEx(SafeRegistryHandle key, string name, uint options, uint access, out SafeRegistryHandle opened);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int RegQueryValueEx(SafeRegistryHandle key, string name, IntPtr reserved, out uint type, IntPtr data, ref uint bytes);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int RegEnumKeyEx(SafeRegistryHandle key, uint index, StringBuilder name, ref uint length,
            IntPtr reserved, IntPtr @class, IntPtr classLength, IntPtr written);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int RegQueryInfoKey(SafeRegistryHandle key, IntPtr @class, IntPtr classLength, IntPtr reserved,
            IntPtr subkeys, IntPtr maxSubkey, IntPtr maxClass, IntPtr values, IntPtr maxValueName, IntPtr maxValue,
            IntPtr securitySize, out long lastWrite);
        [DllImport("ntdll.dll")]
        internal static extern int NtQueryKey(SafeRegistryHandle key, int informationClass, byte[] data, int length, out int resultLength);
    }
}
