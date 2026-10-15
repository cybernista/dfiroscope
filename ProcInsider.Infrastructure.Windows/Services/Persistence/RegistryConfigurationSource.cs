using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ProcInsider.Services.Persistence;

internal interface IRegistryConfigurationKey : IDisposable
{
    PersistenceRegistryMetadata Stamp();
    IReadOnlyList<string> Children(int limit, CancellationToken token);
    PersistenceRegistryRawField? Field(string name, ref int budget);
}
internal interface IRegistryConfigurationSource : IDisposable
{
    bool Is64Bit { get; }
    IRegistryConfigurationKey? Open(string hive, string sid, string view, string path);
    IReadOnlyList<string> LoadedSids(CancellationToken token);
    void VerifyUserAliases(CancellationToken token);
}

/// <summary>Only readonly component opens. Registry links never grant access to arbitrary targets.</summary>
internal sealed class RegistryConfigurationSource : IRegistryConfigurationSource
{
    private PersistenceRegistryMetadata? _systemAliasStamp;
    private byte[]? _systemAliasBytes;
    private RegistryKey? _heldSystemAlias;
    public bool Is64Bit => Environment.Is64BitOperatingSystem;
    public IRegistryConfigurationKey? Open(string hive, string sid, string view, string path)
    {
        if (hive is not ("HKEY_LOCAL_MACHINE" or "HKEY_USERS") || view is not ("Shared" or "32" or "64")) throw new InvalidDataException("Unknown registry declaration.");
        var nativeView = view == "32" ? RegistryView.Registry32 : Is64Bit ? RegistryView.Registry64 : RegistryView.Registry32;
        using var root = RegistryKey.OpenBaseKey(hive == "HKEY_LOCAL_MACHINE" ? RegistryHive.LocalMachine : RegistryHive.Users, nativeView);
        _ = PersistenceRegistryNativeReader.Metadata(root);
        var physicalSid = sid;
        if (hive == "HKEY_USERS" && sid == "S-1-5-18")
        {
            var alias = ReadSystemAlias(root, nativeView);
            if (_systemAliasStamp != null && (_systemAliasStamp != alias.Stamp || !_systemAliasBytes!.SequenceEqual(alias.Bytes)))
                throw new IOException("LocalSystem hive alias changed during the family read.");
            _systemAliasStamp = alias.Stamp; _systemAliasBytes = alias.Bytes;
            physicalSid = ".DEFAULT";
        }
        var components = (physicalSid.Length == 0 ? path : physicalSid + "\\" + path).Split('\\');
        RegistryKey? current = null;
        try
        {
            foreach (var component in components)
            {
                ValidateComponent(component);
                var error = RegOpenKeyEx((current ?? root).Handle, component, 8 /* REG_OPTION_OPEN_LINK */, Access(nativeView, Is64Bit), out var handle);
                if (error == 2)
                {
                    handle.Dispose();
                    if (sid.Length != 0 && current == null) throw new IOException("Loaded user hive disappeared.");
                    return null;
                }
                if (error != 0) { handle.Dispose(); throw new IOException("Declared registry component inaccessible."); }
                var next = RegistryKey.FromHandle(handle, nativeView);
                try
                {
                    var size = 0u;
                    var probe = RegQueryValueEx(next.Handle, "SymbolicLinkValue", IntPtr.Zero, out var type, IntPtr.Zero, ref size);
                    if (probe is not (0 or 2 or 234) || probe != 2 && type == 6)
                        throw new IOException("Registry link or unavailable link metadata rejected.");
                }
                catch { next.Dispose(); throw; }
                current?.Dispose(); current = next;
            }
            var result = new Key(current ?? throw new InvalidDataException("Empty registry declaration."));
            current = null; return result;
        }
        finally { current?.Dispose(); }
    }
    public IReadOnlyList<string> LoadedSids(CancellationToken token)
    {
        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, Is64Bit ? RegistryView.Registry64 : RegistryView.Registry32);
        return PersistenceRegistryNativeReader.Children(users, 1040, token)
            .Where(name => Regex.IsMatch(name, @"^S-\d+(?:-\d+)+$", RegexOptions.CultureInvariant)).Take(513).ToArray();
    }
    internal static int Access(RegistryView view, bool is64Bit) => 0x20019 | (is64Bit ? view == RegistryView.Registry64 ? 0x100 : 0x200 : 0);
    internal static void ValidateComponent(string component)
    {
        if (component.Length == 0 || component.Length > 256 || component is "." or ".." || component.Contains('/') || component.Contains('\0'))
            throw new InvalidDataException("Invalid declared registry component.");
        PersistenceRegistryNativeReader.ValidateText(component);
    }
    public void VerifyUserAliases(CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); if (_systemAliasStamp == null) return;
        var view = Is64Bit ? RegistryView.Registry64 : RegistryView.Registry32;
        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
        var held = ReadAliasData(_heldSystemAlias ?? throw new IOException("Original LocalSystem alias handle unavailable."));
        if (held.Stamp != _systemAliasStamp || !held.Bytes.SequenceEqual(_systemAliasBytes!)) throw new IOException("Original LocalSystem alias changed before completion.");
        var alias = ReadSystemAlias(users, view);
        if (alias.Stamp != _systemAliasStamp || !alias.Bytes.SequenceEqual(_systemAliasBytes!)) throw new IOException("LocalSystem hive alias changed before family completion.");
    }
    private (PersistenceRegistryMetadata Stamp, byte[] Bytes) ReadSystemAlias(RegistryKey users, RegistryView view)
    {
        var error = RegOpenKeyEx(users.Handle, "S-1-5-18", 8, Access(view, Is64Bit), out var handle);
        if (error != 0) { handle.Dispose(); throw new IOException("Declared LocalSystem alias inaccessible."); }
        RegistryKey? alias = RegistryKey.FromHandle(handle, view);
        try
        {
            var result = ReadAliasData(alias);
            if (_heldSystemAlias == null) { _heldSystemAlias = alias; alias = null; }
            return result;
        }
        finally { alias?.Dispose(); }
    }
    private static (PersistenceRegistryMetadata Stamp, byte[] Bytes) ReadAliasData(RegistryKey alias)
    {
        var stamp = PersistenceRegistryNativeReader.Metadata(alias); var budget = 64;
        var field = PersistenceRegistryNativeReader.RawField(alias, "SymbolicLinkValue", ref budget) ?? throw new IOException("Declared LocalSystem alias missing.");
        ValidateSystemAlias(field);
        if (PersistenceRegistryNativeReader.Metadata(alias) != stamp) throw new IOException("Declared LocalSystem alias changed during read.");
        return (stamp, field.Bytes);
    }
    public void Dispose()
    {
        _heldSystemAlias?.Dispose(); _heldSystemAlias = null; _systemAliasStamp = null; _systemAliasBytes = null;
    }
    internal static void ValidateSystemAlias(PersistenceRegistryRawField field)
    {
        if (field.Type != 6 || field.Bytes.Length != 46) throw new InvalidDataException("Unsupported LocalSystem hive alias native form.");
        string target;
        try { target = new UnicodeEncoding(false, false, true).GetString(field.Bytes); }
        catch (DecoderFallbackException error) { throw new InvalidDataException("Malformed LocalSystem alias Unicode.", error); }
        if (!target.Equals(@"\REGISTRY\USER\.DEFAULT", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Unexpected LocalSystem hive alias target.");
    }
    private sealed class Key(RegistryKey key) : IRegistryConfigurationKey
    {
        public PersistenceRegistryMetadata Stamp() => PersistenceRegistryNativeReader.Metadata(key);
        public IReadOnlyList<string> Children(int limit, CancellationToken token) => PersistenceRegistryNativeReader.Children(key, limit, token);
        public PersistenceRegistryRawField? Field(string name, ref int budget) => PersistenceRegistryNativeReader.RawField(key, name, ref budget);
        public void Dispose() => key.Dispose();
    }
    [DllImport("advapi32.dll", EntryPoint = "RegOpenKeyExW", CharSet = CharSet.Unicode)]
    private static extern int RegOpenKeyEx(SafeRegistryHandle key, string name, uint options, int access, out SafeRegistryHandle result);
    [DllImport("advapi32.dll", EntryPoint = "RegQueryValueExW", CharSet = CharSet.Unicode)]
    private static extern int RegQueryValueEx(SafeRegistryHandle key, string name, IntPtr reserved, out uint type, IntPtr bytes, ref uint size);
}
