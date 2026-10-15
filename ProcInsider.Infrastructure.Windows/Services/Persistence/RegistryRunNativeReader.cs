using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

internal sealed record RegistryValueNativeMetadata(uint Count, long LastWriteTime);
internal sealed record RegistryValueNativeRead(int Error, string Name, uint Type, uint RequiredBytes);
internal interface IRegistryValueNativeSource
{
    RegistryValueNativeMetadata Metadata();
    RegistryValueNativeRead Read(uint index, byte[]? buffer);
}

internal sealed class RegistryRunNativeReader : IRegistryRunNativeReader
{
    internal const int MaxValueBytes = 1024 * 1024;
    private static readonly string[] Keys = [@"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"];
    public IReadOnlyList<RegistryRunNativePartition> Read(CancellationToken token)
    {
        var results = new List<RegistryRunNativePartition>();
        var remainingValues = 20000;
        var remainingBytes = 32 * 1024 * 1024;
        foreach (var view in Environment.Is64BitOperatingSystem ? new[] { RegistryView.Registry32, RegistryView.Registry64 } : new[] { RegistryView.Registry32 })
        {
            foreach (var key in Keys) Add(RegistryHive.LocalMachine, "", view, key);
            try
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
                var before = QueryInfo(users.Handle);
                if (before.SubKeys > 512) throw new InvalidDataException("Loaded-user hive bound reached.");
                var sids = new List<string>();
                for (uint index = 0; index < before.SubKeys; index++)
                {
                    token.ThrowIfCancellationRequested();
                    var name = new char[256]; uint length = 256;
                    if (RegEnumKeyEx(users.Handle, index, name, ref length, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out _) != 0)
                        throw new IOException("Loaded-user hive enumeration changed or is unavailable.");
                    var sid = new string(name, 0, (int)length);
                    if (Regex.IsMatch(sid, @"^S-\d+(?:-\d+)+$", RegexOptions.CultureInvariant)) sids.Add(sid);
                }
                if (QueryInfo(users.Handle) != before) throw new IOException("Loaded-user hives changed during enumeration.");
                foreach (var sid in sids) foreach (var key in Keys) Add(RegistryHive.Users, sid, view, key);
            }
            catch (Exception ex) when (Unavailable(ex))
            {
                results.Add(new("HKEY_USERS", "", ViewName(view), "LoadedUserHives", PersistenceCollectionStatus.Failed, [], "Loaded-user hive enumeration unavailable; offline hives are not loaded."));
            }
        }
        return results;
        void Add(RegistryHive hive, string sid, RegistryView view, string path)
        {
            var values = new List<RegistryRunNativeValue>();
            var hiveName = hive == RegistryHive.LocalMachine ? "HKEY_LOCAL_MACHINE" : "HKEY_USERS";
            var status = PersistenceCollectionStatus.Complete;
            try
            {
                token.ThrowIfCancellationRequested();
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var user = sid.Length == 0 ? null : root.OpenSubKey(sid, writable: false);
                if (sid.Length != 0 && user == null) throw new IOException("Loaded hive disappeared.");
                _ = QueryInfo((user ?? root).Handle); // Prove hive access before declaring a missing key empty.
                using var key = (user ?? root).OpenSubKey(path, writable: false);
                if (key != null) ReadValues(new RegistryValueNativeSource(key.Handle), values, remainingValues, ref remainingBytes, token);
            }
            catch (Exception ex) when (Unavailable(ex)) { status = values.Count > 0 ? PersistenceCollectionStatus.Partial : PersistenceCollectionStatus.Failed; }
            remainingValues -= values.Count;
            results.Add(new(hiveName, sid, ViewName(view), path, status, values, status == PersistenceCollectionStatus.Complete
                ? "Accessible declared key enumerated, possibly empty; unloaded profiles are outside coverage."
                : "Registry scope unavailable, changed during read, or exceeded a bound; no removals inferred."));
        }
    }

    internal static void ReadValues(IRegistryValueNativeSource source, List<RegistryRunNativeValue> values,
        int remainingValues, ref int remainingBytes, CancellationToken token)
    {
        var before = source.Metadata();
        if (before.Count > Math.Min(4096, remainingValues)) throw new InvalidDataException("Registry value count bound reached.");
        for (uint index = 0; index < before.Count; index++)
        {
            token.ThrowIfCancellationRequested();
            var query = source.Read(index, null); // Native byte size is queried BEFORE allocation.
            var nameBytes = checked(query.Name.Length * sizeof(char));
            if (query.Error != 0 || nameBytes > remainingBytes || query.RequiredBytes > Math.Min(MaxValueBytes, remainingBytes - nameBytes))
                throw new InvalidDataException("Registry value unavailable or exceeds byte bound.");
            var bytes = new byte[query.RequiredBytes];
            var read = source.Read(index, bytes);
            if (read.Error != 0 || read.RequiredBytes != bytes.Length || read.Type != query.Type || read.Name != query.Name)
                throw new IOException("Registry value grew, changed type/name, or disappeared; no retry allocation.");
            remainingBytes -= bytes.Length + nameBytes;
            values.Add(new(read.Name, "REG_TYPE_" + read.Type, Decode(read.Type, bytes), bytes));
        }
        if (source.Metadata() != before) throw new IOException("Registry key changed during enumeration.");
    }

    internal static object Decode(uint type, byte[] bytes) => type switch
    {
        1 or 2 when bytes.Length % 2 == 0 => Encoding.Unicode.GetString(bytes).TrimEnd('\0'),
        7 when bytes.Length % 2 == 0 => Encoding.Unicode.GetString(bytes).TrimEnd('\0').Split('\0'),
        4 when bytes.Length == 4 => BitConverter.ToUInt32(bytes),
        5 when bytes.Length == 4 => System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes),
        11 when bytes.Length == 8 => BitConverter.ToUInt64(bytes),
        _ => bytes // Unknown/malformed native data remains exact bytes, never guessed text.
    };
    private static string ViewName(RegistryView view) => view == RegistryView.Registry64 ? "64" : "32";
    private static bool Unavailable(Exception ex) => ex is IOException or UnauthorizedAccessException or SecurityException or InvalidDataException or ArgumentException;

    private sealed class RegistryValueNativeSource(SafeRegistryHandle handle) : IRegistryValueNativeSource
    {
        public RegistryValueNativeMetadata Metadata() { var info = QueryInfo(handle); return new(info.Values, info.LastWriteTime); }
        public RegistryValueNativeRead Read(uint index, byte[]? buffer)
        {
            var name = new char[16384]; uint nameLength = 16384; uint bytes = (uint)(buffer?.Length ?? 0);
            var error = RegEnumValue(handle, index, name, ref nameLength, IntPtr.Zero, out var type, buffer, ref bytes);
            return new(error, nameLength <= name.Length ? new string(name, 0, (int)nameLength) : "", type, bytes);
        }
    }
    private sealed record RegistryKeyInfo(uint SubKeys, uint Values, long LastWriteTime);
    private static RegistryKeyInfo QueryInfo(SafeRegistryHandle handle)
    {
        var error = RegQueryInfoKey(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var subkeys, out _, out _, out var values, out _, out _, out _, out var time);
        if (error != 0) throw new IOException("Registry key metadata unavailable.");
        return new(subkeys, values, time);
    }
    [DllImport("advapi32.dll", EntryPoint = "RegEnumValueW", CharSet = CharSet.Unicode)]
    private static extern int RegEnumValue(SafeRegistryHandle key, uint index, [Out] char[] name, ref uint nameLength, IntPtr reserved, out uint type, [Out] byte[]? data, ref uint dataLength);
    [DllImport("advapi32.dll", EntryPoint = "RegEnumKeyExW", CharSet = CharSet.Unicode)]
    private static extern int RegEnumKeyEx(SafeRegistryHandle key, uint index, [Out] char[] name, ref uint nameLength, IntPtr reserved, IntPtr keyClass, IntPtr classLength, out long lastWriteTime);
    [DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKeyW", CharSet = CharSet.Unicode)]
    private static extern int RegQueryInfoKey(SafeRegistryHandle key, IntPtr keyClass, IntPtr classLength, IntPtr reserved, out uint subkeys, out uint maxSubkeyLength,
        out uint maxClassLength, out uint values, out uint maxValueNameLength, out uint maxValueLength, out uint securityDescriptorBytes, out long lastWriteTime);
}
