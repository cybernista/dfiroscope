using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

internal sealed record PersistenceRegistryMetadata(uint SubKeys, uint Values, long LastWrite);
internal sealed record PersistenceRegistryField(int Error, uint Type, uint Bytes);
internal sealed record PersistenceRegistryRawField(uint Type, byte[] Bytes);
internal interface IPersistenceRegistryFieldSource { PersistenceRegistryField Query(byte[]? buffer); }

/// <summary>Narrow readonly registry operations. Existing callers retain their original decoding contracts.</summary>
internal static class PersistenceRegistryNativeReader
{
    internal const int MaxFieldBytes = 64 * 1024;
    internal static PersistenceRegistryMetadata Metadata(RegistryKey key)
    {
        var error = RegQueryInfoKey(key.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var children, out _, out _, out var values, out _, out _, out _, out var time);
        if (error != 0) throw new IOException("Persistence registry metadata unavailable.");
        return new(children, values, time);
    }
    internal static string[] Children(RegistryKey key, int limit, CancellationToken token)
    {
        var before = Metadata(key);
        if (before.SubKeys > limit) throw new InvalidDataException("Persistence registry child bound reached.");
        var names = new List<string>();
        for (uint index = 0; index < before.SubKeys; index++)
        {
            token.ThrowIfCancellationRequested();
            var buffer = new char[257]; uint length = (uint)buffer.Length;
            if (RegEnumKeyEx(key.Handle, index, buffer, ref length, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out _) != 0 || length >= buffer.Length)
                throw new IOException("Persistence registry children changed or exceed the native name bound.");
            var name = new string(buffer, 0, (int)length); ValidateText(name); names.Add(name);
        }
        if (Metadata(key) != before) throw new IOException("Persistence registry children changed during read.");
        return names.ToArray();
    }
    internal static PersistenceNativeValue? Field(RegistryKey key, string name, ref int budget, bool unordered = false)
        => Field(new FieldSource(key.Handle, name), ref budget, unordered);
    internal static string[] ValueNames(RegistryKey key, int limit, CancellationToken token)
    {
        var before = Metadata(key);
        if (before.Values > limit) throw new IOException("Persistence registry value-name bound reached.");
        var names = new List<string>();
        for (uint index = 0; index < before.Values; index++)
        {
            token.ThrowIfCancellationRequested(); var buffer = new char[257]; uint length = (uint)buffer.Length;
            if (RegEnumValue(key.Handle, index, buffer, ref length, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) != 0 || length >= buffer.Length)
                throw new IOException("Persistence registry value names changed or exceed bound.");
            var name = new string(buffer, 0, (int)length); ValidateText(name); names.Add(name);
        }
        if (Metadata(key) != before) throw new IOException("Persistence registry values changed during enumeration.");
        return names.ToArray();
    }
    internal static PersistenceNativeValue? Field(IPersistenceRegistryFieldSource source, ref int budget, bool unordered = false)
    {
        var raw = RawField(source, ref budget);
        if (raw == null) return null;
        return new("REG_TYPE_" + raw.Type, PersistenceValueState.Known, JsonSerializer.Serialize(RegistryRunNativeReader.Decode(raw.Type, raw.Bytes)), unordered);
    }
    internal static PersistenceRegistryRawField? RawField(RegistryKey key, string name, ref int budget)
        => RawField(new FieldSource(key.Handle, name), ref budget);
    internal static PersistenceRegistryRawField? RawField(IPersistenceRegistryFieldSource source, ref int budget)
    {
        var query = source.Query(null);
        if (query.Error == 2) return null; // Missing native member remains absent, not unknown or empty.
        if (query.Error != 0 || query.Bytes > Math.Min(MaxFieldBytes, budget)) throw new IOException("Persistence registry field unavailable or exceeds its byte bound.");
        // Charge each admitted allocation, including failed fills or malformed values.
        // Per-entry failure handling must not replenish the family's aggregate allowance.
        budget -= (int)query.Bytes;
        var bytes = new byte[query.Bytes];
        var read = source.Query(bytes);
        if (read.Error != 0 || read.Type != query.Type || read.Bytes != bytes.Length) throw new IOException("Persistence registry field changed during read; no growing allocation.");
        if (read.Type is 1 or 2 or 7)
        {
            if ((bytes.Length & 1) != 0) throw new InvalidDataException("Persistence registry text has an odd UTF-16 byte length.");
            try { _ = new UnicodeEncoding(false, false, true).GetCharCount(bytes); }
            catch (DecoderFallbackException error) { throw new InvalidDataException("Persistence registry text contains invalid UTF-16.", error); }
        }
        return new(read.Type, bytes);
    }
    internal static string Text(PersistenceNativeValue? value)
    {
        if (value == null || value.NativeType is not ("REG_TYPE_1" or "REG_TYPE_2")) throw new InvalidDataException("Persistence path declaration is missing or has an unsupported native type.");
        using var json = JsonDocument.Parse(value.Json);
        return json.RootElement.ValueKind == JsonValueKind.String ? json.RootElement.GetString()! : throw new InvalidDataException("Malformed native path declaration.");
    }
    internal static void ValidateText(string? value)
    {
        if (value == null) return;
        for (var index = 0; index < value.Length; index++)
        {
            if (char.IsHighSurrogate(value[index]) && index + 1 < value.Length && char.IsLowSurrogate(value[index + 1])) { index++; continue; }
            if (char.IsSurrogate(value[index])) throw new InvalidDataException("Persistence native text contains an unpaired UTF-16 surrogate.");
        }
    }
    private sealed class FieldSource(SafeRegistryHandle key, string name) : IPersistenceRegistryFieldSource
    {
        public PersistenceRegistryField Query(byte[]? buffer)
        {
            uint bytes = (uint)(buffer?.Length ?? 0);
            var error = RegQueryValueEx(key, name, IntPtr.Zero, out var type, buffer, ref bytes);
            return new(error, type, bytes);
        }
    }
    [DllImport("advapi32.dll", EntryPoint = "RegQueryValueExW", CharSet = CharSet.Unicode)]
    private static extern int RegQueryValueEx(SafeRegistryHandle key, string name, IntPtr reserved, out uint type, [Out] byte[]? data, ref uint bytes);
    [DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKeyW", CharSet = CharSet.Unicode)]
    private static extern int RegQueryInfoKey(SafeRegistryHandle key, IntPtr name, IntPtr nameLength, IntPtr reserved, out uint subkeys, out uint maxName, out uint maxClass, out uint values, out uint maxValueName, out uint maxValueBytes, out uint security, out long time);
    [DllImport("advapi32.dll", EntryPoint = "RegEnumKeyExW", CharSet = CharSet.Unicode)]
    private static extern int RegEnumKeyEx(SafeRegistryHandle key, uint index, [Out] char[] name, ref uint length, IntPtr reserved, IntPtr keyClass, IntPtr classLength, out long time);
    [DllImport("advapi32.dll", EntryPoint = "RegEnumValueW", CharSet = CharSet.Unicode)]
    private static extern int RegEnumValue(SafeRegistryHandle key, uint index, [Out] char[] name, ref uint length, IntPtr reserved, IntPtr type, IntPtr data, IntPtr dataLength);
}
