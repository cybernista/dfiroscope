using System.Runtime.InteropServices;
using System.Text.Json;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

/// <summary>Only the native read/path-parser slots used by local permanent-subscription acquisition.</summary>
internal static class WmiPersistenceNativeInterop
{
    internal sealed class Apartment : IDisposable
    {
        private readonly bool _initialized;
        internal Apartment() { var result = CoInitializeEx(IntPtr.Zero, 0); if (result != unchecked((int)0x80010106)) Check(result); _initialized = result >= 0; }
        public void Dispose() { if (_initialized) CoUninitialize(); }
    }
    internal const int MaxValueBytes = 64 * 1024;
    internal const int MaxArrayElements = 4096;
    internal sealed class Budget(int remaining = 32 * 1024 * 1024)
    {
        internal int Remaining { get; private set; } = remaining;
        internal void Charge(int bytes)
        {
            if (bytes < 0 || bytes > Remaining) throw new InvalidDataException("WMI retained allocation allowance exhausted.");
            Remaining -= bytes; // Never refunded after conversion/validation failure.
        }
    }
    internal static T Slot<T>(IntPtr instance, int slot) where T : Delegate
        => Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(instance), slot * IntPtr.Size));
    internal static IntPtr Create(Guid clsid, Guid iid)
    {
        Check(CoCreateInstance(ref clsid, IntPtr.Zero, 1, ref iid, out var result));
        return result;
    }
    internal static void Check(int result) { if (result < 0) Marshal.ThrowExceptionForHR(result); }
    internal static void Release(ref IntPtr value) { if (value != IntPtr.Zero) { Marshal.Release(value); value = IntPtr.Zero; } }
    internal static IntPtr Variant() { var value = Marshal.AllocCoTaskMem(24); ResetVariant(value); return value; }
    internal static void ResetVariant(IntPtr value) { for (var i = 0; i < 24; i++) Marshal.WriteByte(value, i, 0); }
    internal static void FreeVariant(IntPtr value) { if (value != IntPtr.Zero) { VariantClear(value); Marshal.FreeCoTaskMem(value); } }
    internal static string Bstr(IntPtr value, Budget budget, int maxBytes = MaxValueBytes)
    {
        if (value == IntPtr.Zero) return "";
        var bytes = SysStringByteLen(value);
        if ((bytes & 1) != 0 || bytes > maxBytes) throw new InvalidDataException("WMI native string exceeds its retained bound.");
        budget.Charge(checked((int)bytes));
        var text = Marshal.PtrToStringUni(value, (int)bytes / 2)!;
        PersistenceRegistryNativeReader.ValidateText(text);
        return text;
    }
    internal static PersistenceNativeValue NativeValue(IntPtr variant, uint cimType, Budget budget)
    {
        var value = NormalizeCim(ReadVariant(variant, budget), cimType);
        // Reserve a conservative JSON allocation before serialization, including escaped native text.
        var estimate = Estimate(value);
        if (estimate > MaxValueBytes) throw new InvalidDataException("WMI property representation exceeds its bound.");
        budget.Charge(estimate);
        return new("WMI_CIM_" + cimType, PersistenceValueState.Known, JsonSerializer.Serialize(value));
    }
    internal static object? NormalizeCim(object? value, uint type)
    {
        if ((type & 0x2000) != 0)
        {
            if (value == null) return null;
            if (value is not object?[] array) throw new InvalidDataException("WMI CIM array and VARIANT disagree.");
            for (var index = 0; index < array.Length; index++) array[index] = NormalizeCim(array[index], type & ~0x2000u);
            return array;
        }
        if (type is not (2 or 3 or 4 or 5 or 8 or 11 or 16 or 17 or 18 or 19 or 20 or 21 or 101 or 102 or 103))
            throw new InvalidDataException("Unsupported WMI CIM property type.");
        if (value == null) return null;
        return type switch
        {
            2 when value is short => value,
            3 when value is int => value,
            4 when value is float => value,
            5 when value is double => value,
            8 or 101 or 102 when value is string => value,
            11 when value is bool => value,
            16 when value is short number && number is >= sbyte.MinValue and <= sbyte.MaxValue => (sbyte)number,
            17 when value is byte => value,
            18 when value is int number && number is >= 0 and <= ushort.MaxValue => (ushort)number,
            19 when value is int number => unchecked((uint)number),
            19 when value is uint => value,
            20 when value is string text && Integer64(text, true) => value,
            21 when value is string text && Integer64(text, false) => value,
            103 when value is short character && !char.IsSurrogate((char)unchecked((ushort)character)) => unchecked((ushort)character),
            _ => throw new InvalidDataException("WMI native numeric/type range is inconsistent.")
        };
    }
    private static bool Integer64(string text, bool signed)
    {
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return text.Length is >= 3 and <= 18 && text.AsSpan(2).IndexOfAnyExcept("0123456789abcdefABCDEF") < 0;
        return signed ? long.TryParse(text, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out _)
            : ulong.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _);
    }
    internal static int Estimate(object? value) => value switch
    {
        null => 4, string text => checked(text.Length * 6 + 2), object?[] array => checked(2 + array.Sum(item => Estimate(item) + 1)), _ => 32
    };
    internal static object? ReadVariant(IntPtr variant, Budget budget)
    {
        var type = (ushort)Marshal.ReadInt16(variant);
        if ((type & 0x2000) != 0)
        {
            if ((type & ~0x2FFF) != 0) throw new InvalidDataException("Unsupported WMI array flags.");
            return ArrayValue(Marshal.ReadIntPtr(variant, 8), (ushort)(type & 0xFFF), budget);
        }
        budget.Charge(16);
        return type switch
        {
            0 or 1 => null,
            2 => Marshal.ReadInt16(variant, 8), 3 or 22 => Marshal.ReadInt32(variant, 8),
            4 => Finite(BitConverter.Int32BitsToSingle(Marshal.ReadInt32(variant, 8))),
            5 => Finite(BitConverter.Int64BitsToDouble(Marshal.ReadInt64(variant, 8))),
            8 => Bstr(Marshal.ReadIntPtr(variant, 8), budget),
            11 => Marshal.ReadInt16(variant, 8) switch { 0 => false, -1 => true, _ => throw new InvalidDataException("Invalid native Boolean.") },
            16 => unchecked((sbyte)Marshal.ReadByte(variant, 8)), 17 => Marshal.ReadByte(variant, 8),
            18 => unchecked((ushort)Marshal.ReadInt16(variant, 8)), 19 or 23 => unchecked((uint)Marshal.ReadInt32(variant, 8)),
            20 => Marshal.ReadInt64(variant, 8), 21 => unchecked((ulong)Marshal.ReadInt64(variant, 8)),
            _ => throw new InvalidDataException("Unsupported complex WMI property; source incomplete.")
        };
    }
    private static object?[] ArrayValue(IntPtr array, ushort type, Budget budget)
    {
        if (array == IntPtr.Zero || SafeArrayGetDim(array) != 1) throw new InvalidDataException("Unsupported WMI array dimensions.");
        Check(SafeArrayGetLBound(array, 1, out var first)); Check(SafeArrayGetUBound(array, 1, out var last));
        var count = (long)last - first + 1;
        if (count < 0 || count > MaxArrayElements) throw new InvalidDataException("WMI array element bound reached.");
        budget.Charge(checked((int)count * IntPtr.Size));
        var result = new object?[(int)count];
        Check(SafeArrayGetVartype(array, out var actualType));
        if (actualType != type || type is not (2 or 3 or 4 or 5 or 8 or 11 or 16 or 17 or 18 or 19 or 20 or 21 or 22 or 23)) throw new InvalidDataException("Unsupported WMI array element type.");
        budget.Charge(24); var element = Variant();
        try
        {
            for (var i = 0; i < result.Length; i++)
            {
                var index = checked(first + i); ResetVariant(element); Marshal.WriteInt16(element, (short)type);
                try { Check(SafeArrayGetElement(array, ref index, IntPtr.Add(element, 8))); result[i] = ReadVariant(element, budget); }
                finally { VariantClear(element); }
            }
            return result;
        }
        finally { FreeVariant(element); }
    }
    private static float Finite(float value) => float.IsFinite(value) ? value : throw new InvalidDataException("Non-finite WMI numeric property.");
    private static double Finite(double value) => double.IsFinite(value) ? value : throw new InvalidDataException("Non-finite WMI numeric property.");
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)] internal delegate int TextInput(IntPtr self, uint flags, [MarshalAs(UnmanagedType.LPWStr)] string text);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)] internal delegate int IsLocal(IntPtr self, [MarshalAs(UnmanagedType.LPWStr)] string server);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int TextOutput(IntPtr self, ref uint length, IntPtr text);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int IndexedTextOutput(IntPtr self, uint index, ref uint length, IntPtr text);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int CountOutput(IntPtr self, out uint count);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int PointerOutput(IntPtr self, out IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int KeyOutput(IntPtr self, uint index, uint flags, ref uint length, IntPtr name, IntPtr variant, out uint cimType);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int Simple(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int Flags(IntPtr self, int flags);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)] internal delegate int GetProperty(IntPtr self, [MarshalAs(UnmanagedType.LPWStr)] string name, int flags, IntPtr value, out uint cimType, out int flavor);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int NextProperty(IntPtr self, int flags, out IntPtr name, IntPtr value, out uint cimType, out int flavor);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int NextObject(IntPtr self, int timeout, uint count, out IntPtr value, out uint returned);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)] internal delegate int Connect(IntPtr self, [MarshalAs(UnmanagedType.BStr)] string resource, IntPtr user, IntPtr password, IntPtr locale, int flags, IntPtr authority, IntPtr context, out IntPtr services);
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)] internal delegate int Query(IntPtr self, [MarshalAs(UnmanagedType.BStr)] string language, [MarshalAs(UnmanagedType.BStr)] string query, int flags, IntPtr context, out IntPtr enumerator);
    [DllImport("ole32.dll")] private static extern int CoCreateInstance(ref Guid clsid, IntPtr outer, uint context, ref Guid iid, out IntPtr result);
    [DllImport("ole32.dll")] private static extern int CoInitializeEx(IntPtr reserved, uint mode);
    [DllImport("ole32.dll")] private static extern void CoUninitialize();
    [DllImport("oleaut32.dll")] internal static extern int VariantClear(IntPtr value);
    [DllImport("oleaut32.dll")] internal static extern void SysFreeString(IntPtr value);
    [DllImport("oleaut32.dll")] private static extern uint SysStringByteLen(IntPtr value);
    [DllImport("oleaut32.dll")] private static extern uint SafeArrayGetDim(IntPtr value);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayGetLBound(IntPtr value, uint dimension, out int bound);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayGetUBound(IntPtr value, uint dimension, out int bound);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayGetVartype(IntPtr value, out ushort type);
    [DllImport("oleaut32.dll")] private static extern int SafeArrayGetElement(IntPtr value, ref int index, IntPtr element);
    [DllImport("ole32.dll")] internal static extern int CoSetProxyBlanket(IntPtr proxy, uint authentication, uint authorization, IntPtr principal, uint level, uint impersonation, IntPtr credentials, uint capabilities);
}
