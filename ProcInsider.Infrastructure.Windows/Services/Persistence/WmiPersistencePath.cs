using System.Runtime.InteropServices;
using System.Text.Json;
using static ProcInsider.Services.Persistence.WmiPersistenceNativeInterop;

namespace ProcInsider.Services.Persistence;

internal sealed record WmiPersistenceParsedPath(string ClassName, string Canonical,
    IReadOnlyDictionary<string, string> ReferenceKeys, IReadOnlyDictionary<string, (uint Type, string Json)> Keys);

/// <summary>Native IWbemPath grammar; never follows a path or opens its target.</summary>
internal static class WmiPersistencePath
{
    private sealed record TypedKey(uint Type, object Value);
    internal const string Namespace = @"root\subscription";
    internal const int MaxPathCharacters = 16 * 1024;
    internal const int MaxKeys = 32;
    internal const int MaxReferenceDepth = 8;
    private static readonly Guid ParserClass = new("CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA");
    private static readonly Guid ParserInterface = new("3BC15AF2-736C-477E-9E51-238AF8667DCC");
    internal static WmiPersistenceParsedPath Parse(string text, Budget? budget = null, int depth = 0)
    {
        budget ??= new();
        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxPathCharacters || depth > MaxReferenceDepth)
            throw new InvalidDataException("WMI object path or reference nesting bound reached.");
        PersistenceRegistryNativeReader.ValidateText(text);
        using var apartment = new Apartment();
        IntPtr parser = IntPtr.Zero, keys = IntPtr.Zero;
        try
        {
            parser = Create(ParserClass, ParserInterface);
            Check(Slot<TextInput>(parser, 3)(parser, 4, text)); // IWbemPath.SetText(ACCEPT_ALL).
            if (Slot<IsLocal>(parser, 27)(parser, Environment.MachineName) == 0)
                throw new InvalidDataException("WMI reference is outside the declared local server.");
            Check(Slot<CountOutput>(parser, 8)(parser, out var namespaceCount));
            if (namespaceCount > 2) throw new InvalidDataException("WMI reference namespace is outside the declared scope.");
            var namespaces = new List<string>();
            for (uint index = 0; index < namespaceCount; index++)
            {
                budget.Charge(514); uint length = 257; var buffer = Marshal.AllocCoTaskMem(514);
                try { Check(Slot<IndexedTextOutput>(parser, 10)(parser, index, ref length, buffer)); namespaces.Add(BufferText(buffer, length, budget)); }
                finally { Marshal.FreeCoTaskMem(buffer); }
            }
            if (namespaceCount != 0 && !string.Join('\\', namespaces).Equals(Namespace, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("WMI reference namespace is outside root subscription.");
            Check(Slot<CountOutput>(parser, 13)(parser, out var scopes));
            if (scopes != 1) throw new InvalidDataException("Exactly one local WMI object scope is required.");
            var className = Text(Slot<TextOutput>(parser, 21), parser, budget);
            if (className.Length == 0 || className.Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '_')))
                throw new InvalidDataException("Invalid WMI instance class.");
            Check(Slot<PointerOutput>(parser, 22)(parser, out keys));
            Check(Slot<CountOutput>(keys, 3)(keys, out var count));
            if (count == 0 || count > MaxKeys) throw new InvalidDataException("WMI keyed instance path required.");
            var canonicalKeys = new SortedDictionary<string, TypedKey>(StringComparer.Ordinal);
            var references = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var typedKeys = new Dictionary<string, (uint Type, string Json)>(StringComparer.OrdinalIgnoreCase);
            for (uint index = 0; index < count; index++)
            {
                budget.Charge(538); uint length = 257; var nameBuffer = Marshal.AllocCoTaskMem(514); var value = Variant();
                try
                {
                    Check(Slot<KeyOutput>(keys, 7)(keys, index, 0, ref length, nameBuffer, value, out var type));
                    var name = BufferText(nameBuffer, length, budget).ToUpperInvariant();
                    if (name.Length == 0) throw new InvalidDataException("Implicit WMI keys are unsupported.");
                    var native = ReadVariant(value, budget);
                    var bindingReference = className.Equals("__FilterToConsumerBinding", StringComparison.OrdinalIgnoreCase) && (name is "FILTER" or "CONSUMER");
                    object canonicalValue;
                    if (type == 102 || bindingReference)
                    {
                        if (native is not string reference) throw new InvalidDataException("WMI binding reference has a non-string value.");
                        var parsed = Parse(reference, budget, depth + 1);
                        canonicalValue = parsed.Canonical; type = 102; references.Add(name, parsed.Canonical);
                    }
                    else canonicalValue = native switch
                    {
                        string literal => literal.ToUpperInvariant(),
                        bool or byte or sbyte or short or ushort or int or uint or long or ulong => native,
                        _ => throw new InvalidDataException("Unsupported WMI key value.")
                    };
                    if (!canonicalKeys.TryAdd(name, new(type, canonicalValue)))
                        throw new InvalidDataException("Duplicate native WMI key.");
                    budget.Charge(checked(Estimate(canonicalValue) + 64));
                    typedKeys.Add(name, (type, JsonSerializer.Serialize(canonicalValue)));
                }
                finally { FreeVariant(value); Marshal.FreeCoTaskMem(nameBuffer); }
            }
            if (className.Equals("__FilterToConsumerBinding", StringComparison.OrdinalIgnoreCase) &&
                (canonicalKeys.Count != 2 || references.Count != 2 || !references.ContainsKey("FILTER") || !references.ContainsKey("CONSUMER")))
                throw new InvalidDataException("WMI binding requires both exact reference keys.");
            budget.Charge(checked(512 + canonicalKeys.Sum(pair => pair.Key.Length * 6 + Estimate(pair.Value.Value) + 64)));
            var canonical = JsonSerializer.Serialize(new { Namespace = Namespace.ToUpperInvariant(), Class = className.ToUpperInvariant(), Keys = canonicalKeys });
            return new(className, canonical, references, typedKeys);
        }
        finally { Release(ref keys); Release(ref parser); }
    }
    private static string Text(TextOutput getter, IntPtr parser, Budget budget)
    {
        budget.Charge(514); uint length = 257; var buffer = Marshal.AllocCoTaskMem(514);
        try { Check(getter(parser, ref length, buffer)); return BufferText(buffer, length, budget); }
        finally { Marshal.FreeCoTaskMem(buffer); }
    }
    private static string BufferText(IntPtr buffer, uint length, Budget budget)
    {
        if (length == 0) return "";
        if (length > 257 || Marshal.ReadInt16(buffer, checked(((int)length - 1) * 2)) != 0) throw new InvalidDataException("WMI path component exceeds native bound.");
        budget.Charge(checked((int)length * 2));
        var result = Marshal.PtrToStringUni(buffer, (int)length - 1)!;
        PersistenceRegistryNativeReader.ValidateText(result); return result;
    }
}
