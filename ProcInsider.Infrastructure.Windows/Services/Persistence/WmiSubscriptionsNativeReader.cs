using System.Diagnostics;
using System.Runtime.InteropServices;
using ProcInsider.Models.Persistence;
using static ProcInsider.Services.Persistence.WmiPersistenceNativeInterop;

namespace ProcInsider.Services.Persistence;

public sealed record WmiSubscriptionNativeObject(string Path, string ClassName, IReadOnlyDictionary<string, PersistenceNativeValue> Properties,
    IReadOnlyList<string>? Derivation = null);
public sealed record WmiSubscriptionsNativeSnapshot(PersistenceCollectionStatus Status,
    IReadOnlyList<WmiSubscriptionNativeObject> Bindings, IReadOnlyList<WmiSubscriptionNativeObject> Filters,
    IReadOnlyList<WmiSubscriptionNativeObject> Consumers, string Diagnostic);
public interface IWmiSubscriptionsNativeReader { WmiSubscriptionsNativeSnapshot Read(CancellationToken token); }

/// <summary>Local, current-token, semisynchronous reads only. No reference following or subscription execution.</summary>
internal sealed class WmiSubscriptionsNativeReader : IWmiSubscriptionsNativeReader
{
    internal const int MaxCandidates = 20_000;
    internal const int MaxProperties = 128;
    internal static readonly TimeSpan ObservationDeadline = TimeSpan.FromSeconds(150);
    private static readonly Guid LocatorClass = new("4590F811-1D3A-11D0-891F-00AA004B2E24");
    private static readonly Guid LocatorInterface = new("DC12A687-737F-11CF-884D-00AA004B2E24");
    internal static bool ExpectedFailure(Exception error) => error is COMException or IOException or InvalidDataException
        or UnauthorizedAccessException or System.Security.SecurityException or TimeoutException;
    public WmiSubscriptionsNativeSnapshot Read(CancellationToken token)
    {
        using var apartment = new Apartment();
        var watch = Stopwatch.StartNew(); var budget = new Budget(); var attempted = 0;
        IntPtr locator = IntPtr.Zero, services = IntPtr.Zero;
        List<WmiSubscriptionNativeObject> bindings = [], filters = [], consumers = [];
        try
        {
            Guard(); locator = Create(LocatorClass, LocatorInterface);
            // Native ConnectServer MAX_WAIT is at most two minutes; cancellation cannot interrupt that call.
            Check(Slot<Connect>(locator, 3)(locator, WmiPersistencePath.Namespace, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                0x80, IntPtr.Zero, IntPtr.Zero, out services));
            Guard(); Check(CoSetProxyBlanket(services, 10, 0, IntPtr.Zero, 6, 3, IntPtr.Zero, 0));
            bindings = Enumerate("__FilterToConsumerBinding"); filters = Enumerate("__EventFilter"); consumers = Enumerate("__EventConsumer");
            // A second bounded inventory detects observed changes; this is not an atomic OS snapshot.
            var againBindings = Enumerate("__FilterToConsumerBinding"); var againFilters = Enumerate("__EventFilter"); var againConsumers = Enumerate("__EventConsumer");
            if (!Same(bindings, againBindings, budget) || !Same(filters, againFilters, budget) || !Same(consumers, againConsumers, budget))
                throw new IOException("WMI subscription inventory changed during observation.");
            return new(PersistenceCollectionStatus.Complete, bindings, filters, consumers, "Local root subscription inventory and dependencies observed twice.");
        }
        catch (Exception error) when (ExpectedFailure(error))
        { return new(bindings.Count + filters.Count + consumers.Count == 0 ? PersistenceCollectionStatus.Failed : PersistenceCollectionStatus.Partial,
            bindings, filters, consumers, "Local WMI subscriptions unavailable or incomplete; no removals inferred."); }
        finally { Release(ref services); Release(ref locator); }

        void Guard() { token.ThrowIfCancellationRequested(); if (watch.Elapsed > ObservationDeadline) throw new TimeoutException("WMI observation deadline reached."); }
        List<WmiSubscriptionNativeObject> Enumerate(string className)
        {
            Guard(); IntPtr enumerator = IntPtr.Zero; var rows = new List<WmiSubscriptionNativeObject>();
            try
            {
                // ExecQuery slot20; RETURN_IMMEDIATELY | FORWARD_ONLY | ENSURE_LOCATABLE. Derived consumers included.
                Check(Slot<Query>(services, 20)(services, "WQL", "SELECT * FROM " + className, 0x130, IntPtr.Zero, out enumerator));
                while (true)
                {
                    Guard(); IntPtr item = IntPtr.Zero; uint returned = 0; int result;
                    try
                    {
                        result = Slot<NextObject>(enumerator, 4)(enumerator, 250, 1, out item, out returned);
                        Check(result);
                        if (returned > 1 || returned == 1 && item == IntPtr.Zero || returned == 0 && item != IntPtr.Zero) throw new InvalidDataException("Invalid WMI enumeration result.");
                        if (returned == 1)
                        { if (++attempted > MaxCandidates) throw new InvalidDataException("WMI candidate bound reached."); rows.Add(ReadObject(item)); }
                    }
                    finally { Release(ref item); }
                    if (result == 1) return rows; // S_FALSE can accompany a final returned object.
                    if (result is not (0 or 0x40004)) throw new InvalidDataException("Unsupported WMI enumeration status.");
                }
            }
            finally { Release(ref enumerator); }
        }
        WmiSubscriptionNativeObject ReadObject(IntPtr item)
        {
            var path = StringProperty(item, "__PATH"); var className = StringProperty(item, "__CLASS");
            var derivation = Derivation(item);
            var properties = new Dictionary<string, PersistenceNativeValue>(StringComparer.OrdinalIgnoreCase);
            Guard(); Check(Slot<Flags>(item, 8)(item, 0x40)); // NONSYSTEM_ONLY.
            budget.Charge(24); var value = Variant();
            try
            {
                for (var index = 0; ; index++)
                {
                    Guard(); IntPtr name = IntPtr.Zero; ResetVariant(value);
                    try
                    {
                        var result = Slot<NextProperty>(item, 9)(item, 0, out name, value, out var type, out _); Check(result);
                        if (result == 0x40005) break; // WBEM_S_NO_MORE_DATA.
                        if (result != 0 || index >= MaxProperties) throw new InvalidDataException("WMI property bound or status unsupported.");
                        var propertyName = Bstr(name, budget, 512);
                        if (propertyName.Length == 0 || propertyName.StartsWith("__", StringComparison.Ordinal) || !properties.TryAdd(propertyName, NativeValue(value, type, budget)))
                            throw new InvalidDataException("Invalid or duplicate WMI native property.");
                    }
                    finally { SysFreeString(name); VariantClear(value); }
                }
            }
            finally { FreeVariant(value); Check(Slot<Simple>(item, 10)(item)); }
            return new(path, className, properties, derivation);
        }
        string[] Derivation(IntPtr item)
        {
            budget.Charge(24); var value = Variant();
            try
            {
                Check(Slot<GetProperty>(item, 4)(item, "__DERIVATION", 0, value, out var type, out _));
                if (type != (8 | 0x2000) || ReadVariant(value, budget) is not object?[] array || array.Length > 32 || array.Any(item => item is not string))
                    throw new InvalidDataException("WMI class ancestry unavailable or unsupported.");
                return array.Cast<string>().ToArray();
            }
            finally { FreeVariant(value); }
        }
        string StringProperty(IntPtr item, string name)
        {
            budget.Charge(24); var value = Variant();
            try
            {
                Check(Slot<GetProperty>(item, 4)(item, name, 0, value, out var type, out _));
                if (type != 8 || (ushort)Marshal.ReadInt16(value) != 8) throw new InvalidDataException("WMI object identity is unavailable.");
                return Bstr(Marshal.ReadIntPtr(value, 8), budget, WmiPersistencePath.MaxPathCharacters * 2);
            }
            finally { FreeVariant(value); }
        }
    }
    private static bool Same(IReadOnlyList<WmiSubscriptionNativeObject> left, IReadOnlyList<WmiSubscriptionNativeObject> right, Budget budget)
    {
        string Signature(WmiSubscriptionNativeObject row)
        {
            budget.Charge(checked((row.Path.Length + row.ClassName.Length + row.Properties.Sum(pair => pair.Key.Length + pair.Value.NativeType.Length + pair.Value.Json.Length)) * 6 + 1024));
            return System.Text.Json.JsonSerializer.Serialize(new { row.Path, row.ClassName, Properties = row.Properties.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).ToArray() });
        }
        return left.Select(Signature).Order(StringComparer.Ordinal).SequenceEqual(right.Select(Signature).Order(StringComparer.Ordinal));
    }
}
