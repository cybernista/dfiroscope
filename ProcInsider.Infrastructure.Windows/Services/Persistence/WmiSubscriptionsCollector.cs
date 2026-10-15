using System.Diagnostics;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

public sealed class WmiSubscriptionsCollector(EvidenceIdentity identity, IWmiSubscriptionsNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.wmi-subscriptions.v1";
    public string CollectorId => Id;
    internal int ProjectedByteAllowance { get; init; } = 32 * 1024 * 1024;
    private readonly IWmiSubscriptionsNativeReader _reader = reader ?? new WmiSubscriptionsNativeReader();
    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requestedIdentity, CancellationToken token)
    {
        if (requestedIdentity != identity) throw new InvalidDataException("WMI collector scope mismatch.");
        token.ThrowIfCancellationRequested(); var watch = Stopwatch.StartNew(); var budget = new WmiPersistenceNativeInterop.Budget(ProjectedByteAllowance);
        var artifacts = new List<PersistenceArtifact>(); var status = PersistenceCollectionStatus.Failed;
        var diagnostic = "Local WMI subscriptions unavailable; no removals inferred.";
        try
        {
            var snapshot = _reader.Read(token); status = snapshot.Status; diagnostic = snapshot.Diagnostic;
            if (snapshot.Bindings.Count + snapshot.Filters.Count + snapshot.Consumers.Count > WmiSubscriptionsNativeReader.MaxCandidates)
                throw new InvalidDataException("WMI candidate bound reached.");
            var bindings = Inventory(snapshot.Bindings); var filters = Inventory(snapshot.Filters); var consumers = Inventory(snapshot.Consumers);
            if (filters.Values.Any(item => !item.ClassName.Equals("__EventFilter", StringComparison.OrdinalIgnoreCase)) ||
                consumers.Values.Any(item => !item.ClassName.Equals("__EventConsumer", StringComparison.OrdinalIgnoreCase) &&
                    !(item.Derivation?.Contains("__EventConsumer", StringComparer.OrdinalIgnoreCase) ?? false)))
                throw new InvalidDataException("WMI dependency class outside its declared inventory.");
            foreach (var (path, binding) in bindings)
            {
                token.ThrowIfCancellationRequested(); var parsed = WmiPersistencePath.Parse(binding.Path, budget);
                if (!parsed.ClassName.Equals("__FilterToConsumerBinding", StringComparison.OrdinalIgnoreCase) ||
                    !parsed.ReferenceKeys.TryGetValue("FILTER", out var filterPath) || !parsed.ReferenceKeys.TryGetValue("CONSUMER", out var consumerPath) ||
                    !filters.TryGetValue(filterPath, out var filter) || !consumers.TryGetValue(consumerPath, out var consumer))
                    throw new InvalidDataException("WMI binding dependency is missing or outside the declared inventory.");
                var configuration = new Dictionary<string, PersistenceNativeValue>(StringComparer.Ordinal);
                Add("Binding", binding); Add("Filter", filter); Add("Consumer", consumer);
                configuration.Add("CanonicalBindingPath", Native("WMI_CANONICAL_PATH_V1", path));
                var filterName = StringValue(filter, "Name") ?? filter.ClassName;
                var consumerName = StringValue(consumer, "Name") ?? consumer.ClassName;
                artifacts.Add(new() { EvidenceIdentity = identity, CollectorId = Id, Category = "WMI", Coverage = Coverage(PersistenceSourceAvailability.Available),
                    NativeLocation = binding.Path, NativeName = filterName + " → " + consumerName, Configuration = configuration });
                void Add(string prefix, WmiSubscriptionNativeObject item)
                {
                    var itemPath = WmiPersistencePath.Parse(item.Path, budget);
                    if (!itemPath.ClassName.Equals(item.ClassName, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("WMI class and object path disagree.");
                    configuration.Add(prefix + ".Path", Native("WMI_RAW_PATH_V1", item.Path));
                    configuration.Add(prefix + ".Path.Canonical", Native("WMI_CANONICAL_PATH_V1", itemPath.Canonical));
                    configuration.Add(prefix + ".Class", Native("WMI_CLASS_V1", item.ClassName.ToUpperInvariant()));
                    foreach (var (name, value) in item.Properties)
                    {
                        token.ThrowIfCancellationRequested(); PersistenceRegistryNativeReader.ValidateText(name);
                        if (item.Properties.Count > WmiSubscriptionsNativeReader.MaxProperties || name.Length > 256 || value.Json.Length > WmiPersistenceNativeInterop.MaxValueBytes)
                            throw new InvalidDataException("WMI retained property bound reached.");
                        var key = prefix + "." + name.ToUpperInvariant();
                        // Shared dependencies are projected into each binding. Charge every copy, including failed projections.
                        budget.Charge(checked((key.Length + value.NativeType.Length + value.Json.Length) * 6 + 128));
                        using var document = JsonDocument.Parse(value.Json);
                        if (value.State != PersistenceValueState.Known || !value.NativeType.StartsWith("WMI_CIM_", StringComparison.Ordinal)) throw new InvalidDataException("Unsupported WMI typed property.");
                        if (value.NativeType == "WMI_CIM_102" || itemPath.ReferenceKeys.ContainsKey(name))
                        {
                            var reference = document.RootElement.GetString() ?? throw new InvalidDataException("WMI reference missing.");
                            var referencePath = WmiPersistencePath.Parse(reference, budget).Canonical;
                            if (itemPath.ReferenceKeys.TryGetValue(name, out var identityReference) && referencePath != identityReference) throw new InvalidDataException("WMI binding reference property disagrees with path.");
                            configuration.Add(key, Native("WMI_RAW_REFERENCE_V1", reference)); configuration.Add(key + ".Canonical", Native("WMI_CANONICAL_PATH_V1", referencePath));
                        }
                        else if (itemPath.Keys.TryGetValue(name, out var nativeIdentity))
                        {
                            var normalized = document.RootElement.ValueKind == JsonValueKind.String ? JsonSerializer.Serialize(document.RootElement.GetString()!.ToUpperInvariant()) : PersistenceComparisonPolicy.CanonicalJson(value.Json);
                            if (value.NativeType != "WMI_CIM_" + nativeIdentity.Type || normalized != nativeIdentity.Json) throw new InvalidDataException("WMI identity property disagrees with native typed path key.");
                            if (document.RootElement.ValueKind == JsonValueKind.String)
                            {
                                var nativeKey = document.RootElement.GetString()!; configuration.Add(key, Native("WMI_RAW_KEY_V1", nativeKey));
                                configuration.Add(key + ".Canonical", Native("WMI_CANONICAL_KEY_V1", nativeKey.ToUpperInvariant()));
                            }
                            else configuration.Add(key, value);
                        }
                        else configuration.Add(key, value);
                    }
                    if (itemPath.Keys.Keys.Any(name => !item.Properties.ContainsKey(name))) throw new InvalidDataException("WMI identity property missing from inventory.");
                }
            }
            _ = PersistenceComparisonPolicy.Inventory(artifacts);
        }
        catch (Exception error) when (WmiSubscriptionsNativeReader.ExpectedFailure(error))
        { status = artifacts.Count == 0 ? PersistenceCollectionStatus.Failed : PersistenceCollectionStatus.Partial; diagnostic = "Local WMI subscription dependencies malformed, unavailable or incomplete; no removals inferred."; }
        var coverage = Coverage(status == PersistenceCollectionStatus.Complete ? PersistenceSourceAvailability.Available : PersistenceSourceAvailability.Unavailable);
        return Task.FromResult<IReadOnlyList<PersistenceCollectorResult>>([new(Id, coverage, status,
            artifacts.Select(item => item with { Coverage = coverage }).ToArray(), watch.Elapsed, diagnostic)]);

        Dictionary<string, WmiSubscriptionNativeObject> Inventory(IReadOnlyList<WmiSubscriptionNativeObject> rows)
        {
            var result = new Dictionary<string, WmiSubscriptionNativeObject>(StringComparer.Ordinal);
            foreach (var item in rows)
            {
                token.ThrowIfCancellationRequested(); var path = WmiPersistencePath.Parse(item.Path, budget).Canonical;
                if (result.TryGetValue(path, out var prior) && !Same(prior, item, budget)) throw new InvalidDataException("Conflicting WMI dependency identity.");
                result.TryAdd(path, item);
            }
            return result;
        }
        PersistenceNativeValue Native(string type, string value)
        { budget.Charge(checked((type.Length + value.Length) * 6 + 128)); return new(type, PersistenceValueState.Known, JsonSerializer.Serialize(value)); }
    }
    internal static PersistenceCoverage Coverage(PersistenceSourceAvailability availability) => new("LocalPermanentSubscriptions", "", "", "LocalRootSubscription", availability);
    private static string? StringValue(WmiSubscriptionNativeObject item, string name)
    { if (!item.Properties.TryGetValue(name, out var value)) return null; using var json = JsonDocument.Parse(value.Json); return json.RootElement.ValueKind == JsonValueKind.String ? json.RootElement.GetString() : null; }
    private static bool Same(WmiSubscriptionNativeObject a, WmiSubscriptionNativeObject b, WmiPersistenceNativeInterop.Budget budget)
    {
        if (!a.ClassName.Equals(b.ClassName, StringComparison.OrdinalIgnoreCase) || a.Properties.Count != b.Properties.Count) return false;
        var path = WmiPersistencePath.Parse(a.Path, budget);
        foreach (var (name, value) in a.Properties)
        {
            if (!b.Properties.TryGetValue(name, out var other) || value.NativeType != other.NativeType || value.State != other.State || value.Unordered != other.Unordered) return false;
            using var left = JsonDocument.Parse(value.Json); using var right = JsonDocument.Parse(other.Json);
            if (value.NativeType == "WMI_CIM_102" || path.ReferenceKeys.ContainsKey(name))
            { if (WmiPersistencePath.Parse(left.RootElement.GetString()!, budget).Canonical != WmiPersistencePath.Parse(right.RootElement.GetString()!, budget).Canonical) return false; }
            else if (path.Keys.ContainsKey(name) && left.RootElement.ValueKind == JsonValueKind.String && right.RootElement.ValueKind == JsonValueKind.String)
            { if (!string.Equals(left.RootElement.GetString(), right.RootElement.GetString(), StringComparison.OrdinalIgnoreCase)) return false; }
            else if (PersistenceComparisonPolicy.CanonicalJson(value.Json, value.Unordered) != PersistenceComparisonPolicy.CanonicalJson(other.Json, other.Unordered)) return false;
        }
        return true;
    }
}
