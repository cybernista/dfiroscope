using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services;

/// <summary>Pure version-1 location identity and meaningful configuration comparison.</summary>
public static class PersistenceComparisonPolicy
{
    public const string Version = "persistence-comparison-v1";
    public static string ScopeKey(EvidenceIdentity identity) => Hash(JsonSerializer.Serialize(identity));
    public static string PartitionKey(string collectorId, PersistenceCoverage coverage)
        => Hash(JsonSerializer.Serialize(new { collectorId, coverage.PartitionId,
            UserSid = coverage.UserSid.ToUpperInvariant(), RegistryView = coverage.RegistryView.ToUpperInvariant(),
            coverage.ProfileScope }));
    public static string ArtifactKey(PersistenceArtifact artifact)
        => Hash(JsonSerializer.Serialize(new { Scope = ScopeKey(artifact.EvidenceIdentity), artifact.CollectorId,
            Partition = PartitionKey(artifact.CollectorId, artifact.Coverage),
            Location = WmiV1(artifact) ? CanonicalWmiLocation(artifact) : artifact.NativeLocation.ToUpperInvariant(),
            Name = WmiV1(artifact) ? "" : artifact.NativeName.ToUpperInvariant() }));

    public static string Fingerprint(PersistenceArtifact artifact)
    {
        var taskV2 = artifact.CollectorId == "persistence.scheduled-tasks.v2" && artifact.Category == "ScheduledTasks" && artifact.SourceSchemaVersion == 2;
        var wmiV1 = WmiV1(artifact);
        if (wmiV1) _ = CanonicalWmiLocation(artifact);
        var configuration = artifact.Configuration.OrderBy(x => x.Key, StringComparer.Ordinal)
            .Where(pair => !wmiV1 || !WmiRaw(pair, artifact))
            .Select(x => new { x.Key, x.Value.NativeType, x.Value.State,
                Json = taskV2 && x.Value.State == PersistenceValueState.Known &&
                    ((x.Key == "NativeXml" && x.Value.NativeType == "TaskSchedulerXml") || (x.Key == "OrderedActions" && x.Value.NativeType == "TaskActions"))
                    ? CanonicalTaskXmlValue(x.Value.Json) : CanonicalJson(x.Value.Json, x.Value.Unordered), x.Value.Unordered }).ToArray();
        return Hash(JsonSerializer.Serialize(new { Version, artifact.Category, artifact.Target, artifact.Command,
            artifact.Arguments, Principal = taskV2 && artifact.Principal != null ? CanonicalTaskXml(artifact.Principal) : artifact.Principal,
            artifact.Enabled, artifact.SourceSchemaVersion, configuration }));
    }

    private static bool WmiV1(PersistenceArtifact artifact)
    {
        if (artifact.CollectorId != "persistence.wmi-subscriptions.v1") return false;
        if (artifact.Category != "WMI" || artifact.SourceSchemaVersion != 1) throw new InvalidDataException("Unsupported WMI source representation.");
        return true;
    }
    private static string CanonicalWmiLocation(PersistenceArtifact artifact)
    {
        if (!artifact.Configuration.TryGetValue("CanonicalBindingPath", out var value) || value.NativeType != "WMI_CANONICAL_PATH_V1" || value.State != PersistenceValueState.Known)
            throw new InvalidDataException("WMI canonical binding identity required.");
        using var json = JsonDocument.Parse(value.Json);
        var canonical = json.RootElement.GetString() ?? throw new InvalidDataException("WMI canonical binding identity missing.");
        ValidateWmiPath(canonical, true, 0); return CanonicalJson(canonical);
    }
    private static bool WmiRaw(KeyValuePair<string, PersistenceNativeValue> pair, PersistenceArtifact artifact)
    {
        if (pair.Value.NativeType is not ("WMI_RAW_PATH_V1" or "WMI_RAW_REFERENCE_V1" or "WMI_RAW_KEY_V1")) return false;
        if (pair.Value.State != PersistenceValueState.Known || !artifact.Configuration.TryGetValue(pair.Key + ".Canonical", out var canonical) || canonical.State != PersistenceValueState.Known)
            throw new InvalidDataException("WMI raw identity requires its canonical companion.");
        using var raw = JsonDocument.Parse(pair.Value.Json); using var normalized = JsonDocument.Parse(canonical.Json);
        if (raw.RootElement.ValueKind != JsonValueKind.String || normalized.RootElement.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("WMI native identity must be text.");
        if (pair.Value.NativeType == "WMI_RAW_KEY_V1")
        {
            if (canonical.NativeType != "WMI_CANONICAL_KEY_V1" || normalized.RootElement.GetString() != raw.RootElement.GetString()!.ToUpperInvariant())
                throw new InvalidDataException("Invalid WMI canonical native key.");
        }
        else
        {
            if (canonical.NativeType != "WMI_CANONICAL_PATH_V1") throw new InvalidDataException("Invalid WMI canonical path type.");
            ValidateWmiPath(normalized.RootElement.GetString()!, false, 0);
        }
        return true;
    }
    private static void ValidateWmiPath(string text, bool binding, int depth)
    {
        if (text.Length > 128 * 1024 || depth > 8) throw new InvalidDataException("WMI canonical path bound reached.");
        using var document = JsonDocument.Parse(text); var root = document.RootElement;
        if (root.GetProperty("Namespace").GetString() != "ROOT\\SUBSCRIPTION" || root.GetProperty("Class").ValueKind != JsonValueKind.String)
            throw new InvalidDataException("WMI canonical path scope invalid.");
        var keys = root.GetProperty("Keys");
        if (keys.ValueKind != JsonValueKind.Object || keys.EnumerateObject().Count() is < 1 or > 32) throw new InvalidDataException("WMI canonical path keys invalid.");
        foreach (var key in keys.EnumerateObject())
        {
            if (key.Name != key.Name.ToUpperInvariant() || key.Name.Length == 0) throw new InvalidDataException("WMI canonical key name invalid.");
            if (key.Value.GetProperty("Type").GetUInt32() == 102) ValidateWmiPath(key.Value.GetProperty("Value").GetString()!, false, depth + 1);
        }
        if (binding && (root.GetProperty("Class").GetString() != "__FILTERTOCONSUMERBINDING" || keys.EnumerateObject().Count() != 2 ||
            !keys.TryGetProperty("FILTER", out var filter) || filter.GetProperty("Type").GetUInt32() != 102 || !keys.TryGetProperty("CONSUMER", out var consumer) || consumer.GetProperty("Type").GetUInt32() != 102))
            throw new InvalidDataException("WMI canonical binding references required.");
    }

    private static string CanonicalTaskXmlValue(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.ValueKind switch
        {
            JsonValueKind.String => JsonSerializer.Serialize(CanonicalTaskXml(document.RootElement.GetString()!)),
            JsonValueKind.Array => JsonSerializer.Serialize(document.RootElement.EnumerateArray().Select(value => CanonicalTaskXml(value.GetString()!)).ToArray()),
            _ => throw new InvalidDataException("Unsupported task XML representation.")
        };
    }

    private static string CanonicalTaskXml(string xml)
    {
        using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 });
        return JsonSerializer.Serialize(Element(XElement.Load(reader, LoadOptions.PreserveWhitespace)), new JsonSerializerOptions { MaxDepth = 256 });
        static object Element(XElement element)
        {
            var attributes = element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration)
                .OrderBy(attribute => attribute.Name.NamespaceName, StringComparer.Ordinal).ThenBy(attribute => attribute.Name.LocalName, StringComparer.Ordinal)
                .Select(attribute => new { Namespace = attribute.Name.NamespaceName, Name = attribute.Name.LocalName, attribute.Value }).ToArray();
            var children = new List<object>();
            var textRun = new StringBuilder();
            foreach (var node in element.Nodes())
            {
                if (node is XComment) continue;
                if (node is XText text) { textRun.Append(text.Value); continue; }
                FlushText();
                children.Add(node switch { XElement child => Element(child), XProcessingInstruction instruction => new { instruction.Target, instruction.Data }, _ => node.ToString() });
            }
            FlushText();
            return new { Namespace = element.Name.NamespaceName, Name = element.Name.LocalName, attributes, children };
            void FlushText()
            {
                if (textRun.Length == 0) return;
                var text = textRun.ToString(); textRun.Clear();
                if (!(element.HasElements && string.IsNullOrWhiteSpace(text))) children.Add(new { Text = text });
            }
        }
    }

    public static string CanonicalJson(string json, bool unordered = false)
    {
        using var document = JsonDocument.Parse(json);
        return Canonical(document.RootElement, unordered);
    }

    private static string Canonical(JsonElement value, bool unordered = false) => value.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", value.EnumerateObject().OrderBy(x => x.Name, StringComparer.Ordinal)
            .Select(x => JsonSerializer.Serialize(x.Name) + ":" + Canonical(x.Value))) + "}",
        JsonValueKind.Array => "[" + string.Join(",", unordered
            ? value.EnumerateArray().Select(x => Canonical(x)).Order(StringComparer.Ordinal)
            : value.EnumerateArray().Select(x => Canonical(x))) + "]",
        JsonValueKind.String => JsonSerializer.Serialize(value.GetString()),
        _ => value.GetRawText()
    };

    public static IReadOnlyDictionary<string, PersistenceArtifact> Inventory(IEnumerable<PersistenceArtifact> artifacts)
    {
        var inventory = new Dictionary<string, PersistenceArtifact>(StringComparer.Ordinal);
        foreach (var artifact in artifacts)
        {
            var key = ArtifactKey(artifact);
            if (inventory.TryGetValue(key, out var existing) && Fingerprint(existing) != Fingerprint(artifact))
                throw new InvalidDataException("Conflicting duplicate persistence location.");
            inventory.TryAdd(key, artifact);
        }
        return inventory;
    }

    public static IReadOnlyList<PersistenceVersion> Diff(PersistenceCollection collection,
        PersistenceCollectorResult result, IReadOnlyDictionary<string, PersistenceArtifact>? predecessor)
    {
        if (result.Status != PersistenceCollectionStatus.Complete) return [];
        var inventory = Inventory(result.Artifacts);
        if (predecessor is { Count: > 0 } && inventory.Count > 0 &&
            !predecessor.Values.Select(a => a.SourceSchemaVersion).ToHashSet().SetEquals(inventory.Values.Select(a => a.SourceSchemaVersion)))
            throw new InvalidDataException("A collector representation change requires a distinct collector partition.");
        var versions = new List<PersistenceVersion>();
        foreach (var (key, artifact) in inventory.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            var before = predecessor != null && predecessor.TryGetValue(key, out var previous) ? previous : null;
            if (before != null && before.SourceSchemaVersion != artifact.SourceSchemaVersion)
                throw new InvalidDataException("A collector representation change requires a distinct collector partition.");
            if (before != null && Fingerprint(before) == Fingerprint(artifact)) continue;
            versions.Add(new(collection.CollectionId, collection.StateGenerationId, result.CollectorId, result.Coverage,
                key, predecessor == null ? PersistenceChangeKind.Baseline : before == null
                    ? PersistenceChangeKind.Added : PersistenceChangeKind.Modified, before, artifact));
        }
        if (predecessor != null)
            foreach (var (key, before) in predecessor.Where(x => !inventory.ContainsKey(x.Key)).OrderBy(x => x.Key, StringComparer.Ordinal))
                versions.Add(new(collection.CollectionId, collection.StateGenerationId, result.CollectorId,
                    result.Coverage, key, PersistenceChangeKind.Removed, before, null));
        return versions;
    }

    public static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    public static IReadOnlyList<PersistenceBaselineDifference> CompareBaseline(PersistenceAcceptedState accepted)
    {
        var differences = new List<PersistenceBaselineDifference>();
        foreach (var (partition, current) in accepted.Previous.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            if (!accepted.Baseline.TryGetValue(partition, out var baseline) || !accepted.PartitionObservations.TryGetValue(partition, out var observation))
                throw new InvalidDataException("Baseline comparison requires exact accepted partition establishment and observation.");
            if (baseline.Count > 0 && current.Count > 0 && !baseline.Values.Select(a => a.SourceSchemaVersion).ToHashSet().SetEquals(current.Values.Select(a => a.SourceSchemaVersion)))
                throw new InvalidDataException("Baseline comparison representation differs.");
            foreach (var key in baseline.Keys.Union(current.Keys).Order(StringComparer.Ordinal))
            {
                var before = baseline.GetValueOrDefault(key); var after = current.GetValueOrDefault(key);
                if (before != null && after != null && Fingerprint(before) == Fingerprint(after)) continue;
                if (before != null && after != null && before.SourceSchemaVersion != after.SourceSchemaVersion)
                    throw new InvalidDataException("Baseline comparison representation differs.");
                differences.Add(new(accepted.Checkpoint.StateGenerationId, partition, key,
                    before == null ? PersistenceChangeKind.Added : after == null ? PersistenceChangeKind.Removed : PersistenceChangeKind.Modified,
                    before, after, observation));
            }
        }
        return differences.AsReadOnly();
    }

    public static bool IsUnattemptedStartupProfile(PersistenceCollectorResult result)
        => result.CollectorId == "persistence.startup-folders.v1" && result.Artifacts.Count == 0 &&
            result.Status == PersistenceCollectionStatus.Failed && result.Coverage.SourceAvailability == PersistenceSourceAvailability.Unavailable &&
            result.Coverage.RegistryView.Length == 0 && result.Coverage.UserSid.Length > 0 &&
            (result.Coverage.ProfileScope == "ExcludedUnloadedProfile" || result.Coverage.ProfileScope == "ExcludedServiceProfile" && result.Coverage.UserSid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") &&
            result.Coverage.PartitionId == result.Coverage.ProfileScope + ":" + result.Coverage.UserSid;

    public static void ValidateBoundaryUse(PersistenceCollection? previous, PersistenceCollection collection)
    {
        if (collection.BoundaryAcquisitionId == null)
        {
            if (collection.BoundaryPreviousPeriodId != null || previous?.BoundaryAcquisitionId != null && previous.CollectionId != previous.BoundaryAcquisitionId)
                throw new InvalidDataException("Persistence boundary provenance is incomplete.");
            return;
        }
        if (string.IsNullOrWhiteSpace(collection.BoundaryPreviousPeriodId) || collection.Results.All(IsUnattemptedStartupProfile) ||
            collection.Results.Where(r => !IsUnattemptedStartupProfile(r)).Any(r => r.Status != PersistenceCollectionStatus.Complete || r.Coverage.SourceAvailability != PersistenceSourceAvailability.Available))
            throw new InvalidDataException("Persistence boundary coverage is not coherent.");
        if (collection.CollectionId == collection.BoundaryAcquisitionId)
        {
            if (previous == null || previous.CollectionId != collection.CollectionId + ".final" ||
                previous.BoundaryAcquisitionId != collection.BoundaryAcquisitionId || previous.StateGenerationId != collection.BoundaryPreviousPeriodId ||
                previous.BoundaryPreviousPeriodId != collection.BoundaryPreviousPeriodId || previous.EvidenceIdentity != collection.EvidenceIdentity ||
                previous.SourceRunId != collection.SourceRunId || previous.IngestionJobId != collection.IngestionJobId ||
                previous.StartedUtc != collection.StartedUtc || previous.CompletedUtc != collection.CompletedUtc ||
                collection.CollectionSequence != 1 || collection.StateGenerationId == previous.StateGenerationId || collection.Reason != PersistenceCollectionReason.Rebaseline ||
                JsonSerializer.Serialize(previous.Results) != JsonSerializer.Serialize(collection.Results))
                throw new InvalidDataException("Persistence boundary uses disagree on acquisition provenance.");
        }
        else if (collection.CollectionId != collection.BoundaryAcquisitionId + ".final" || collection.StateGenerationId != collection.BoundaryPreviousPeriodId ||
            collection.Reason != PersistenceCollectionReason.UserRequested)
            throw new InvalidDataException("Persistence final differential use is invalid.");
    }
}
