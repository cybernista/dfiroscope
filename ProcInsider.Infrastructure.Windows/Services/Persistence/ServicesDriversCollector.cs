using System.Diagnostics;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

public sealed record ServicePersistenceNativeEntry(string Name, uint ServiceType, uint StartType, uint ErrorControl,
    string? DisplayName, string? ImagePath, string? Account, IReadOnlyList<string>? Dependencies,
    IReadOnlyDictionary<string, PersistenceNativeValue> NativeConfiguration);
public sealed record ServicePersistenceNativeIssue(string Name, string Category,
    IReadOnlyDictionary<string, PersistenceNativeValue> NativeConfiguration, string Diagnostic);
public sealed record ServicesDriversNativeSnapshot(PersistenceCollectionStatus Status, IReadOnlyList<ServicePersistenceNativeEntry> Entries,
    string Diagnostic, IReadOnlyList<ServicePersistenceNativeIssue>? Issues = null);
public interface IServicesDriversNativeReader { ServicesDriversNativeSnapshot Read(CancellationToken token); }

/// <summary>Services and Drivers share one authoritative partition and native location identity.</summary>
public sealed class ServicesDriversCollector(EvidenceIdentity identity, IServicesDriversNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.services-drivers.v1";
    public string CollectorId => Id;
    private readonly IServicesDriversNativeReader _reader = reader ?? new ServicesDriversNativeReader();
    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requestedIdentity, CancellationToken token)
    {
        if (requestedIdentity != identity) throw new InvalidDataException("Service collector scope mismatch.");
        token.ThrowIfCancellationRequested(); var watch = Stopwatch.StartNew();
        ServicesDriversNativeSnapshot snapshot;
        try { snapshot = _reader.Read(token); }
        catch (Exception ex) when (ServicesDriversNativeReader.ExpectedFailure(ex)) { snapshot = new(PersistenceCollectionStatus.Failed, [], "Service configuration unavailable; no removals inferred."); }
        var status = snapshot.Status; var artifacts = new List<PersistenceArtifact>();
        var invalidValues = new List<string>();
        foreach (var entry in snapshot.Entries)
        {
            token.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(entry.Name) || entry.Name.Length > 256 || !TryCategory(entry.ServiceType, out var category))
            { status = PersistenceCollectionStatus.Partial; continue; }
            var invalidActivation = entry.StartType > 4 || entry.ErrorControl > 3;
            if (invalidActivation)
            {
                status = PersistenceCollectionStatus.Partial;
                if (invalidValues.Count < 3) invalidValues.Add(entry.Name);
            }
            var configuration = new Dictionary<string, PersistenceNativeValue>(entry.NativeConfiguration, StringComparer.Ordinal)
            {
                ["DisplayName"] = Native("SCM_STRING", entry.DisplayName), ["ImagePath"] = Native("SCM_STRING", entry.ImagePath),
                ["ServiceType"] = Native("SCM_DWORD", entry.ServiceType), ["StartType"] = Native("SCM_DWORD", entry.StartType),
                ["ErrorControl"] = Native("SCM_DWORD", entry.ErrorControl), ["Account"] = Native("SCM_STRING", entry.Account),
                ["Dependencies"] = Native("SCM_MULTI_SZ", entry.Dependencies, unordered: true)
            };
            if (invalidActivation)
                configuration["ObservationIssue"] = Native("COLLECTOR_DIAGNOSTIC",
                    "Service Start or ErrorControl DWORD is outside the supported range; activation is unknown.");
            artifacts.Add(new() { EvidenceIdentity = identity, CollectorId = Id, Category = category,
                Coverage = Coverage(PersistenceSourceAvailability.Available), NativeName = entry.Name,
                NativeLocation = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + entry.Name,
                Command = entry.ImagePath, Principal = entry.Account,
                Enabled = invalidActivation ? null : entry.StartType != 4, Configuration = configuration });
        }
        foreach (var issue in snapshot.Issues ?? [])
        {
            token.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(issue.Name) || issue.Name.Length > 256 || issue.Category is not ("Services" or "Drivers"))
            { status = PersistenceCollectionStatus.Partial; continue; }
            status = PersistenceCollectionStatus.Partial;
            var configuration = new Dictionary<string, PersistenceNativeValue>(issue.NativeConfiguration, StringComparer.Ordinal)
            {
                ["ObservationIssue"] = Native("COLLECTOR_DIAGNOSTIC", issue.Diagnostic)
            };
            artifacts.Add(new() { EvidenceIdentity = identity, CollectorId = Id, Category = issue.Category,
                Coverage = Coverage(PersistenceSourceAvailability.Unavailable), NativeName = issue.Name,
                NativeLocation = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + issue.Name,
                Command = OptionalText(configuration, "Registry.ImagePath"),
                Principal = OptionalText(configuration, "Registry.ObjectName"),
                Enabled = null, Configuration = configuration });
        }
        var coverage = Coverage(status == PersistenceCollectionStatus.Complete ? PersistenceSourceAvailability.Available : PersistenceSourceAvailability.Unavailable);
        var frozen = artifacts.Select(artifact => artifact with { Coverage = coverage }).ToArray();
        var diagnostic = invalidValues.Count == 0 ? snapshot.Diagnostic :
            snapshot.Diagnostic + " Invalid Start/ErrorControl for " + string.Join(", ", invalidValues) + "; affected entries are unconfirmed.";
        return Task.FromResult<IReadOnlyList<PersistenceCollectorResult>>([new(Id, coverage, status, frozen, watch.Elapsed,
            diagnostic.Length > 2048 ? diagnostic[..2048] : diagnostic)]);
    }
    internal static bool TryCategory(uint type, out string category)
    {
        var driver = type & 0xB; var win32 = type & 0x30;
        if ((type & ~0x3FBu) != 0 || driver != 0 && (type != 1 && type != 2 && type != 8) || driver == 0 && win32 is not (0x10 or 0x20)) { category = ""; return false; }
        category = driver != 0 ? "Drivers" : "Services"; return true;
    }
    internal static PersistenceCoverage Coverage(PersistenceSourceAvailability availability) => new("LocalServiceConfigurations", "", "", "MachineServicesAndDrivers", availability);
    private static PersistenceNativeValue Native(string type, object? value, bool unordered = false) => new(type, PersistenceValueState.Known, JsonSerializer.Serialize(value), unordered);
    private static string? OptionalText(IReadOnlyDictionary<string, PersistenceNativeValue> native, string field)
    {
        if (!native.TryGetValue(field, out var value) || value.State != PersistenceValueState.Known ||
            value.NativeType is not ("REG_TYPE_1" or "REG_TYPE_2")) return null;
        try { return PersistenceRegistryNativeReader.Text(value); }
        catch (Exception ex) when (ex is InvalidDataException or JsonException) { return null; }
    }
}
