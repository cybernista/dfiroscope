using System.Diagnostics;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

public enum RegistryPersistenceFamily { Winlogon, IFEO, AppInit, LSA }
public sealed record RegistryConfigurationEntry(string Name, string Location,
    IReadOnlyDictionary<string, PersistenceNativeValue> Configuration, string? Command = null, bool? Enabled = null);
public sealed record RegistryConfigurationPartition(string Hive, string Sid, string View, string Path,
    PersistenceCollectionStatus Status, IReadOnlyList<RegistryConfigurationEntry> Entries, string Diagnostic);
public interface IRegistryConfigurationNativeReader
{
    IReadOnlyList<RegistryConfigurationPartition> Read(CancellationToken token);
}

public sealed class WinlogonCollector(EvidenceIdentity identity, IRegistryConfigurationNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.winlogon.v1";
    public string CollectorId => Id;
    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requested, CancellationToken token)
        => RegistryConfigurationCollection.Collect(identity, requested, RegistryPersistenceFamily.Winlogon, Id, reader, token);
}
public sealed class IfeoCollector(EvidenceIdentity identity, IRegistryConfigurationNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.ifeo.v1";
    public string CollectorId => Id;
    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requested, CancellationToken token)
        => RegistryConfigurationCollection.Collect(identity, requested, RegistryPersistenceFamily.IFEO, Id, reader, token);
}
public sealed class AppInitCollector(EvidenceIdentity identity, IRegistryConfigurationNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.appinit.v1";
    public string CollectorId => Id;
    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requested, CancellationToken token)
        => RegistryConfigurationCollection.Collect(identity, requested, RegistryPersistenceFamily.AppInit, Id, reader, token);
}
public sealed class LsaCollector(EvidenceIdentity identity, IRegistryConfigurationNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.lsa.v1";
    public string CollectorId => Id;
    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requested, CancellationToken token)
        => RegistryConfigurationCollection.Collect(identity, requested, RegistryPersistenceFamily.LSA, Id, reader, token);
}

internal static class RegistryConfigurationCollection
{
    internal static Task<IReadOnlyList<PersistenceCollectorResult>> Collect(EvidenceIdentity identity, EvidenceIdentity requested,
        RegistryPersistenceFamily family, string id, IRegistryConfigurationNativeReader? reader, CancellationToken token)
    {
        if (requested != identity) throw new InvalidDataException("Registry configuration collector scope mismatch.");
        token.ThrowIfCancellationRequested(); var watch = Stopwatch.StartNew();
        IReadOnlyList<RegistryConfigurationPartition> partitions;
        try { partitions = (reader ?? new RegistryConfigurationNativeReader(family)).Read(token); }
        catch (Exception error) when (ServicesDriversNativeReader.ExpectedFailure(error))
        { partitions = [new("HKEY_LOCAL_MACHINE", "", "Shared", family.ToString(), PersistenceCollectionStatus.Failed, [], "Declared registry family unavailable; no removals inferred.")]; }
        var incomplete = partitions.Any(partition => partition.Status != PersistenceCollectionStatus.Complete);
        var results = new List<PersistenceCollectorResult>();
        foreach (var partition in partitions)
        {
            token.ThrowIfCancellationRequested();
            var status = incomplete ? partition.Entries.Count == 0 ? PersistenceCollectionStatus.Failed : PersistenceCollectionStatus.Partial : PersistenceCollectionStatus.Complete;
            var coverage = new PersistenceCoverage(partition.Hive + "\\" + partition.Path, partition.Sid, partition.View,
                partition.Sid.Length == 0 ? "DeclaredMachineRegistryConfiguration" : "AccessibleLoadedUserHive",
                incomplete ? PersistenceSourceAvailability.Unavailable : PersistenceSourceAvailability.Available);
            var artifacts = partition.Entries.Select(entry => new PersistenceArtifact
            {
                EvidenceIdentity = identity, CollectorId = id, Category = family.ToString(), Coverage = coverage,
                NativeName = entry.Name, NativeLocation = entry.Location, Principal = partition.Sid.Length == 0 ? null : partition.Sid,
                Command = entry.Command, Enabled = entry.Enabled, Configuration = entry.Configuration
            }).ToArray();
            results.Add(new(id, coverage, status, artifacts, watch.Elapsed, incomplete
                ? partition.Diagnostic + " Attempted family incomplete; previous state and confirmation retained." : partition.Diagnostic));
        }
        return Task.FromResult<IReadOnlyList<PersistenceCollectorResult>>(results);
    }
}
