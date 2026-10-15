using System.Diagnostics;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Persistence;

namespace ProcInsider.Services.Persistence;

public sealed record RegistryRunNativeValue(string Name, string NativeType, object? UnexpandedData, byte[]? NativeBytes = null);
public sealed record RegistryRunNativePartition(string Hive, string UserSid, string View, string Key,
    PersistenceCollectionStatus Status, IReadOnlyList<RegistryRunNativeValue> Values, string Diagnostic);

/// <summary>Read-only seam; an inaccessible hive is never a complete empty key.</summary>
public interface IRegistryRunNativeReader
{
    IReadOnlyList<RegistryRunNativePartition> Read(CancellationToken cancellationToken);
}

public sealed class RegistryRunCollector(EvidenceIdentity identity, IRegistryRunNativeReader? reader = null) : IPersistenceCollector
{
    public const string Id = "persistence.registry-run.v1";
    public string CollectorId => Id;
    private readonly IRegistryRunNativeReader _reader = reader ?? new RegistryRunNativeReader();

    public Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity requestedIdentity, CancellationToken cancellationToken)
    {
        if (requestedIdentity != identity) throw new InvalidDataException("Registry collector scope mismatch.");
        var watch = Stopwatch.StartNew();
        var results = new List<PersistenceCollectorResult>();
        foreach (var partition in _reader.Read(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var coverage = new PersistenceCoverage(partition.Hive + "\\" + partition.Key, partition.UserSid,
                partition.View, partition.Hive == "HKEY_LOCAL_MACHINE" ? "Machine" : "AccessibleLoadedUserHive",
                partition.Status == PersistenceCollectionStatus.Complete ? PersistenceSourceAvailability.Available : PersistenceSourceAvailability.Unavailable);
            var artifacts = partition.Values.Select(value => new PersistenceArtifact
            {
                EvidenceIdentity = identity, CollectorId = Id, Category = partition.Key.EndsWith("RunOnce", StringComparison.Ordinal) ? "RunOnce" : "Run",
                Coverage = coverage, NativeName = value.Name,
                NativeLocation = partition.Hive + (partition.UserSid.Length == 0 ? "" : "\\" + partition.UserSid) + "\\" + partition.Key,
                Command = value.UnexpandedData as string,
                Configuration = new Dictionary<string, PersistenceNativeValue>
                {
                    ["NativeData"] = new(value.NativeType, PersistenceValueState.Known, JsonSerializer.Serialize(value.UnexpandedData)),
                    ["NativeBytes"] = new(value.NativeType, value.NativeBytes == null ? PersistenceValueState.Unknown : PersistenceValueState.Known, JsonSerializer.Serialize(value.NativeBytes))
                }
            }).ToArray();
            results.Add(new(Id, coverage, partition.Status, artifacts, watch.Elapsed, partition.Diagnostic));
        }
        return Task.FromResult<IReadOnlyList<PersistenceCollectorResult>>(results);
    }
}
