namespace ProcInsider.Models.Persistence;

public enum PersistenceCollectionReason { Startup, Scheduled, UserRequested, Rebaseline, ComparisonStateRecovery }
public enum PersistenceCollectionStatus { Complete, Partial, Failed, Cancelled }
public enum PersistenceChangeKind { Baseline, Added, Modified, Removed, ObservedIncomplete }
public enum PersistenceValueState { Known, Unknown }
public enum PersistenceSourceAvailability { Available, Unavailable, Unknown }

/// <summary>Absent dictionary member, Unknown, JSON null and empty native value are distinct.</summary>
public sealed record PersistenceNativeValue(string NativeType, PersistenceValueState State, string Json,
    bool Unordered = false);

public sealed record PersistenceCoverage(string PartitionId, string UserSid, string RegistryView,
    string ProfileScope, PersistenceSourceAvailability SourceAvailability);

public sealed record PersistenceArtifact
{
    public required EvidenceIdentity EvidenceIdentity { get; init; }
    public required string CollectorId { get; init; }
    public required string Category { get; init; }
    public required PersistenceCoverage Coverage { get; init; }
    public required string NativeName { get; init; }
    public required string NativeLocation { get; init; }
    public string? Target { get; init; }
    public string? Command { get; init; }
    public string? Arguments { get; init; }
    public string? Principal { get; init; }
    public bool? Enabled { get; init; }
    public int SourceSchemaVersion { get; init; } = 1;
    public IReadOnlyDictionary<string, PersistenceNativeValue> Configuration { get; init; }
        = new Dictionary<string, PersistenceNativeValue>();
}

public sealed record PersistenceCollectorResult(string CollectorId, PersistenceCoverage Coverage,
    PersistenceCollectionStatus Status, IReadOnlyList<PersistenceArtifact> Artifacts,
    TimeSpan Duration, string DiagnosticSummary = "");

public sealed record PersistenceCollection
{
    public const string LocalSourceIdentityId = "persistence.local.v1";
    public required EvidenceIdentity EvidenceIdentity { get; init; }
    public required string SourceRunId { get; init; }
    public required string IngestionJobId { get; init; }
    public required string CollectionId { get; init; }
    public required string StateGenerationId { get; init; }
    public string? ExpectedPredecessorCollectionId { get; init; }
    public long CollectionSequence { get; init; }
    public PersistenceCollectionReason Reason { get; init; }
    public string ResetReason { get; init; } = "";
    // One real acquisition may have a final differential use and a new baseline use.
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? BoundaryAcquisitionId { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? BoundaryPreviousPeriodId { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? DeferredBaselineGenerationId { get; init; }
    public DateTime StartedUtc { get; init; }
    public DateTime CompletedUtc { get; init; }
    public IReadOnlyList<PersistenceCollectorResult> Results { get; init; } = [];
}

public sealed record PersistenceVersion(string CollectionId, string StateGenerationId, string CollectorId,
    PersistenceCoverage Coverage, string ArtifactKey, PersistenceChangeKind Kind,
    PersistenceArtifact? Before, PersistenceArtifact? After);
public sealed record PersistenceCurrent(string StateGenerationId, string CollectorId, PersistenceCoverage Coverage,
    string ArtifactKey, PersistenceArtifact Artifact, DateTime LastConfirmedUtc, bool Stale);
public sealed record PersistenceCheckpoint(string StateGenerationId, long CollectionSequence,
    string CollectionId);
public sealed record PersistenceAcceptance(string CollectionId, bool Replayed, PersistenceCollectionStatus Status,
    int VersionCount, bool BoundaryDeferred = false);

public sealed record PersistenceAcceptedState(EvidenceIdentity Scope, PersistenceCheckpoint Checkpoint,
    DateTime? PeriodStartedUtc, IReadOnlyDictionary<string, IReadOnlyDictionary<string, PersistenceArtifact>> Baseline,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, PersistenceArtifact>> Previous,
    IReadOnlyDictionary<string, PersistencePartitionObservation> PartitionObservations)
{
    public IReadOnlyList<PersistenceBaselineDifference> BaselineRelative { get; init; } = [];
}
public sealed record PersistencePartitionObservation(string CollectionId, DateTime ObservedUtc);
/// <summary>Derived B→P result, separate from immutable P→S transition evidence.</summary>
public sealed record PersistenceBaselineDifference(string PeriodId, string PartitionKey, string ArtifactKey,
    PersistenceChangeKind Kind, PersistenceArtifact? Baseline, PersistenceArtifact? Current,
    PersistencePartitionObservation Observation);

/// <summary>Collectors enumerate only; scheduling and durable acceptance belong to the Agent.</summary>
public interface IPersistenceCollector
{
    string CollectorId { get; }
    Task<IReadOnlyList<PersistenceCollectorResult>> CollectAsync(EvidenceIdentity identity,
        CancellationToken cancellationToken);
}
