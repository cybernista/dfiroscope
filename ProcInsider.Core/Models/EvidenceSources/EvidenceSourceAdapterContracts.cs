using System;
using System.Collections.Generic;

namespace ProcInsider.Models.EvidenceSources;

public enum EvidenceSourceCategory
{
    PrimaryAcquisition,
    DirectInspection,
    Importer,
    DerivedAnalyzer,
    CompatibilityOnly
}

[Flags]
public enum EvidenceSourceCapability
{
    None = 0,
    ProcessObservations = 1 << 0,
    ProcessStatistics = 1 << 1,
    Events = 1 << 2,
    IndependentArtifacts = 1 << 3,
    Relationships = 1 << 4,
    RawReferences = 1 << 5,
    DerivationLineage = 1 << 6,
    IncrementalPublication = 1 << 7,
    LiveCollection = 1 << 8
}

public enum EvidenceSourcePrerequisiteKind
{
    Capability,
    File,
    Directory,
    Executable,
    EnvironmentVariable,
    SourceRun
}

public enum EvidenceRawPreservationMode
{
    None,
    FileReference,
    HashAndFileReference,
    BoundedInlineAndFileReference
}

public enum EvidenceSourceCompletionState
{
    Completed,
    Partial,
    Failed,
    Cancelled
}

public enum EvidenceSourceDiagnosticSeverity
{
    Information,
    Warning,
    Error
}

public sealed record EvidenceSourcePrerequisite
{
    public string PrerequisiteId { get; init; } = string.Empty;

    public EvidenceSourcePrerequisiteKind Kind { get; init; }

    public string Description { get; init; } = string.Empty;

    public bool IsRequired { get; init; } = true;
}

public sealed record EvidenceRawPreservationPolicy
{
    public EvidenceRawPreservationMode Mode { get; init; }

    public int MaxInlineBytes { get; init; }

    public bool RequireContentHash { get; init; }
}

/// <summary>
/// Serializable source capability metadata shared with the viewer. Operational
/// job names remain separate from this stable adapter identity.
/// </summary>
public sealed record EvidenceSourceAdapterDescriptor
{
    public string AdapterId { get; init; } = string.Empty;

    public string AdapterVersion { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    public EvidenceSourceCategory Category { get; init; }

    public EvidenceSourceCapability Capabilities { get; init; }

    public bool IsPublished { get; init; } = true;

    public int MaxBatchRowCount { get; init; } = 512;

    public EvidenceRawPreservationPolicy RawPreservation { get; init; } = new();

    public IReadOnlyList<EvidenceSourcePrerequisite> Prerequisites { get; init; } =
        Array.Empty<EvidenceSourcePrerequisite>();
}

/// <summary>
/// One scheduler-owned invocation. Payload is adapter-specific; durable scope,
/// provenance, and available prerequisites remain explicit and common.
/// </summary>
public sealed record EvidenceSourceAdapterRequest
{
    public string SourceRunId { get; init; } = string.Empty;

    public Guid IngestionJobId { get; init; }

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string ParentSourceRunId { get; init; } = string.Empty;

    public string InputArtifactId { get; init; } = string.Empty;

    public string InputPath { get; init; } = string.Empty;

    public string InputHash { get; init; } = string.Empty;

    public object? Payload { get; init; }

    public IReadOnlySet<string> AvailablePrerequisiteIds { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}

public sealed record EvidenceSourceValidationResult
{
    public bool IsValid => Errors.Count == 0;

    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();

    public static EvidenceSourceValidationResult Valid { get; } = new();
}

public sealed record EvidenceSourceDiagnostic
{
    public string Code { get; init; } = string.Empty;

    public EvidenceSourceDiagnosticSeverity Severity { get; init; }

    public string Message { get; init; } = string.Empty;

    public string EvidenceId { get; init; } = string.Empty;

    public bool IsRetryable { get; init; }
}

/// <summary>
/// Stable source-native identity and deduplication identity for one emitted row.
/// It is intentionally separate from ProcessKey so independent artifacts and
/// unresolved relationships can participate in the same contract.
/// </summary>
public sealed record EvidenceSourceEmissionIdentity
{
    public EvidenceReferenceKind EvidenceKind { get; init; }

    public string EvidenceId { get; init; } = string.Empty;

    public string ExternalIdentity { get; init; } = string.Empty;

    public string DeduplicationKey { get; init; } = string.Empty;

    public string RawReference { get; init; } = string.Empty;
}

/// <summary>
/// Typed, bounded publication unit. Established evidence families stay typed;
/// adapters do not flatten them into a universal property bag.
/// </summary>
public sealed record EvidenceSourceEmissionBatch
{
    public string SourceRunId { get; init; } = string.Empty;

    public Guid IngestionJobId { get; init; }

    public int Sequence { get; init; }

    public bool IsFinalBatch { get; init; }

    public IReadOnlyList<ProcessRecord> Processes { get; init; } = Array.Empty<ProcessRecord>();

    public IReadOnlyList<ProcessObservation> ProcessObservations { get; init; } =
        Array.Empty<ProcessObservation>();

    public IReadOnlyList<ProcessAlias> ProcessAliases { get; init; } =
        Array.Empty<ProcessAlias>();

    public IReadOnlyList<ProcessStatisticsRecord> ProcessStatistics { get; init; } =
        Array.Empty<ProcessStatisticsRecord>();

    public IReadOnlyList<TelemetryEventRecord> Events { get; init; } =
        Array.Empty<TelemetryEventRecord>();

    public IReadOnlyList<FilesystemArtifactRecord> FilesystemArtifacts { get; init; } =
        Array.Empty<FilesystemArtifactRecord>();

    public IReadOnlyList<NetworkCaptureRecord> NetworkCaptures { get; init; } =
        Array.Empty<NetworkCaptureRecord>();

    public IReadOnlyList<ZeekNetworkRecord> ZeekNetworkArtifacts { get; init; } =
        Array.Empty<ZeekNetworkRecord>();

    public IReadOnlyList<MemoryImageRecord> MemoryImages { get; init; } =
        Array.Empty<MemoryImageRecord>();

    public IReadOnlyList<VolatilityPluginRunRecord> VolatilityPluginRuns { get; init; } =
        Array.Empty<VolatilityPluginRunRecord>();

    public IReadOnlyList<MemoryProcessRecord> MemoryProcesses { get; init; } =
        Array.Empty<MemoryProcessRecord>();

    public IReadOnlyList<EvidenceRelation> Relations { get; init; } =
        Array.Empty<EvidenceRelation>();

    public IReadOnlyList<EvidenceSourceEmissionIdentity> Identities { get; init; } =
        Array.Empty<EvidenceSourceEmissionIdentity>();

    public IReadOnlyList<EvidenceSourceDiagnostic> Diagnostics { get; init; } =
        Array.Empty<EvidenceSourceDiagnostic>();

    public int RowCount =>
        Processes.Count +
        ProcessObservations.Count +
        ProcessAliases.Count +
        ProcessStatistics.Count +
        Events.Count +
        FilesystemArtifacts.Count +
        NetworkCaptures.Count +
        ZeekNetworkArtifacts.Count +
        MemoryImages.Count +
        VolatilityPluginRuns.Count +
        MemoryProcesses.Count +
        Relations.Count;
}

public sealed record EvidenceSourcePublishResult
{
    public int PersistedRowCount { get; init; }

    public int DuplicateRowCount { get; init; }

    public IReadOnlyList<EvidenceSourceDiagnostic> Diagnostics { get; init; } =
        Array.Empty<EvidenceSourceDiagnostic>();
}

public sealed record EvidenceSourceProgress
{
    public string AdapterId { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public long ReceivedCount { get; init; }

    public long NormalizedCount { get; init; }

    public long UnresolvedCount { get; init; }

    public long AmbiguousCount { get; init; }

    public long DuplicateCount { get; init; }

    public long PersistedCount { get; init; }

    public long FailedCount { get; init; }

    public string Message { get; init; } = string.Empty;
}

public sealed record EvidenceSourceExecutionResult
{
    public EvidenceSourceCompletionState State { get; init; }

    public long ReceivedCount { get; init; }

    public long NormalizedCount { get; init; }

    public long UnresolvedCount { get; init; }

    public long AmbiguousCount { get; init; }

    public long DuplicateCount { get; init; }

    public long PersistedCount { get; init; }

    public long FailedCount { get; init; }

    public IReadOnlyList<EvidenceSourceDiagnostic> Diagnostics { get; init; } =
        Array.Empty<EvidenceSourceDiagnostic>();
}

public interface IEvidenceSourcePublisher
{
    int MaxBatchRowCount { get; }

    ValueTask<EvidenceSourcePublishResult> PublishAsync(
        EvidenceSourceEmissionBatch batch,
        CancellationToken cancellationToken);
}

public interface IEvidenceSourceAdapter
{
    EvidenceSourceAdapterDescriptor Descriptor { get; }

    Type InputType { get; }

    EvidenceSourceValidationResult Validate(EvidenceSourceAdapterRequest request);

    ValueTask<EvidenceSourceExecutionResult> ExecuteAsync(
        EvidenceSourceAdapterRequest request,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken);
}

public sealed class EvidenceSourceValidationException : InvalidOperationException
{
    public EvidenceSourceValidationException(string adapterId, IReadOnlyList<string> errors)
        : base($"Evidence source adapter '{adapterId}' rejected its input: {string.Join("; ", errors)}")
    {
        AdapterId = adapterId;
        Errors = errors;
    }

    public string AdapterId { get; }

    public IReadOnlyList<string> Errors { get; }
}

public sealed class EvidenceSourcePublishException : Exception
{
    public EvidenceSourcePublishException(string message, int persistedRowCount, Exception innerException)
        : base(message, innerException)
    {
        PersistedRowCount = Math.Max(0, persistedRowCount);
    }

    public int PersistedRowCount { get; }
}
