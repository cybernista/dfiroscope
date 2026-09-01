using System;
using System.Collections.Generic;

namespace ProcInsider.Models;

public enum ProcessObservationValueState
{
    Available,
    NotCollected,
    Unavailable,
    AccessDenied
}

public enum ProcessCorrelationMethod
{
    ExactScopedPidStartTime,
    SourceNativeAlias,
    SysmonProcessGuid,
    ExactMemoryPidCreateTime,
    LegacyCompatibility
}

public enum ProcessObservationKind
{
    PeriodicSnapshot,
    RuntimeLifecycle,
    WmiLifecycle,
    EtwLifecycle,
    SysmonProcessCreate,
    SysmonProcessTerminate,
    ProcmonSyntheticProcess,
    VolatilityMemoryProcess,
    LegacyCompatibility
}

public sealed class ProcessObservation
{
    public string ObservationId { get; set; } = string.Empty;
    public string AdapterId { get; set; } = string.Empty;
    public ProcessObservationKind ObservationKind { get; set; } = ProcessObservationKind.LegacyCompatibility;
    public string ProcessEntityId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public Guid? IngestionJobId { get; set; }
    public string RawRecordId { get; set; } = string.Empty;
    public string SourceNativeAlias { get; set; } = string.Empty;
    public DateTime ObservedUtc { get; set; }
    public DateTime? ValidFromUtc { get; set; }
    public DateTime? ValidToUtc { get; set; }
    public ProcessStatus StatusAssertion { get; set; }
    public ProcessCorrelationMethod CorrelationMethod { get; set; }
    public double CorrelationConfidence { get; set; }
    public string ParserVersion { get; set; } = string.Empty;
    public string MetadataJson { get; set; } = "{}";
    public Dictionary<string, ProcessObservationValueState> FieldStates { get; set; } = new(StringComparer.Ordinal);
    public ProcessRecord Fields { get; set; } = new();
}

public sealed record ProcessObservationWriteResult(
    int PersistedObservationCount,
    int DuplicateObservationCount,
    int PersistedAliasCount,
    int DuplicateAliasCount,
    int PersistedStatisticsCount)
{
    public int PersistedRowCount =>
        PersistedObservationCount + PersistedAliasCount + PersistedStatisticsCount;

    public int DuplicateRowCount => DuplicateObservationCount + DuplicateAliasCount;
}

public sealed record ProcessProjectionFieldWinner(
    string FieldName,
    string ObservationId,
    string SourceRunId,
    int ValueQuality,
    string ResolutionReason);

public sealed record ProcessProjectionResolution(
    ProcessRecord Process,
    IReadOnlyList<ProcessProjectionFieldWinner> Winners,
    int ConflictCount);

public sealed class ProcessProjectionDiagnostics
{
    public int ObservationCount { get; set; }
    public int UnresolvedEntityLinkCount { get; set; }
    public int ProjectionConflictCount { get; set; }
    public string ProjectionVersion { get; set; } = string.Empty;
    public DateTime? LastRebuildUtc { get; set; }
}
