using System;
using System.Collections.Generic;

namespace ProcInsider.Models;

public enum EvidenceReferenceKind
{
    ProcessEntity,
    ProcessObservation,
    Event,
    Module,
    Handle,
    FileArtifact,
    NetworkFlow,
    Account,
    MemoryImage,
    MemoryProcess,
    Capture,
    SourceRun,
    RawRecord,
    VolatilityPluginRun,
    PeAnalysis,
    ProcessStatistic,
    MemoryDump,
    GenericArtifact,
    AuthenticodeVerification,
    EvidenceRelation
}

public enum EvidenceRelationType
{
    Spawned,
    ObservedProcess,
    Loaded,
    Opened,
    Created,
    ConnectedTo,
    ResolvedTo,
    ExtractedFrom,
    DerivedFrom,
    OwnedBy,
    CorrelatesWith
}

public enum EvidenceRelationStatus
{
    Active,
    Superseded
}

public sealed record EvidenceReference(EvidenceReferenceKind Kind, string Id)
{
    public bool IsEmpty => string.IsNullOrWhiteSpace(Id);
}

public sealed class EvidenceRelation : IHasEvidenceIdentity
{
    public string RelationId { get; set; } = string.Empty;
    public string DecisionKey { get; set; } = string.Empty;
    public EvidenceReferenceKind FromKind { get; set; }
    public string FromId { get; set; } = string.Empty;
    public EvidenceReferenceKind ToKind { get; set; }
    public string ToId { get; set; } = string.Empty;
    public EvidenceRelationType RelationType { get; set; }
    public EvidenceCorrelationState State { get; set; }
    public string CorrelationMethod { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public int CandidateCount { get; set; }
    public string CorrelationDiagnostics { get; set; } = string.Empty;
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string RawInputId { get; set; } = string.Empty;
    public DateTime ObservedFromUtc { get; set; }
    public DateTime? ObservedToUtc { get; set; }
    public DateTime? ValidFromUtc { get; set; }
    public DateTime? ValidToUtc { get; set; }
    public string ResolverName { get; set; } = string.Empty;
    public string ResolverVersion { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; }
    public DateTime UpdatedUtc { get; set; }
    public EvidenceRelationStatus Status { get; set; } = EvidenceRelationStatus.Active;
    public string SupersededByRelationId { get; set; } = string.Empty;
    public string AnalystAnnotationId { get; set; } = string.Empty;
}

public sealed class EvidenceRelationQuery
{
    public EvidenceReferenceKind? ReferenceKind { get; set; }
    public string ReferenceId { get; set; } = string.Empty;
    public string ProcessEntityId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public DateTime? TimelineFromUtc { get; set; }
    public DateTime? TimelineToUtc { get; set; }
    public bool IncludeSuperseded { get; set; }
    public IReadOnlyList<EvidenceCorrelationState> States { get; set; } = Array.Empty<EvidenceCorrelationState>();
    public int MaxCount { get; set; } = 200;
}
