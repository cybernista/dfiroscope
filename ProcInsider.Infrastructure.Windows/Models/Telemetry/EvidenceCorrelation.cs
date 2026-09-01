using System;
using System.Collections.Generic;

namespace ProcInsider.Models;

public sealed class EvidenceCorrelationInput : IHasEvidenceIdentity
{
    public string InputId { get; set; } = string.Empty;
    public EvidenceReferenceKind EvidenceKind { get; set; } = EvidenceReferenceKind.GenericArtifact;
    public string EvidenceId { get; set; } = string.Empty;
    public string EvidenceType { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public EvidenceRelationType RelationType { get; set; } = EvidenceRelationType.CorrelatesWith;
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string RawInputId { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public DateTime? ProcessStartTimeUtc { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public string SourceNativeId { get; set; } = string.Empty;
    public string SourceEndpoint { get; set; } = string.Empty;
    public string DestinationEndpoint { get; set; } = string.Empty;
    public DateTime ObservedUtc { get; set; }
    public DateTime CreatedUtc { get; set; }

    // Active decision projection. These values are derived from EvidenceRelations and do not
    // replace or mutate the source evidence row represented by this input.
    public EvidenceCorrelationState CurrentState { get; set; } = EvidenceCorrelationState.Unresolved;
    public string CurrentProcessEntityId { get; set; } = string.Empty;
    public string CurrentMethod { get; set; } = string.Empty;
    public double CurrentConfidence { get; set; }
    public int CandidateCount { get; set; }
    public string CorrelationDiagnostics { get; set; } = string.Empty;
    public string ResolverVersion { get; set; } = string.Empty;

    public string DecisionKey => EvidenceKind switch
    {
        EvidenceReferenceKind.Event => $"event:{EvidenceId}:process",
        EvidenceReferenceKind.MemoryProcess => $"memory-process:{EvidenceId}:process",
        EvidenceReferenceKind.NetworkFlow => $"zeek:{EvidenceId}:process",
        _ => $"correlation:{EvidenceKind}:{EvidenceId}:process"
    };

    public EvidenceIdentity Identity => new()
    {
        CaseId = CaseId,
        EvidenceSessionId = EvidenceSessionId,
        CaptureId = CaptureId,
        SourceIdentityId = SourceIdentityId,
        HostId = HostId,
        ExecutionRootId = ExecutionRootId
    };
}

public sealed record ProcessCorrelationCandidate
{
    public string ProcessEntityId { get; init; } = string.Empty;
    public string ProcessKey { get; init; } = string.Empty;
    public int ProcessId { get; init; }
    public string ProcessGuid { get; init; } = string.Empty;
    public DateTime? StartTimeUtc { get; init; }
    public DateTime? EndTimeUtc { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ProcessPath { get; init; } = string.Empty;
    public EvidenceIdentity Identity { get; init; } = new();
    public IReadOnlyList<ProcessAlias> Aliases { get; init; } = Array.Empty<ProcessAlias>();
}

public sealed record EvidenceCorrelationResolution(
    EvidenceRelation Decision,
    int CompatibleCandidateCount,
    int RejectedScopeCandidateCount);

public sealed class EvidenceReCorrelationRequest
{
    public EvidenceCorrelationState? State { get; init; }
    public EvidenceReferenceKind? EvidenceKind { get; init; }
    public string Source { get; init; } = string.Empty;
    public string CaseId { get; init; } = string.Empty;
    public string EvidenceSessionId { get; init; } = string.Empty;
    public string HostId { get; init; } = string.Empty;
    public string ExecutionRootId { get; init; } = string.Empty;
    public int? ProcessId { get; init; }
    public string ProcessGuid { get; init; } = string.Empty;
    public bool IncludeAlreadyResolved { get; init; }
    public int MaxCount { get; init; } = 100;
}

public sealed record EvidenceReCorrelationResult(
    int ExaminedCount,
    int ChangedCount,
    int UnchangedCount,
    int ExactCount,
    int InferredCount,
    int AmbiguousCount,
    int UnresolvedCount,
    bool ReachedLimit,
    string ResolverVersion);

public sealed record EvidenceCorrelationGroupSummary(
    EvidenceCorrelationState State,
    EvidenceReferenceKind EvidenceKind,
    string Source,
    int Count);
