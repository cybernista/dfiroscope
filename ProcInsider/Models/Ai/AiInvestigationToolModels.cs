namespace ProcInsider.Models.Ai;

public enum AiInvestigationToolAvailability
{
    Available = 0,
    Unavailable = 1,
    InvalidRequest = 2,
    NotFound = 3,
    Ambiguous = 4,
    IdentityMismatch = 5,
    NotEvaluated = 6
}

public sealed record AiEvidenceReadDiagnostics(
    bool IsReadable,
    string ReadPath,
    string StatusCode,
    string Message);

public sealed record AiProcessReference(
    string ProcessEntityId,
    string ProcessKey,
    string CaseId,
    string EvidenceSessionId,
    string CaptureId,
    string SourceIdentityId,
    string HostId,
    string ExecutionRootId);

public sealed record AiProcessSummary(
    AiProcessReference Reference,
    int ProcessId,
    string ProcessName,
    string ProcessPath,
    string CommandLine,
    string UserName,
    string Status,
    DateTime? StartTimeUtc,
    DateTime? EndTimeUtc,
    string ParentProcessEntityId,
    string ParentProcessKey,
    string ParentProcessName);

public sealed record AiRelatedProcessEvent(
    long SequenceId,
    DateTime TimestampUtc,
    int? EventCode,
    string Category,
    string Action,
    string Target,
    string Summary,
    string Details,
    string RiskFlags,
    int RepeatCount,
    string SourceRunId);

public sealed record AiProcessListRequest(bool IncludeExited = true, int MaxCount = 50);

public sealed class AiProcessListResult
{
    public AiInvestigationToolAvailability Availability { get; init; }

    public string StatusMessage { get; init; } = string.Empty;

    public IReadOnlyList<AiProcessSummary> Processes { get; init; } = [];

    public int AvailableCount { get; init; }

    public bool IsTruncated { get; init; }

    public AiEvidenceReadDiagnostics Diagnostics { get; init; } =
        new(false, "Unavailable", "evidence.path.unavailable", "No evidence read path is available.");
}

public sealed record AiProcessContextRequest(
    AiProcessReference Process,
    int MaxChildren = 25,
    int MaxEvents = 25);

public sealed class AiProcessContextResult
{
    public AiInvestigationToolAvailability Availability { get; init; }

    public string StatusMessage { get; init; } = string.Empty;

    public AiProcessSummary? SelectedProcess { get; init; }

    public AiProcessSummary? ParentProcess { get; init; }

    public AiInvestigationToolAvailability ParentAvailability { get; init; } =
        AiInvestigationToolAvailability.NotEvaluated;

    public string ParentStatusMessage { get; init; } = string.Empty;

    public IReadOnlyList<AiProcessSummary> ImmediateChildren { get; init; } = [];

    public int ObservedChildCount { get; init; }

    public bool ChildCountIsExact { get; init; }

    public bool ChildrenTruncated { get; init; }

    public IReadOnlyList<AiRelatedProcessEvent> RelatedEvents { get; init; } = [];

    public int ObservedEventCount { get; init; }

    public bool EventCountIsExact { get; init; }

    public bool EventsTruncated { get; init; }

    public AiEvidenceReadDiagnostics Diagnostics { get; init; } =
        new(false, "Unavailable", "evidence.path.unavailable", "No evidence read path is available.");
}
