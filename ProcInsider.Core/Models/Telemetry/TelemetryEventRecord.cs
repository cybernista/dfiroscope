using System;

namespace ProcInsider.Models;

public class TelemetryEventRecord : IHasProcessEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public long SequenceId { get; set; }
    public DateTime TimestampUtc { get; set; }
    public string Source { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public DateTime? ProcessStartTimeUtc { get; set; }
    public string ProcessName { get; set; } = "<unknown>";
    public int ParentProcessId { get; set; }
    public int? EventCode { get; set; }
    public ProcessEventCategory Category { get; set; }
    public ProcessEventAction Action { get; set; }
    public string Target { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string RiskFlags { get; set; } = string.Empty;
    public bool IsInteresting { get; set; }
    public int RepeatCount { get; set; } = 1;
    public string RawProvider { get; set; } = string.Empty;
    public string RawLogName { get; set; } = string.Empty;
    public string RawRecordId { get; set; } = string.Empty;
    public string CorrelationMethod { get; set; } = string.Empty;
    public string ProcessEntityId { get; set; } = string.Empty;
    public EvidenceCorrelationState CorrelationState { get; set; } = EvidenceCorrelationState.Unresolved;
    public int CorrelationCandidateCount { get; set; }
    public string CorrelationDiagnostics { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;

    public ProcessEventInfo ToProcessEventInfo()
    {
        return new ProcessEventInfo
        {
            SequenceId = SequenceId,
            TimestampUtc = TimestampUtc,
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            ProcessGuid = ProcessGuid,
            ProcessStartTimeUtc = ProcessStartTimeUtc,
            ProcessName = ProcessName,
            ParentProcessId = ParentProcessId,
            EventCode = EventCode,
            Category = Category,
            Action = Action,
            Target = Target,
            Summary = Summary,
            Details = Details,
            RiskFlags = RiskFlags,
            IsInteresting = IsInteresting,
            RepeatCount = RepeatCount,
            ProcessEntityId = ProcessEntityId,
            SourceRunId = SourceRunId,
            IngestionJobId = IngestionJobId
        };
    }
}
