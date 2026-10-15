namespace ProcInsider.Models.Ai;

public sealed record AiProcessReference(
    string ProcessEntityId,
    string ProcessKey,
    string CaseId,
    string EvidenceSessionId,
    string CaptureId,
    string SourceIdentityId,
    string HostId,
    string ExecutionRootId);
