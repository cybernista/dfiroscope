using ProcInsider.Models.Analysis;

namespace ProcInsider.Models.Ai;

public enum InvestigationState { New, Investigating, NeedsEvidence, NeedsHumanDecision, Completed, Closed, Failed, Cancelled }
public enum InvestigationTaskState { Pending, Running, NeedsEvidence, Completed, Failed, Cancelled }
public enum HypothesisState { Active, Supported, Rejected, Unresolved }
public enum FindingVerificationState { NotVerified, Supported, WeaklySupported, Contradicted, NeedsMoreEvidence, AnalystVerified }
public enum AgentExecutionState { Running, Completed, Failed, Cancelled, Interrupted }
public enum AgentToolCallState { Running, Completed, Failed, Cancelled, Interrupted, Denied }
public enum InvestigationEvidenceOwner { Finding, Hypothesis, ToolCall }
public enum InvestigationEvidencePolarity { Supporting, Contradicting }
public enum AiExecutionOwnerState { Active, Abandoned, Unknown }
public sealed record AiExecutionOwner(string LifetimeId, string MachineFingerprint, int WindowsSessionId);

public sealed record Investigation(
    string Id, string ConversationId, string Title, string Objective, InvestigationState Status,
    AiEvidenceReference? Target, DateTime CreatedUtc, DateTime UpdatedUtc, DateTime? CompletedUtc,
    string Summary, IReadOnlyList<string> OpenQuestions);

public sealed record InvestigationTask(
    string Id, string InvestigationId, string? ParentTaskId, string Objective,
    InvestigationTaskState Status, string AssignedAgentId, string? CreatedByExecutionId,
    DateTime CreatedUtc, DateTime? CompletedUtc, string ResultSummary);

public sealed record InvestigationFinding(
    string Id, string InvestigationId, string Title, string Claim, string Description,
    AnalysisFindingSeverity Severity, double? Confidence, FindingVerificationState VerificationStatus,
    string CreatedByExecutionId, DateTime CreatedUtc, string? AnalystVerifiedBy = null,
    DateTime? AnalystVerifiedUtc = null, string? AssessedByExecutionId = null);

public sealed record InvestigationHypothesis(
    string Id, string InvestigationId, string Statement, HypothesisState Status,
    double? Confidence, string CreatedByExecutionId, DateTime CreatedUtc, DateTime UpdatedUtc,
    string? UpdatedByExecutionId = null);

public sealed record AgentExecution(
    string Id, string ConversationId, string? InvestigationId, string? TaskId,
    string AgentId, string SkillId, string ProviderId, string ModelId,
    DateTime StartedUtc, DateTime? CompletedUtc, AgentExecutionState Status,
    int IterationCount, int ToolCallCount, ModelTokenUsage? TokenUsage,
    string ErrorCategory, string ErrorText, AiExecutionOwner? Owner = null);

public sealed record AgentToolCall(
    string Id, string AgentExecutionId, string ToolName,
    DateTime StartedUtc, DateTime? CompletedUtc, AgentToolCallState Status,
    string InputSummary, string ResultSummary, string ErrorCategory, string ErrorText);

public sealed record InvestigationEvidenceLink(
    InvestigationEvidenceOwner Owner, string OwnerId, InvestigationEvidencePolarity Polarity,
    AiEvidenceReference Reference);

public sealed record InvestigationPublication(
    string InvestigationId, InvestigationState InvestigationStatus, string Summary,
    IReadOnlyList<string> OpenQuestions, InvestigationTaskState? TaskStatus,
    string TaskResultSummary, AgentExecution CompletedExecution,
    IReadOnlyList<InvestigationTask> FollowUpTasks,
    IReadOnlyList<InvestigationFinding> Findings,
    IReadOnlyList<InvestigationHypothesis> Hypotheses,
    IReadOnlyList<InvestigationEvidenceLink> EvidenceLinks,
    AiConversationMessage? VisibleMessage);
