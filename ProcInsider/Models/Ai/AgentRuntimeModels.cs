namespace ProcInsider.Models.Ai;

/// <summary>Immutable analyst-visible hints captured for one general Assistant submission; none is evidence.</summary>
public sealed record AiGeneralSubmissionContext(
    ProcInsider.Models.EvidenceIdentity ScopeIdentity,
    DateTime CapturedUtc,
    DateTime? TimeStartUtc,
    DateTime? TimeEndUtc,
    string Workspace,
    string SelectedEntityHint,
    string? ActiveInvestigationId);

/// <summary>The destination and model the analyst saw before an explicit AI submission.</summary>
public sealed record AiSubmissionConstraint(AiProviderKind ProviderKind, string Endpoint, string ModelName,
    bool AllowPrivateNetworkHttp = false)
{
    public static AiSubmissionConstraint Capture(AiProviderSettings settings) => new(
        settings.ProviderKind,
        settings.TryGetEndpoint(out var endpoint) ? endpoint.AbsoluteUri : string.Empty,
        settings.ModelName ?? string.Empty,
        settings.AllowPrivateNetworkHttp);
}

// A single analyst action. Persisted investigation state and provider configuration are loaded
// by the runtime; callers cannot submit replacement findings, limits or provider credentials.
public sealed record AgentRuntimeRequest(
    string ConversationId,
    string SkillId,
    AiObjectContext? Target,
    string Objective,
    Func<bool> IsCurrentGeneration,
    string? InvestigationId = null,
    string? TaskId = null,
    IReadOnlyList<SkillToolQuery>? Queries = null,
    AiSubmissionConstraint? ExpectedSubmission = null,
    AiGeneralSubmissionContext? GeneralContext = null,
    string AnalystInstructions = "",
    Func<AiConversationMessage, AiPromptRequest, CancellationToken, Task>? PromptSubmitted = null,
    // Complete behavioral instructions never change typed authorization or evidence validation.
    string? SystemInstructionsOverride = null,
    string? RecoveryMessageId = null,
    bool ConversationOnly = false);

public sealed record AgentRuntimeResult(
    AgentExecution Execution,
    AgentSkillResult? SkillResult,
    ContextBrokerBudgetReport? BudgetReport,
    string SubmissionDestination = "");
