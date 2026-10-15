namespace ProcInsider.Models.Ai;

// A record is an indivisible attributable unit. Its text is selected whole or deferred whole.
public sealed record BrokerEvidenceRecord(
    string RecordId, string Text, string Provenance,
    AiEvidenceReference? Reference = null,
    bool IsDerived = false,
    string? AttributionGroupId = null,
    InvestigationEvidencePolarity? Polarity = null,
    bool IsRequired = false);

public sealed record BrokerEvidenceSource(
    string SourceId, IReadOnlyList<BrokerEvidenceRecord> Records,
    int ObservedCount, bool CountIsExact, bool IsTruncated,
    string Coverage, int Priority = 1);

// Runtime-owned facts for this inference, separate from editable behavioral instructions.
public sealed record BrokerRuntimeBudget(int RemainingToolCalls, int RemainingModelIterations,
    bool FinalizationRequired, string FinalizationReason, int OlderResultsInExchanges);

public sealed record ContextBrokerInput(
    ModelCapabilities Capabilities,
    string SystemInstructions,
    string CurrentQuestion,
    AiConversationScope Scope,
    Func<bool> IsCurrentGeneration,
    IReadOnlyList<ModelMessage> History,
    AiObjectContext? Target = null,
    Investigation? Investigation = null,
    IReadOnlyList<InvestigationTask>? Tasks = null,
    IReadOnlyList<InvestigationFinding>? Findings = null,
    IReadOnlyList<InvestigationHypothesis>? Hypotheses = null,
    IReadOnlyList<InvestigationEvidenceLink>? EvidenceLinks = null,
    IReadOnlyList<BrokerEvidenceSource>? Sources = null,
    IReadOnlyList<ModelToolDefinition>? Tools = null,
    ModelOutputStructure? OutputStructure = null,
    int? ContextWindowOverrideTokens = null,
    int? RequestedOutputTokens = null,
    string? PinnedTargetDescription = null,
    int PreOmittedHistoryMessages = 0,
    // Trusted caller's already checked values, used only for context selection, never evidence authority.
    IReadOnlyList<AiEvidenceReference>? AdmittedRelatedReferences = null,
    AiGeneralSubmissionContext? GeneralContext = null,
    // Runtime-owned suffix of completed Tool exchanges belonging to this question.
    int CurrentTurnToolMessageCount = 0,
    BrokerRuntimeBudget? RuntimeBudget = null);

public enum ContextBrokerFailureCode
{
    InvalidInput,
    StaleScope,
    InsufficientContext
}

public sealed record ContextBrokerFailure(ContextBrokerFailureCode Code, string Message);

public sealed record BrokerSourceSelection(
    string SourceId, int ObservedCount, bool CountIsExact,
    int OfferedRecords, int SelectedRecords, int OmittedRecords,
    bool SourceTruncated, string Coverage, string OmissionReason,
    int OfferedContradictingRecords = 0, int OmittedContradictingRecords = 0);

public sealed record ContextBrokerInputComponents(int Instructions, int QuestionAndHistory,
    int ToolMessages, int StructuredContext, int ToolDefinitions, int OutputSchema, int ProtocolOverhead)
{
    public int Total => Instructions + QuestionAndHistory + ToolMessages + StructuredContext +
        ToolDefinitions + OutputSchema + ProtocolOverhead;
}

public sealed record ContextBrokerBudgetReport(
    int ContextWindowTokens,
    string WindowBasis,
    int EstimatedInputTokens,
    int OutputReserveTokens,
    int SafetyMarginTokens,
    int SelectedHistoryMessages,
    int OmittedHistoryMessages,
    int SelectedStateRecords,
    int OmittedStateRecords,
    int SelectedToolDefinitions,
    int OmittedToolDefinitions,
    IReadOnlyList<BrokerSourceSelection> Sources,
    string EstimationMethod,
    ContextBrokerInputComponents? EstimatedInputComponents = null);

public sealed record ContextBrokerResult(
    ModelRequest? Request,
    ContextBrokerBudgetReport Report,
    ContextBrokerFailure? Failure)
{
    public bool Success => Request is not null && Failure is null;
}
