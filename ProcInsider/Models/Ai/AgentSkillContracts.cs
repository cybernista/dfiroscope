using System.Text.Json;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Models.Ai;

public sealed record AgentSkillDescriptor(
    string Id, string Name, string Description,
    IReadOnlyList<string> RequiredInput,
    IReadOnlyList<string> AllowedToolIds,
    IReadOnlyList<AgentPermission> RequiredPermissions,
    JsonElement OutputSchema);

public sealed record SkillToolQuery(string ToolId, JsonElement Arguments);

public sealed record AgentSkillRequest(
    string SkillId, AiObjectContext? Target, string Objective,
    Investigation? CurrentInvestigation = null,
    IReadOnlyList<InvestigationTask>? CurrentTasks = null,
    IReadOnlyList<InvestigationFinding>? CurrentFindings = null,
    IReadOnlyList<InvestigationHypothesis>? CurrentHypotheses = null,
    IReadOnlyList<SkillToolQuery>? Queries = null,
    IReadOnlyList<InvestigationEvidenceLink>? CurrentEvidenceLinks = null);

public enum AgentSkillAssertionKind { Observation, Inference }

public sealed record AgentSkillObservation(
    AgentSkillAssertionKind Kind, string Text,
    IReadOnlyList<AiEvidenceReference> EvidenceReferences);

// These are proposals. Runtime/storage assigns authoritative IDs, execution provenance and time.
public sealed record AgentSkillFinding(
    string Title, string Claim, string Description, AnalysisFindingSeverity Severity,
    double? Confidence, FindingVerificationState Assessment,
    string Uncertainty,
    IReadOnlyList<AiEvidenceReference> SupportingEvidence,
    IReadOnlyList<AiEvidenceReference> ContradictingEvidence);

public sealed record AgentSkillHypothesis(
    string Statement, double? Confidence, string Uncertainty,
    IReadOnlyList<AiEvidenceReference> SupportingEvidence,
    IReadOnlyList<AiEvidenceReference> ContradictingEvidence);

public sealed record AgentSkillTask(string Objective);

public sealed record AgentSkillToolCoverage(
    string ToolId, AgentToolStatus Status, int ObservedCount,
    bool CountIsExact, bool IsTruncated,
    IReadOnlyList<string> Omissions, string DiagnosticCode, string Coverage = "");

public sealed record AgentSkillResult(
    string Summary,
    IReadOnlyList<AgentSkillObservation> Observations,
    IReadOnlyList<AgentSkillFinding> Findings,
    IReadOnlyList<AgentSkillHypothesis> Hypotheses,
    IReadOnlyList<AgentSkillTask> Tasks,
    IReadOnlyList<AiEvidenceReference> EvidenceReferences,
    IReadOnlyList<string> OpenQuestions,
    IReadOnlyList<AgentSkillToolCoverage> ToolCoverage,
    IReadOnlyList<string> NotCheckedSources,
    bool InitialContextOriginalVerified)
{
    public string ValidationDiagnostic { get; init; } = string.Empty;
}
