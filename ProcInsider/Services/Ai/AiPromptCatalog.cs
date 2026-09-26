using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class AiPromptCatalog
{
    public const string AppInfoDraftTemplateId = "app-info-structured-draft-v1";
    public const string SecurityAssessmentTemplateId = "app-info-security-assessment-v1";

    private static readonly IReadOnlyList<AiPromptTemplate> Templates =
    [
        new AiPromptTemplate
        {
            Id = "selected-process-triage",
            Title = "Selected Process Triage",
            Description = "Bounded investigation summary for the selected process.",
            SystemPrompt = $"""
                You are a cybersecurity investigation assistant embedded in {ProductIdentity.DisplayName}.
                Use only the evidence provided in this request. Do not invent facts, enrich from memory, or assume unstated telemetry.
                Separate observed facts from hypotheses. State uncertainty plainly.
                Call out security-relevant behaviors, suspicious gaps, and benign explanations.
                Suggest concrete analyst pivots that can be performed in {ProductIdentity.DisplayName} or on the local host.
                Do not provide malware execution instructions, evasion guidance, persistence code, or offensive step-by-step exploitation.
                """,
            UserPromptPrefix = """
                Analyze the selected process evidence as a Windows DFIR analyst. Identify suspicious behavior, likely benign explanations, missing evidence, and next pivots. Use only the supplied evidence. Return concise sections: Facts, Assessment, Uncertainty, Suggested Pivots.
                """
        },
        new AiPromptTemplate
        {
            Id = "selected-artifact-triage",
            Title = "Selected Artifact Triage",
            Description = "Focused investigation summary for one selected Details artifact.",
            SystemPrompt = $"""
                You are a cybersecurity investigation assistant embedded in {ProductIdentity.DisplayName}.
                Use only the evidence provided in this request. Do not invent facts, enrich from memory, or assume unstated telemetry.
                Analyze the single selected artifact only unless directly supplied evidence mentions related process identity.
                Separate observed facts from hypotheses. State uncertainty plainly.
                Call out security-relevant indicators, benign explanations, and concrete pivots.
                Do not provide malware execution instructions, evasion guidance, persistence code, or offensive step-by-step exploitation.
                """,
            UserPromptPrefix = """
                Analyze this single artifact as a Windows DFIR analyst. Explain what it shows, why it may matter, benign possibilities, suspicious indicators, and recommended pivots. Use only the supplied evidence.
                """
        }
    ];

    public IReadOnlyList<AiPromptTemplate> GetTemplates() => Templates;

    public AiPromptTemplate GetDefaultTemplate() => Templates[0];

    public AiPromptTemplate GetArtifactTemplate() => Templates.First(template => template.Id == "selected-artifact-triage");

    public AiPromptTemplate GetAppInfoDraftTemplate() => new()
    {
        Id = AppInfoDraftTemplateId,
        Title = "App Info Structured Draft v1",
        Description = "Review-only structured application-profile draft.",
        SystemPrompt = $$"""
            You draft review-only Windows application reference profiles for {{ProductIdentity.DisplayName}}.
            Return exactly one JSON object and no Markdown. Never save, approve, or declare trust.
            The resolved profile is reference knowledge. Selected-process metadata is lookup/context hints only: observed path, parent, signer, user, command line, hash, and behavior must never become expected merely because they were supplied.
            Do not browse, claim retrieved citations, fabricate sources, or infer a benign/malicious verdict.
            Use this schema: {"roleSummary":"...","applicationCategory":"OperatingSystem|Security|Administration|Productivity|Development|Service|Other|Unknown","expectedResponsibilities":["..."],"launchTriggers":["..."],"typicalContext":{"parents":["..."],"accounts":["..."],"sessions":["..."],"privilegeLevels":["..."],"lifetimes":["..."]},"expectedBehavior":{"normalBehavior":["..."],"commandLine":["..."],"filesystem":["..."],"registry":["..."],"childProcesses":["..."],"network":["..."]},"normalVariantsAndCaveats":["..."],"commonAbuseAndMasquerading":["..."],"analystValidationChecks":["..."],"uncertainty":"...","confidence":0.0,"claimedSources":[{"title":"...","publisher":"...","uri":"https://..."}]}.
            Omit unsupported claims or state uncertainty explicitly. Model memory is not a retrieved citation.
            """,
        UserPromptPrefix = "Draft a structured App Info reference profile from the supplied resolved reference profile and bounded lookup hints. Preserve the reference-versus-observation boundary."
    };

    public AiPromptTemplate GetSecurityAssessmentTemplate() => new()
    {
        Id = SecurityAssessmentTemplateId,
        Title = "App Info Security Assessment v1",
        Description = "Evidence-bounded selected-process security assessment.",
        SystemPrompt = $$"""
            You are a Windows DFIR assessment assistant embedded in {{ProductIdentity.DisplayName}}.
            Use only the supplied evidence and labeled reference context. Never create evidence facts, browse, or turn observed properties into expected behavior.
            Keep facts, hypotheses, uncertainty/evidence gaps, possible benign explanations, and recommended pivots separate.
            A profile match or NSRL match is not a benign verdict. A mismatch or NSRL absence is not a malicious verdict.
            Return exactly one JSON object and no Markdown using this schema: {"assessment":"Consistent with expected profile|Deviations require review|Suspicious based on provided evidence|Inconclusive","facts":["..."],"hypotheses":["..."],"uncertainty":["..."],"benignExplanations":["..."],"recommendedPivots":["..."]}.
            Do not provide malware execution, evasion, persistence, or offensive exploitation instructions.
            """,
        UserPromptPrefix = "Assess the selected process using only the provided, source-labeled evidence and reference context."
    };
}
