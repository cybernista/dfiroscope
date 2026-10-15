using System.Text.Json;
using ProcInsider.Models;

namespace ProcInsider.Models.Ai;

// Annotation context points at canonical evidence; its snapshot is never a substitute for that evidence.
public sealed record AiEvidenceReference(
    string ReferenceId,
    EvidenceIdentity Identity,
    EvidenceReference Evidence,
    string DataSource,
    string SourceRunId,
    string SourceRevision,
    DateTime? TimestampUtc,
    string DisplayName,
    string CompactSnapshot,
    string SnapshotProvenance,
    AiProcessReference? Process = null)
{
    public string ObjectType => Evidence.Kind.ToString();
    public string ObjectId => Evidence.Id;

    // A durable object remains the same through later observations. An observation row requires its run/revision.
    public string CanonicalObjectKey => JsonSerializer.Serialize(new[]
    {
        Identity.CaseId, Identity.EvidenceSessionId, Identity.CaptureId,
        Identity.SourceIdentityId, Identity.HostId, Identity.ExecutionRootId,
        Evidence.Kind.ToString(), Evidence.Kind == EvidenceReferenceKind.ProcessEntity &&
            string.IsNullOrWhiteSpace(Evidence.Id) ? "legacy-process-key" : "canonical-evidence-id",
        Evidence.Kind == EvidenceReferenceKind.ProcessEntity &&
            string.IsNullOrWhiteSpace(Evidence.Id) ? Process?.ProcessKey ?? string.Empty : Evidence.Id,
        Evidence.Kind == EvidenceReferenceKind.ProcessEntity ? string.Empty : SourceRunId,
        Evidence.Kind == EvidenceReferenceKind.ProcessEntity ? string.Empty : SourceRevision
    });
}

public sealed class AiObjectContext
{
    public AiObjectContext(AiEvidenceReference reference,
        IReadOnlyDictionary<string, string> displayProperties,
        IReadOnlyDictionary<string, string> keyProperties,
        IReadOnlyList<string> relatedDataHints,
        DateTime? rangeStartUtc = null, DateTime? rangeEndUtc = null)
    {
        Reference = reference;
        DisplayProperties = new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(displayProperties, StringComparer.Ordinal));
        KeyProperties = new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(keyProperties, StringComparer.Ordinal));
        RelatedDataHints = Array.AsReadOnly(relatedDataHints.ToArray());
        RangeStartUtc = rangeStartUtc;
        RangeEndUtc = rangeEndUtc;
    }

    public AiEvidenceReference Reference { get; }
    public IReadOnlyDictionary<string, string> DisplayProperties { get; }
    public IReadOnlyDictionary<string, string> KeyProperties { get; }
    public IReadOnlyList<string> RelatedDataHints { get; }
    public DateTime? RangeStartUtc { get; }
    public DateTime? RangeEndUtc { get; }
}

public enum AiConversationContextType { General, Object, Investigation }

public sealed record AiConversationScope(
    AiConversationContextType ContextType,
    string ContextId,
    EvidenceIdentity Identity,
    AiEvidenceReference? ObjectReference = null,
    string ScopeQualifier = "")
{
    public static AiConversationScope ForObject(AiEvidenceReference reference) =>
        new(AiConversationContextType.Object, reference.CanonicalObjectKey, reference.Identity, reference);

    public static AiConversationScope ForProcessObject(AiEvidenceReference reference) =>
        new(AiConversationContextType.Object, reference.CanonicalObjectKey, reference.Identity, reference,
            "Processes");

    public static AiConversationScope ForNewProcessObject(AiEvidenceReference reference, string uniqueId)
    {
        if (!Guid.TryParseExact(uniqueId, "N", out var id) ||
            !string.Equals(uniqueId, id.ToString("N"), StringComparison.Ordinal))
            throw new ArgumentException("A new process conversation requires a canonical unique ID.", nameof(uniqueId));
        return new(AiConversationContextType.Object, reference.CanonicalObjectKey, reference.Identity, reference,
            "Processes:" + uniqueId);
    }

    public static AiConversationScope ForGeneral(string sessionContextId, EvidenceIdentity identity) =>
        new(AiConversationContextType.General, sessionContextId, identity);

    public static AiConversationScope ForInvestigation(string investigationId, EvidenceIdentity identity) =>
        new(AiConversationContextType.Investigation, investigationId, identity);

    public string ScopeKey => JsonSerializer.Serialize(string.IsNullOrEmpty(ScopeQualifier)
        ? new[] { ContextType.ToString(), Identity.CaseId, Identity.EvidenceSessionId,
            Identity.CaptureId, Identity.SourceIdentityId, Identity.HostId, Identity.ExecutionRootId, ContextId }
        : new[] { ContextType.ToString(), Identity.CaseId, Identity.EvidenceSessionId,
            Identity.CaptureId, Identity.SourceIdentityId, Identity.HostId, Identity.ExecutionRootId, ContextId,
            ScopeQualifier });
}

public sealed record AiConversationCreationOrigin(string Surface, EvidenceIdentity ProcessIdentity,
    string ProcessEntityId)
{
    public static AiConversationCreationOrigin ForProcess(AiEvidenceReference processReference)
    {
        ArgumentNullException.ThrowIfNull(processReference);
        if (processReference.Evidence.Kind != EvidenceReferenceKind.ProcessEntity ||
            string.IsNullOrWhiteSpace(processReference.Evidence.Id))
            throw new ArgumentException("Creation origin requires a durable process entity.", nameof(processReference));
        return new AiConversationCreationOrigin("Processes", processReference.Identity,
            processReference.Evidence.Id);
    }
}

public sealed record AiConversation(
    string Id,
    string Title,
    AiConversationScope Scope,
    string HostId,
    DateTime? CreatedUtc,
    DateTime? UpdatedUtc,
    bool IsHistorical = false,
    string OriginalCreatedUtc = "",
    string OriginalUpdatedUtc = "",
    AiConversationCreationOrigin? CreationOrigin = null);

public sealed record AiConversationMessage(
    string Id,
    string ConversationId,
    string Role,
    string Content,
    DateTime? TimestampUtc,
    string ProviderId,
    string ModelId,
    string Status,
    string ErrorText,
    bool IsHistorical = false,
    string? OriginalProviderKind = null,
    string? OriginalBaseUrl = null,
    string? OriginalCreatedUtc = null,
    string? OriginalProviderName = null,
    string? OriginalModelName = null,
    string? OriginalErrorText = null,
    string TechnicalDetails = "",
    bool HasPromptRequests = false)
{
    // Loaded only for an explicit question inspection, never part of Runtime history.
    public IReadOnlyList<AiPromptRequest> PromptRequests { get; init; } = Array.Empty<AiPromptRequest>();
    // Presentation projection from saved tasks and execution provenance, never parsed from answer text.
    [System.Text.Json.Serialization.JsonIgnore]
    public IReadOnlyList<InvestigationTask> InvestigationTasks { get; init; } = Array.Empty<InvestigationTask>();
    // Transient WPF state: record replacements retain an open inspection; saved history starts collapsed.
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsPromptExpanded { get; set; }
    // Runtime's persisted readable answer labels explicit proposed questions. These remain text,
    // and a separate analyst click only prepares the composer for explicit submission.
    public IReadOnlyList<string> SuggestedFollowUps =>
        IsHistorical || !Status.Equals("Succeeded", StringComparison.OrdinalIgnoreCase) ||
        !(Role.Equals("assistant", StringComparison.OrdinalIgnoreCase))
            ? Array.Empty<string>()
            : Content.Split('\n').Select(line => line.Trim())
                .Where(line => line.StartsWith("Open question:", StringComparison.Ordinal))
                .Select(line => line["Open question:".Length..].Trim())
                .Where(AiFollowUpQuestionClassifier.IsAnalystQuestion)
                .Distinct(StringComparer.Ordinal).Take(16).ToArray();
}

// Submitted means an attempted POST after local validation, not confirmed delivery.
public sealed record AiPromptRequest(string Id, string ConversationId, string MessageId, string ExecutionId,
    int Iteration, string ProviderId, string ModelId, DateTime SubmittedUtc, string RequestBody);

// Conservative English presentation classification, not a claim of general language understanding.
// Uncertain wording remains readable answer text rather than an executable suggestion.
public static class AiFollowUpQuestionClassifier
{
    public static bool IsAnalystQuestion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        var question = text.Trim();
        if (System.Text.Encoding.UTF8.GetByteCount(question) > 2000 || !question.EndsWith('?') ||
            question.Contains('\n') || question.Contains('\r') || question[..^1].Contains('?') ||
            System.Text.RegularExpressions.Regex.Matches(question, @"\b[\p{L}\p{N}]+\b").Count < 2) return false;
        if (!Matches(question, @"^(?:who|what|when|where|why|which|how|can|could|do|does|did|is|are|was|were|will|would|has|have|had|may|might|should|must)\b"))
            return false;
        // A polite question mark does not turn an instruction to operate or supply evidence into clarification.
        if (Matches(question, @"\b(?:can|could|would|will|should|may|might|must|do|does|did)\s+(?:(?:you|we|i|the\s+(?:analyst|assistant|ai))\s+)?(?:please\s+)?(?:(?:like|want|wish|prefer)\s+(?:(?:me|us)\s+)?to\s+)?(?:run|execute|inspect|query|retrieve|fetch|search|collect|capture|take\s+(?:a\s+)?screenshots?|upload|attach|enable|grant|authorize|authorise|allow|install|connect|restart|start|turn\s+on)\b") ||
            Matches(question, @"^how\s+(?:can|could|do|does|should|would|may|might)\s+(?:you|we|i|the\s+analyst)\s+(?:run|execute|inspect|query|retrieve|fetch|search|collect|capture|upload|attach|enable|grant|authorize|authorise|allow|install|connect)\b"))
            return false;
        var asksForAction = Matches(question, @"\b(?:can|could|would|will|should|may|might|must)\b");
        if (asksForAction &&
            (Matches(question, @"\b(?:provide|supply|give|send|share|show|get|request|obtain|approve|authorize|authorise)\b.{0,120}\b(?:tools?|permissions?|authori[sz]ation|access|capabilit(?:y|ies)|screenshots?|quer(?:y|ies)|results?|checked\s+evidence)\b") ||
             Matches(question, @"\b(?:tools?|permissions?|authori[sz]ation|access|capabilit(?:y|ies)|screenshots?|quer(?:y|ies)|results?|checked\s+evidence)\b.{0,120}\b(?:be\s+)?(?:provide|supply|give|send|share|show|get|request|obtain|approve|authorize|authorise|provided|supplied|granted|enabled|approved|uploaded|attached)\b")))
            return false;
        if (Matches(question, @"\b(?:must|should|needs?\s+to|has\s+to)\s+be\s+(?:collected|retrieved|queried|captured|provided|supplied|enabled|granted|authorized|authorised)\b"))
            return false;
        if (Matches(question, @"\b(?:tools?|capabilit(?:y|ies)|permissions?|authori[sz]ation)\b.{0,80}\b(?:missing|unavailable|needed|required|disabled|not\s+available)\b") ||
            Matches(question, @"\b(?:missing|unavailable|needed|required|disabled|not\s+available)\b.{0,80}\b(?:tools?|capabilit(?:y|ies)|permissions?|authori[sz]ation)\b"))
            return false;
        return true;
    }

    private static bool Matches(string text, string pattern) => System.Text.RegularExpressions.Regex.IsMatch(text, pattern,
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
}

// One bounded snapshot of prior successful turns. Historical citations are not
// admission proof for a new execution; the current checked query must provide them.
public sealed record AiRuntimeHistoryPage(
    IReadOnlyList<AiConversationMessage> Messages,
    int EligibleTotal,
    int DiagnosticTotal)
{
    public int PreOmittedHistoryMessages => EligibleTotal - Messages.Count;
}
