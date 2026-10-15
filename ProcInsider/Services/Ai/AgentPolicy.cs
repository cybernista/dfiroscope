using System.Diagnostics;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.Ai;

public sealed class AgentToolSession
{
    private readonly object _relatedGate = new();
    private readonly Dictionary<string, AiEvidenceReference> _checkedRelated = new(StringComparer.Ordinal);
    private int _attemptedToolCalls;
    private int _attemptedIterations;
    private readonly long _startedTimestamp = Stopwatch.GetTimestamp();

    internal AgentToolSession(AgentPolicy ownerPolicy, TelemetryProjectionService ownerProjection,
        AgentDefinition definition, string skillId, AiConversationScope scope,
        AiEvidenceReference? target, object? readBindingToken)
    {
        OwnerPolicy = ownerPolicy;
        OwnerProjection = ownerProjection;
        Definition = definition;
        SkillId = skillId;
        Scope = scope;
        Target = target;
        ReadBindingToken = readBindingToken;
        StartedUtc = DateTime.UtcNow;
        if (AllowsConversationReads && target is not null) _checkedRelated.Add(target.ReferenceId, target);
    }

    internal AgentDefinition Definition { get; }
    internal object? ReadBindingToken { get; }
    internal AgentPolicy OwnerPolicy { get; }
    internal TelemetryProjectionService OwnerProjection { get; }
    public string AgentId => Definition.Id;
    public string SkillId { get; }
    public AiConversationScope Scope { get; }
    public AiEvidenceReference? Target { get; }
    public DateTime StartedUtc { get; }
    public int AttemptedToolCalls => Volatile.Read(ref _attemptedToolCalls);
    public int AttemptedIterations => Volatile.Read(ref _attemptedIterations);
    public int RemainingToolCalls => Math.Max(0, Definition.Limits.MaximumToolCalls - AttemptedToolCalls);
    public int RemainingIterations => Math.Max(0, Definition.Limits.MaximumIterations - AttemptedIterations);
    public TimeSpan RemainingRuntime => Definition.Limits.MaximumRuntime - Stopwatch.GetElapsedTime(_startedTimestamp);

    internal bool TryCountAttempt() => Interlocked.Increment(ref _attemptedToolCalls) <=
        Definition.Limits.MaximumToolCalls;
    public bool TryBeginIteration() => OwnerPolicy.CheckIteration(this) &&
        Interlocked.Increment(ref _attemptedIterations) <= Definition.Limits.MaximumIterations;

    internal bool TryRecordCheckedRelatedEvidence(IReadOnlyList<AiEvidenceReference> references)
    {
        if (!OwnerPolicy.CheckIteration(this))
            throw new InvalidOperationException("The related-evidence read binding expired.");
        lock (_relatedGate)
        {
            var proposed = new Dictionary<string, AiEvidenceReference>(_checkedRelated, StringComparer.Ordinal);
            foreach (var reference in references)
            {
                if (!ReadBoundaryAdmits(reference.Identity))
                    return false;
                if (proposed.TryGetValue(reference.ReferenceId, out var prior) && prior != reference)
                    return false;
                proposed[reference.ReferenceId] = reference;
            }
            if (proposed.Count > MaximumCheckedReferences ||
                JsonSerializer.SerializeToUtf8Bytes(proposed.Values).Length > MaximumCheckedReferenceBytes)
                return false;
            _checkedRelated.Clear();
            foreach (var pair in proposed) _checkedRelated.Add(pair.Key, pair.Value);
            return true;
        }
    }

    internal bool AllowsConversationReads => SkillId is AgentDefinition.ExplainObjectSkillId or AgentDefinition.QueryEvidenceSkillId;
    internal int MaximumCheckedReferences => AllowsConversationReads
        ? Definition.Limits.MaximumToolCalls * 50 : 50;
    internal int MaximumCheckedReferenceBytes => AllowsConversationReads ? 4_096_000 : 64_000;

    internal AiEvidenceReference? ResolveCheckedReference(JsonElement arguments)
    {
        if (!OwnerPolicy.CheckIteration(this)) return null;
        if (!arguments.TryGetProperty("reference_id", out var selector)) return Target;
        var referenceId = selector.GetString();
        if (string.IsNullOrWhiteSpace(referenceId)) return null;
        // Formal investigations keep their pinned process workflow.
        if (!AllowsConversationReads) return Target?.ReferenceId == referenceId ? Target : null;
        lock (_relatedGate)
            return _checkedRelated.TryGetValue(referenceId, out var reference) ? reference : null;
    }

    internal bool ReadBoundaryAdmits(EvidenceIdentity identity) =>
        AgentPolicy.ScopeAdmits(Scope, identity) || AgentPolicy.RelatedBoundaryAdmits(Scope, identity);

    internal EvidenceIdentity HostQueryIdentity => Scope.ContextType == AiConversationContextType.Object
        ? Scope.Identity with { SourceIdentityId = string.Empty }
        : Scope.Identity;

    internal IReadOnlyList<AiEvidenceReference> SnapshotCheckedRelatedReferences()
    {
        if (!OwnerPolicy.CheckIteration(this))
            throw new InvalidOperationException("The related-evidence read binding expired.");
        lock (_relatedGate)
            return Array.AsReadOnly(_checkedRelated.Values.ToArray());
    }

    internal bool AdmitReference(AiEvidenceReference reference)
    {
        if (reference is null || !OwnerPolicy.CheckIteration(this)) return false;
        if (AgentPolicy.ScopeAdmits(Scope, reference.Identity)) return true;
        if (Scope.ContextType != AiConversationContextType.Object ||
            !AgentPolicy.RelatedBoundaryAdmits(Scope, reference.Identity)) return false;
        lock (_relatedGate)
            return _checkedRelated.TryGetValue(reference.ReferenceId, out var admitted) &&
                admitted == reference;
    }
}

public sealed record AgentPolicyDecision(bool Allowed, string Code);

public sealed class AgentPolicy
{
    private readonly FeatureAccessService _access;
    private readonly TelemetryProjectionService _projection;

    public AgentPolicy(FeatureAccessService access, TelemetryProjectionService projection)
    {
        _access = access ?? throw new ArgumentNullException(nameof(access));
        _projection = projection ?? throw new ArgumentNullException(nameof(projection));
    }

    internal FeatureAccessService Access => _access;

    public AgentToolSession OpenExecution(string agentId, string skillId,
        AiConversationScope scope, AiEvidenceReference? target)
    {
        if (!_access.IsPublished(FeatureIds.AiAssistance))
            throw new InvalidOperationException("AI assistance is not published.");
        var definition = AgentDefinition.InteractiveInvestigator;
        if (scope is null || scope.Identity is null ||
            string.IsNullOrWhiteSpace(scope.Identity.EvidenceSessionId) ||
            (string.IsNullOrWhiteSpace(scope.Identity.CaptureId) &&
                (scope.ContextType != AiConversationContextType.General ||
                 !string.IsNullOrWhiteSpace(scope.Identity.HostId))) ||
            (target is null && (scope.ContextType != AiConversationContextType.General ||
                skillId != AgentDefinition.QueryEvidenceSkillId) ||
             target is not null && (target.Identity is null ||
                string.IsNullOrWhiteSpace(target.Identity.EvidenceSessionId) ||
                string.IsNullOrWhiteSpace(target.Identity.CaptureId) ||
                string.IsNullOrWhiteSpace(target.Identity.SourceIdentityId) ||
                string.IsNullOrWhiteSpace(target.Identity.HostId))) ||
            !string.Equals(agentId, definition.Id, StringComparison.Ordinal) ||
            !definition.AllowedSkillIds.Contains(skillId, StringComparer.Ordinal) ||
            !string.Equals(definition.Initiator, "Human", StringComparison.Ordinal) ||
            !string.Equals(definition.Mode, "Interactive", StringComparison.Ordinal) ||
            target is not null && !ScopeAdmits(scope, target.Identity) ||
            (scope.ContextType == AiConversationContextType.Object &&
                scope.ObjectReference?.CanonicalObjectKey != target?.CanonicalObjectKey))
            throw new InvalidOperationException("Agent, Skill or evidence scope is not authorized.");
        return new AgentToolSession(this, _projection, definition, skillId, scope, target,
            _projection.CaptureReadBindingToken());
    }

    internal AgentPolicyDecision CheckTool(AgentToolSession session, AgentToolDescriptor tool)
    {
        if (!_access.IsPublished(FeatureIds.AiAssistance))
            return new(false, "feature.unpublished");
        if (session is null || !ReferenceEquals(session.OwnerPolicy, this) ||
            !ReferenceEquals(session.OwnerProjection, _projection) ||
            session.Definition != AgentDefinition.InteractiveInvestigator ||
            !session.Definition.AllowedSkillIds.Contains(session.SkillId, StringComparer.Ordinal) ||
            !tool.AllowedSkillIds.Contains(session.SkillId, StringComparer.Ordinal) ||
            tool.RequiredPermissions.Any(permission => !session.Definition.AllowedPermissions.Contains(permission)) ||
            (session.Target is not null && !ScopeAdmits(session.Scope, session.Target.Identity)) ||
            (session.Target is null && (session.Scope.ContextType != AiConversationContextType.General ||
                string.IsNullOrWhiteSpace(session.Scope.Identity.HostId))))
            return new(false, "tool.permission-denied");
        if (session.RemainingRuntime <= TimeSpan.Zero)
            return new(false, "tool.runtime-limit");
        return new(true, "tool.allowed");
    }

    internal bool CheckIteration(AgentToolSession session) =>
        _access.IsPublished(FeatureIds.AiAssistance) &&
        ReferenceEquals(session.OwnerPolicy, this) &&
        ReferenceEquals(session.OwnerProjection, _projection) &&
        session.Definition == AgentDefinition.InteractiveInvestigator &&
        session.Definition.AllowedSkillIds.Contains(session.SkillId, StringComparer.Ordinal) &&
        session.ReadBindingToken is not null &&
        _projection.IsCurrentReadBinding(session.ReadBindingToken) &&
        session.RemainingRuntime > TimeSpan.Zero;

    public AgentPolicyDecision CheckPublication(AgentToolSession session, InvestigationPublication publication)
    {
        if (!_access.IsPublished(FeatureIds.AiAssistance) ||
            session is null || publication is null ||
            !ReferenceEquals(session.OwnerPolicy, this) ||
            !ReferenceEquals(session.OwnerProjection, _projection) ||
            session.RemainingRuntime <= TimeSpan.Zero || session.ReadBindingToken is null ||
            !_projection.IsCurrentReadBinding(session.ReadBindingToken) ||
            session.Definition != AgentDefinition.InteractiveInvestigator ||
            session.Scope.ContextType != AiConversationContextType.Investigation ||
            session.Scope.ContextId != publication.InvestigationId ||
            !Has(session, AgentPermission.InvestigationModify) ||
            publication.Findings is null || publication.Hypotheses is null ||
            publication.FollowUpTasks is null || publication.EvidenceLinks is null ||
            publication.Findings.Count > 0 && !Has(session, AgentPermission.FindingCreate) ||
            publication.Hypotheses.Count > 0 && !Has(session, AgentPermission.HypothesisCreate) ||
            publication.FollowUpTasks.Count > 0 && !Has(session, AgentPermission.TaskCreate) ||
            publication.Findings.Any(f => f.VerificationStatus == FindingVerificationState.AnalystVerified ||
                f.AnalystVerifiedBy is not null || f.AnalystVerifiedUtc is not null) ||
            publication.EvidenceLinks.Any(link => !ScopeAdmits(session.Scope, link.Reference.Identity)))
            return new(false, "publication.permission-denied");
        return new(true, "publication.allowed");
    }

    private static bool Has(AgentToolSession session, AgentPermission permission) =>
        session.Definition.AllowedPermissions.Contains(permission);

    public static bool ScopeAdmits(AiConversationScope scope, EvidenceIdentity reference)
    {
        if (scope is null || scope.Identity is null || reference is null ||
            string.IsNullOrWhiteSpace(scope.Identity.EvidenceSessionId) ||
            (string.IsNullOrWhiteSpace(scope.Identity.HostId) &&
                scope.ContextType != AiConversationContextType.General) ||
            string.IsNullOrWhiteSpace(reference.HostId) ||
            scope.Identity.CaseId != reference.CaseId ||
            scope.Identity.EvidenceSessionId != reference.EvidenceSessionId ||
            scope.Identity.CaptureId != reference.CaptureId ||
            scope.Identity.HostId != reference.HostId)
            return false;
        if (scope.ContextType == AiConversationContextType.Object)
            return scope.Identity == reference;
        return (string.IsNullOrEmpty(scope.Identity.SourceIdentityId) ||
                scope.Identity.SourceIdentityId == reference.SourceIdentityId) &&
            (string.IsNullOrEmpty(scope.Identity.ExecutionRootId) ||
                scope.Identity.ExecutionRootId == reference.ExecutionRootId);
    }

    internal static bool RelatedBoundaryAdmits(AiConversationScope scope, EvidenceIdentity reference) =>
        scope is not null && reference is not null &&
        scope.ContextType == AiConversationContextType.Object &&
        scope.ObjectReference is not null &&
        scope.Identity == scope.ObjectReference.Identity &&
        scope.Identity.CaseId == reference.CaseId &&
        scope.Identity.EvidenceSessionId == reference.EvidenceSessionId &&
        scope.Identity.CaptureId == reference.CaptureId &&
        scope.Identity.HostId == reference.HostId &&
        EvidenceIdentity.ExecutionRootsCompatible(scope.Identity.ExecutionRootId,
            reference.ExecutionRootId, scope.Identity.EvidenceSessionId);

}
