using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public interface IAgentSkill
{
    AgentSkillDescriptor Descriptor { get; }
    AgentSkillPlan Prepare(AgentToolSession session, AgentSkillRequest request,
        CancellationToken lifetime = default);
}

public sealed class AgentSkillPlan
{
    private readonly object _gate = new();
    private readonly List<AgentSkillToolCoverage> _coverage = [];
    private readonly Dictionary<string, AiEvidenceReference> _admitted = new(StringComparer.Ordinal);
    private readonly HashSet<string> _consumedSelections = new(StringComparer.Ordinal);

    internal AgentSkillPlan(AgentSkillRegistry owner, AgentToolSession session,
        AgentSkillDescriptor descriptor, AiObjectContext? target, string objective,
        Investigation? investigation, IReadOnlyList<InvestigationTask> tasks,
        IReadOnlyList<InvestigationFinding> findings,
        IReadOnlyList<InvestigationHypothesis> hypotheses,
        IReadOnlyList<InvestigationEvidenceLink> evidenceLinks,
        IReadOnlyList<ModelToolRequest> initialRequests, CancellationToken lifetime)
    {
        Owner = owner;
        Session = session;
        Descriptor = descriptor;
        Target = target;
        AllowedToolIds = descriptor.AllowedToolIds;
        Objective = objective;
        CurrentInvestigation = investigation;
        CurrentTasks = tasks;
        CurrentFindings = findings;
        CurrentHypotheses = hypotheses;
        CurrentEvidenceLinks = evidenceLinks;
        InitialToolRequests = initialRequests;
        Lifetime = lifetime;
        if (target is not null) _admitted.Add(target.Reference.ReferenceId, target.Reference);
        foreach (var link in evidenceLinks)
        {
            var reference = link.Reference;
            if (_admitted.TryGetValue(reference.ReferenceId, out var prior) && prior != reference)
                throw new ArgumentException("Saved evidence has a conflicting reference ID.");
            _admitted[reference.ReferenceId] = reference;
        }
        if (_admitted.Count > 50 || JsonSerializer.SerializeToUtf8Bytes(_admitted.Values).Length > 64_000)
            throw new ArgumentException("Saved Skill evidence exceeds its bound.");
    }

    internal AgentSkillRegistry Owner { get; }
    internal AgentToolSession Session { get; }
    internal CancellationToken Lifetime { get; }
    public AgentSkillDescriptor Descriptor { get; }
    public string SkillId => Descriptor.Id;
    public AiObjectContext? Target { get; }
    public string Objective { get; }
    public Investigation? CurrentInvestigation { get; }
    public IReadOnlyList<InvestigationTask> CurrentTasks { get; }
    public IReadOnlyList<InvestigationFinding> CurrentFindings { get; }
    public IReadOnlyList<InvestigationHypothesis> CurrentHypotheses { get; }
    public IReadOnlyList<InvestigationEvidenceLink> CurrentEvidenceLinks { get; }
    public IReadOnlyList<ModelToolRequest> InitialToolRequests { get; }
    public IReadOnlyList<string> AllowedToolIds { get; }
    public IReadOnlyList<string> NotCheckedSources
    {
        get
        {
            lock (_gate) return NotCheckedSourcesFor(_coverage);
        }
    }
    public ModelOutputStructure OutputStructure => new(SkillId + "Result",
        SkillId == AgentDefinition.QueryEvidenceSkillId && Target is null &&
        Session.Scope.ContextType == AiConversationContextType.General
            ? AgentSkillRegistry.GeneralQueryResultSchema.Clone() : Descriptor.OutputSchema.Clone());
    public string Guidance => AiPromptCatalog.GetSystemInstructions(SkillId, Target is not null,
        Session.AllowsConversationReads);

    internal void EnsureLive()
    {
        Lifetime.ThrowIfCancellationRequested();
        if (!Session.OwnerPolicy.CheckIteration(Session))
            throw new InvalidOperationException("The Skill's evidence binding or execution has expired.");
    }

    public bool AllowsGeneralReadTools => SkillId == AgentDefinition.QueryEvidenceSkillId && Target is null &&
        Session.Scope.ContextType == AiConversationContextType.General &&
        !string.IsNullOrWhiteSpace(Session.Scope.Identity.HostId) && !string.IsNullOrWhiteSpace(Session.Scope.Identity.CaptureId);

    internal bool AdmitsModelTool(string name) =>
        AllowedToolIds.Contains(name, StringComparer.Ordinal) &&
        (Target is not null || AllowsGeneralReadTools);

    internal bool TryConsumeSelected(ModelToolRequest request)
    {
        if (request.Arguments.ValueKind != JsonValueKind.Object ||
            string.IsNullOrWhiteSpace(request.CallId)) return false;
        lock (_gate)
        {
            var selected = InitialToolRequests.FirstOrDefault(item => item.CallId == request.CallId);
            return selected is not null && selected.Name == request.Name &&
                selected.Arguments.GetRawText() == request.Arguments.GetRawText() &&
                _consumedSelections.Add(request.CallId);
        }
    }

    internal void Record(AgentToolResult result)
    {
        EnsureLive();
        lock (_gate)
        {
            if (_coverage.Count >= 64)
                throw new InvalidOperationException("The Skill Tool-result limit was exceeded.");
            var proposed = new Dictionary<string, AiEvidenceReference>(_admitted, StringComparer.Ordinal);
            foreach (var reference in result.Status == AgentToolStatus.Available
                ? result.Evidence : Array.Empty<AiEvidenceReference>())
            {
                if (proposed.TryGetValue(reference.ReferenceId, out var prior) && prior != reference)
                    throw new InvalidOperationException("A Tool returned a conflicting evidence reference ID.");
                proposed[reference.ReferenceId] = reference;
            }
            // Conversation reads retain checked identities across bounded Tool calls; final output still cites at most 50.
            if (proposed.Count > Session.MaximumCheckedReferences ||
                JsonSerializer.SerializeToUtf8Bytes(proposed.Values).Length > Session.MaximumCheckedReferenceBytes)
                throw new InvalidOperationException("The Skill evidence ledger exceeds its bound.");
            _admitted.Clear();
            foreach (var pair in proposed) _admitted.Add(pair.Key, pair.Value);
            _coverage.Add(new AgentSkillToolCoverage(result.ToolId, result.Status,
                result.ObservedCount, result.CountIsExact, result.IsTruncated,
                Array.AsReadOnly(result.Omissions.ToArray()), result.DiagnosticCode,
                result.Output.ValueKind == JsonValueKind.Object && result.Output.TryGetProperty("coverage", out var coverage)
                    ? coverage.GetString() ?? "" : ""));
        }
    }

    internal void AdmitRevalidatedPrior(IReadOnlyList<AiEvidenceReference> references)
    {
        EnsureLive();
        if (SkillId == AgentDefinition.ReviewRecordSkillId || references.Count > 8)
            throw new InvalidOperationException("Prior citations are outside the bounded conversation recovery policy.");
        var checkedRelated = Session.SnapshotCheckedRelatedReferences()
            .ToDictionary(reference => reference.ReferenceId, StringComparer.Ordinal);
        lock (_gate)
        {
            var proposed = new Dictionary<string, AiEvidenceReference>(_admitted, StringComparer.Ordinal);
            foreach (var reference in references)
            {
                if (!checkedRelated.TryGetValue(reference.ReferenceId, out var checkedReference) ||
                    checkedReference != reference || !Session.AdmitReference(reference) ||
                    proposed.TryGetValue(reference.ReferenceId, out var prior) && prior != reference)
                    throw new InvalidOperationException("A prior citation was not revalidated in this evidence binding.");
                proposed[reference.ReferenceId] = reference;
            }
            if (proposed.Count > Session.MaximumCheckedReferences ||
                JsonSerializer.SerializeToUtf8Bytes(proposed.Values).Length > Session.MaximumCheckedReferenceBytes)
                throw new InvalidOperationException("The Skill evidence ledger exceeds its bound.");
            _admitted.Clear();
            foreach (var pair in proposed) _admitted.Add(pair.Key, pair.Value);
        }
    }

    internal (IReadOnlyDictionary<string, AiEvidenceReference> References,
        IReadOnlyList<AgentSkillToolCoverage> Coverage) Snapshot()
    {
        EnsureLive();
        lock (_gate)
        {
            return (new Dictionary<string, AiEvidenceReference>(_admitted, StringComparer.Ordinal),
                Array.AsReadOnly(_coverage.ToArray()));
        }
    }

    private static readonly IReadOnlyList<string> ProcessNotChecked = Array.AsReadOnly(new[]
    {
        "Signer and hash", "Files", "Detections and enrichments", "Windows session"
    });
    private static readonly IReadOnlyList<string> ObjectNotChecked =
        Array.AsReadOnly(new[] { "Canonical original evidence" });
    internal IReadOnlyList<string> NotCheckedSourcesFor(IReadOnlyList<AgentSkillToolCoverage> coverage)
    {
        if (SkillId == AgentDefinition.ReviewRecordSkillId) return Array.AsReadOnly(new[] { "Related activity outside the selected record" });
        var missing = new List<string>(Target?.Reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity
            ? ProcessNotChecked : ObjectNotChecked);
        if (Target is null) missing = ["No selected evidence object"];
        if (SkillId == AgentDefinition.InvestigateProcessSkillId)
            missing.Add("Saved investigation references not re-resolved");
        foreach (var (toolId, label) in new[]
        {
            ("GetProcessDetails", "Process details"), ("GetProcessTree", "Process tree"),
            ("GetProcessEvents", "Process events"), ("GetProcessNetwork", "Process network"),
            ("GetProcessPersistence", "Process persistence")
        })
            if (AllowedToolIds.Contains(toolId, StringComparer.Ordinal) &&
                !coverage.Any(item => item.ToolId == toolId && item.Status == AgentToolStatus.Available))
                missing.Add(label);
        return Array.AsReadOnly(missing.ToArray());
    }
}

public sealed class AgentSkillRegistry
{
    private const int MaximumObjectiveBytes = 4_000;
    private readonly AgentToolRegistry _checkedTools;
    private readonly IReadOnlyDictionary<string, IAgentSkill> _skills;

    internal static readonly JsonElement ResultSchema = JsonDocument.Parse("""
        {"type":"object","properties":{
          "summary":{"type":"string","maxLength":4000},
          "observations":{"type":"array","maxItems":16,"items":{"type":"object","properties":{
            "kind":{"type":"string","enum":["Observation","Inference"]},
            "text":{"type":"string","maxLength":1000},
            "evidence_reference_ids":{"type":"array","minItems":1,"maxItems":8,"items":{"type":"string","maxLength":160}}},
            "required":["kind","text","evidence_reference_ids"],"additionalProperties":false}},
          "findings":{"type":"array","maxItems":12,"items":{"type":"object","properties":{
            "title":{"type":"string","maxLength":200},"claim":{"type":"string","maxLength":1000},
            "description":{"type":"string","maxLength":2000},
            "severity":{"type":"string","enum":["Unknown","Informational","Low","Medium","High","Critical"]},
            "confidence":{"type":"number","minimum":0,"maximum":1},
            "assessment":{"type":"string","enum":["NotVerified","Supported","WeaklySupported","Contradicted","NeedsMoreEvidence"]},
            "uncertainty":{"type":"string","maxLength":1000},
            "supporting_reference_ids":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":160}},
            "contradicting_reference_ids":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":160}}},
            "required":["title","claim","description","severity","assessment","uncertainty","supporting_reference_ids","contradicting_reference_ids"],"additionalProperties":false}},
          "hypotheses":{"type":"array","maxItems":12,"items":{"type":"object","properties":{
            "statement":{"type":"string","maxLength":1000},
            "confidence":{"type":"number","minimum":0,"maximum":1},
            "uncertainty":{"type":"string","maxLength":1000},
            "supporting_reference_ids":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":160}},
            "contradicting_reference_ids":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":160}}},
            "required":["statement","uncertainty","supporting_reference_ids","contradicting_reference_ids"],"additionalProperties":false}},
          "tasks":{"type":"array","maxItems":12,"items":{"type":"object","properties":{
            "objective":{"type":"string","maxLength":500}},"required":["objective"],"additionalProperties":false}},
          "evidence_reference_ids":{"type":"array","maxItems":50,"items":{"type":"string","maxLength":160}},
          "open_questions":{"type":"array","maxItems":16,"items":{"type":"string","maxLength":500}}},
          "required":["summary","observations","findings","hypotheses","tasks","evidence_reference_ids","open_questions"],
          "additionalProperties":false}
        """).RootElement.Clone();

    internal static readonly JsonElement GeneralQueryResultSchema = CompactGeneralQuerySchema();

    private static JsonElement CompactGeneralQuerySchema()
    {
        var schema = JsonNode.Parse(ResultSchema.GetRawText())!.AsObject();
        var properties = schema["properties"]!.AsObject();
        foreach (var name in new[] { "findings", "hypotheses", "tasks" })
            properties.Remove(name);
        schema["required"] = JsonNode.Parse("""["summary","observations","evidence_reference_ids","open_questions"]""");
        return JsonSerializer.SerializeToElement(schema);
    }

    private static JsonElement OutputSchemaFor(string skillId)
    {
        if (skillId == AgentDefinition.InvestigateProcessSkillId) return ResultSchema.Clone();
        var schema = JsonNode.Parse(ResultSchema.GetRawText())!.AsObject();
        var properties = schema["properties"]!.AsObject();
        foreach (var name in new[] { "findings", "hypotheses", "tasks" })
            properties[name] = JsonNode.Parse("""{"type":"array","maxItems":0,"items":{"type":"null"}}""");
        return JsonSerializer.SerializeToElement(schema);
    }

    public AgentSkillRegistry(AgentToolRegistry checkedTools)
    {
        _checkedTools = checkedTools ?? throw new ArgumentNullException(nameof(checkedTools));
        var registered = new IAgentSkill[]
        {
            new FixedSkill(this, AgentDefinition.ReviewRecordSkillId,
                "Assess all captured fields of only the exact selected record.",
                ["Target", "Objective"], ["GetReviewRecord"],
                [AgentPermission.EvidenceRead, AgentPermission.QueryLocal]),
            new FixedSkill(this, AgentDefinition.ExplainObjectSkillId,
                "Explain the selected evidence with observed context and explicit uncertainty.",
                ["Target", "Objective"], _checkedTools.Descriptors.Where(tool => tool.RequiredPermissions.All(permission =>
                    permission is AgentPermission.EvidenceRead or AgentPermission.QueryLocal) && tool.AllowedSkillIds.Contains(AgentDefinition.ExplainObjectSkillId)).Select(tool => tool.Id),
                [AgentPermission.EvidenceRead, AgentPermission.QueryLocal]),
            new FixedSkill(this, AgentDefinition.QueryEvidenceSkillId,
                "Run selected Object queries or explicit bounded General read requests through registered evidence Tools.",
                ["Objective", "Queries"],
                _checkedTools.Descriptors.Where(tool => tool.RequiredPermissions.All(permission =>
                    permission is AgentPermission.EvidenceRead or AgentPermission.QueryLocal) && tool.AllowedSkillIds.Contains(AgentDefinition.QueryEvidenceSkillId)).Select(tool => tool.Id),
                [AgentPermission.EvidenceRead, AgentPermission.QueryLocal]),
            new FixedSkill(this, AgentDefinition.InvestigateProcessSkillId,
                "Investigate one scoped process using attributable evidence and open questions.",
                ["Target", "Objective", "CurrentInvestigation"],
                ["GetProcessDetails", "GetProcessTree", "GetProcessEvents", "GetProcessNetwork", "GetProcessPersistence"],
                [AgentPermission.EvidenceRead, AgentPermission.QueryLocal,
                    AgentPermission.InvestigationModify, AgentPermission.FindingCreate,
                    AgentPermission.HypothesisCreate, AgentPermission.TaskCreate])
        };
        _skills = registered.ToDictionary(skill => skill.Descriptor.Id, StringComparer.Ordinal);
        Descriptors = Array.AsReadOnly(registered.Select(skill => skill.Descriptor).ToArray());
    }

    public IReadOnlyList<AgentSkillDescriptor> Descriptors { get; }

    public AgentSkillPlan Prepare(AgentToolSession session, AgentSkillRequest request,
        CancellationToken lifetime = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!_skills.TryGetValue(request.SkillId, out var skill))
            throw new ArgumentException("The Skill ID is not registered.", nameof(request));
        return skill.Prepare(session, request, lifetime);
    }

    public async Task<AgentToolResult> ExecuteToolAsync(AgentSkillPlan plan,
        ModelToolRequest request, CancellationToken cancellationToken = default)
    {
        CheckPlan(plan);
        ArgumentNullException.ThrowIfNull(request);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(plan.Lifetime, cancellationToken);
        linked.Token.ThrowIfCancellationRequested();
        var selected = plan.SkillId != AgentDefinition.QueryEvidenceSkillId ||
            plan.TryConsumeSelected(request) || plan.AdmitsModelTool(request.Name);
        var tool = _checkedTools.Descriptors.FirstOrDefault(item => item.Id == request.Name);
        if (!selected || !plan.AllowedToolIds.Contains(request.Name, StringComparer.Ordinal) ||
            tool is null || tool.RequiredPermissions.Any(permission =>
                !plan.Descriptor.RequiredPermissions.Contains(permission)))
        {
            plan.Session.TryCountAttempt();
            var denied = AgentToolResult.Rejected(string.Empty, AgentToolStatus.Denied, "skill.tool-denied");
            plan.Record(denied);
            return denied;
        }
        var result = await _checkedTools.DispatchAsync(plan.Session, request, linked.Token);
        linked.Token.ThrowIfCancellationRequested();
        CheckPlan(plan);
        plan.Record(result);
        return result;
    }

    public AgentSkillResult NormalizeResult(AgentSkillPlan plan, JsonElement modelOutput)
    {
        CheckPlan(plan);
        var snapshot = plan.Snapshot();
        var result = AgentSkillResultNormalizer.Normalize(plan, modelOutput, snapshot.References, snapshot.Coverage);
        CheckPlan(plan);
        return result;
    }

    public AgentSkillResult NormalizeConversation(AgentSkillPlan plan, string content,
        string? validationFailure = null)
    {
        CheckPlan(plan);
        var snapshot = plan.Snapshot();
        var result = AgentSkillResultNormalizer.NormalizeConversation(plan, content,
            snapshot.References, snapshot.Coverage, validationFailure);
        CheckPlan(plan);
        return result;
    }

    private void CheckPlan(AgentSkillPlan plan)
    {
        if (plan is null || !ReferenceEquals(plan.Owner, this))
            throw new InvalidOperationException("The Skill plan does not belong to this registry.");
        plan.EnsureLive();
    }

    private AgentSkillPlan PrepareCore(AgentSkillDescriptor descriptor,
        AgentToolSession session, AgentSkillRequest request, CancellationToken lifetime)
    {
        ArgumentNullException.ThrowIfNull(session);
        lifetime.ThrowIfCancellationRequested();
        var targetlessGeneral = session.Scope.ContextType == AiConversationContextType.General &&
            descriptor.Id == AgentDefinition.QueryEvidenceSkillId &&
            request.Target is null && session.Target is null;
        if (!session.OwnerPolicy.CheckIteration(session) || session.SkillId != descriptor.Id ||
            !Enum.IsDefined(session.Scope.ContextType) ||
            (!targetlessGeneral && (request.Target?.Reference is null ||
                session.Target is null ||
                session.Target.CanonicalObjectKey != request.Target!.Reference.CanonicalObjectKey ||
                !AgentPolicy.ScopeAdmits(session.Scope, request.Target.Reference.Identity))) ||
            descriptor.RequiredPermissions.Any(permission => !session.Definition.AllowedPermissions.Contains(permission)))
            throw new InvalidOperationException("The Skill input is outside the active execution scope.");
        if (string.IsNullOrWhiteSpace(request.Objective) ||
            Encoding.UTF8.GetByteCount(request.Objective) > MaximumObjectiveBytes)
            throw new ArgumentException("A bounded objective is required.", nameof(request));
        if (request.CurrentTasks?.Count > 32 || request.CurrentFindings?.Count > 32 ||
            request.CurrentHypotheses?.Count > 32 || request.CurrentEvidenceLinks?.Count > 50 ||
            request.CurrentInvestigation?.OpenQuestions?.Count > 16)
            throw new ArgumentException("Current investigation state exceeds its count bounds.", nameof(request));
        var target = request.Target is null ? null : FreezeTarget(request.Target);
        if (descriptor.Id == AgentDefinition.ReviewRecordSkillId && target is not null)
            target = new AiObjectContext(target.Reference with { CompactSnapshot = "", SnapshotProvenance = "" },
                new Dictionary<string, string>(), new Dictionary<string, string>(), []);
        var investigation = FreezeInvestigation(request.CurrentInvestigation);
        var tasks = Array.AsReadOnly((request.CurrentTasks ?? []).ToArray());
        var findings = Array.AsReadOnly((request.CurrentFindings ?? []).ToArray());
        var hypotheses = Array.AsReadOnly((request.CurrentHypotheses ?? []).ToArray());
        var evidenceLinks = Array.AsReadOnly((request.CurrentEvidenceLinks ?? []).ToArray());
        ValidateCurrentState(descriptor.Id, session, target, investigation,
            tasks, findings, hypotheses, evidenceLinks);
        var initial = BuildInitialRequests(descriptor, session, target, request.Queries);
        return new AgentSkillPlan(this, session, descriptor, target, request.Objective,
            investigation, tasks, findings, hypotheses, evidenceLinks, initial, lifetime);
    }

    private static AiObjectContext FreezeTarget(AiObjectContext target)
    {
        if (!ValidReference(target.Reference) ||
            target.DisplayProperties.Count > 32 || target.KeyProperties.Count > 16 ||
            target.RelatedDataHints.Count > 16 ||
            target.DisplayProperties.Any(pair => !Bounded(pair.Key, 80) || !Bounded(pair.Value, 1_000)) ||
            target.KeyProperties.Any(pair => !Bounded(pair.Key, 80) || !Bounded(pair.Value, 1_000)) ||
            target.RelatedDataHints.Any(hint => !Bounded(hint, 200)) ||
            !Bounded(target.Reference.CompactSnapshot, 4_096) ||
            !Bounded(target.Reference.DisplayName, 500) ||
            target.RangeStartUtc is { Kind: not DateTimeKind.Utc } ||
            target.RangeEndUtc is { Kind: not DateTimeKind.Utc } ||
            target.RangeStartUtc > target.RangeEndUtc ||
            JsonSerializer.SerializeToUtf8Bytes(target.Reference).Length > 16_000)
            throw new ArgumentException("Selected context is unbounded.");
        return new AiObjectContext(target.Reference, target.DisplayProperties,
            target.KeyProperties, target.RelatedDataHints, target.RangeStartUtc, target.RangeEndUtc);
    }

    private static Investigation? FreezeInvestigation(Investigation? value) => value is null
        ? null : value with { OpenQuestions = Array.AsReadOnly((value.OpenQuestions ?? []).ToArray()) };

    private static bool Bounded(string? value, int maximumBytes) =>
        value is not null && Encoding.UTF8.GetByteCount(value) <= maximumBytes;

    private static bool ValidReference(AiEvidenceReference reference)
    {
        if (reference is null || reference.Identity is null || reference.Evidence is null ||
            !Enum.IsDefined(reference.Evidence.Kind) ||
            string.IsNullOrWhiteSpace(reference.ReferenceId) || !Bounded(reference.ReferenceId, 160) ||
            string.IsNullOrWhiteSpace(reference.Identity.EvidenceSessionId) ||
            string.IsNullOrWhiteSpace(reference.Identity.CaptureId) ||
            string.IsNullOrWhiteSpace(reference.Identity.SourceIdentityId) ||
            string.IsNullOrWhiteSpace(reference.Identity.HostId) ||
            !Bounded(reference.Identity.CaseId, 4_096) ||
            !Bounded(reference.Identity.EvidenceSessionId, 4_096) ||
            !Bounded(reference.Identity.CaptureId, 4_096) ||
            !Bounded(reference.Identity.SourceIdentityId, 4_096) ||
            !Bounded(reference.Identity.HostId, 4_096) ||
            !Bounded(reference.Identity.ExecutionRootId, 4_096) ||
            !Bounded(reference.Evidence.Id, 4_096) ||
            !Bounded(reference.SourceRunId, 4_096) ||
            !Bounded(reference.SourceRevision, 4_096) ||
            string.IsNullOrWhiteSpace(reference.DataSource) || !Bounded(reference.DataSource, 120) ||
            !Bounded(reference.DisplayName, 500) || !Bounded(reference.CompactSnapshot, 4_096) ||
            !Bounded(reference.SnapshotProvenance, 1_000) ||
            reference.TimestampUtc is { Kind: not DateTimeKind.Utc } ||
            reference.CompactSnapshot.Length > 0 && string.IsNullOrWhiteSpace(reference.SnapshotProvenance) ||
            reference.Process is { } process &&
                (!Bounded(process.ProcessEntityId, 4_096) ||
                 !Bounded(process.ProcessKey, 4_096) ||
                 !Bounded(process.CaseId, 4_096) ||
                 !Bounded(process.EvidenceSessionId, 4_096) ||
                 !Bounded(process.CaptureId, 4_096) ||
                 !Bounded(process.SourceIdentityId, 4_096) ||
                 !Bounded(process.HostId, 4_096) ||
                 !Bounded(process.ExecutionRootId, 4_096) ||
                 process.CaseId != reference.Identity.CaseId ||
                 process.EvidenceSessionId != reference.Identity.EvidenceSessionId ||
                 process.CaptureId != reference.Identity.CaptureId ||
                 process.SourceIdentityId != reference.Identity.SourceIdentityId ||
                 process.HostId != reference.Identity.HostId ||
                 process.ExecutionRootId != reference.Identity.ExecutionRootId) ||
            JsonSerializer.SerializeToUtf8Bytes(reference).Length > 16_000)
            return false;
        if (reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity)
            return string.IsNullOrWhiteSpace(reference.SourceRunId) &&
                string.IsNullOrWhiteSpace(reference.SourceRevision) &&
                (!string.IsNullOrWhiteSpace(reference.Evidence.Id) ||
                 !string.IsNullOrWhiteSpace(reference.Process?.ProcessKey)) &&
                (reference.Process is null ||
                 reference.Process.ProcessEntityId == reference.Evidence.Id &&
                 reference.Process.CaseId == reference.Identity.CaseId &&
                 reference.Process.EvidenceSessionId == reference.Identity.EvidenceSessionId &&
                 reference.Process.CaptureId == reference.Identity.CaptureId &&
                 reference.Process.SourceIdentityId == reference.Identity.SourceIdentityId &&
                 reference.Process.HostId == reference.Identity.HostId &&
                 reference.Process.ExecutionRootId == reference.Identity.ExecutionRootId);
        return !string.IsNullOrWhiteSpace(reference.Evidence.Id) &&
            (!string.IsNullOrWhiteSpace(reference.SourceRunId) ||
             !string.IsNullOrWhiteSpace(reference.SourceRevision));
    }

    private static void ValidateCurrentState(string skillId, AgentToolSession session,
        AiObjectContext? target, Investigation? investigation,
        IReadOnlyList<InvestigationTask> tasks,
        IReadOnlyList<InvestigationFinding> findings,
        IReadOnlyList<InvestigationHypothesis> hypotheses,
        IReadOnlyList<InvestigationEvidenceLink> evidenceLinks)
    {
        if (tasks.Count > 32 || findings.Count > 32 || hypotheses.Count > 32 ||
            evidenceLinks.Count > 50 || evidenceLinks.Any(link => link is null) ||
            tasks.Any(task => task is null) || findings.Any(finding => finding is null) ||
            hypotheses.Any(hypothesis => hypothesis is null) ||
            tasks.Any(task => !Enum.IsDefined(task.Status) || !Bounded(task.Id, 160) ||
                !Bounded(task.InvestigationId, 160) || !Bounded(task.Objective, 1_000) ||
                !Bounded(task.ResultSummary, 2_000)) ||
            findings.Any(finding => !Enum.IsDefined(finding.Severity) ||
                !Enum.IsDefined(finding.VerificationStatus) || !Bounded(finding.Id, 160) ||
                !Bounded(finding.InvestigationId, 160) || !Bounded(finding.Title, 200) ||
                !Bounded(finding.Claim, 1_000) || !Bounded(finding.Description, 2_000)) ||
            hypotheses.Any(hypothesis => !Enum.IsDefined(hypothesis.Status) ||
                !Bounded(hypothesis.Id, 160) || !Bounded(hypothesis.InvestigationId, 160) ||
                !Bounded(hypothesis.Statement, 1_000)) ||
            investigation is not null && (!Enum.IsDefined(investigation.Status) ||
                !Bounded(investigation.Id, 160) || !Bounded(investigation.Title, 500) ||
                !Bounded(investigation.Objective, 2_000) ||
                !Bounded(investigation.Summary, 4_000) || investigation.OpenQuestions.Count > 16 ||
                investigation.OpenQuestions.Any(question => !Bounded(question, 500))) ||
            JsonSerializer.SerializeToUtf8Bytes(new { investigation, tasks, findings,
                hypotheses, evidenceLinks }).Length > 64_000)
            throw new ArgumentException("Current investigation state is invalid or unbounded.");
        if (skillId != AgentDefinition.InvestigateProcessSkillId)
        {
            if (investigation is not null || tasks.Count > 0 || findings.Count > 0 ||
                hypotheses.Count > 0 || evidenceLinks.Count > 0)
                throw new ArgumentException("This Skill does not accept investigation state.");
            return;
        }
        if (target?.Reference.Evidence.Kind != EvidenceReferenceKind.ProcessEntity ||
            investigation is null || investigation.Target is null ||
            session.Scope.ContextType != AiConversationContextType.Investigation ||
            session.Scope.ContextId != investigation.Id ||
            investigation.Target.CanonicalObjectKey != target!.Reference.CanonicalObjectKey ||
            investigation.Status == InvestigationState.Closed ||
            tasks.Any(task => task.InvestigationId != investigation.Id) ||
            findings.Any(finding => finding.InvestigationId != investigation.Id) ||
            hypotheses.Any(hypothesis => hypothesis.InvestigationId != investigation.Id) ||
            tasks.Select(task => task.Id).Distinct(StringComparer.Ordinal).Count() != tasks.Count ||
            findings.Select(finding => finding.Id).Distinct(StringComparer.Ordinal).Count() != findings.Count ||
            hypotheses.Select(hypothesis => hypothesis.Id).Distinct(StringComparer.Ordinal).Count() != hypotheses.Count)
            throw new ArgumentException("InvestigateProcess requires matching active process investigation state.");
        var findingIds = findings.Select(finding => finding.Id).ToHashSet(StringComparer.Ordinal);
        var hypothesisIds = hypotheses.Select(hypothesis => hypothesis.Id).ToHashSet(StringComparer.Ordinal);
        var seenLinks = new HashSet<string>(StringComparer.Ordinal);
        foreach (var link in evidenceLinks)
        {
            if (!Enum.IsDefined(link.Owner) || !Enum.IsDefined(link.Polarity) ||
                link.Reference is null || !ValidReference(link.Reference) ||
                !session.AdmitReference(link.Reference) ||
                link.Owner == InvestigationEvidenceOwner.Finding && !findingIds.Contains(link.OwnerId) ||
                link.Owner == InvestigationEvidenceOwner.Hypothesis && !hypothesisIds.Contains(link.OwnerId) ||
                link.Owner is not (InvestigationEvidenceOwner.Finding or InvestigationEvidenceOwner.Hypothesis) ||
                !seenLinks.Add($"{link.Owner}|{link.OwnerId}|{link.Polarity}|{link.Reference.ReferenceId}"))
                throw new ArgumentException("Saved evidence link is outside the current investigation state.");
        }
    }

    private IReadOnlyList<ModelToolRequest> BuildInitialRequests(AgentSkillDescriptor descriptor,
        AgentToolSession session, AiObjectContext? target, IReadOnlyList<SkillToolQuery>? queries)
    {
        if (target is null)
        {
            if (descriptor.Id != AgentDefinition.QueryEvidenceSkillId || queries?.Count > 1 ||
                string.IsNullOrWhiteSpace(session.Scope.Identity.HostId) && queries is { Count: > 0 } ||
                queries is { Count: > 0 } && queries.Any(query => query.ToolId != "GetHostProcesses"))
                throw new ArgumentException("Targetless general discussion permits at most one checked host query.");
            if (queries is null || queries.Count == 0) return [];
        }
        if (descriptor.Id == AgentDefinition.ReviewRecordSkillId)
        {
            if (queries is { Count: > 0 }) throw new ArgumentException("ReviewRecord accepts no query selections.");
            return Array.AsReadOnly(new[] { Request("GetReviewRecord", 0, EmptyArguments) });
        }
        if (descriptor.Id == AgentDefinition.ExplainObjectSkillId)
        {
            if (queries is { Count: > 0 }) throw new ArgumentException("ExplainObject does not accept query selections.");
            return target?.Reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity
                ? Array.AsReadOnly(new[] { Request("GetProcessDetails", 0, EmptyArguments) })
                : Array.AsReadOnly(new[] { Request("GetSelectedEvidence", 0, EmptyArguments) });
        }
        if (descriptor.Id == AgentDefinition.InvestigateProcessSkillId)
        {
            if (queries is { Count: > 0 }) throw new ArgumentException("InvestigateProcess selects additional Tools during execution.");
            return Array.AsReadOnly(new[] { Request("GetProcessDetails", 0, EmptyArguments),
                Request("GetProcessTree", 1, EmptyArguments) });
        }
        if (target is not null && (queries is null || queries.Count is < 1 or > 5))
            throw new ArgumentException("QueryEvidence requires one to five checked queries.");
        if (queries is null) return [];
        var registered = _checkedTools.Descriptors.ToDictionary(tool => tool.Id, StringComparer.Ordinal);
        var selected = new List<ModelToolRequest>(queries.Count);
        for (var i = 0; i < queries.Count; i++)
        {
            var query = queries[i];
            if (query is null || !descriptor.AllowedToolIds.Contains(query.ToolId, StringComparer.Ordinal) ||
                target is not null && target.Reference.Evidence.Kind != EvidenceReferenceKind.ProcessEntity &&
                    query.ToolId is not ("GetSelectedEvidence" or "GetRelatedEvidence") ||
                target is not null && target.Reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity &&
                    query.ToolId is "GetSelectedEvidence" or "GetRelatedEvidence" or "GetHostProcesses" ||
                !registered.TryGetValue(query.ToolId, out var tool) ||
                tool.RequiredPermissions.Any(permission =>
                    !descriptor.RequiredPermissions.Contains(permission)) ||
                query.Arguments.ValueKind != JsonValueKind.Object ||
                Encoding.UTF8.GetByteCount(query.Arguments.GetRawText()) > 16_000 ||
                !UniqueArguments(query.Arguments, 0, new ArgumentCounter()) ||
                !ModelJsonSchemaValidator.IsValid(query.Arguments, tool.InputSchema))
                throw new ArgumentException("Query selection is unsupported or invalid.");
            selected.Add(Request(query.ToolId, i, query.Arguments));
        }
        return Array.AsReadOnly(selected.ToArray());
    }

    private static ModelToolRequest Request(string toolId, int index, JsonElement arguments) =>
        new($"skill-{index}-{toolId}", toolId, arguments.Clone());

    private sealed class ArgumentCounter { public int Value; }

    private static bool UniqueArguments(JsonElement value, int depth, ArgumentCounter counter)
    {
        if (depth > 12 || ++counter.Value > 1_024) return false;
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
                if (!names.Add(property.Name) || !UniqueArguments(property.Value, depth + 1, counter))
                    return false;
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray())
                if (!UniqueArguments(item, depth + 1, counter)) return false;
        return true;
    }

    private static readonly JsonElement EmptyArguments = JsonDocument.Parse("{}").RootElement.Clone();

    private sealed class FixedSkill : IAgentSkill
    {
        private readonly AgentSkillRegistry _owner;

        public FixedSkill(AgentSkillRegistry owner, string id, string description,
            IEnumerable<string> requiredInput, IEnumerable<string> allowedToolIds,
            IEnumerable<AgentPermission> requiredPermissions)
        {
            _owner = owner;
            Descriptor = new AgentSkillDescriptor(id, id, description,
                Array.AsReadOnly(requiredInput.ToArray()), Array.AsReadOnly(allowedToolIds.ToArray()),
                Array.AsReadOnly(requiredPermissions.ToArray()), OutputSchemaFor(id));
        }

        public AgentSkillDescriptor Descriptor { get; }

        public AgentSkillPlan Prepare(AgentToolSession session, AgentSkillRequest request,
            CancellationToken lifetime = default) => _owner.PrepareCore(Descriptor, session, request, lifetime);
    }
}
