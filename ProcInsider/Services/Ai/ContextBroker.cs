using System.Text;
using System.Text.Json;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

// Selects whole attributable context for one inference. It never calls a provider or a Tool.
public sealed class ContextBroker
{
    private const int ConservativeUnknownWindow = 4_096;
    private const int MaximumInputBytes = 8_000_000;
    private const int MaximumHistoryBytes = 4_000_000;
    private const int MaximumRecordBytes = 1_000_000;
    private const string EstimationMethod = "Heuristic: ASCII UTF-8 content at three bytes per token, non-ASCII UTF-8 bytes at one per token, plus message/schema overhead; transport escaping excluded; 20% window reserve; estimate, not tokenizer or provider usage.";

    public Task<ContextBrokerResult> BuildAsync(ContextBrokerInput input,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        return Task.Run(() => BuildCore(input, cancellationToken), cancellationToken);
    }

    private static ContextBrokerResult BuildCore(ContextBrokerInput input, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!Current(input)) return Fail(ContextBrokerFailureCode.StaleScope,
            "The captured workspace selection changed.", EmptyReport());
        try
        {
            var frozen = Freeze(input, ct);
            if (!Current(input)) return Fail(ContextBrokerFailureCode.StaleScope,
                "The captured workspace selection changed.", EmptyReport());
            return Pack(frozen, input.IsCurrentGeneration, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or JsonException)
        {
            return Fail(ContextBrokerFailureCode.InvalidInput,
                "Context input is invalid or exceeds its safe bound.\n" +
                ModelDiagnosticRedactor.Sanitize(exception.ToString()), EmptyReport());
        }
    }

    private static FrozenInput Freeze(ContextBrokerInput input, CancellationToken ct)
    {
        if (input.Capabilities is null || input.Scope is null || input.Scope.Identity is null ||
            input.IsCurrentGeneration is null || input.History is null ||
            !Enum.IsDefined(input.Scope.ContextType) ||
            !Bounded(input.Scope.Identity.CaseId, 4_096) ||
            !Bounded(input.Scope.Identity.EvidenceSessionId, 4_096) ||
            !Bounded(input.Scope.Identity.CaptureId, 4_096) ||
            !Bounded(input.Scope.Identity.SourceIdentityId, 4_096) ||
            !Bounded(input.Scope.Identity.HostId, 4_096) ||
            !Bounded(input.Scope.Identity.ExecutionRootId, 4_096) ||
            string.IsNullOrWhiteSpace(input.Scope.ContextId) ||
            !Bounded(input.Scope.ContextId, 8_192) ||
            !Bounded(input.SystemInstructions, 16_000) ||
            string.IsNullOrWhiteSpace(input.SystemInstructions) ||
            !Bounded(input.CurrentQuestion, 16_000) ||
            string.IsNullOrWhiteSpace(input.CurrentQuestion) ||
            !Bounded(input.PinnedTargetDescription, 16_000, allowNull: true) ||
            input.Sources?.Count > 32 || input.Tools?.Count > 64 ||
            input.AdmittedRelatedReferences?.Count > (input.Scope.ContextType == AiConversationContextType.Investigation
                ? 50 : AgentDefinition.InteractiveInvestigator.Limits.MaximumToolCalls * 50) ||
            input.Tasks?.Count > 100 || input.Findings?.Count > 100 ||
            input.Hypotheses?.Count > 100 || input.EvidenceLinks?.Count > 200 ||
            input.PreOmittedHistoryMessages < 0 ||
            (long)input.PreOmittedHistoryMessages + input.History.Count > int.MaxValue ||
            input.Investigation?.OpenQuestions is null && input.Investigation is not null ||
            input.Investigation?.OpenQuestions.Count > 100)
            throw new ArgumentException("Broker input bound is invalid.");
        if (input.Scope.ContextType == AiConversationContextType.Object &&
            (input.Scope.ObjectReference is null ||
             !ValidReference(input.Scope, input.Scope.ObjectReference) ||
             input.Scope.ContextId != input.Scope.ObjectReference.CanonicalObjectKey) ||
            input.Scope.ContextType != AiConversationContextType.Object &&
                input.Scope.ObjectReference is not null)
            throw new ArgumentException("Conversation scope is invalid.");
        if (input.GeneralContext is { } general &&
            (input.Scope.ContextType != AiConversationContextType.General || input.Target is not null ||
             general.ScopeIdentity != input.Scope.Identity ||
             general.CapturedUtc.Kind != DateTimeKind.Utc ||
             general.TimeStartUtc is { Kind: not DateTimeKind.Utc } ||
             general.TimeEndUtc is { Kind: not DateTimeKind.Utc } ||
             general.TimeStartUtc > general.TimeEndUtc ||
             !Bounded(general.Workspace, 160) ||
             !Bounded(general.SelectedEntityHint, 500) ||
             !Bounded(general.ActiveInvestigationId, 160, allowNull: true)))
            throw new ArgumentException("General submission hints are outside the captured scope.");
        var related = (input.AdmittedRelatedReferences ?? []).ToArray();
        if (input.RuntimeBudget is { } runtimeBudget &&
            (runtimeBudget.RemainingToolCalls is < 0 or > 1_000 ||
             runtimeBudget.RemainingModelIterations is < 0 or > 1_000 ||
             runtimeBudget.OlderResultsInExchanges is < 0 or > 1_000 ||
             !Bounded(runtimeBudget.FinalizationReason, 3_000)))
            throw new ArgumentException("Runtime budget is invalid or unbounded.");
        var relatedScope = input.Scope with
        {
            ContextType = AiConversationContextType.Investigation,
            ObjectReference = null,
            Identity = input.Scope.Identity with { SourceIdentityId = "", ExecutionRootId = "" }
        };
        if (related.Any(reference => !ValidReference(relatedScope, reference) ||
                !(AgentPolicy.ScopeAdmits(input.Scope, reference.Identity) ||
                  AgentPolicy.RelatedBoundaryAdmits(input.Scope, reference.Identity))) ||
            related.Select(reference => reference.ReferenceId).Distinct(StringComparer.Ordinal).Count() != related.Length ||
            JsonSerializer.SerializeToUtf8Bytes(related).Length > (input.Scope.ContextType == AiConversationContextType.Investigation
                ? 64_000 : 4_096_000))
            throw new ArgumentException("Admitted related context is invalid or unbounded.");
        var admittedBytes = (long)Encoding.UTF8.GetByteCount(input.SystemInstructions) +
            Encoding.UTF8.GetByteCount(input.CurrentQuestion) +
            Encoding.UTF8.GetByteCount(input.PinnedTargetDescription ?? string.Empty) +
            JsonSerializer.SerializeToUtf8Bytes(input.GeneralContext).Length;
        var historyOffered = input.History.Count;
        if (input.CurrentTurnToolMessageCount < 0 || input.CurrentTurnToolMessageCount > historyOffered || input.CurrentTurnToolMessageCount > 500)
            throw new ArgumentException("Current turn Tool history is invalid.");
        var currentTurn = input.History.Skip(historyOffered - input.CurrentTurnToolMessageCount).ToArray();
        if (currentTurn.Any(message => message is null ||
            (message.Role != ModelMessageRole.Tool &&
             !(message.Role == ModelMessageRole.Assistant && message.ToolRequests is { Count: > 0 }))))
            throw new ArgumentException("Current turn history must contain only completed Tool exchanges.");
        GroupHistory(currentTurn);
        var currentTurnCallIds = currentTurn.SelectMany(message => message.ToolRequests ?? [])
            .Select(call => call.CallId).ToHashSet(StringComparer.Ordinal);
        var historyStart = Math.Max(0, historyOffered - 500);
        var historyBytes = 0L;
        for (var index = historyOffered - 1; index >= historyStart; index--)
        {
            ct.ThrowIfCancellationRequested();
            var candidate = input.History[index];
            var size = Encoding.UTF8.GetByteCount(candidate?.Content ?? string.Empty);
            if (candidate?.ProviderOutputItems is { } providerItems)
                size += Encoding.UTF8.GetByteCount(providerItems.GetRawText());
            if (size > 256_000 || historyBytes + size > MaximumHistoryBytes)
            {
                historyStart = index + 1;
                break;
            }
            historyBytes += size;
        }
        // A bounded tail may begin between an assistant Tool call and its replies.
        // Omit those replies rather than sending orphaned Tool messages.
        while (historyStart < historyOffered &&
            input.History[historyStart]?.Role == ModelMessageRole.Tool)
            historyStart++;
        if (input.CurrentTurnToolMessageCount > 0 &&
            historyStart > historyOffered - input.CurrentTurnToolMessageCount)
            throw new ArgumentException("A completed current-turn Tool exchange exceeds the safe history bound.");
        for (var index = historyStart; index < historyOffered; index++)
        {
            ct.ThrowIfCancellationRequested();
            var message = input.History[index];
            admittedBytes += Encoding.UTF8.GetByteCount(message?.Content ?? string.Empty);
            if (message?.ProviderOutputItems is { } providerItems)
                admittedBytes += Encoding.UTF8.GetByteCount(providerItems.GetRawText());
            if (admittedBytes > MaximumInputBytes) throw new ArgumentException("Conversation is unbounded.");
        }
        foreach (var source in input.Sources ?? [])
        {
            ct.ThrowIfCancellationRequested();
            if (source?.Records is null || source.Records.Count > 500)
                throw new ArgumentException("Source is unbounded.");
            admittedBytes += Encoding.UTF8.GetByteCount(source.Coverage ?? string.Empty);
            foreach (var record in source.Records)
            {
                if (record is null) throw new ArgumentException("Record is invalid.");
                admittedBytes += Encoding.UTF8.GetByteCount(record.Text ?? string.Empty);
                if (admittedBytes > MaximumInputBytes) throw new ArgumentException("Evidence is unbounded.");
            }
        }
        var history = new ModelMessage[historyOffered - historyStart];
        for (var index = historyStart; index < historyOffered; index++)
        {
            ct.ThrowIfCancellationRequested();
            history[index - historyStart] = FreezeMessage(input.History[index]);
        }
        var historyGroups = GroupHistory(history);
        var sources = (input.Sources ?? []).Select(source => FreezeSource(input.Scope, source, related)).ToArray();
        var tools = (input.Tools ?? []).Select(tool => FreezeTool(tool)).ToArray();
        if (tools.Select(tool => tool.Name).Distinct(StringComparer.Ordinal).Count() != tools.Length)
            throw new ArgumentException("Duplicate Tool definitions.");
        var tasks = (input.Tasks ?? []).ToArray();
        var findings = (input.Findings ?? []).ToArray();
        var hypotheses = (input.Hypotheses ?? []).ToArray();
        var links = (input.EvidenceLinks ?? []).ToArray();
        if (tasks.Any(item => item is null || input.Investigation is null ||
                item.InvestigationId != input.Investigation.Id) ||
            findings.Any(item => item is null || input.Investigation is null ||
                item.InvestigationId != input.Investigation.Id) ||
            hypotheses.Any(item => item is null || input.Investigation is null ||
                item.InvestigationId != input.Investigation.Id) ||
            links.Any(item => item is null || item.Reference is null ||
                !ValidReference(input.Scope, item.Reference) ||
                (item.Owner == InvestigationEvidenceOwner.Finding &&
                    !findings.Any(finding => finding.Id == item.OwnerId)) ||
                (item.Owner == InvestigationEvidenceOwner.Hypothesis &&
                    !hypotheses.Any(hypothesis => hypothesis.Id == item.OwnerId)) ||
                item.Owner == InvestigationEvidenceOwner.ToolCall || !Enum.IsDefined(item.Owner) ||
                !Enum.IsDefined(item.Polarity)) ||
            hypotheses.Any(item => item is null) || links.Any(item => item is null) ||
            input.Target is { } target &&
                (!ValidReference(input.Scope, target.Reference) ||
                 input.Scope.ContextType == AiConversationContextType.Object &&
                    (input.Scope.ObjectReference is null ||
                     !ValidReference(input.Scope, input.Scope.ObjectReference) ||
                     target.Reference.CanonicalObjectKey !=
                        input.Scope.ObjectReference.CanonicalObjectKey)) ||
            input.Investigation is { } investigation &&
                (input.Scope.ContextType != AiConversationContextType.Investigation ||
                 input.Scope.ContextId != investigation.Id ||
                 investigation.Target is { } investigationTarget &&
                    (!ValidReference(input.Scope, investigationTarget) ||
                     input.Target is not null &&
                        input.Target.Reference.CanonicalObjectKey !=
                            investigationTarget.CanonicalObjectKey)))
            throw new ArgumentException("Broker state has invalid scope.");
        if (input.OutputStructure is { } output &&
            (!SafeSchemaName(output.Name) ||
             output.Schema.ValueKind != JsonValueKind.Object ||
             Encoding.UTF8.GetByteCount(output.Schema.GetRawText()) > 32_000 ||
             !ModelJsonSchemaValidator.IsSupportedSchema(output.Schema) ||
             !ObjectSchema(output.Schema)))
            throw new ArgumentException("Output schema is invalid or unbounded.");
        var stateBytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            input.Target, input.GeneralContext, input.Investigation, tasks, findings, hypotheses, links
        }).Length;
        if (stateBytes > 1_000_000) throw new ArgumentException("Broker state is unbounded.");
        var bytes = stateBytes + Encoding.UTF8.GetByteCount(input.SystemInstructions) +
            Encoding.UTF8.GetByteCount(input.CurrentQuestion) +
            Encoding.UTF8.GetByteCount(input.PinnedTargetDescription ?? string.Empty);
        foreach (var message in history)
        {
            ct.ThrowIfCancellationRequested();
            bytes += JsonSerializer.SerializeToUtf8Bytes(message).Length;
            if (message.ProviderOutputItems is { } providerItems)
                bytes += Encoding.UTF8.GetByteCount(providerItems.GetRawText());
        }
        foreach (var source in sources)
        {
            ct.ThrowIfCancellationRequested();
            bytes += JsonSerializer.SerializeToUtf8Bytes(source).Length;
        }
        foreach (var tool in tools) bytes += JsonSerializer.SerializeToUtf8Bytes(tool).Length;
        if (bytes > MaximumInputBytes) throw new ArgumentException("Broker input is unbounded.");
        return new FrozenInput(input.Capabilities, input.SystemInstructions,
            input.CurrentQuestion, input.Scope with { Identity = input.Scope.Identity with { } },
            history, historyOffered + input.PreOmittedHistoryMessages, historyGroups, currentTurnCallIds,
            input.Target is null ? null : new AiObjectContext(input.Target.Reference,
                input.Target.DisplayProperties, input.Target.KeyProperties,
                input.Target.RelatedDataHints, input.Target.RangeStartUtc, input.Target.RangeEndUtc),
            input.Investigation is null ? null : input.Investigation with
                { OpenQuestions = Array.AsReadOnly(input.Investigation.OpenQuestions.ToArray()) },
            tasks, findings, hypotheses, links, sources, tools,
            input.PinnedTargetDescription,
            input.OutputStructure is null ? null : new ModelOutputStructure(
                input.OutputStructure.Name, input.OutputStructure.Schema.Clone()),
            input.ContextWindowOverrideTokens, input.RequestedOutputTokens,
            input.GeneralContext is null ? null : input.GeneralContext with
                { ScopeIdentity = input.GeneralContext.ScopeIdentity with { } }, input.RuntimeBudget);
    }

    private static ModelMessage FreezeMessage(ModelMessage message)
    {
        if (message is null || !Enum.IsDefined(message.Role) ||
            !Bounded(message.Content, 256_000) ||
            message.ProviderOutputItems is { } providerItems &&
                (message.Role != ModelMessageRole.Assistant || providerItems.ValueKind != JsonValueKind.Array ||
                 Encoding.UTF8.GetByteCount(providerItems.GetRawText()) > 256_000) ||
            !Bounded(message.ToolCallId, 160, allowNull: true) ||
            message.ToolRequests?.Count > 32 ||
            message.ToolRequests?.Any(request => request is null ||
                !SafeSchemaName(request.Name) || !Bounded(request.CallId, 160) ||
                request.Arguments.ValueKind != JsonValueKind.Object ||
                Encoding.UTF8.GetByteCount(request.Arguments.GetRawText()) > 16_000) == true)
            throw new ArgumentException("Conversation message is invalid or unbounded.");
        return message with { ProviderOutputItems = message.ProviderOutputItems?.Clone(),
            ToolRequests = message.ToolRequests is null ? null :
            Array.AsReadOnly(message.ToolRequests.Select(request => request with
                { Arguments = request.Arguments.Clone() }).ToArray()) };
    }

    private static HistoryGroup[] GroupHistory(ModelMessage[] history)
    {
        var groups = new List<HistoryGroup>();
        var seenCalls = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < history.Length;)
        {
            var start = index;
            var message = history[index++];
            if (message.Role == ModelMessageRole.Tool ||
                (message.ToolRequests is { Count: > 0 } && message.Role != ModelMessageRole.Assistant) ||
                (message.Role != ModelMessageRole.Tool && !string.IsNullOrEmpty(message.ToolCallId)))
                throw new ArgumentException("Malformed Tool exchange in history.");
            if (message.ToolRequests is { Count: > 0 } requests)
            {
                var pending = requests.Select(request => request.CallId).ToHashSet(StringComparer.Ordinal);
                if (pending.Count != requests.Count || pending.Contains(string.Empty))
                    throw new ArgumentException("Duplicate Tool call IDs in history.");
                if (pending.Any(callId => !seenCalls.Add(callId)))
                    throw new ArgumentException("Repeated Tool call ID in history.");
                while (pending.Count > 0 && index < history.Length &&
                    history[index].Role == ModelMessageRole.Tool)
                {
                    if (!pending.Remove(history[index].ToolCallId ?? string.Empty))
                        throw new ArgumentException("Unmatched Tool result in history.");
                    index++;
                }
                if (pending.Count > 0) throw new ArgumentException("Incomplete Tool exchange in history.");
            }
            groups.Add(new HistoryGroup(history[start..index]));
        }
        return groups.ToArray();
    }

    private static bool ValidReference(AiConversationScope scope, AiEvidenceReference? reference,
        IReadOnlyList<AiEvidenceReference>? related = null)
    {
        if (reference?.Evidence is null || reference.Identity is null ||
            !Enum.IsDefined(reference.Evidence.Kind) ||
            (!AgentPolicy.ScopeAdmits(scope, reference.Identity) &&
                !(scope.ContextType == AiConversationContextType.Object &&
                  related?.Contains(reference) == true)) ||
            string.IsNullOrWhiteSpace(reference.ReferenceId) ||
            !Bounded(reference.ReferenceId, 160) ||
            !Bounded(reference.Identity.CaseId, 4_096) ||
            !Bounded(reference.Identity.EvidenceSessionId, 4_096) ||
            !Bounded(reference.Identity.CaptureId, 4_096) ||
            !Bounded(reference.Identity.SourceIdentityId, 4_096) ||
            !Bounded(reference.Identity.HostId, 4_096) ||
            !Bounded(reference.Identity.ExecutionRootId, 4_096) ||
            !Bounded(reference.Evidence.Id, 4_096) ||
            !Bounded(reference.DataSource, 120) ||
            string.IsNullOrWhiteSpace(reference.DataSource) ||
            !Bounded(reference.SourceRunId, 4_096) ||
            !Bounded(reference.SourceRevision, 4_096) ||
            !Bounded(reference.DisplayName, 500) ||
            !Bounded(reference.CompactSnapshot, 4_096) ||
            !Bounded(reference.SnapshotProvenance, 1_000) ||
            reference.TimestampUtc is { Kind: not DateTimeKind.Utc } ||
            reference.CompactSnapshot.Length > 0 &&
                string.IsNullOrWhiteSpace(reference.SnapshotProvenance) ||
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
        if (reference.Evidence.Kind == ProcInsider.Models.EvidenceReferenceKind.ProcessEntity)
            return string.IsNullOrWhiteSpace(reference.SourceRunId) &&
                string.IsNullOrWhiteSpace(reference.SourceRevision) &&
                (!string.IsNullOrWhiteSpace(reference.Evidence.Id) ||
                 !string.IsNullOrWhiteSpace(reference.Process?.ProcessKey)) &&
                (reference.Process is null ||
                 reference.Process.ProcessEntityId == reference.Evidence.Id);
        return !string.IsNullOrWhiteSpace(reference.Evidence.Id) &&
            (!string.IsNullOrWhiteSpace(reference.SourceRunId) ||
             !string.IsNullOrWhiteSpace(reference.SourceRevision));
    }

    private static BrokerEvidenceSource FreezeSource(AiConversationScope scope, BrokerEvidenceSource source,
        IReadOnlyList<AiEvidenceReference> related)
    {
        if (source is null || !Bounded(source.SourceId, 160) ||
            string.IsNullOrWhiteSpace(source.SourceId) || !Bounded(source.Coverage, 3_000) ||
            source.Records is null || source.Records.Count > 500 || source.ObservedCount < 0 ||
            source.ObservedCount < source.Records.Count ||
            string.IsNullOrWhiteSpace(source.Coverage) ||
            source.Priority is < 0 or > 3)
            throw new ArgumentException("Evidence source is invalid or unbounded.");
        var records = source.Records.Select(record =>
        {
            if (record is null || !Bounded(record.RecordId, 160) ||
                string.IsNullOrWhiteSpace(record.RecordId) ||
                !Bounded(record.Provenance, 500) || string.IsNullOrWhiteSpace(record.Provenance) ||
                !Bounded(record.Text, MaximumRecordBytes) ||
                !Bounded(record.AttributionGroupId, 160, allowNull: true) ||
                record.Polarity is { } polarity && !Enum.IsDefined(polarity) ||
                record.Reference is { } reference && !ValidReference(scope, reference, related))
                throw new ArgumentException("Evidence record lacks bounded attribution or scope.");
            return record;
        }).ToArray();
        if (records.Select(record => record.RecordId).Distinct(StringComparer.Ordinal).Count() != records.Length)
            throw new ArgumentException("Evidence source has duplicate record IDs.");
        return source with { Records = Array.AsReadOnly(records) };
    }

    private static ModelToolDefinition FreezeTool(ModelToolDefinition tool)
    {
        if (tool is null || !SafeSchemaName(tool.Name) ||
            !Bounded(tool.Description, 500) ||
            tool.ParametersSchema.ValueKind != JsonValueKind.Object ||
            Encoding.UTF8.GetByteCount(tool.ParametersSchema.GetRawText()) > 32_000 ||
            !ModelJsonSchemaValidator.IsSupportedSchema(tool.ParametersSchema) ||
            !ObjectSchema(tool.ParametersSchema))
            throw new ArgumentException("Tool definition is invalid or unbounded.");
        return tool with { ParametersSchema = tool.ParametersSchema.Clone() };
    }

    private static ContextBrokerResult Pack(FrozenInput input, Func<bool> isCurrent, CancellationToken ct)
    {
        var known = input.Capabilities.ContextTokenLimit;
        if (known is <= 0 || input.ContextOverride is <= 0 or > 128_000 ||
            input.RequestedOutput is <= 0 or > 64_000 ||
            input.Capabilities.OutputTokenLimit is <= 0)
            return Fail(ContextBrokerFailureCode.InvalidInput,
                "Configure a positive model context and output token limit.", EmptyReport());
        var window = known is { } providerWindow
            ? Math.Min(128_000, Math.Min(providerWindow, input.ContextOverride ?? providerWindow))
            : input.ContextOverride ?? ConservativeUnknownWindow;
        var basis = known is { } && input.ContextOverride is { } chosen && chosen < known
            ? "ExplicitOverrideWithinProviderCap"
            : known is > 128_000 && input.ContextOverride is null ? "KnownProviderCapBounded128000" :
                known is not null ? "KnownProviderCap" :
                input.ContextOverride is not null ? "ExplicitOverrideUnknownProvider" : "ConservativeUnknown4096";
        var outputReserve = input.RequestedOutput ??
            Math.Min(1_024, input.Capabilities.OutputTokenLimit ?? 1_024);
        if (input.Capabilities.OutputTokenLimit is { } outputLimit && outputReserve > outputLimit)
            return Fail(ContextBrokerFailureCode.InvalidInput,
                "Requested output reserve exceeds the known model output limit.", EmptyReport());
        var margin = Math.Max(256, (int)Math.Ceiling(window * 0.20));
        var inputBudget = window - outputReserve - margin;
        var selections = input.Sources.Select(source => new MutableSelection(source)).ToArray();
        var selectedHistory = new List<ModelMessage>();
        var selectedHistoryGroups = new List<HistoryGroup>();
        var selectedState = new List<JsonElement>();
        var selectedEvidence = new List<IndexedRecord>();
        var selectedTools = new List<ModelToolDefinition>();
        var units = EvidenceUnits(input.Sources);
        var selectedKeys = new HashSet<string>(StringComparer.Ordinal);
        var selectedEvidenceUnits = new List<EvidenceUnit>();
        var includeOptionalGuide = false;
        void AddUnit(EvidenceUnit unit)
        {
            selectedKeys.Add(unit.Key);
            selectedEvidenceUnits.Add(unit);
            selectedEvidence.AddRange(unit.Records);
            foreach (var member in unit.Records)
            {
                selections[member.SourceIndex].Selected++;
                if (member.Record.Polarity == InvestigationEvidencePolarity.Contradicting)
                    selections[member.SourceIndex].SelectedContradicting++;
            }
        }
        ModelRequest MakeRequest() => BuildRequest(input, selectedHistory, selectedState,
            selectedEvidence, selectedTools, selections, window, outputReserve, includeOptionalGuide);
        // Every completed exchange from this question is required. Dropping an earlier
        // result can make the model lose checked context while still seeing later results.
        var currentTurnExchanges = input.HistoryGroups.Where(group =>
            group.Messages.Any(message => message.ToolRequests?.Any(call =>
                input.CurrentTurnCallIds.Contains(call.CallId)) == true)).ToArray();
        foreach (var exchange in currentTurnExchanges)
        {
            selectedHistory.AddRange(exchange.Messages);
            selectedHistoryGroups.Add(exchange);
        }
        var requiredHistoryCount = selectedHistory.Count;
        var required = MakeRequest();
        var components = EstimateComponents(required, input.Capabilities);
        var requiredCost = components.Total;
        var report = Report(window, basis, requiredCost, outputReserve, margin,
            input.HistoryOfferedCount, selectedHistory.Count,
            input.Tasks.Length + input.Findings.Length + input.Hypotheses.Length,
            0, 0, selections, input.Tools.Length, components);
        if (inputBudget <= 0 || requiredCost > inputBudget ||
            (input.CurrentTurnCallIds.Count > 0 && currentTurnExchanges.Length == 0))
            return Fail(ContextBrokerFailureCode.InsufficientContext,
                "Required instructions, current question, target, Tool exchange, state, schemas and output reserve do not fit. Configure a larger context window or reduce required input.", report);
        foreach (var unit in units.Where(unit => unit.Records.Any(record => record.Record.IsRequired)))
        {
            ct.ThrowIfCancellationRequested();
            AddUnit(unit);
            components = EstimateComponents(MakeRequest(), input.Capabilities);
            requiredCost = components.Total;
            if (requiredCost > inputBudget)
            {
                report = Report(window, basis, requiredCost, outputReserve, margin,
                    input.HistoryOfferedCount, selectedHistory.Count,
                    input.Tasks.Length + input.Findings.Length + input.Hypotheses.Length,
                    0, 0, selections, input.Tools.Length, components);
                return Fail(ContextBrokerFailureCode.InsufficientContext,
                    "Required attributable evidence cannot fit whole with the question, instructions and output reserve. Configure a larger context window or narrow the requested analysis.",
                    report);
            }
        }
        var requiredUnitCount = selectedEvidenceUnits.Count;
        var used = requiredCost;
        foreach (var tool in input.Tools)
        {
            ct.ThrowIfCancellationRequested();
            var cost = UnitCost(tool);
            if (used + cost > inputBudget) continue;
            selectedTools.Add(tool);
            used += cost;
        }
        var states = StateUnits(input);
        foreach (var state in states)
        {
            ct.ThrowIfCancellationRequested();
            var cost = UnitCost(state);
            if (used + cost > inputBudget) continue;
            selectedState.Add(state);
            used += cost;
        }
        void TrySelect(EvidenceUnit unit)
        {
            if (selectedKeys.Contains(unit.Key) || used + unit.Cost > inputBudget) return;
            AddUnit(unit);
            used += unit.Cost;
        }
        // Give each selected source a chance before filling from the highest-priority rows.
        foreach (var sourceIndex in Enumerable.Range(0, input.Sources.Length)
            .OrderBy(index => input.Sources[index].Priority).ThenBy(index => index))
        {
            ct.ThrowIfCancellationRequested();
            foreach (var unit in units.Where(unit => unit.Records.Any(record => record.SourceIndex == sourceIndex)))
            {
                if (selectedKeys.Contains(unit.Key)) continue;
                if (used + unit.Cost <= inputBudget) { TrySelect(unit); break; }
            }
        }
        foreach (var unit in units.OrderBy(unit => unit.Priority).ThenBy(unit => unit.FirstIndex))
        {
            ct.ThrowIfCancellationRequested();
            TrySelect(unit);
        }
        foreach (var group in input.HistoryGroups.Reverse())
        {
            ct.ThrowIfCancellationRequested();
            if (currentTurnExchanges.Contains(group)) continue;
            var cost = UnitCost(group.Messages);
            if (selectedHistory.Count + group.Messages.Length > 99 || used + cost > inputBudget) continue;
            selectedHistory.InsertRange(0, group.Messages);
            selectedHistoryGroups.Insert(0, group);
            used += cost;
        }
        var request = MakeRequest();
        components = EstimateComponents(request, input.Capabilities);
        var estimated = components.Total;
        while (estimated > inputBudget &&
            (selectedHistory.Count > requiredHistoryCount || selectedEvidenceUnits.Count > requiredUnitCount ||
             selectedState.Count > 0 || selectedTools.Count > 0))
        {
            ct.ThrowIfCancellationRequested();
            if (selectedHistory.Count > requiredHistoryCount)
            {
                var oldest = selectedHistoryGroups[0];
                selectedHistoryGroups.RemoveAt(0);
                selectedHistory.RemoveRange(0, oldest.Messages.Length);
            }
            else if (selectedEvidenceUnits.Count > requiredUnitCount)
            {
                var unit = selectedEvidenceUnits[^1];
                selectedEvidenceUnits.RemoveAt(selectedEvidenceUnits.Count - 1);
                selectedKeys.Remove(unit.Key);
                foreach (var member in unit.Records)
                {
                    selections[member.SourceIndex].Selected--;
                    if (member.Record.Polarity == InvestigationEvidencePolarity.Contradicting)
                        selections[member.SourceIndex].SelectedContradicting--;
                }
                var members = unit.Records.ToHashSet();
                selectedEvidence.RemoveAll(members.Contains);
            }
            else if (selectedState.Count > 0) selectedState.RemoveAt(selectedState.Count - 1);
            else selectedTools.RemoveAt(selectedTools.Count - 1);
            request = MakeRequest();
            components = EstimateComponents(request, input.Capabilities);
            estimated = components.Total;
        }
        if (estimated <= inputBudget)
        {
            // Packaged guidance is optional context. Admit it only after the current
            // question, checked exchanges, selected Tools and evidence have fitted.
            includeOptionalGuide = true;
            var guided = MakeRequest();
            var guidedComponents = EstimateComponents(guided, input.Capabilities);
            if (guidedComponents.Total <= inputBudget)
            {
                request = guided;
                components = guidedComponents;
                estimated = guidedComponents.Total;
            }
            else includeOptionalGuide = false;
        }
        report = Report(window, basis, estimated, outputReserve, margin,
            input.HistoryOfferedCount, selectedHistory.Count, states.Count, selectedState.Count,
            selectedTools.Count, selections, input.Tools.Length, components);
        if (estimated > inputBudget)
            return Fail(ContextBrokerFailureCode.InsufficientContext,
                "Required model context does not fit the configured window.", report);
        ct.ThrowIfCancellationRequested();
        if (!SafeCurrent(isCurrent))
            return Fail(ContextBrokerFailureCode.StaleScope,
                "The captured workspace selection changed.", report);
        return new ContextBrokerResult(request, report, null);
    }

    private static ModelRequest BuildRequest(FrozenInput input,
        IReadOnlyList<ModelMessage> history, IReadOnlyList<JsonElement> state,
        IReadOnlyList<IndexedRecord> evidence, IReadOnlyList<ModelToolDefinition> tools,
        IReadOnlyList<MutableSelection> selections, int window, int outputReserve,
        bool includeOptionalGuide)
    {
        object guide;
        if (includeOptionalGuide)
        {
            guide = new
            {
                catalog = JsonSerializer.Deserialize<JsonElement>(AgentEvidenceGuide.BuildCatalog(tools, input.Scope)),
                excerpt = JsonSerializer.Deserialize<JsonElement>(AgentEvidenceGuide.BuildExcerpt(
                    tools, input.Scope, input.Question, maxBytes: 4_096))
            };
        }
        else guide = new
        {
            guide_version = AgentEvidenceGuide.Version,
            omitted_sections = AgentEvidenceGuide.SectionIds.Select(section => new
                { section_id = section, reason = "context-budget-or-not-yet-packed" }).ToArray()
        };
        var context = JsonSerializer.SerializeToElement(new
        {
            scope = new { input.Scope.ContextType, input.Scope.ContextId, input.Scope.Identity },
            pinned_target_description = input.PinnedTargetDescription,
            target = input.Target,
            general_submission_hints = input.GeneralContext,
            runtime_budget = input.RuntimeBudget,
            assistant_guidance = guide,
            investigation = input.Investigation,
            state,
            evidence = evidence.Select(item => new
            {
                source_id = input.Sources[item.SourceIndex].SourceId,
                item.Record.RecordId, item.Record.Text, item.Record.Provenance,
                item.Record.Reference, item.Record.IsDerived,
                item.Record.AttributionGroupId, item.Record.Polarity,
                item.Record.IsRequired
            }).ToArray(),
            omitted_context = new
            {
                history_messages = input.HistoryOfferedCount - history.Count,
                saved_state_records = input.Tasks.Length + input.Findings.Length +
                    input.Hypotheses.Length - state.Count,
                tool_definitions = input.Tools.Length - tools.Count
            },
            source_coverage = selections.Select(item => item.ToReport()).ToArray()
        });
        // Keep the current question before its completed exchanges. Re-appending it after
        // every Tool result reissues the instruction and can cause repeated Tool calls.
        var questionIndex = history.Count;
        for (var index = 0; index < history.Count; index++)
        {
            if (history[index].ToolRequests?.Any(call => input.CurrentTurnCallIds.Contains(call.CallId)) == true)
            {
                questionIndex = index;
                break;
            }
        }
        var messages = history.Take(questionIndex)
            .Concat([new ModelMessage(ModelMessageRole.User, input.Question)])
            .Concat(history.Skip(questionIndex)).ToArray();
        return new ModelRequest(input.Instructions, Array.AsReadOnly(messages), context,
            Array.AsReadOnly(tools.ToArray()), input.OutputStructure,
            outputReserve, window);
    }

    private static List<JsonElement> StateUnits(FrozenInput input)
    {
        var units = new List<JsonElement>();
        foreach (var finding in input.Findings.OrderByDescending(finding =>
            input.Links.Any(link => link.Owner == InvestigationEvidenceOwner.Finding &&
                link.OwnerId == finding.Id && link.Polarity == InvestigationEvidencePolarity.Contradicting))
            .ThenByDescending(finding => finding.CreatedUtc))
            units.Add(JsonSerializer.SerializeToElement(new
            {
                kind = "Finding", finding,
                evidence_links = input.Links.Where(link =>
                    link.Owner == InvestigationEvidenceOwner.Finding && link.OwnerId == finding.Id).ToArray()
            }));
        foreach (var hypothesis in input.Hypotheses.OrderByDescending(item => item.UpdatedUtc))
            units.Add(JsonSerializer.SerializeToElement(new
            {
                kind = "Hypothesis", hypothesis,
                evidence_links = input.Links.Where(link =>
                    link.Owner == InvestigationEvidenceOwner.Hypothesis && link.OwnerId == hypothesis.Id).ToArray()
            }));
        foreach (var task in input.Tasks.OrderByDescending(item => item.CreatedUtc))
            units.Add(JsonSerializer.SerializeToElement(new { kind = "Task", task }));
        return units;
    }

    private static List<EvidenceUnit> EvidenceUnits(IReadOnlyList<BrokerEvidenceSource> sources)
    {
        var all = sources.SelectMany((source, sourceIndex) => source.Records.Select((record, index) =>
            new IndexedRecord(sourceIndex, index, record))).ToArray();
        var groups = all.GroupBy(item => string.IsNullOrWhiteSpace(item.Record.AttributionGroupId)
            ? $"single:{item.SourceIndex}:{item.RecordIndex}"
            : "group:" + item.Record.AttributionGroupId, StringComparer.Ordinal);
        return groups.Select(group =>
        {
            var records = group.ToArray();
            return new EvidenceUnit(group.Key, records,
                records.Min(item => sources[item.SourceIndex].Priority),
                records.Min(item => item.SourceIndex * 1_000 + item.RecordIndex),
                UnitCost(records));
        }).ToList();
    }

    private static ContextBrokerInputComponents EstimateComponents(ModelRequest request, ModelCapabilities capabilities)
    {
        // Providers decode transport JSON before tokenizing message content. Counting
        // nested transport escapes as tokens severely inflates checked JSON Tool rows.
        var instructions = TextCost(request.SystemInstructions);
        var questionAndHistory = 0;
        var toolMessages = 0;
        var overhead = 96 + request.Messages.Count * 32;
        foreach (var message in request.Messages)
        {
            if (message.ProviderOutputItems is { } items)
                toolMessages += TextCost(items.GetRawText());
            if (message.Role == ModelMessageRole.Tool) toolMessages += TextCost(message.Content);
            else questionAndHistory += TextCost(message.Content);
            if (message.ToolRequests is { Count: > 0 })
            {
                toolMessages += TextCost(JsonSerializer.Serialize(message.ToolRequests));
                overhead += 32;
            }
        }
        var structuredContext = request.StructuredContext is { } context ? TextCost(context.GetRawText()) : 0;
        var toolDefinitions = 0;
        if (request.Tools is { Count: > 0 })
        {
            toolDefinitions = TextCost(JsonSerializer.Serialize(request.Tools));
            overhead += 32 + (capabilities.SupportsTools == true ? 32 : 160);
        }
        var outputSchema = 0;
        if (request.OutputStructure is not null)
        {
            outputSchema = TextCost(JsonSerializer.Serialize(request.OutputStructure));
            overhead += 32 +
                (capabilities.SupportsStructuredOutput == true &&
                    (request.Tools is not { Count: > 0 } || capabilities.SupportsTools == true) ? 32 : 96);
        }
        return new(instructions, questionAndHistory, toolMessages, structuredContext, toolDefinitions,
            outputSchema, overhead);
    }

    private static int UnitCost<T>(T value) =>
        TextCost(JsonSerializer.Serialize(value)) + 32;

    private static int TextCost(string text)
    {
        var ascii = 0;
        var nonAsciiBytes = 0;
        foreach (var rune in text.EnumerateRunes())
            if (rune.IsAscii) ascii++;
            else nonAsciiBytes += rune.Utf8SequenceLength;
        return (ascii + 2) / 3 + nonAsciiBytes;
    }

    private static ContextBrokerBudgetReport Report(int window, string basis, int estimate,
        int reserve, int margin, int historyOffered, int historySelected,
        int stateOffered, int stateSelected, int toolsSelected,
        IReadOnlyList<MutableSelection> selections, int toolsOffered = 0,
        ContextBrokerInputComponents? components = null) =>
        new(window, basis, estimate, reserve, margin,
            historySelected, historyOffered - historySelected,
            stateSelected, stateOffered - stateSelected,
            toolsSelected, toolsOffered - toolsSelected,
            Array.AsReadOnly(selections.Select(selection => selection.ToReport()).ToArray()),
            EstimationMethod, components);

    private static ContextBrokerBudgetReport EmptyReport() =>
        new(0, "Unavailable", 0, 0, 0, 0, 0, 0, 0, 0, 0, [], EstimationMethod);

    private static ContextBrokerResult Fail(ContextBrokerFailureCode code, string message,
        ContextBrokerBudgetReport report) => new(null, report, new(code, message));

    private static bool Current(ContextBrokerInput input) => SafeCurrent(input.IsCurrentGeneration);
    private static bool SafeCurrent(Func<bool>? predicate)
    {
        try { return predicate?.Invoke() == true; }
        catch (Exception) { return false; }
    }

    private static bool Bounded(string? value, int maximumBytes, bool allowNull = false) =>
        value is null ? allowNull : Encoding.UTF8.GetByteCount(value) <= maximumBytes;

    private static bool ObjectSchema(JsonElement schema) =>
        schema.TryGetProperty("type", out var type) &&
        type.ValueKind == JsonValueKind.String && type.GetString() == "object";

    private static bool SafeSchemaName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= 64 &&
        name.All(character => char.IsLetterOrDigit(character) || character is '_' or '-');

    private sealed record FrozenInput(ModelCapabilities Capabilities, string Instructions,
        string Question, AiConversationScope Scope, ModelMessage[] History,
        int HistoryOfferedCount,
        HistoryGroup[] HistoryGroups, HashSet<string> CurrentTurnCallIds,
        AiObjectContext? Target, Investigation? Investigation,
        InvestigationTask[] Tasks, InvestigationFinding[] Findings,
        InvestigationHypothesis[] Hypotheses, InvestigationEvidenceLink[] Links,
        BrokerEvidenceSource[] Sources, ModelToolDefinition[] Tools,
        string? PinnedTargetDescription,
        ModelOutputStructure? OutputStructure, int? ContextOverride, int? RequestedOutput,
        AiGeneralSubmissionContext? GeneralContext, BrokerRuntimeBudget? RuntimeBudget);

    private sealed record IndexedRecord(int SourceIndex, int RecordIndex, BrokerEvidenceRecord Record);
    private sealed record HistoryGroup(ModelMessage[] Messages);
    private sealed record EvidenceUnit(string Key, IndexedRecord[] Records,
        int Priority, int FirstIndex, int Cost);

    private sealed class MutableSelection(BrokerEvidenceSource source)
    {
        public int Selected;
        public int SelectedContradicting;
        public BrokerSourceSelection ToReport() => new(source.SourceId, source.ObservedCount,
            source.CountIsExact, source.Records.Count, Selected, source.Records.Count - Selected,
            source.IsTruncated, source.Coverage,
            Selected == source.Records.Count ? "None" : "DeferredByBudget",
            source.Records.Count(record => record.Polarity == InvestigationEvidencePolarity.Contradicting),
            source.Records.Count(record => record.Polarity == InvestigationEvidencePolarity.Contradicting)
                - SelectedContradicting);
    }
}
