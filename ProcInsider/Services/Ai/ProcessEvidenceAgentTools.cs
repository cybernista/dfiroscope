using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Ai;

internal static class ProcessEvidenceAgentTools
{
    internal static bool IsCheckedRelatedTool(IAgentTool tool, TelemetryProjectionService projection) =>
        tool is ProcessTool processTool && ReferenceEquals(processTool.Projection, projection);
    private const int MaximumRows = 50;
    private const int MaximumFieldBytes = 2_000;
    private const int MaximumOutputBytes = 48_000;
    private const int MaximumTimeRangeDays = 7;
    internal static readonly JsonElement EmptyInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"reference_id":{"type":"string","minLength":1,"maxLength":160}},"additionalProperties":false}
        """).RootElement.Clone();
    private static readonly JsonElement PagedInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"reference_id":{"type":"string","minLength":1,"maxLength":160},"max_rows":{"type":"integer","minimum":1,"maximum":50}},"additionalProperties":false}
        """).RootElement.Clone();
    internal static readonly JsonElement TimedInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"reference_id":{"type":"string","minLength":1,"maxLength":160},"max_rows":{"type":"integer","minimum":1,"maximum":50},"from_utc_ticks":{"type":"integer","minimum":0},"to_utc_ticks":{"type":"integer","minimum":0}},"additionalProperties":false}
        """).RootElement.Clone();
    internal static readonly JsonElement OutputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{
          "availability":{"type":"string","maxLength":40},
          "records":{"type":"array","maxItems":50,"items":{"type":"object","properties":{
            "reference_id":{"type":"string","maxLength":160},"kind":{"type":"string","maxLength":40},
            "fields":{"type":"array","maxItems":16,"items":{"type":"object","properties":{
              "name":{"type":"string","maxLength":80},"value":{"type":"string","maxLength":2000}},
              "required":["name","value"],"additionalProperties":false}}},
            "required":["reference_id","kind","fields"],"additionalProperties":false}},
          "observed_count":{"type":"integer","minimum":0},"count_exact":{"type":"boolean"},
          "truncated":{"type":"boolean"},"coverage":{"type":"string","maxLength":2000},
          "omissions":{"type":"array","maxItems":16,"items":{"type":"string","maxLength":100}}},
          "required":["availability","records","observed_count","count_exact","truncated","coverage","omissions"],
          "additionalProperties":false}
        """).RootElement.Clone();

    internal static IEnumerable<IAgentTool> Create(TelemetryProjectionService projection)
    {
        yield return new ProcessTool(projection, "GetProcessDetails", "Read bounded selected process metadata.",
            EmptyInputSchema, ExecuteDetails);
        yield return new ProcessTool(projection, "GetProcessTree", "Read proven immediate parent and child processes.",
            PagedInputSchema, ExecuteTree);
        yield return new ProcessTool(projection, "GetProcessEvents", "Read qualified events for the selected process when supported.",
            TimedInputSchema, ExecuteEvents);
        yield return new ProcessTool(projection, "GetProcessNetwork", "Read verified-lifetime network endpoints for the selected process.",
            TimedInputSchema, ExecuteNetwork);
        yield return new ProcessTool(projection, "GetProcessPersistence", "Report whether process-linked persistence evidence is available.",
            EmptyInputSchema, ExecutePersistence);
    }

    private delegate AgentToolResult ToolAction(TelemetryProjectionService projection,
        AgentToolSession session, JsonElement arguments, CancellationToken ct);

    private sealed class ProcessTool : IAgentTool, IAgentToolAvailability
    {
        private readonly TelemetryProjectionService _projection;
        public TelemetryProjectionService Projection => _projection;
        private readonly ToolAction _action;

        public ProcessTool(TelemetryProjectionService projection, string id, string description,
            JsonElement inputSchema, ToolAction action)
        {
            _projection = projection;
            _action = action;
            Descriptor = new AgentToolDescriptor(id, id, description,
                [AgentPermission.EvidenceRead, AgentPermission.QueryLocal],
                [AgentDefinition.ExplainObjectSkillId, AgentDefinition.QueryEvidenceSkillId,
                    AgentDefinition.InvestigateProcessSkillId], inputSchema, OutputSchema);
        }

        public AgentToolDescriptor Descriptor { get; }

        public bool IsAvailableFor(AgentToolSession session) => Descriptor.Id switch
        {
            "GetProcessEvents" => session.OwnerPolicy.Access.IsPublished(FeatureIds.EventsWorkspace),
            "GetProcessNetwork" => session.OwnerPolicy.Access.IsPublished(FeatureIds.NetworkWorkspace),
            "GetProcessPersistence" => session.OwnerPolicy.Access.IsPublished(FeatureIds.Persistence),
            _ => session.OwnerPolicy.Access.IsPublished(FeatureIds.SelectedProcessDetails)
        };

        public Task<AgentToolResult> ExecuteAsync(AgentToolSession session, JsonElement arguments,
            CancellationToken cancellationToken) => Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            return _action(_projection, session, arguments, cancellationToken);
        }, cancellationToken);
    }

    private static AgentToolResult ExecuteDetails(TelemetryProjectionService projection,
        AgentToolSession session, JsonElement arguments, CancellationToken ct)
    {
        var selected = ResolveSelected(projection, session, arguments, ct);
        if (selected is null) return Unavailable("GetProcessDetails", "process.unavailable");
        var omissions = new List<string>();
        var record = ToProcessRecord(selected, omissions);
        return Result("GetProcessDetails", AgentToolStatus.Available, [record],
            [ProcessReference(selected)], 1, true, false, omissions, "process.details");
    }

    private static AgentToolResult ExecuteTree(TelemetryProjectionService projection,
        AgentToolSession session, JsonElement arguments, CancellationToken ct)
    {
        var selected = ResolveSelected(projection, session, arguments, ct);
        if (selected is null) return Unavailable("GetProcessTree", "process.unavailable");
        var max = Maximum(arguments);
        var children = projection.GetImmediateChildProcesses(selected, max + 1);
        ct.ThrowIfCancellationRequested();
        if (!children.IsComplete)
            return Result("GetProcessTree", children.IsAmbiguous ? AgentToolStatus.Ambiguous : AgentToolStatus.Unavailable,
                [], [], 0, false, false, ["child-relation-unproved"], "process.tree-unproved");
        var processes = new List<ProcessInfo> { selected };
        var omissions = new List<string>();
        var parentResolved = false;
        if (!string.IsNullOrWhiteSpace(selected.ParentProcessEntityId))
        {
            var parent = projection.GetProcessByEntityId(selected.ParentProcessEntityId);
            if (parent is not null && parent.ProcessEntityId == selected.ParentProcessEntityId &&
                session.ReadBoundaryAdmits(Identity(parent)))
            {
                parentResolved = true;
                if (processes.Count < max) processes.Add(parent);
                else omissions.Add("parent-deferred-by-row-cap");
            }
            else omissions.Add("parent-unavailable");
        }
        else omissions.Add("parent-relation-unproved");
        var childSlots = Math.Max(0, max - processes.Count);
        processes.AddRange(children.Processes.Take(childSlots));
        ct.ThrowIfCancellationRequested();
        var childCountExact = children.Processes.Count < max + 1;
        var parentAvailability = parentResolved ? "proved" :
            string.IsNullOrWhiteSpace(selected.ParentProcessEntityId) ? "relation_unproved" : "unavailable";
        var records = processes.Select((process, index) =>
        {
            var record = ToProcessRecord(process, omissions);
            var fields = record.Fields.ToList();
            var parentRow = index == 1 && parentResolved;
            AddField(fields, omissions, "tree_role", index == 0 ? "target" :
                parentRow ? "parent" : "immediate_child");
            AddField(fields, omissions, "process_entity_id", process.ProcessEntityId);
            AddField(fields, omissions, "tree_target_entity_id", selected.ProcessEntityId);
            AddField(fields, omissions, "tree_target_reference_id", ProcessReference(selected).ReferenceId);
            if (index == 0)
            {
                AddField(fields, omissions, "own_parent_availability", parentAvailability);
                AddField(fields, omissions, "immediate_children_observed_count", children.Processes.Count.ToString(CultureInfo.InvariantCulture));
                AddField(fields, omissions, "immediate_children_count_exact", childCountExact ? "true" : "false");
                AddField(fields, omissions, "immediate_children_relationships_checked", "true");
            }
            else
            {
                AddField(fields, omissions, "checked_parent_entity_id", parentRow ? process.ProcessEntityId : selected.ProcessEntityId);
                AddField(fields, omissions, "checked_parent_reference_id", ProcessReference(parentRow ? process : selected).ReferenceId);
                AddField(fields, omissions, "relationship_child_reference_id", ProcessReference(parentRow ? selected : process).ReferenceId);
            }
            return record with { Fields = fields };
        }).ToArray();
        var observedTotal = 1 + (parentResolved ? 1 : 0) + children.Processes.Count;
        return Result("GetProcessTree", AgentToolStatus.Available, records,
            processes.Select(ProcessReference).ToArray(), observedTotal,
            childCountExact,
            observedTotal > processes.Count,
            omissions, "process.tree", $"observed_count counts tree rows (target, proved parent, immediate children), not children; own_parent={parentAvailability}; immediate_children_observed_count={children.Processes.Count}; immediate_children_count_exact={childCountExact.ToString().ToLowerInvariant()}; child relationships checked independently of target's own parent availability; returned child rows may be capped");
    }

    private static AgentToolResult ExecuteEvents(TelemetryProjectionService projection,
        AgentToolSession session, JsonElement arguments, CancellationToken ct)
    {
        if (!TryTimeRange(arguments, out var from, out var to))
            return Result("GetProcessEvents", AgentToolStatus.InvalidRequest,
                [], [], 0, false, false, ["invalid-time-range"], "tool.invalid-time-range");
        var selected = ResolveSelected(projection, session, arguments, ct);
        if (selected is null) return Unavailable("GetProcessEvents", "process.unavailable");
        var max = Maximum(arguments);
        var permitted = session.Scope.ContextType == AiConversationContextType.Object
            ? session.Scope.Identity with
            {
                SourceIdentityId = string.Empty,
                ExecutionRootId = string.Empty
            }
            : session.Scope.Identity;
        var events = projection.GetEventEvidenceForProcess(new EventProjectionQuery
        {
            ProcessEntityId = selected.ProcessEntityId,
            ProcessKey = selected.GetUniqueKey(),
            MaxCount = max + 1
        }, from, to, permitted, ct);
        ct.ThrowIfCancellationRequested();
        var included = events.Take(max).ToArray();
        var omissions = new List<string>();
        var records = new List<ToolRecord>(included.Length);
        var references = new List<AiEvidenceReference>(included.Length);
        foreach (var row in included)
        {
            ct.ThrowIfCancellationRequested();
            var identity = new EvidenceIdentity
            {
                CaseId = row.CaseId, EvidenceSessionId = row.EvidenceSessionId,
                CaptureId = row.CaptureId, SourceIdentityId = row.SourceIdentityId,
                HostId = row.HostId, ExecutionRootId = row.ExecutionRootId
            };
            if (row.ProcessEntityId != selected.ProcessEntityId ||
                row.CorrelationState is not (EvidenceCorrelationState.Asserted or
                    EvidenceCorrelationState.Exact or EvidenceCorrelationState.Confirmed) ||
                row.CorrelationCandidateCount > 1 || row.SequenceId <= 0 ||
                string.IsNullOrWhiteSpace(row.SourceRunId) ||
                !(AgentPolicy.ScopeAdmits(session.Scope, identity) ||
                  AgentPolicy.RelatedBoundaryAdmits(session.Scope, identity)))
                return Result("GetProcessEvents", AgentToolStatus.Ambiguous,
                    [], [], 0, false, false, ["event-relation-unproved"], "event.identity-mismatch");
            var reference = EventReference(row, identity);
            var fields = new List<ToolField>();
            AddField(fields, omissions, "source", row.Source);
            AddField(fields, omissions, "correlation_state", row.CorrelationState.ToString());
            AddField(fields, omissions, "category", row.Category.ToString());
            AddField(fields, omissions, "action", row.Action.ToString());
            AddField(fields, omissions, "event_code", row.EventCode?.ToString(CultureInfo.InvariantCulture));
            AddField(fields, omissions, "target", row.Target);
            AddField(fields, omissions, "summary", row.Summary);
            AddField(fields, omissions, "timestamp_utc", row.TimestampUtc.ToString("O", CultureInfo.InvariantCulture));
            records.Add(new ToolRecord(reference.ReferenceId, "Event", fields));
            references.Add(reference);
        }
        return Result("GetProcessEvents", AgentToolStatus.Available, records, references,
            events.Count, events.Count <= max, events.Count > max,
            omissions, "event.attached-process-relation",
            "Recorded attached events only; collection coverage is not established, and zero rows do not prove absence.");
    }

    private static AgentToolResult ExecutePersistence(TelemetryProjectionService projection,
        AgentToolSession session, JsonElement arguments, CancellationToken ct) =>
        Unavailable("GetProcessPersistence", "persistence.canonical-relation-unavailable");

    private static AgentToolResult ExecuteNetwork(TelemetryProjectionService projection,
        AgentToolSession session, JsonElement arguments, CancellationToken ct)
    {
        if (!TryTimeRange(arguments, out var from, out var to))
            return Result("GetProcessNetwork", AgentToolStatus.InvalidRequest,
                [], [], 0, false, false, ["invalid-time-range"], "tool.invalid-time-range");
        var selected = ResolveSelected(projection, session, arguments, ct);
        if (selected is null) return Unavailable("GetProcessNetwork", "process.unavailable");
        var max = Maximum(arguments);
        var sourcePin = session.Scope.ContextType == AiConversationContextType.Object ||
            string.IsNullOrWhiteSpace(session.Scope.Identity.SourceIdentityId)
            ? null : session.Scope.Identity.SourceIdentityId;
        var page = projection.GetNetworkEndpointsForProcess(selected, max + 1, from, to, sourcePin, ct);
        ct.ThrowIfCancellationRequested();
        var coverage = BoundedCoverage(page.Diagnostic);
        if (!page.Supported)
            return Result("GetProcessNetwork", AgentToolStatus.Unavailable, [], [], 0, false, false,
                ["network.source-unavailable"], "network.source-unavailable", coverage);
        var rows = page.Rows.Take(max).ToArray();
        var records = new List<ToolRecord>();
        var references = new List<AiEvidenceReference>();
        var omissions = new List<string>();
        if (coverage != page.Diagnostic) omissions.Add("network-coverage-omitted");
        foreach (var row in rows)
        {
            ct.ThrowIfCancellationRequested();
            if (row.Observation.Native.Ownership != EndpointOwnership.VerifiedLifetime ||
                row.Observation.Native.ProcessEntityId != selected.ProcessEntityId ||
                !(AgentPolicy.ScopeAdmits(session.Scope, row.Poll.Scope) ||
                  AgentPolicy.RelatedBoundaryAdmits(session.Scope, row.Poll.Scope)) ||
                string.IsNullOrWhiteSpace(row.Poll.SourceRunId))
                return Result("GetProcessNetwork", AgentToolStatus.Ambiguous,
                    [], [], 0, false, false, ["network-row-unproved"], "network.identity-mismatch");
            var reference = NetworkReference(row);
            var fields = new List<ToolField>();
            AddField(fields, omissions, "family", row.Observation.Native.Family.ToString());
            AddField(fields, omissions, "local", row.Observation.Native.LocalDisplay);
            AddField(fields, omissions, "remote", row.Observation.Native.RemoteDisplay);
            AddField(fields, omissions, "first_observed_utc", row.FirstObservedUtc.ToString("O", CultureInfo.InvariantCulture));
            AddField(fields, omissions, "last_observed_utc", row.LastObservedUtc.ToString("O", CultureInfo.InvariantCulture));
            records.Add(new ToolRecord(reference.ReferenceId, "NetworkFlow", fields));
            references.Add(reference);
        }
        return Result("GetProcessNetwork", AgentToolStatus.Available, records, references,
            (int)Math.Min(int.MaxValue, page.MatchingRows), page.MatchingRows <= int.MaxValue,
            page.MatchingRows > records.Count,
            omissions, "network.verified-lifetime", coverage);
    }

    private static ProcessInfo? ResolveSelected(TelemetryProjectionService projection,
        AgentToolSession session, JsonElement arguments, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var target = session.ResolveCheckedReference(arguments);
        if (target?.Evidence.Kind != EvidenceReferenceKind.ProcessEntity) return null;
        ProcessInfo? selected;
        if (!string.IsNullOrWhiteSpace(target.Evidence.Id))
            selected = projection.GetProcessByEntityId(target.Evidence.Id);
        else if (target.Process is { ProcessKey: { Length: > 0 } } alias)
        {
            var matches = projection.GetProcessesByExactScope(new ExplorerScope
            {
                Kind = ExplorerScopeKind.AllProcesses, ProcessKey = alias.ProcessKey,
                CaseId = alias.CaseId, EvidenceSessionId = alias.EvidenceSessionId,
                CaptureId = alias.CaptureId, SourceIdentityId = alias.SourceIdentityId,
                HostId = alias.HostId, ExecutionRootId = alias.ExecutionRootId
            }, 2);
            selected = matches.Count == 1 ? matches[0] : null;
        }
        else return null;
        ct.ThrowIfCancellationRequested();
        return selected is not null && Identity(selected) == target.Identity &&
            (string.IsNullOrWhiteSpace(target.Process?.ProcessKey) ||
                selected.GetUniqueKey() == target.Process.ProcessKey)
            ? selected : null;
    }

    private static EvidenceIdentity Identity(ProcessInfo process) => new()
    {
        CaseId = process.CaseId, EvidenceSessionId = process.EvidenceSessionId,
        CaptureId = process.CaptureId, SourceIdentityId = process.SourceIdentityId,
        HostId = process.HostId, ExecutionRootId = process.ExecutionRootId
    };

    internal static AiObjectContext CreateObjectContext(ProcessInfo process)
    {
        var reference = ProcessReference(process);
        var display = new Dictionary<string, string>(StringComparer.Ordinal) {
            ["Name"] = process.ProcessName, ["PID"] = process.ProcessId.ToString(),
            ["Path"] = process.ProcessPath ?? "" };
        if (HasRecordedCommandLine(process.CommandLine)) display["Command line"] = process.CommandLine;
        if (process.StartTime is { } start)
            display["Recorded start time UTC"] = start.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        if (!string.IsNullOrWhiteSpace(process.ParentProcessEntityId))
            display["Recorded parent entity ID (resolve relationship with GetProcessTree)"] = process.ParentProcessEntityId;
        if (!string.IsNullOrWhiteSpace(process.ParentProcessKey))
            display["Recorded parent process key (unproved alias)"] = process.ParentProcessKey;
        return new AiObjectContext(reference, display,
            new Dictionary<string, string>(StringComparer.Ordinal) { ["ProcessEntityId"] = process.ProcessEntityId },
            ["Process tree", "Events", "Network", "Persistence"]);
    }

    private static bool HasRecordedCommandLine(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var trimmed = value.Trim();
        return !trimmed.Equals("<not available>", StringComparison.OrdinalIgnoreCase) &&
               !trimmed.Equals("<unknown>", StringComparison.OrdinalIgnoreCase);
    }

    internal static AiEvidenceReference ProcessReference(ProcessInfo process)
    {
        var reference = new AiEvidenceReference(string.Empty, Identity(process),
            new EvidenceReference(EvidenceReferenceKind.ProcessEntity, process.ProcessEntityId),
            "ProcessProjection", string.Empty, string.Empty, null,
            BoundedDisplay(process.ProcessName), string.Empty, string.Empty,
            new AiProcessReference(process.ProcessEntityId, process.GetUniqueKey(), process.CaseId,
                process.EvidenceSessionId, process.CaptureId, process.SourceIdentityId,
                process.HostId, process.ExecutionRootId));
        return reference with { ReferenceId = StableReferenceId(reference) };
    }

    internal static AiEvidenceReference NetworkReference(NetworkEndpointHistoryRow row)
    {
        var reference = new AiEvidenceReference(string.Empty, row.Poll.Scope,
            new EvidenceReference(EvidenceReferenceKind.NetworkFlow, row.Observation.ObservationId),
            "NetworkEndpoint", row.Poll.SourceRunId, row.Poll.SegmentId,
            row.FirstObservedUtc, "Verified process network endpoint", string.Empty, string.Empty);
        return reference with { ReferenceId = StableReferenceId(reference) };
    }

    internal static AiEvidenceReference EventReference(TelemetryEventRecord row, EvidenceIdentity identity)
    {
        var reference = new AiEvidenceReference(string.Empty, identity,
            new EvidenceReference(EvidenceReferenceKind.Event, row.SequenceId.ToString(CultureInfo.InvariantCulture)),
            string.IsNullOrWhiteSpace(row.Source) ? "Event" : row.Source,
            row.SourceRunId, string.Empty, row.TimestampUtc,
            "Process event", string.Empty, string.Empty);
        return reference with { ReferenceId = StableReferenceId(reference) };
    }

    internal static string StableReferenceId(AiEvidenceReference reference) => "tool-" +
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(reference.CanonicalObjectKey)));

    private static string BoundedDisplay(string value) =>
        Encoding.UTF8.GetByteCount(value ?? string.Empty) <= 500 ? value ?? string.Empty : "Process name omitted (oversized)";

    private static string BoundedCoverage(string? value) =>
        Encoding.UTF8.GetByteCount(value ?? string.Empty) <= 2_000
            ? value ?? string.Empty : "Coverage diagnostic omitted (oversized).";

    internal static ToolRecord ToProcessRecord(ProcessInfo process, List<string> omissions)
    {
        var reference = ProcessReference(process);
        var fields = new List<ToolField>();
        AddField(fields, omissions, "process_id", process.ProcessId.ToString(CultureInfo.InvariantCulture));
        AddField(fields, omissions, "name", process.ProcessName);
        AddField(fields, omissions, "path", process.ProcessPath);
        AddField(fields, omissions, "command_line", process.CommandLine);
        AddField(fields, omissions, "user", process.UserName);
        AddField(fields, omissions, "status", process.Status.ToString());
        AddField(fields, omissions, "start_utc", process.StartTime?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        AddField(fields, omissions, "end_utc", process.EndTime?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        return new ToolRecord(reference.ReferenceId, "ProcessEntity", fields);
    }

    internal static void AddField(List<ToolField> fields, List<string> omissions, string name, string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        if (Encoding.UTF8.GetByteCount(value) > MaximumFieldBytes)
        {
            if (omissions.Count < 15) omissions.Add($"field-omitted.{name}");
            else if (omissions.Count == 15) omissions.Add("additional-fields-omitted");
            else omissions[15] = "additional-fields-omitted";
            return;
        }
        fields.Add(new ToolField(name, value));
    }

    internal static int Maximum(JsonElement arguments) => arguments.TryGetProperty("max_rows", out var max)
        ? Math.Clamp(max.GetInt32(), 1, MaximumRows) : 25;

    internal static bool TryTimeRange(JsonElement arguments, out long? from, out long? to)
    {
        from = arguments.TryGetProperty("from_utc_ticks", out var f) ? f.GetInt64() : null;
        to = arguments.TryGetProperty("to_utc_ticks", out var t) ? t.GetInt64() : null;
        return (from is null && to is null) ||
            (from.HasValue && to.HasValue && from.Value >= 0 &&
             from.Value <= DateTime.MaxValue.Ticks && to.Value > 0 &&
             to.Value <= DateTime.MaxValue.Ticks && to.Value > from.Value &&
             to.Value - from.Value <= TimeSpan.FromDays(MaximumTimeRangeDays).Ticks);
    }

    internal static AgentToolResult Unavailable(string id, string code) =>
        Result(id, AgentToolStatus.Unavailable, [], [], 0, false, false, [code], code);

    internal static AgentToolResult Result(string id, AgentToolStatus status,
        IReadOnlyList<ToolRecord> records, IReadOnlyList<AiEvidenceReference> references,
        int observedCount, bool countExact, bool truncated, IReadOnlyList<string> omissions,
        string code, string coverage = "")
    {
        var admittedRecords = records.ToList();
        var admittedReferences = references.ToList();
        var admittedOmissions = omissions.Take(16).ToList();
        if (admittedOmissions.Any(omission => omission.StartsWith("field-omitted.", StringComparison.Ordinal) ||
            omission == "additional-fields-omitted"))
            truncated = true;
        JsonElement Serialize() => JsonSerializer.SerializeToElement(new
            {
                availability = status.ToString(), records = admittedRecords,
                observed_count = observedCount, count_exact = countExact,
                truncated, coverage, omissions = admittedOmissions
            }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
        var output = Serialize();
        while (Encoding.UTF8.GetByteCount(output.GetRawText()) +
               JsonSerializer.SerializeToUtf8Bytes(admittedReferences).Length > MaximumOutputBytes &&
               admittedRecords.Count > 0)
        {
            var removed = admittedRecords[^1];
            admittedRecords.RemoveAt(admittedRecords.Count - 1);
            admittedReferences.RemoveAll(reference => reference.ReferenceId == removed.ReferenceId);
            truncated = true;
            if (admittedOmissions.Count < 16) admittedOmissions.Add("record-omitted-by-output-cap");
            else admittedOmissions[15] = "additional-data-omitted";
            output = Serialize();
        }
        return new AgentToolResult(id, status, output,
            admittedReferences.AsReadOnly(), observedCount, countExact, truncated,
            admittedOmissions.AsReadOnly(), code);
    }

    internal sealed record ToolField(string Name, string Value);
    internal sealed record ToolRecord(string ReferenceId, string Kind, IReadOnlyList<ToolField> Fields);
}
