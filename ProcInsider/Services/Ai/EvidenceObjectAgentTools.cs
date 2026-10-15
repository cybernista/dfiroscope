using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Features.PersistenceWorkspace;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;
using static ProcInsider.Services.Ai.ProcessEvidenceAgentTools;

namespace ProcInsider.Services.Ai;

// Adapters over the existing assessed query owners. These never acquire or modify evidence.
internal static class EvidenceObjectAgentTools
{
    internal static IEnumerable<IAgentTool> Create(TelemetryProjectionService projection, FeatureAccessService access)
    {
        yield return new ObjectTool(projection, access, "GetSelectedEvidence", EmptyInputSchema);
        yield return new ObjectTool(projection, access, "GetRelatedEvidence", TimedInputSchema);
        yield return new ObjectTool(projection, access, "GetHostProcesses", HostInputSchema);
        foreach (var id in GeneralReadToolIds.Where(id => id != "GetHostProcesses"))
            yield return new ObjectTool(projection, access, id, GeneralPageInputSchema);
    }

    internal static readonly string[] GeneralReadToolIds =
        ["GetHostProcesses", "GetHostEvents", "GetHostNetwork", "GetHostPersistence"];
    private static readonly JsonElement HostInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"max_rows":{"type":"integer","minimum":1,"maximum":50},
        "offset":{"type":"integer","minimum":0,"maximum":10000},
        "process_name_contains":{"type":"string","minLength":1,"maxLength":160},
        "from_utc_ticks":{"type":"integer","minimum":0},"to_utc_ticks":{"type":"integer","minimum":0}},"additionalProperties":false}
        """).RootElement.Clone();
    private static readonly JsonElement GeneralPageInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"max_rows":{"type":"integer","minimum":1,"maximum":50},
        "offset":{"type":"integer","minimum":0,"maximum":10000},
        "from_utc_ticks":{"type":"integer","minimum":0},"to_utc_ticks":{"type":"integer","minimum":0}},"additionalProperties":false}
        """).RootElement.Clone();

    internal static bool IsCheckedRelatedTool(IAgentTool tool, TelemetryProjectionService projection) =>
        tool is ObjectTool adapter && ReferenceEquals(adapter.Projection, projection);

    private sealed class ObjectTool : IAgentTool, IAgentToolAvailability
    {
        internal TelemetryProjectionService Projection { get; }
        private readonly FeatureAccessService _access;
        public AgentToolDescriptor Descriptor { get; }
        public bool IsAvailableFor(AgentToolSession session) => Descriptor.Id switch
        {
            "GetHostProcesses" => _access.IsPublished(FeatureIds.ProcessListing),
            "GetHostEvents" => _access.IsPublished(FeatureIds.EventsWorkspace),
            "GetHostNetwork" => _access.IsPublished(FeatureIds.NetworkWorkspace),
            "GetHostPersistence" => _access.IsPublished(FeatureIds.Persistence),
            _ => true
        };
        internal ObjectTool(TelemetryProjectionService projection, FeatureAccessService access, string id, JsonElement schema)
        {
            Projection = projection;
            _access = access;
            Descriptor = new(id, id, id switch
            {
                "GetSelectedEvidence" => "Read the exact selected Event, recorded Network endpoint or Persistence version.",
                "GetRelatedEvidence" => "Read bounded surrounding events, verified network-owner activity or persistence history.",
                "GetHostProcesses" => "Count recorded processes within the checked host/capture source and execution-root boundary; return a bounded page. process_name_contains matches names with or without .exe; offset pages matching rows. Omit time bounds for totals within that boundary. Coverage states execution_root_filter. A preview is never a full inventory.",
                "GetHostEvents" => "Read bounded published recorded events within the checked host/capture source and execution-root boundary; optional UTC time bounds. Coverage states execution_root_filter. No acquisition completeness is implied.",
                "GetHostNetwork" => "Read bounded recorded connection snapshots within the checked host/capture source and execution-root boundary. Coverage states execution_root_filter. Samples do not prove traffic or reachability.",
                _ => "Read bounded current recorded persistence entries within the checked host/capture source and execution-root boundary. Coverage states execution_root_filter. Stale records do not prove current machine state."
            }, [AgentPermission.EvidenceRead, AgentPermission.QueryLocal],
                [AgentDefinition.ExplainObjectSkillId, AgentDefinition.QueryEvidenceSkillId], schema, OutputSchema);
        }

        public Task<AgentToolResult> ExecuteAsync(AgentToolSession session, JsonElement arguments, CancellationToken token) =>
            Task.Run(async () =>
            {
                var id = Descriptor.Id;
                if (!TryTimeRange(arguments, out var from, out var to)) return Unavailable(id, "object.invalid-time-range");
                var query = Projection.ScopedQuery;
                var maximum = Maximum(arguments);
                if (GeneralReadToolIds.Contains(id))
                {
                    if (session.Scope.ContextType is not (AiConversationContextType.General or AiConversationContextType.Object) ||
                        string.IsNullOrWhiteSpace(session.Scope.Identity.HostId) || string.IsNullOrWhiteSpace(session.Scope.Identity.CaptureId))
                        return Unavailable(id, "general.host-capture-required");
                    if (id == "GetHostProcesses") return HostProcesses(query, session, arguments, maximum, from, to, token);
                    return await HostEvidence(query, session, id, arguments, maximum, from, to, token);
                }
                if (session.ResolveCheckedReference(arguments) is not { } target) return Unavailable(id, "object.no-target");
                // Object Tool output has its own object-tool- ID. A process Tool citation may be
                // the selected input, but reusing its tool- ID here would collide with the
                // already checked input ledger entry, whose display fields differ.
                var lookup = target.Evidence.Kind is EvidenceReferenceKind.Event or EvidenceReferenceKind.NetworkFlow &&
                    target.ReferenceId == StableReferenceId(target)
                    ? target with { ReferenceId = "object-" + target.ReferenceId }
                    : target;
                var resolved = await ResolveAsync(query, _access, lookup, session.Scope.Identity.EvidenceSessionId, token);
                if (resolved is null) return Unavailable(id, "object.original-unavailable");
                if (id == "GetSelectedEvidence") return ContextResult(id, [resolved], 1, true, "Exact recorded object; context fields are bounded.");
                if (target.Evidence.Kind == EvidenceReferenceKind.Event)
                {
                    var at = resolved.Reference.TimestampUtc;
                    if (at is null) return Unavailable(id, "event.time-unavailable");
                    var lower = from is { } f ? new DateTime(f, DateTimeKind.Utc) : at.Value.AddMinutes(-5);
                    var upper = to is { } t ? new DateTime(t, DateTimeKind.Utc) : at.Value.AddMinutes(5);
                    await using var reader = Events(query, _access, target.Identity);
                    var page = await reader.QueryAsync(new EventsQuery { PageSize = maximum + 1,
                        Filter = new EventsFilter { Columns = new Dictionary<EventSort, ColumnFilterCriteria> {
                            [EventSort.Host] = new() { AllValues = false, Values = [target.Identity.HostId] },
                            [EventSort.Timestamp] = new() { FromUtc = lower, ToUtc = upper } } } }, token);
                    var contexts = page.Rows.Select(row => EventContext(row.Native)).Where(value =>
                        AgentPolicy.ScopeAdmits(session.Scope, value.Reference.Identity) ||
                        AgentPolicy.RelatedBoundaryAdmits(session.Scope, value.Reference.Identity)).ToArray();
                    return ContextResult(id, contexts.Take(maximum).ToArray(), contexts.Length, false,
                        "Recorded events in the selected host/time window; proximity is not a causal or process relationship.");
                }
                if (target.DataSource == "PersistenceVersions")
                {
                    var reference = JsonSerializer.Deserialize<PersistenceObjectReference>(target.Evidence.Id)!;
                    var history = query.PersistenceQueries.History(new(reference, PageSize: maximum), token);
                    return ContextResult(id, history.Rows.Select(row => PersistenceContext(row)).ToArray(),
                        (int)Math.Min(int.MaxValue, history.MatchingRows), history.MatchingRows <= int.MaxValue,
                        "Recorded versions of this exact persistence object; no process ownership is inferred.");
                }
                if (target.Evidence.Kind == EvidenceReferenceKind.NetworkFlow)
                {
                    var endpoint = FindEndpoint(query, target, token);
                    var native = endpoint?.Observation.Native;
                    if (native is not { Ownership: EndpointOwnership.VerifiedLifetime, ProcessEntityId.Length: > 0 })
                        return Unavailable(id, "network.owner-unproved");
                    var process = Projection.GetProcessByEntityId(native.ProcessEntityId);
                    if (process is null || process.StartTime?.ToUniversalTime() != native.ProcessStartUtc ||
                        !session.ReadBoundaryAdmits(ProcessReference(process).Identity))
                        return Unavailable(id, "network.owner-unavailable");
                    var contexts = new List<AiObjectContext> { CreateObjectContext(process) };
                    var identity = target.Identity with { SourceIdentityId = "", ExecutionRootId = "" };
                    var rows = Projection.GetEventEvidenceForProcess(new() { ProcessEntityId = process.ProcessEntityId,
                        ProcessKey = process.GetUniqueKey(), MaxCount = maximum }, from, to, identity, token);
                    contexts.AddRange(rows.Where(row => row.ProcessEntityId == process.ProcessEntityId &&
                        row.CorrelationCandidateCount <= 1 && row.CorrelationState is
                            (EvidenceCorrelationState.Exact or EvidenceCorrelationState.Asserted or EvidenceCorrelationState.Confirmed))
                        .Select(EventContext).Where(context => session.ReadBoundaryAdmits(context.Reference.Identity)));
                    return ContextResult(id, contexts.Take(maximum).ToArray(), contexts.Count, false,
                        "Verified owner process and recorded attached events only; no complete collection coverage is claimed.");
                }
                return Unavailable(id, "object.related-unavailable");
            }, token);
    }

    internal static async Task<AiObjectContext?> ResolveAsync(SqliteStagingQueryService query,
        FeatureAccessService access, AiEvidenceReference reference, string sessionId, CancellationToken token)
    {
        if (reference.Identity.EvidenceSessionId != sessionId || string.IsNullOrWhiteSpace(reference.Identity.HostId)) return null;
        AiObjectContext? context = null;
        if (reference.Evidence.Kind == EvidenceReferenceKind.Event && long.TryParse(reference.Evidence.Id, out var sequence))
        {
            await using var reader = Events(query, access, reference.Identity);
            var scope = reference.Identity;
            var page = await reader.QueryAsync(new EventsQuery { PageSize = 2,
                Filter = new EventsFilter { ExactEvent = new(scope.CaseId, scope.EvidenceSessionId,
                    scope.CaptureId, scope.SourceIdentityId, scope.HostId, reference.SourceRunId, sequence) } }, token);
            if (page.Rows.Count == 1) context = EventContext(page.Rows[0].Native);
        }
        else if (reference.Evidence.Kind == EvidenceReferenceKind.NetworkFlow && access.IsPublished(FeatureIds.NetworkWorkspace))
        {
            var row = FindEndpoint(query, reference, token);
            if (row is not null) context = NetworkContext(row);
        }
        else if (reference.Evidence.Kind == EvidenceReferenceKind.GenericArtifact &&
            reference.DataSource == "PersistenceVersions" && access.IsPublished(FeatureIds.Persistence))
        {
            PersistenceObjectReference? locator;
            try { locator = JsonSerializer.Deserialize<PersistenceObjectReference>(reference.Evidence.Id); }
            catch (JsonException) { return null; }
            if (locator is not null && locator.Scope == reference.Identity)
                context = PersistenceContext(query.PersistenceQueries.Detail(locator, token).Row);
        }
        if (context?.Reference.CanonicalObjectKey != reference.CanonicalObjectKey ||
            context.Reference.Identity != reference.Identity) return null;

        // Process Tools issued the same exact Event/Network object with a tool- ID before
        // the object adapter issued object-tool- IDs. Preserve both saved citations,
        // but only for the ID derived from this re-read original's canonical key.
        if (reference.Evidence.Kind is EvidenceReferenceKind.Event or EvidenceReferenceKind.NetworkFlow &&
            reference.ReferenceId == StableReferenceId(context.Reference))
        {
            var resolved = context.Reference with { ReferenceId = reference.ReferenceId };
            return new AiObjectContext(resolved, context.DisplayProperties,
                new Dictionary<string, string> { ["Exact object"] = resolved.ReferenceId },
                context.RelatedDataHints, context.RangeStartUtc, context.RangeEndUtc);
        }
        return context;
    }

    private static EventsWorkspaceQueryService Events(SqliteStagingQueryService query, FeatureAccessService access, EvidenceIdentity identity) =>
        new(access.Catalog, query, new(identity.CaseId, identity.EvidenceSessionId, identity.CaptureId, 0, 0), () => true);

    internal static NetworkEndpointHistoryRow? FindEndpoint(SqliteStagingQueryService query, AiEvidenceReference reference, CancellationToken token)
    {
        var matches = new List<NetworkEndpointHistoryRow>();
        foreach (var kind in new[] { EndpointScopeKind.ListenerHistory, EndpointScopeKind.ConnectionSnapshots })
            matches.AddRange(query.NetworkEndpointQueries.Query(new(kind, Scope: reference.Identity,
                SourceRunId: reference.SourceRunId, ExactObservationId: reference.Evidence.Id, PageSize: 2), token).Rows);
        return matches.Count == 1 && matches[0].Poll.SegmentId == reference.SourceRevision ? matches[0] : null;
    }

    private static AgentToolResult HostProcesses(SqliteStagingQueryService query, AgentToolSession session,
        JsonElement arguments, int maximum, long? from, long? to, CancellationToken token)
    {
        const string id = "GetHostProcesses";
        if (session.Scope.ContextType is not (AiConversationContextType.General or AiConversationContextType.Object) || string.IsNullOrWhiteSpace(session.Scope.Identity.HostId))
            return Unavailable(id, "general.host-required");
        var scope = session.HostQueryIdentity;
        var filters = new ProcessListingFilterSet { CaseId = scope.CaseId, EvidenceSessionId = scope.EvidenceSessionId,
            CaptureId = scope.CaptureId, HostId = scope.HostId,
            SourceIdentityId = string.IsNullOrEmpty(scope.SourceIdentityId) ? null : scope.SourceIdentityId,
            ExecutionRootId = string.IsNullOrEmpty(scope.ExecutionRootId) ? null : scope.ExecutionRootId,
            IncludeCompatibleExecutionRoots = session.Scope.ContextType == AiConversationContextType.Object,
            ReadScope = scope };
        var total = query.ProcessListingQueries.CountProcesses(filters, token);
        var name = arguments.TryGetProperty("process_name_contains", out var nameNode) ? nameNode.GetString() : null;
        // Windows process inventory may retain the display name without its executable suffix.
        // The Tool promises a substring name filter, so the same query must cover both forms.
        if (name is { Length: > 4 } && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            name = name[..^4];
        filters.ProcessNameContains = name;
        if (from.HasValue) filters.ColumnFilters = new Dictionary<ProcessListingSortColumn, ColumnFilterCriteria> {
            [ProcessListingSortColumn.StartTime] = new() { FromUtc = new(from.Value, DateTimeKind.Utc), ToUtc = new(to!.Value, DateTimeKind.Utc) } };
        var offset = Offset(arguments);
        var page = query.ProcessListingQueries.GetProcessPage(new() { Filters = filters, PageSize = maximum, Offset = offset,
            Sort = new() { Column = ProcessListingSortColumn.StartTime, Direction = ProcessListingSortDirection.Descending } }, token);
        var contexts = page.Rows.Select(row => CreateObjectContext(row.ToProcessInfo())).ToArray();
        if (contexts.Any(context => !session.ReadBoundaryAdmits(context.Reference.Identity)))
            return Unavailable(id, "general.scope-mismatch");
        var result = ContextResult(id, contexts, page.TotalCount, page.TotalCount >= 0,
            "Recorded process inventory only; start-time filters do not represent all host activity.");
        return WithQueryCoverage(result, session, "recorded-processes", offset, maximum, page.TotalCount,
            total, name, from, to);
    }

    private static int Offset(JsonElement arguments) => arguments.TryGetProperty("offset", out var value) ? value.GetInt32() : 0;

    private static AgentToolResult WithQueryCoverage(AgentToolResult result, AgentToolSession session, string query,
        int offset, int maximum, long matching, long? total, string? name, long? from, long? to)
    {
        var scope = session.HostQueryIdentity;
        var executionRootFilter = string.IsNullOrEmpty(scope.ExecutionRootId) ? "unrestricted"
            : session.Scope.ContextType == AiConversationContextType.Object ? "compatible" : "exact";
        var returned = result.Evidence.Count;
        var next = offset + returned < matching && returned > 0 ? offset + returned : (int?)null;
        var coverage = JsonSerializer.Serialize(new { scope, execution_root_filter = executionRootFilter, query, total_count = total,
            matching_count = matching, process_name_contains = name, from_utc_ticks = from, to_utc_ticks = to,
            from_utc = from.HasValue ? new DateTime(from.Value, DateTimeKind.Utc).ToString("O", CultureInfo.InvariantCulture) : null,
            to_utc = to.HasValue ? new DateTime(to.Value, DateTimeKind.Utc).ToString("O", CultureInfo.InvariantCulture) : null,
            offset, returned_count = returned, next_offset = next, page_bound = maximum,
            count_basis = "Bounded stored query rows within the stated case/session/capture/host, source and execution-root filters; not acquisition completeness",
            omissions = result.Omissions });
        if (Encoding.UTF8.GetByteCount(coverage) > 2000) return Unavailable(result.ToolId, "general.coverage-bound");
        var output = JsonNode.Parse(result.Output.GetRawText())!.AsObject();
        output["coverage"] = coverage;
        output["truncated"] = next.HasValue || result.IsTruncated;
        return result with { Output = JsonSerializer.SerializeToElement(output), IsTruncated = next.HasValue || result.IsTruncated };
    }

    private static async Task<AgentToolResult> HostEvidence(SqliteStagingQueryService query, AgentToolSession session,
        string id, JsonElement arguments, int maximum, long? from, long? to, CancellationToken token)
    {
        var scope = session.HostQueryIdentity;
        var offset = Offset(arguments);
        AiObjectContext[] contexts;
        long matching;
        if (id == "GetHostEvents")
        {
            await using var reader = Events(query, session.OwnerPolicy.Access, scope);
            var columns = new Dictionary<EventSort, ColumnFilterCriteria> {
                [EventSort.Host] = new() { AllValues = false, Values = [scope.HostId] } };
            if (from.HasValue) columns[EventSort.Timestamp] = new() { FromUtc = new(from.Value, DateTimeKind.Utc), ToUtc = new(to!.Value, DateTimeKind.Utc) };
            var page = await reader.QueryAsync(new EventsQuery { PageSize = maximum, Offset = offset,
                Filter = new EventsFilter { Columns = columns, ReadScope = scope,
                    IncludeCompatibleExecutionRoots = session.Scope.ContextType == AiConversationContextType.Object } }, token);
            contexts = page.Rows.Select(row => EventContext(row.Native)).ToArray();
            matching = page.MatchingEvents;
        }
        else if (id == "GetHostNetwork")
        {
            if (!session.OwnerPolicy.Access.IsPublished(FeatureIds.NetworkWorkspace)) return Unavailable(id, "general.network-unpublished");
            var page = query.NetworkEndpointQueries.QueryForHostCapture(new(EndpointScopeKind.ConnectionSnapshots,
                Scope: scope, PageSize: maximum, Offset: offset, FromUtcTicks: from, ToUtcTicks: to),
                session.Scope.ContextType == AiConversationContextType.Object, token);
            if (!page.Supported) return Unavailable(id, "general.network-unsupported");
            contexts = page.Rows.Select(NetworkContext).ToArray();
            matching = page.MatchingRows;
        }
        else
        {
            if (!session.OwnerPolicy.Access.IsPublished(FeatureIds.Persistence)) return Unavailable(id, "general.persistence-unpublished");
            if (from.HasValue) return Unavailable(id, "general.persistence-time-unsupported");
            // Each assessed producer retains its exact query/provenance policy. Concatenate scopes
            // in stable identity order, counting all admitted scopes and retaining only this page.
            var included = new List<AiObjectContext>(maximum);
            long skip = offset;
            matching = 0;
            var scopes = query.PersistenceQueries.Scopes(scope.EvidenceSessionId, token)
                .Where(session.ReadBoundaryAdmits)
                .OrderBy(value => value.CaseId, StringComparer.Ordinal)
                .ThenBy(value => value.EvidenceSessionId, StringComparer.Ordinal)
                .ThenBy(value => value.CaptureId, StringComparer.Ordinal)
                .ThenBy(value => value.HostId, StringComparer.Ordinal)
                .ThenBy(value => value.ExecutionRootId, StringComparer.Ordinal)
                .ThenBy(value => value.SourceIdentityId, StringComparer.Ordinal);
            foreach (var producer in scopes)
            {
                token.ThrowIfCancellationRequested();
                var page = query.PersistenceQueries.Query(new(producer, PageSize: Math.Max(1, maximum - included.Count),
                    Offset: skip), token);
                matching = checked(matching + page.MatchingRows);
                skip = Math.Max(0, skip - page.MatchingRows);
                if (included.Count < maximum) included.AddRange(page.Rows.Select(PersistenceContext));
            }
            contexts = included.ToArray();
        }
        if (contexts.Any(context => !session.ReadBoundaryAdmits(context.Reference.Identity)))
            return Unavailable(id, "general.scope-mismatch");
        var result = ContextResult(id, contexts, (int)Math.Min(int.MaxValue, matching), matching <= int.MaxValue,
            "Bounded recorded evidence only; source collection coverage is not complete machine state.");
        return WithQueryCoverage(result, session, id, offset, maximum, matching, null, null, from, to);
    }

    internal static AiObjectContext EventContext(TelemetryEventRecord row)
    {
        var scope = new EvidenceIdentity { CaseId = row.CaseId, EvidenceSessionId = row.EvidenceSessionId,
            CaptureId = row.CaptureId, SourceIdentityId = row.SourceIdentityId, HostId = row.HostId, ExecutionRootId = row.ExecutionRootId };
        var reference = EventReference(row, scope) with { DisplayName = $"Recorded {row.Source} event {row.EventCode}" };
        reference = reference with { ReferenceId = "object-" + StableReferenceId(reference) };
        return Context(reference, new() { ["Source"] = row.Source, ["Event code"] = row.EventCode?.ToString() ?? "Unknown",
            ["Provider"] = row.RawProvider ?? "", ["Channel"] = row.RawLogName ?? "", ["Summary"] = row.Summary ?? "",
            ["Details"] = row.Details ?? "", ["Correlation"] = row.CorrelationState.ToString() }, ["Surrounding recorded events"]);
    }

    internal static AiObjectContext NetworkContext(NetworkEndpointHistoryRow row)
    {
        var native = row.Observation.Native;
        var reference = NetworkReference(row) with { DisplayName = "Recorded network endpoint" };
        reference = reference with { ReferenceId = "object-" + StableReferenceId(reference) };
        return Context(reference, new() { ["Local endpoint"] = native.LocalPresentation, ["Remote endpoint"] = native.RemotePresentation,
            ["Family"] = native.Family.ToString(), ["TCP state"] = native.TcpState?.ToString() ?? "Not applicable",
            ["Ownership"] = native.Ownership.ToString(), ["Process entity"] = native.ProcessEntityId,
            ["Observation"] = row.Observation.Kind.ToString(), ["Limitation"] = "OS table samples do not prove socket lifetime, traffic direction or reachability." }, ["Verified owner activity if available"]);
    }

    internal static AiObjectContext PersistenceContext(PersistenceWorkspaceRow row)
    {
        var locator = new PersistenceObjectReference(row.Scope, row.PartitionKey, row.ArtifactKey, row.Collection.CollectionId);
        var reference = new AiEvidenceReference("", row.Scope, new(EvidenceReferenceKind.GenericArtifact, JsonSerializer.Serialize(locator)),
            "PersistenceVersions", row.Collection.SourceRunId, row.Collection.CollectionId, row.ObservedUtc,
            "Recorded persistence entry", "", "");
        reference = reference with { ReferenceId = "object-" + StableReferenceId(reference) };
        return Context(reference, new() { ["Type"] = row.Type, ["Name"] = row.Name, ["Location"] = row.Location,
            ["Target command"] = row.TargetCommand ?? "", ["Principal"] = row.Principal ?? "", ["Change"] = row.Change,
            ["Freshness"] = row.Freshness }, ["Recorded history of this persistence object"]);
    }

    private static AiObjectContext Context(AiEvidenceReference reference, Dictionary<string, string> fields, string[] hints)
    {
        var bounded = fields.Where(pair => !string.IsNullOrWhiteSpace(pair.Value) && Encoding.UTF8.GetByteCount(pair.Value) <= 1_000)
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        if (bounded.Count != fields.Count) bounded["Context omissions"] = "Empty or oversized fields were omitted whole.";
        return new(reference, bounded, new Dictionary<string, string> { ["Exact object"] = reference.ReferenceId }, hints);
    }

    private static AgentToolResult ContextResult(string id, IReadOnlyList<AiObjectContext> contexts,
        int observed, bool exact, string coverage)
    {
        var omissions = new List<string>();
        var records = contexts.Select(context => { var fields = new List<ToolField>();
            foreach (var pair in context.DisplayProperties.Take(16)) AddField(fields, omissions, pair.Key, pair.Value);
            return new ToolRecord(context.Reference.ReferenceId, context.Reference.ObjectType, fields); }).ToArray();
        return Result(id, AgentToolStatus.Available, records, contexts.Select(context => context.Reference).ToArray(),
            Math.Max(contexts.Count, observed), exact, observed > contexts.Count, omissions, "object.recorded", coverage);
    }
}
