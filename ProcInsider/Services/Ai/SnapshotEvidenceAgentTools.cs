using System.Text;
using System.Text.Json;
using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Features.PersistenceWorkspace;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;
using static ProcInsider.Services.Ai.ProcessEvidenceAgentTools;

namespace ProcInsider.Services.Ai;

// Snapshot adapters use the same admitted generation and typed readers as the workspaces.
internal static class SnapshotEvidenceAgentTools
{
    internal static readonly string[] ToolIds = ["DiscoverSnapshotEvidence",
        "SearchSnapshotProcesses", "CountSnapshotProcesses", "SearchSnapshotEvents", "CountSnapshotEvents",
        "SearchSnapshotNetwork", "CountSnapshotNetwork", "SearchSnapshotPersistence", "CountSnapshotPersistence",
        "GetSnapshotEvidenceDetails", "GetSnapshotEvidenceProvenance", "GetSnapshotSourceRuns", "GetSnapshotProcessObservations",
        "GetSnapshotEvidenceRelations", "GetSnapshotSourceRunLineage", "GetSnapshotEvidenceContent",
        "GetSnapshotProcessStatistics", "GetSnapshotProcessProjection", "GetSnapshotPersistenceHistory", "GetSnapshotAccounts",
        "GetSnapshotCorrelationInputs", "GetSnapshotCorrelationGroups"];

    private static readonly JsonElement ContentOutputSchema = MakeContentSchema();
    private static JsonElement MakeContentSchema()
    {
        var schema = System.Text.Json.Nodes.JsonNode.Parse(OutputSchema.GetRawText())!;
        schema["properties"]!["records"]!["maxItems"] = 1;
        schema["properties"]!["records"]!["items"]!["properties"]!["fields"]!["items"]!["properties"]!["value"]!["maxLength"] = 32_000;
        return JsonSerializer.SerializeToElement(schema);
    }

    internal static IEnumerable<IAgentTool> Create(TelemetryProjectionService projection, FeatureAccessService access)
    {
        foreach (var id in ToolIds) yield return new SnapshotTool(projection, access, id);
    }

    internal static bool IsCheckedRelatedTool(IAgentTool tool, TelemetryProjectionService projection) =>
        tool is SnapshotTool adapter && ReferenceEquals(adapter.Projection, projection);

    internal static AiObjectContext? ResolveSnapshotReference(SqliteStagingQueryService query, AiEvidenceReference reference,
        CancellationToken token = default)
    {
        if (reference.DataSource is not ("SourceRuns" or "ProcessObservations" or "EvidenceRelations" or "SourceRunLineage" or "ProcessStatistics" or "ProcessProjectionFields" or "EvidenceCorrelationInputs")) return null;
        var context = SnapshotTool.ReadExtra(query, reference, token);
        return context?.Reference.CanonicalObjectKey == reference.CanonicalObjectKey && context.Reference.Identity == reference.Identity
            ? context : null;
    }

    private static JsonElement Schema(string id)
    {
        var properties = new Dictionary<string, object>();
        if (id == "GetSnapshotEvidenceContent")
        {
            properties["reference_id"] = new { type = "string", minLength = 1, maxLength = 160 };
            properties["field_offset"] = new { type = "integer", minimum = 0, maximum = int.MaxValue };
            properties["max_fields"] = new { type = "integer", minimum = 1, maximum = 16 };
        }
        else if (id is "GetSnapshotEvidenceDetails" or "GetSnapshotEvidenceProvenance")
            properties["reference_id"] = new { type = "string", minLength = 1, maxLength = 160 };
        else if (id is "GetSnapshotSourceRuns" or "GetSnapshotProcessObservations" or "GetSnapshotEvidenceRelations" or "GetSnapshotSourceRunLineage" or
            "GetSnapshotProcessStatistics" or "GetSnapshotProcessProjection" or "GetSnapshotPersistenceHistory" or "GetSnapshotAccounts" or "GetSnapshotCorrelationInputs" or "GetSnapshotCorrelationGroups")
        {
            properties["offset"] = new { type = "integer", minimum = 0, maximum = int.MaxValue };
            properties["max_rows"] = new { type = "integer", minimum = 1, maximum = 50 };
            if (id == "GetSnapshotCorrelationInputs")
            {
                properties["state"] = new { type = "string", @enum = Enum.GetNames<EvidenceCorrelationState>() };
                properties["evidence_kind"] = new { type = "string", @enum = Enum.GetNames<EvidenceReferenceKind>() };
                properties["source"] = new { type = "string", minLength = 1, maxLength = 160 };
            }
            if (id is not ("GetSnapshotSourceRuns" or "GetSnapshotAccounts" or "GetSnapshotCorrelationInputs" or "GetSnapshotCorrelationGroups"))
                properties["reference_id"] = new { type = "string", minLength = 1, maxLength = 160 };
        }
        else if (id != "DiscoverSnapshotEvidence")
        {
            if (id.StartsWith("Search", StringComparison.Ordinal))
            {
                properties["offset"] = new { type = "integer", minimum = 0, maximum = int.MaxValue };
                properties["max_rows"] = new { type = "integer", minimum = 1, maximum = 50 };
            }
            properties["from_utc_ticks"] = new { type = "integer", minimum = 0 };
            properties["to_utc_ticks"] = new { type = "integer", minimum = 0 };
            string[] filters = id.EndsWith("Processes", StringComparison.Ordinal)
                ? ["process_name_contains", "path_contains", "command_line_contains", "user_contains"]
                : id.EndsWith("Events", StringComparison.Ordinal) ? ["provider", "channel", "source"]
                : id.EndsWith("Network", StringComparison.Ordinal) ? ["text_contains"] : ["category"];
            foreach (var filter in filters) properties[filter] = new { type = "string", minLength = 1, maxLength = 160 };
            if (id.EndsWith("Processes", StringComparison.Ordinal))
            {
                properties["process_id"] = new { type = "integer", minimum = 0, maximum = int.MaxValue };
                properties["process_entity_id"] = new { type = "string", minLength = 1, maxLength = 160 };
            }
            if (id.EndsWith("Persistence", StringComparison.Ordinal))
                properties["view"] = new { type = "string", @enum = new[] { "Current", "Changes" } };
            if (id.EndsWith("Events", StringComparison.Ordinal))
            {
                properties["event_id"] = new { type = "integer", minimum = 0, maximum = int.MaxValue,
                    description = "Recorded native event code; this is not the snapshot sequence ID." };
                properties["sequence_id"] = new { type = "integer", minimum = 1L, maximum = long.MaxValue,
                    description = "Exact stored snapshot event sequence ID, distinct from event_id." };
            }
            if (id.EndsWith("Network", StringComparison.Ordinal))
                properties["endpoint_kind"] = new { type = "string", @enum = new[] { "ConnectionSnapshots", "ListenerHistory", "TcpListeners", "UdpEndpoints" } };
        }
        return JsonSerializer.SerializeToElement(new { type = "object", properties, additionalProperties = false });
    }

    private sealed class SnapshotTool : IAgentTool, IAgentToolAvailability
    {
        internal TelemetryProjectionService Projection { get; }
        private readonly FeatureAccessService _access;
        public AgentToolDescriptor Descriptor { get; }

        public bool IsAvailableFor(AgentToolSession session) => Descriptor.Id == "GetSnapshotAccounts"
            ? EventsAvailable(_access) && _access.IsPublished(FeatureIds.WindowsSecurityEvents) : Descriptor.Id.EndsWith("Events", StringComparison.Ordinal)
            ? EventsAvailable(_access) : Descriptor.Id.EndsWith("Network", StringComparison.Ordinal)
            ? _access.IsPublished(FeatureIds.NetworkWorkspace) : Descriptor.Id.EndsWith("Persistence", StringComparison.Ordinal) || Descriptor.Id == "GetSnapshotPersistenceHistory"
            ? _access.IsPublished(FeatureIds.Persistence) : true;

        internal SnapshotTool(TelemetryProjectionService projection, FeatureAccessService access, string id)
        {
            Projection = projection;
            _access = access;
            Descriptor = new(id, id, id switch
            {
                "DiscoverSnapshotEvidence" => "Describe the admitted snapshot boundary and published snapshot read families. Availability is query support, not proof of collection or full host state.",
                "GetSnapshotEvidenceDetails" => "Read the checked exact process, event, network observation or persistence version by a previously returned reference_id.",
                "GetSnapshotEvidenceProvenance" => "Revalidate a checked exact reference and report its stored source/run/revision identity. Missing producer metadata remains explicit; no source-run health is inferred.",
                "GetSnapshotSourceRuns" => "Count and page recorded producer runs within the admitted snapshot scope, including stored status and parser/tool provenance. Run status is recorded execution state, not current producer health or acquisition completeness.",
                "GetSnapshotProcessObservations" => "Count and page immutable observations of a previously checked durable process reference. Return typed stored observation scalars and exact run provenance; payload, field-state map and metadata JSON are omitted.",
                "GetSnapshotEvidenceRelations" => "Count and page scoped recorded relation decisions for a checked reference. Preserve direction, confidence, candidate ambiguity, resolver and superseded state. Related endpoint IDs remain recorded claims; no causal or identity proof is inferred.",
                "GetSnapshotSourceRunLineage" => "Count and page recorded parent/input lineage rows of an exact checked producer run. Input IDs, paths and hashes are recorded provenance only; no filesystem access or parent-object resolution.",
                "GetSnapshotEvidenceContent" => "Read checked native process/event/observation/statistic/network/source-run/correlation-input/relation fields and persistence version content in stable name order, including recorded payload/field-state JSON and event raw record. field_offset pages fields; values are JSON encoded. Whole native SQL records above 64 KB and fields above 32 KB are explicitly unavailable/omitted; total response stays bounded.",
                "GetSnapshotProcessStatistics" => "Count and page recorded counter samples for a checked durable process entity. Missing counters remain null; samples do not infer live state or interval rates.",
                "GetSnapshotProcessProjection" => "Count and page stored field-winner provenance linked to scoped observations of a checked process. Recorded quality/reason/version are projection decisions, not new evidence or conflict history.",
                "GetSnapshotPersistenceHistory" => "Count and page recorded versions of a checked exact persistence object using the assessed History reader. No process relationship or current machine state is inferred.",
                "GetSnapshotAccounts" => "Count and page recorded account identity occurrences in scoped published Windows Security events, each backed by an exact event citation. Account aggregates are interpretations, not independently persisted Account objects or full host inventory.",
                "GetSnapshotCorrelationInputs" => "Count and page scoped recorded correlation inputs with typed state/evidence_kind/source filters. Includes unresolved inputs without a decision; candidate counts/state are the latest scoped active decision, not independent identity proof.",
                "GetSnapshotCorrelationGroups" => "Count and page derived scoped correlation state/kind/source groups including no-decision inputs. Each group cites one recorded input anchor; groups are interpretations, not persisted objects.",
                "SearchSnapshotEvents" or "CountSnapshotEvents" => "Query stored events within the admitted snapshot boundary. sequence_id is the exact stored event sequence; event_id is the native event code and must not be used for a sequence. Provider/channel/source use exact equality. Counts and pages describe stored matches only; zero rows never prove absence from the machine.",
                _ => "Query recorded " + id.Split("Snapshot")[1] + " within the admitted host/capture/source/execution-root boundary using typed filters. Counts describe stored matching rows; pages and UTC ranges are bounded. Zero rows never establish absence from the machine."
            }, [AgentPermission.EvidenceRead, AgentPermission.QueryLocal],
                [AgentDefinition.ExplainObjectSkillId, AgentDefinition.QueryEvidenceSkillId], Schema(id),
                id == "GetSnapshotEvidenceContent" ? ContentOutputSchema : OutputSchema);
        }

        public Task<AgentToolResult> ExecuteAsync(AgentToolSession session, JsonElement arguments, CancellationToken token) =>
            Task.Run(async () =>
            {
                token.ThrowIfCancellationRequested();
                var id = Descriptor.Id;
                if (id == "GetSnapshotEvidenceContent") return await NativeContent(session, arguments, token);
                if (id is "GetSnapshotEvidenceDetails" or "GetSnapshotEvidenceProvenance") return await Exact(session, arguments, token);
                if (id == "GetSnapshotProcessObservations") return ObservationPage(session, arguments, token);
                if (id == "GetSnapshotEvidenceRelations") return RelationPage(session, arguments, token);
                if (id == "GetSnapshotSourceRunLineage") return LineagePage(session, arguments, token);
                if (id is "GetSnapshotProcessStatistics" or "GetSnapshotProcessProjection") return ProcessDerivedPage(session, arguments, token);
                if (id == "GetSnapshotPersistenceHistory") return await PersistenceHistoryPage(session, arguments, token);
                if (id == "GetSnapshotAccounts") return await AccountPage(session, arguments, token);
                if (id == "GetSnapshotCorrelationGroups")
                {
                    var scope = session.HostQueryIdentity;
                    var page = Projection.ScopedQuery.GetCorrelationGroupPageForAi(scope,
                        session.Scope.ContextType == AiConversationContextType.Object, PageOffset(arguments), Maximum(arguments), token);
                    if (!page.Supported) return Unavailable(id, "snapshot.correlation-group-schema-unavailable");
                    var groups = new List<AiObjectContext>();
                    foreach (var group in page.Rows)
                    {
                        var anchor = Projection.ScopedQuery.GetCorrelationInputPageForAi(scope, session.Scope.ContextType == AiConversationContextType.Object,
                            pageSize: 2, exactInputId: group.AnchorInputId, cancellationToken: token);
                        if (anchor.Rows.Count != 1) return Unavailable(id, "snapshot.correlation-group-anchor-unavailable");
                        var context = CorrelationInputContext(anchor.Rows[0]);
                        groups.Add(new(context.Reference, new Dictionary<string, string> { ["Group state"] = group.State,
                            ["Group evidence kind"] = group.EvidenceKind, ["Group source"] = group.Source,
                            ["Matching recorded inputs"] = group.InputCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                            ["Provenance"] = "Derived scoped aggregate; this citation is one recorded input anchor." }, new Dictionary<string, string>(), []));
                    }
                    return PageResult(session, groups.ToArray(), page.MatchingRows, arguments, page.Diagnostic);
                }
                if (id == "GetSnapshotCorrelationInputs")
                {
                    var page = Projection.ScopedQuery.GetCorrelationInputPageForAi(session.HostQueryIdentity,
                        session.Scope.ContextType == AiConversationContextType.Object, PageOffset(arguments), Maximum(arguments),
                        Enum.TryParse<EvidenceCorrelationState>(Text(arguments, "state"), out var state) ? state : null,
                        Enum.TryParse<EvidenceReferenceKind>(Text(arguments, "evidence_kind"), out var kind) ? kind : null,
                        Text(arguments, "source"), cancellationToken: token);
                    return page.Supported ? PageResult(session, page.Rows.Select(CorrelationInputContext).ToArray(), page.MatchingRows, arguments,
                        page.Diagnostic, ["correlation-endpoints-and-candidates-not-independently-resolved"])
                        : Unavailable(id, "snapshot.correlation-input-schema-unavailable");
                }
                if (session.Scope.ContextType is not (AiConversationContextType.General or AiConversationContextType.Object) ||
                    string.IsNullOrWhiteSpace(session.Scope.Identity.HostId) || string.IsNullOrWhiteSpace(session.Scope.Identity.CaptureId))
                    return Unavailable(id, "snapshot.host-capture-required");
                if (id == "DiscoverSnapshotEvidence")
                {
                    var coverage = JsonSerializer.Serialize(new { scope = session.HostQueryIdentity,
                        read_path = Projection.PathDiagnostics.ReadPath.ToString(),
                        execution_root_filter = RootFilter(session),
                        processes = "typed stored process query",
                        events = EventsAvailable(_access) ? "published typed events query" : "unavailable publication or event-source prerequisite",
                        network = _access.IsPublished(FeatureIds.NetworkWorkspace) ? "published recorded endpoint query" : "unpublished",
                        persistence = _access.IsPublished(FeatureIds.Persistence) ? "published recorded persistence query" : "unpublished",
                        producer_runs = "scoped pageable stored producer status",
                        process_observations = "checked process observation pages",
                        relations = "checked recorded relation decision pages",
                        run_lineage = "checked producer lineage pages",
                        content = "checked native fields; explicit 64KB record/32KB field bounds",
                        statistics_and_projection = "checked samples and observation-linked field winners",
                        persistence_history = _access.IsPublished(FeatureIds.Persistence) ? "Current/Changes searches and checked History versions" : "unpublished",
                        accounts = EventsAvailable(_access) && _access.IsPublished(FeatureIds.WindowsSecurityEvents) ? "Security actor aggregates with exact event anchors" : "unpublished Security source",
                        correlation_inputs = "inputs including no-decision Unresolved rows and state/kind/source groups",
                        sigma = "unavailable: no persisted result rows",
                        limitations = "Query support within the admitted snapshot; no completeness, current health or live state claim." });
                    return Encoding.UTF8.GetByteCount(coverage) > 2000 ? Unavailable(id, "snapshot.coverage-bound") :
                        Result(id, AgentToolStatus.Available, [], [], 0, false, false, [], "snapshot.discovery", coverage);
                }
                if (id == "GetSnapshotSourceRuns")
                {
                    var page = Projection.ScopedQuery.GetSourceRunPageForAi(session.HostQueryIdentity,
                        session.Scope.ContextType == AiConversationContextType.Object, PageOffset(arguments), Maximum(arguments), cancellationToken: token);
                    if (!page.Supported) return Unavailable(id, "snapshot.source-runs-schema-unavailable");
                    return PageResult(session, page.Rows.Select(SourceRunContext).ToArray(), page.MatchingRows, arguments, page.Diagnostic);
                }
                if (!TryTimeRange(arguments, out var from, out var to))
                    return Result(id, AgentToolStatus.InvalidRequest, [], [], 0, false, false,
                        ["invalid-time-range"], "snapshot.invalid-time-range");
                return await Search(session, arguments, from, to, token);
            }, token);

        private async Task<AgentToolResult> NativeContent(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            var id = Descriptor.Id;
            if (session.ResolveCheckedReference(arguments) is not { } target) return Unavailable(id, "snapshot.unchecked-reference");
            var query = Projection.ScopedQuery;
            IReadOnlyDictionary<string, object?>? native = null;
            try
            {
                if (target.Evidence.Kind == EvidenceReferenceKind.ProcessEntity && !string.IsNullOrWhiteSpace(target.Evidence.Id))
                {
                    var resolved = new AiEvidenceReferenceResolver(query).ResolveProcess(target, session.Scope.Identity.EvidenceSessionId);
                    if (!resolved.IsResolved) return Unavailable(id, "snapshot.process-original-unavailable");
                    var process = query.GetProcessByEntityId(target.Evidence.Id).Process;
                    if (process is not null) native = query.GetProcessRecordFields(process, token);
                }
                else if (target.Evidence.Kind == EvidenceReferenceKind.Event && EventsAvailable(_access) &&
                    long.TryParse(target.Evidence.Id, out var sequence))
                {
                    var scope = target.Identity;
                    await using var reader = new EventsWorkspaceQueryService(_access.Catalog, query,
                        new(scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, 0, 0), () => true);
                    var page = await reader.QueryAsync(new() { PageSize = 2, Filter = new() {
                        ExactEvent = new(scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, scope.SourceIdentityId,
                            scope.HostId, target.SourceRunId, sequence) } }, token);
                    if (page.Rows.Count == 1)
                    {
                        var context = EvidenceObjectAgentTools.EventContext(page.Rows[0].Native);
                        if (context.Reference.CanonicalObjectKey != target.CanonicalObjectKey || context.Reference.Identity != target.Identity)
                            return Unavailable(id, "snapshot.event-original-mismatch");
                        native = await reader.GetEventRecordFieldsAsync(page.Rows[0].Native, token);
                    }
                }
                else if (target.Evidence.Kind == EvidenceReferenceKind.NetworkFlow && _access.IsPublished(FeatureIds.NetworkWorkspace))
                {
                    var row = EvidenceObjectAgentTools.FindEndpoint(query, target, token);
                    if (row is null) return Unavailable(id, "snapshot.network-original-unavailable");
                    var original = EvidenceObjectAgentTools.NetworkContext(row).Reference;
                    if (original.CanonicalObjectKey != target.CanonicalObjectKey || original.Identity != target.Identity)
                        return Unavailable(id, "snapshot.network-original-mismatch");
                    var endpoint = row.Observation.Native;
                    native = new Dictionary<string, object?> { ["ObservationId"] = row.Observation.ObservationId,
                        ["PollId"] = row.Observation.PollId, ["EpisodeId"] = row.Observation.EpisodeId,
                        ["ObservationKind"] = row.Observation.Kind, ["Family"] = endpoint.Family,
                        ["LocalAddress"] = endpoint.LocalAddress, ["LocalScopeId"] = endpoint.LocalScopeId, ["LocalPort"] = endpoint.LocalPort,
                        ["RemoteAddress"] = endpoint.RemoteAddress, ["RemoteScopeId"] = endpoint.RemoteScopeId, ["RemotePort"] = endpoint.RemotePort,
                        ["TcpState"] = endpoint.TcpState, ["ProcessId"] = endpoint.ProcessId, ["NativeCreationUtc"] = endpoint.NativeCreationUtc,
                        ["ProcessStartUtc"] = endpoint.ProcessStartUtc, ["ProcessEntityId"] = endpoint.ProcessEntityId, ["Ownership"] = endpoint.Ownership,
                        ["Metadata"] = endpoint.Metadata, ["Poll"] = row.Poll, ["ObservationProvenance"] = row.Observation.Provenance,
                        ["FirstObservedUtc"] = row.FirstObservedUtc, ["LastObservedUtc"] = row.LastObservedUtc,
                        ["FirstAbsentUtc"] = row.FirstAbsentUtc, ["FirstAbsentWindowStartUtc"] = row.FirstAbsentWindowStartUtc,
                        ["HasContinuityGap"] = row.HasContinuityGap };
                }
                else if (target.DataSource == "SourceRuns")
                {
                    if (ResolveExtra(target, token) is null) return Unavailable(id, "snapshot.source-run-original-unavailable");
                    native = query.GetSourceRunRecordFieldsForAi(target.Identity, target.Evidence.Id, token);
                }
                else if (target.DataSource is "EvidenceCorrelationInputs" or "EvidenceRelations")
                {
                    var context = ResolveExtra(target, token);
                    if (context is null || context.Reference.CanonicalObjectKey != target.CanonicalObjectKey ||
                        context.Reference.Identity != target.Identity || context.Reference.SourceRunId != target.SourceRunId ||
                        context.Reference.SourceRevision != target.SourceRevision)
                        return Unavailable(id, "snapshot.correlation-original-unavailable");
                    native = target.DataSource == "EvidenceCorrelationInputs"
                        ? query.GetCorrelationInputRecordFieldsForAi(target.Identity, target.Evidence.Id, target.SourceRunId, token)
                        : query.GetEvidenceRelationRecordFieldsForAi(target.Identity, target.Evidence.Id, target.SourceRunId, token);
                }
                else if (target.DataSource == "ProcessObservations")
                {
                    var context = ResolveExtra(target, token);
                    if (context is null || context.Reference.CanonicalObjectKey != target.CanonicalObjectKey || context.Reference.Identity != target.Identity)
                        return Unavailable(id, "snapshot.observation-original-unavailable");
                    var locator = JsonSerializer.Deserialize<string[]>(target.Evidence.Id)!;
                    native = query.GetProcessObservationRecordFieldsForAi(target.Identity, locator[0], locator[1], token);
                }
                else if (target.DataSource == "ProcessStatistics" && target.Process?.ProcessEntityId is { Length: > 0 } statisticEntity)
                {
                    if (ResolveExtra(target, token) is null) return Unavailable(id, "snapshot.statistic-original-unavailable");
                    native = query.GetProcessStatisticRecordFieldsForAi(target.Identity, statisticEntity, target.Evidence.Id, token);
                }
                else if (target.DataSource == "PersistenceVersions" && _access.IsPublished(FeatureIds.Persistence))
                {
                    if (await ResolveOriginal(target, session.Scope.Identity.EvidenceSessionId, token) is null) return Unavailable(id, "snapshot.persistence-original-unavailable");
                    var locator = JsonSerializer.Deserialize<PersistenceObjectReference>(target.Evidence.Id)!;
                    var detail = query.PersistenceQueries.Detail(locator, token);
                    native = new Dictionary<string, object?> { ["Artifact"] = detail.Row.Artifact, ["Collection"] = detail.Row.Collection,
                        ["Version"] = detail.Row.Version, ["Before"] = detail.Before, ["After"] = detail.After };
                }
                else return Unavailable(id, "snapshot.native-content-kind-unsupported");
            }
            catch (ArgumentOutOfRangeException error) when (error.ParamName == "recordSizeBytes")
            {
                return Result(id, AgentToolStatus.Unavailable, [], [], 0, false, false,
                    ["native-record-over-64000-bytes"], "snapshot.native-record-size-bound",
                    "The checked native record exceeds the assessed reader's 64,000-byte whole-record bound; no partial record was substituted.");
            }
            token.ThrowIfCancellationRequested();
            if (native is null) return Unavailable(id, "snapshot.native-original-unavailable");
            var ordered = native.OrderBy(pair => pair.Key, StringComparer.Ordinal).ToArray();
            var offset = arguments.TryGetProperty("field_offset", out var fieldOffset) ? fieldOffset.GetInt32() : 0;
            var maximum = arguments.TryGetProperty("max_fields", out var maximumFields) ? maximumFields.GetInt32() : 16;
            var fields = new List<ToolField>();
            var omissions = new List<string>();
            var examined = 0;
            JsonElement Output() => JsonSerializer.SerializeToElement(new {
                availability = AgentToolStatus.Available.ToString(),
                records = new[] { new ToolRecord(target.ReferenceId, target.ObjectType, fields) },
                observed_count = ordered.Length, count_exact = true,
                truncated = offset + (long)examined < ordered.Length || omissions.Count > 0,
                coverage = JsonSerializer.Serialize(new { scope = target.Identity, reference_id = target.ReferenceId,
                    count_basis = "native stored fields in this exact original, including SQL nulls", field_offset = offset,
                    examined_fields = examined, returned_fields = fields.Count,
                    next_field_offset = offset + (long)examined < ordered.Length ? offset + (long)examined : (long?)null,
                    values = "JSON encoded native values; PayloadJson/FieldStatesJson/MetadataJson retain recorded strings",
                    per_field_utf8_bound = 32_000, whole_record_reader_bound = 64_000,
                    event_raw_record = "Exact attached RawRecords row is included when recorded and resolvable; each native row uses the reader's 64 KB bound" }),
                omissions
            }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
            foreach (var pair in ordered.Skip(offset).Take(maximum))
            {
                token.ThrowIfCancellationRequested();
                examined++;
                var value = JsonSerializer.Serialize(pair.Value);
                if (Encoding.UTF8.GetByteCount(value) > 32_000)
                {
                    omissions.Add("native-field-over-32000-bytes." + pair.Key);
                    continue;
                }
                fields.Add(new(pair.Key, value));
                if (Encoding.UTF8.GetByteCount(Output().GetRawText()) + JsonSerializer.SerializeToUtf8Bytes(target).Length > 48_000)
                {
                    fields.RemoveAt(fields.Count - 1);
                    omissions.Add("native-field-response-size-bound." + pair.Key);
                }
            }
            var output = Output();
            if (Encoding.UTF8.GetByteCount(output.GetProperty("coverage").GetString()!) > 2000)
                return Unavailable(id, "snapshot.coverage-bound");
            return new(id, AgentToolStatus.Available, output, [target], ordered.Length, true,
                offset + (long)examined < ordered.Length || omissions.Count > 0, omissions.AsReadOnly(), "snapshot.native-content");
        }

        private async Task<AgentToolResult> Exact(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            var id = Descriptor.Id;
            if (session.ResolveCheckedReference(arguments) is not { } target) return Unavailable(id, "snapshot.unchecked-reference");
            AgentToolResult resolved;
            if (target.DataSource is "SourceRuns" or "ProcessObservations" or "EvidenceRelations" or "SourceRunLineage" or "ProcessStatistics" or "ProcessProjectionFields" or "EvidenceCorrelationInputs")
            {
                var extra = ResolveExtra(target, token);
                if (extra is null || extra.Reference.CanonicalObjectKey != target.CanonicalObjectKey || extra.Reference.Identity != target.Identity)
                    return Unavailable(id, "snapshot.original-unavailable");
                resolved = ContextResult(id, [extra], 1, "Exact recorded producer or process observation; bounded scalar fields only.",
                    target.DataSource == "ProcessObservations" ? ["observation-payload-and-field-map-not-included"] : null);
            }
            else
            {
                var context = await ResolveOriginal(target, session.Scope.Identity.EvidenceSessionId, token);
                if (context is null) return Unavailable(id, "snapshot.original-unavailable");
                resolved = ContextResult(id, [context], 1, "Exact recorded object; bounded stored display fields only.");
            }
            if (resolved.Status != AgentToolStatus.Available) return resolved with { ToolId = id };
            if (id == "GetSnapshotEvidenceDetails") return resolved with { ToolId = id };
            var reference = resolved.Evidence.Single();
            var fields = new List<ToolField>();
            var omissions = new List<string>();
            AddField(fields, omissions, "source_identity_id", reference.Identity.SourceIdentityId);
            AddField(fields, omissions, "execution_root_id", reference.Identity.ExecutionRootId);
            AddField(fields, omissions, "data_source", reference.DataSource);
            AddField(fields, omissions, "source_run_id", reference.SourceRunId);
            AddField(fields, omissions, "source_revision", reference.SourceRevision);
            AddField(fields, omissions, "observed_utc", reference.TimestampUtc?.ToString("O"));
            if (!string.IsNullOrEmpty(reference.SourceRunId))
            {
                var runPage = Projection.ScopedQuery.GetSourceRunPageForAi(reference.Identity,
                    pageSize: 2, exactRunId: reference.SourceRunId, cancellationToken: token);
                if (runPage.Supported && runPage.Rows.Count == 1)
                {
                    var run = runPage.Rows[0];
                    AddField(fields, omissions, "recorded_run_status", run.Status);
                    AddField(fields, omissions, "recorded_run_source_type", run.SourceType);
                    AddField(fields, omissions, "recorded_run_parser_version", run.ParserVersion);
                    AddField(fields, omissions, "recorded_run_tool_version", run.ToolVersion);
                }
                else omissions.Add("exact-source-run-metadata-unavailable");
            }
            if (string.IsNullOrEmpty(reference.SourceRunId)) omissions.Add("source-run-not-recorded-on-reference");
            if (string.IsNullOrEmpty(reference.SourceRevision)) omissions.Add("source-revision-not-recorded-on-reference");
            return Result(id, AgentToolStatus.Available, [new(reference.ReferenceId, reference.ObjectType, fields)],
                [reference], 1, true, false, omissions, "snapshot.reference-provenance",
                "Exact stored object and scoped recorded producer-run provenance; stored run status is not current health or acquisition completeness.");
        }

        private AgentToolResult ObservationPage(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            var id = Descriptor.Id;
            if (session.ResolveCheckedReference(arguments) is not { Evidence.Kind: EvidenceReferenceKind.ProcessEntity } target ||
                string.IsNullOrWhiteSpace(target.Evidence.Id)) return Unavailable(id, "snapshot.checked-durable-process-required");
            token.ThrowIfCancellationRequested();
            var resolved = new AiEvidenceReferenceResolver(Projection.ScopedQuery).ResolveProcess(target, session.Scope.Identity.EvidenceSessionId);
            if (!resolved.IsResolved) return Unavailable(id, "snapshot.process-original-unavailable");
            var scope = session.AllowsConversationReads ? session.HostQueryIdentity : target.Identity;
            var page = Projection.ScopedQuery.GetProcessObservationPageForAi(scope, target.Evidence.Id,
                session.Scope.ContextType == AiConversationContextType.Object, PageOffset(arguments), Maximum(arguments), cancellationToken: token);
            if (!page.Supported) return Unavailable(id, "snapshot.observations-schema-unavailable");
            return PageResult(session, page.Rows.Select(ObservationContext).ToArray(), page.MatchingRows, arguments, page.Diagnostic,
                ["observation-payload-and-field-map-not-included"]);
        }

        private AgentToolResult RelationPage(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            var id = Descriptor.Id;
            if (session.ResolveCheckedReference(arguments) is not { } target) return Unavailable(id, "snapshot.unchecked-reference");
            var endpoint = target.Evidence;
            if (target.DataSource == "SourceRuns") endpoint = new(EvidenceReferenceKind.SourceRun, target.Evidence.Id);
            else if (target.DataSource == "ProcessObservations")
            {
                string[]? locator;
                try { locator = JsonSerializer.Deserialize<string[]>(target.Evidence.Id); }
                catch (JsonException) { return Unavailable(id, "snapshot.observation-invalid-locator"); }
                if (locator is not { Length: 2 }) return Unavailable(id, "snapshot.observation-invalid-locator");
                endpoint = new(EvidenceReferenceKind.ProcessObservation, locator[1]);
            }
            else if (target.DataSource == "SourceRunLineage") return Unavailable(id, "snapshot.lineage-endpoint-unsupported");
            if (endpoint.IsEmpty) return Unavailable(id, "snapshot.legacy-endpoint-unsupported");
            var page = Projection.ScopedQuery.GetEvidenceRelationPageForAi(session.HostQueryIdentity, endpoint,
                session.Scope.ContextType == AiConversationContextType.Object, PageOffset(arguments), Maximum(arguments), cancellationToken: token);
            if (!page.Supported) return Unavailable(id, "snapshot.relation-schema-unavailable");
            return PageResult(session, page.Rows.Select(row => RelationContext(row, endpoint)).ToArray(), page.MatchingRows,
                arguments, page.Diagnostic, ["relation-endpoints-not-independently-resolved"]);
        }

        private AgentToolResult LineagePage(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            var id = Descriptor.Id;
            if (session.ResolveCheckedReference(arguments) is not { DataSource: "SourceRuns" } target ||
                ResolveExtra(target, token) is null) return Unavailable(id, "snapshot.checked-source-run-required");
            var page = Projection.ScopedQuery.GetSourceRunLineagePageForAi(target.Identity, target.Evidence.Id,
                PageOffset(arguments), Maximum(arguments), cancellationToken: token);
            if (!page.Supported) return Unavailable(id, "snapshot.lineage-schema-unavailable");
            return PageResult(session, page.Rows.Select(LineageContext).ToArray(), page.MatchingRows, arguments, page.Diagnostic,
                ["lineage-parent-and-input-not-independently-resolved"]);
        }

        private AgentToolResult ProcessDerivedPage(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            var id = Descriptor.Id;
            if (session.ResolveCheckedReference(arguments) is not { Evidence.Kind: EvidenceReferenceKind.ProcessEntity } target ||
                string.IsNullOrWhiteSpace(target.Evidence.Id)) return Unavailable(id, "snapshot.checked-durable-process-required");
            if (!new AiEvidenceReferenceResolver(Projection.ScopedQuery).ResolveProcess(target, session.Scope.Identity.EvidenceSessionId).IsResolved)
                return Unavailable(id, "snapshot.process-original-unavailable");
            var scope = session.HostQueryIdentity;
            if (id == "GetSnapshotProcessStatistics")
            {
                var page = Projection.ScopedQuery.GetProcessStatisticsPageForAi(scope, target.Evidence.Id,
                    session.Scope.ContextType == AiConversationContextType.Object, PageOffset(arguments), Maximum(arguments), cancellationToken: token);
                return page.Supported ? PageResult(session, page.Rows.Select(StatisticsContext).ToArray(), page.MatchingRows, arguments, page.Diagnostic)
                    : Unavailable(id, "snapshot.statistics-schema-unavailable");
            }
            var provenance = Projection.ScopedQuery.GetProcessProjectionPageForAi(scope, target.Evidence.Id,
                session.Scope.ContextType == AiConversationContextType.Object, PageOffset(arguments), Maximum(arguments), cancellationToken: token);
            return provenance.Supported ? PageResult(session, provenance.Rows.Select(ProjectionContext).ToArray(), provenance.MatchingRows, arguments, provenance.Diagnostic)
                : Unavailable(id, "snapshot.projection-schema-unavailable");
        }

        private async Task<AgentToolResult> PersistenceHistoryPage(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            var id = Descriptor.Id;
            if (!_access.IsPublished(FeatureIds.Persistence) || session.ResolveCheckedReference(arguments) is not { DataSource: "PersistenceVersions" } target)
                return Unavailable(id, "snapshot.checked-persistence-required");
            if (await ResolveOriginal(target, session.Scope.Identity.EvidenceSessionId, token) is null) return Unavailable(id, "snapshot.persistence-original-unavailable");
            var locator = JsonSerializer.Deserialize<PersistenceObjectReference>(target.Evidence.Id)!;
            var page = Projection.ScopedQuery.PersistenceQueries.History(new(locator, Offset: PageOffset(arguments), PageSize: Maximum(arguments)), token);
            return PageResult(session, page.Rows.Select(EvidenceObjectAgentTools.PersistenceContext).ToArray(), page.MatchingRows, arguments,
                "Recorded versions of this exact persistence object only; no process ownership or current state is inferred.");
        }

        private async Task<AgentToolResult> AccountPage(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            var id = Descriptor.Id;
            if (!IsAvailableFor(session)) return Unavailable(id, "snapshot.account-source-unpublished");
            var scope = session.HostQueryIdentity;
            if (string.IsNullOrWhiteSpace(scope.HostId) || string.IsNullOrWhiteSpace(scope.CaptureId)) return Unavailable(id, "snapshot.host-capture-required");
            await using var reader = new EventsWorkspaceQueryService(_access.Catalog, Projection.ScopedQuery,
                new(scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, 0, 0), () => true);
            var filter = new EventsFilter { ReadScope = scope, Source = "Security", IdentityRole = EventIdentityRole.Actor,
                IncludeCompatibleExecutionRoots = session.Scope.ContextType == AiConversationContextType.Object,
                Columns = new Dictionary<EventSort, ColumnFilterCriteria> { [EventSort.Host] = new() { AllValues = false, Values = [scope.HostId] } } };
            var aggregates = await reader.AggregateAsync(filter, EventAggregateDimension.Identity, EventIdentityRole.Actor,
                PageOffset(arguments), Maximum(arguments), token);
            var contexts = new List<AiObjectContext>();
            foreach (var group in aggregates.Groups)
            {
                if (group.Identity is not { } identity) return Unavailable(id, "snapshot.account-identity-unavailable");
                var anchor = await reader.QueryAsync(new() { PageSize = 1, Filter = filter with { IdentityKey = group.Key } }, token);
                if (anchor.Rows.Count != 1) return Unavailable(id, "snapshot.account-anchor-unavailable");
                var reference = EvidenceObjectAgentTools.EventContext(anchor.Rows[0].Native).Reference;
                contexts.Add(new(reference, new Dictionary<string, string> { ["Account identity key"] = group.Key,
                    ["Recorded SID"] = identity.Sid, ["Recorded domain"] = identity.Domain, ["Recorded name"] = identity.Name,
                    ["Identity status"] = identity.Status.ToString(), ["Identity scope"] = identity.Scope.ToString(),
                    ["Identity role"] = identity.Role.ToString(), ["Matching event occurrences"] = group.EventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["Provenance"] = "Derived scoped identity aggregate backed by this exact recorded Security event; no independent Account object is created." },
                    new Dictionary<string, string>(), []));
            }
            var result = PageResult(session, contexts.ToArray(), aggregates.TotalGroups, arguments,
                "Actor account identities in the scoped recorded Security event subset; count is identity groups, not all host accounts. Each row cites one recorded event anchor.");
            if (aggregates.Completeness.StoredQueryComplete) return result;
            var output = System.Text.Json.Nodes.JsonNode.Parse(result.Output.GetRawText())!.AsObject();
            output["count_exact"] = false;
            return result with { CountIsExact = false, Output = JsonSerializer.SerializeToElement(output) };
        }

        private async Task<AiObjectContext?> ResolveOriginal(AiEvidenceReference target, string sessionId, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (target.Identity.EvidenceSessionId != sessionId) return null;
            var query = Projection.ScopedQuery;
            AiObjectContext? context = null;
            if (target.Evidence.Kind == EvidenceReferenceKind.ProcessEntity)
            {
                var resolved = new AiEvidenceReferenceResolver(query).ResolveProcess(target, sessionId);
                if (!resolved.IsResolved) return null;
                var process = resolved.Process!;
                var original = CreateObjectContext(process);
                var fields = original.DisplayProperties.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
                fields["User"] = process.UserName ?? "";
                fields["Status"] = process.Status.ToString();
                fields["Recorded end time UTC"] = process.EndTime?.ToUniversalTime().ToString("O") ?? "Not recorded";
                context = new(original.Reference, fields, original.KeyProperties, original.RelatedDataHints);
            }
            else if (target.Evidence.Kind == EvidenceReferenceKind.Event && EventsAvailable(_access) &&
                long.TryParse(target.Evidence.Id, out var sequence))
            {
                var scope = target.Identity;
                await using var reader = new EventsWorkspaceQueryService(_access.Catalog, query,
                    new(scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, 0, 0), () => true);
                var page = await reader.QueryAsync(new() { PageSize = 2, Filter = new() {
                    ExactEvent = new(scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, scope.SourceIdentityId,
                        scope.HostId, target.SourceRunId, sequence) } }, token);
                if (page.Rows.Count == 1) context = EvidenceObjectAgentTools.EventContext(page.Rows[0].Native);
            }
            else if (target.Evidence.Kind == EvidenceReferenceKind.NetworkFlow && _access.IsPublished(FeatureIds.NetworkWorkspace))
            {
                var row = EvidenceObjectAgentTools.FindEndpoint(query, target, token);
                if (row is not null) context = EvidenceObjectAgentTools.NetworkContext(row);
            }
            else if (target.Evidence.Kind == EvidenceReferenceKind.GenericArtifact && target.DataSource == "PersistenceVersions" &&
                _access.IsPublished(FeatureIds.Persistence))
            {
                PersistenceObjectReference? locator;
                try { locator = JsonSerializer.Deserialize<PersistenceObjectReference>(target.Evidence.Id); }
                catch (JsonException) { return null; }
                if (locator is not null && locator.Scope == target.Identity)
                    context = EvidenceObjectAgentTools.PersistenceContext(query.PersistenceQueries.Detail(locator, token).Row);
            }
            token.ThrowIfCancellationRequested();
            return context?.Reference.CanonicalObjectKey == target.CanonicalObjectKey && context.Reference.Identity == target.Identity ? context : null;
        }

        private AiObjectContext? ResolveExtra(AiEvidenceReference target, CancellationToken token) =>
            ResolveSnapshotReference(Projection.ScopedQuery, target, token);

        internal static AiObjectContext? ReadExtra(SqliteStagingQueryService query, AiEvidenceReference target, CancellationToken token)
        {
            if (target.DataSource == "EvidenceCorrelationInputs")
            {
                var input = query.GetCorrelationInputPageForAi(target.Identity, pageSize: 2, exactInputId: target.Evidence.Id, cancellationToken: token);
                return input.Supported && input.Rows.Count == 1 ? CorrelationInputContext(input.Rows[0]) : null;
            }
            if (target.DataSource == "ProcessStatistics")
            {
                if (target.Process?.ProcessEntityId is not { Length: > 0 } entity) return null;
                var statistics = query.GetProcessStatisticsPageForAi(target.Identity, entity, pageSize: 2, exactSampleId: target.Evidence.Id, cancellationToken: token);
                return statistics.Supported && statistics.Rows.Count == 1 ? StatisticsContext(statistics.Rows[0]) : null;
            }
            if (target.DataSource == "EvidenceRelations")
            {
                var page = query.GetEvidenceRelationPageForAi(target.Identity, target.Evidence,
                    pageSize: 2, exactRelationId: target.Evidence.Id, cancellationToken: token);
                return page.Supported && page.Rows.Count == 1 ? RelationContext(page.Rows[0], null) : null;
            }
            if (target.DataSource == "SourceRuns")
            {
                var page = query.GetSourceRunPageForAi(target.Identity, pageSize: 2,
                    exactRunId: target.Evidence.Id, cancellationToken: token);
                return page.Supported && page.Rows.Count == 1 ? SourceRunContext(page.Rows[0]) : null;
            }
            string[]? locator;
            try { locator = JsonSerializer.Deserialize<string[]>(target.Evidence.Id); }
            catch (JsonException) { return null; }
            if (target.DataSource == "ProcessProjectionFields")
            {
                if (locator is not { Length: 5 }) return null;
                var projection = query.GetProcessProjectionPageForAi(target.Identity, locator[0], pageSize: 2, exactFieldName: locator[1], cancellationToken: token);
                return projection.Supported && projection.Rows.Count == 1 ? ProjectionContext(projection.Rows[0]) : null;
            }
            if (target.DataSource == "SourceRunLineage")
            {
                if (locator is not { Length: 8 } || string.IsNullOrWhiteSpace(locator[0]) || !long.TryParse(locator[1], out var rowId)) return null;
                var lineage = query.GetSourceRunLineagePageForAi(target.Identity, locator[0],
                    pageSize: 2, exactLineageId: rowId, cancellationToken: token);
                return lineage.Supported && lineage.Rows.Count == 1 ? LineageContext(lineage.Rows[0]) : null;
            }
            if (locator is not { Length: 2 } || locator.Any(string.IsNullOrWhiteSpace)) return null;
            var observations = query.GetProcessObservationPageForAi(target.Identity, locator[0],
                pageSize: 2, exactObservationId: locator[1], cancellationToken: token);
            return observations.Supported && observations.Rows.Count == 1 ? ObservationContext(observations.Rows[0]) : null;
        }

        private AgentToolResult PageResult(AgentToolSession session, AiObjectContext[] contexts, long matching,
            JsonElement arguments, string limitation, string[]? omissions = null)
        {
            var id = Descriptor.Id;
            if (contexts.Any(context => !session.ReadBoundaryAdmits(context.Reference.Identity))) return Unavailable(id, "snapshot.scope-mismatch");
            var result = ContextResult(id, contexts, matching, limitation, omissions);
            var offset = PageOffset(arguments);
            var returned = result.Evidence.Count;
            var coverage = JsonSerializer.Serialize(new { scope = session.HostQueryIdentity,
                execution_root_filter = RootFilter(session), matching_count = matching, count_basis = "stored query rows",
                offset, returned_count = returned, next_offset = returned > 0 && offset + (long)returned < matching ? offset + (long)returned : (long?)null,
                page_bound = Maximum(arguments), limitation });
            if (Encoding.UTF8.GetByteCount(coverage) > 2000) return Unavailable(id, "snapshot.coverage-bound");
            var output = System.Text.Json.Nodes.JsonNode.Parse(result.Output.GetRawText())!.AsObject();
            output["coverage"] = coverage;
            output["truncated"] = result.IsTruncated || offset + (long)returned < matching;
            return result with { Output = JsonSerializer.SerializeToElement(output), IsTruncated = result.IsTruncated || offset + (long)returned < matching };
        }

        private async Task<AgentToolResult> Search(AgentToolSession session, JsonElement arguments, long? from, long? to, CancellationToken token)
        {
            var id = Descriptor.Id;
            var query = Projection.ScopedQuery;
            var scope = session.HostQueryIdentity;
            var countOnly = id.StartsWith("Count", StringComparison.Ordinal);
            var maximum = countOnly ? 1 : Maximum(arguments);
            var offset = countOnly ? 0 : arguments.TryGetProperty("offset", out var value) ? value.GetInt32() : 0;
            var compatible = session.Scope.ContextType == AiConversationContextType.Object;
            AiObjectContext[] contexts;
            long matching;
            var omissions = new List<string>();
            var detail = "Stored matching rows only; collection completeness is unknown.";
            if (id.EndsWith("Processes", StringComparison.Ordinal))
            {
                var name = Text(arguments, "process_name_contains");
                if (name is { Length: > 4 } && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
                var filters = new ProcessListingFilterSet { ReadScope = scope, CaseId = scope.CaseId,
                    EvidenceSessionId = scope.EvidenceSessionId, CaptureId = scope.CaptureId, HostId = scope.HostId,
                    SourceIdentityId = NullIfEmpty(scope.SourceIdentityId), ExecutionRootId = NullIfEmpty(scope.ExecutionRootId),
                    IncludeCompatibleExecutionRoots = compatible, ProcessNameContains = name,
                    ProcessIdEquals = arguments.TryGetProperty("process_id", out var pid) ? pid.GetInt32() : null,
                    ProcessEntityIdEquals = Text(arguments, "process_entity_id"),
                    ProcessPathContains = Text(arguments, "path_contains"), CommandLineContains = Text(arguments, "command_line_contains"),
                    UserNameContains = Text(arguments, "user_contains") };
                if (from.HasValue) filters.ColumnFilters = new Dictionary<ProcessListingSortColumn, ColumnFilterCriteria> {
                    [ProcessListingSortColumn.StartTime] = new() { FromUtc = new(from.Value, DateTimeKind.Utc), ToUtc = new(to!.Value, DateTimeKind.Utc) } };
                var page = query.ProcessListingQueries.GetProcessPage(new() { Filters = filters, Offset = offset, PageSize = maximum,
                    Sort = new() { Column = ProcessListingSortColumn.StartTime, Direction = ProcessListingSortDirection.Descending } }, token);
                matching = page.TotalCount;
                contexts = page.Rows.Select(row => CreateObjectContext(row.ToProcessInfo())).ToArray();
                detail = "Process start-time filter; not all process activity. Names accept a trailing .exe; remaining filters are substring matches.";
            }
            else if (id.EndsWith("Events", StringComparison.Ordinal))
            {
                if (!EventsAvailable(_access)) return Unavailable(id, "snapshot.events-unavailable");
                await using var reader = new EventsWorkspaceQueryService(_access.Catalog, query,
                    new(scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, 0, 0), () => true);
                var columns = new Dictionary<EventSort, ColumnFilterCriteria> {
                    [EventSort.Host] = new() { AllValues = false, Values = [scope.HostId] } };
                if (from.HasValue) columns[EventSort.Timestamp] = new() { FromUtc = new(from.Value, DateTimeKind.Utc), ToUtc = new(to!.Value, DateTimeKind.Utc) };
                if (arguments.TryGetProperty("sequence_id", out var sequenceId))
                    columns[EventSort.Sequence] = new() { AllValues = false,
                        Values = [sequenceId.GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture)] };
                var page = await reader.QueryAsync(new() { Offset = offset, PageSize = maximum,
                    Filter = new() { ReadScope = scope, IncludeCompatibleExecutionRoots = compatible, Columns = columns,
                        Provider = Text(arguments, "provider"), Channel = Text(arguments, "channel"), Source = Text(arguments, "source"),
                        EventId = arguments.TryGetProperty("event_id", out var eventId) ? eventId.GetInt32() : null } }, token);
                matching = page.MatchingEvents;
                contexts = page.Rows.Select(row => EvidenceObjectAgentTools.EventContext(row.Native)).ToArray();
                detail = "Published stored event query; sequence ID, native event ID, provider, channel and source use separate exact filters. Acquisition coverage: " + page.Completeness.AcquisitionCoverage;
                if (!page.Completeness.StoredQueryComplete) omissions.Add("events-stored-query-incomplete");
                if (page.Completeness.MissingSourceRunEvents > 0) omissions.Add("events-missing-source-run");
            }
            else if (id.EndsWith("Network", StringComparison.Ordinal))
            {
                if (!_access.IsPublished(FeatureIds.NetworkWorkspace)) return Unavailable(id, "snapshot.network-unpublished");
                var kind = Text(arguments, "endpoint_kind") is { } kindName ? Enum.Parse<EndpointScopeKind>(kindName) : EndpointScopeKind.ConnectionSnapshots;
                var page = query.NetworkEndpointQueries.QueryForHostCapture(new(kind, Scope: scope, Offset: offset,
                    PageSize: maximum, FromUtcTicks: from, ToUtcTicks: to, Text: Text(arguments, "text_contains")), compatible, token);
                if (!page.Supported) return Unavailable(id, "snapshot.network-unsupported");
                matching = page.MatchingRows;
                contexts = page.Rows.Select(EvidenceObjectAgentTools.NetworkContext).ToArray();
                detail = "Recorded endpoint observations; text uses the reader's native search. OS samples do not prove traffic or reachability.";
            }
            else
            {
                if (!_access.IsPublished(FeatureIds.Persistence)) return Unavailable(id, "snapshot.persistence-unpublished");
                if (from.HasValue) return Unavailable(id, "snapshot.persistence-time-unsupported");
                var rows = new List<AiObjectContext>();
                long skip = offset;
                matching = 0;
                var producers = query.PersistenceQueries.Scopes(scope.EvidenceSessionId, token).Where(session.ReadBoundaryAdmits)
                    .OrderBy(identity => JsonSerializer.Serialize(identity), StringComparer.Ordinal).ToArray();
                if (producers.Length == 0) return Unavailable(id, "snapshot.persistence-no-admitted-producer");
                foreach (var producer in producers)
                {
                    token.ThrowIfCancellationRequested();
                    var view = Text(arguments, "view") is { } viewName ? Enum.Parse<PersistenceView>(viewName) : PersistenceView.Current;
                    var page = query.PersistenceQueries.Query(new(producer, View: view, Category: Text(arguments, "category"), Offset: skip,
                        PageSize: Math.Max(1, maximum - rows.Count)), token);
                    matching = checked(matching + page.MatchingRows);
                    skip = Math.Max(0, skip - page.MatchingRows);
                    if (rows.Count < maximum) rows.AddRange(page.Rows.Select(EvidenceObjectAgentTools.PersistenceContext));
                }
                contexts = rows.ToArray();
                detail = "Recorded persistence view (Current by default, or Changes), ordered across admitted producer scopes; category is exact. Stale records do not prove current machine state.";
            }
            token.ThrowIfCancellationRequested();
            if (matching < 0 || contexts.Any(context => !session.ReadBoundaryAdmits(context.Reference.Identity)))
                return Unavailable(id, "snapshot.scope-or-count-unavailable");
            if (countOnly) contexts = [];
            var records = contexts.Select(context => { var fields = new List<ToolField>();
                foreach (var field in context.DisplayProperties.Take(16)) AddField(fields, omissions, field.Key, field.Value);
                return new ToolRecord(context.Reference.ReferenceId, context.Reference.ObjectType, fields); }).ToArray();
            var result = Result(id, AgentToolStatus.Available, records, contexts.Select(context => context.Reference).ToArray(),
                (int)Math.Min(int.MaxValue, matching), matching <= int.MaxValue && !omissions.Contains("events-stored-query-incomplete"),
                !countOnly && matching > offset + contexts.Length, omissions, "snapshot.typed-query");
            // Output byte limits can omit whole records; continuation follows the actual returned rows.
            var returned = result.Evidence.Count;
            long? next = !countOnly && returned > 0 && offset + (long)returned < matching ? offset + (long)returned : null;
            var coverage = JsonSerializer.Serialize(new { scope, execution_root_filter = RootFilter(session),
                filters = arguments, count_basis = "stored matching query rows, not machine completeness", matching_count = matching,
                count_exact = result.CountIsExact, offset, returned_count = returned, next_offset = next, page_bound = maximum,
                count_only = countOnly, limitations = detail });
            if (Encoding.UTF8.GetByteCount(coverage) > 2000) return Unavailable(id, "snapshot.coverage-bound");
            var output = System.Text.Json.Nodes.JsonNode.Parse(result.Output.GetRawText())!.AsObject();
            output["coverage"] = coverage;
            return result with { Output = JsonSerializer.SerializeToElement(output) };
        }
    }

    private static string? Text(JsonElement arguments, string name) => arguments.TryGetProperty(name, out var value) ? value.GetString() : null;
    private static int PageOffset(JsonElement arguments) => arguments.TryGetProperty("offset", out var value) ? value.GetInt32() : 0;

    private static AgentToolResult ContextResult(string id, AiObjectContext[] contexts, long matching, string coverage,
        string[]? explicitOmissions = null)
    {
        var omissions = new List<string>(explicitOmissions ?? []);
        var records = contexts.Select(context => { var fields = new List<ToolField>();
            foreach (var pair in context.DisplayProperties) AddField(fields, omissions, pair.Key, pair.Value);
            return new ToolRecord(context.Reference.ReferenceId, context.Reference.ObjectType, fields); }).ToArray();
        return Result(id, AgentToolStatus.Available, records, contexts.Select(context => context.Reference).ToArray(),
            (int)Math.Min(int.MaxValue, matching), matching <= int.MaxValue, false, omissions, "snapshot.stored-scalars", coverage);
    }

    private static AiObjectContext CorrelationInputContext(EvidenceCorrelationInput row)
    {
        var reference = new AiEvidenceReference("", row.Identity, new(EvidenceReferenceKind.GenericArtifact, row.InputId),
            "EvidenceCorrelationInputs", row.SourceRunId, row.InputId, row.ObservedUtc, "Recorded correlation input", "", "");
        reference = reference with { ReferenceId = StableReferenceId(reference) };
        return new(reference, new Dictionary<string, string> { ["Input ID"] = row.InputId, ["Evidence kind"] = row.EvidenceKind.ToString(),
            ["Recorded evidence ID"] = row.EvidenceId, ["Source"] = row.Source, ["Recorded process ID"] = row.ProcessId.ToString(),
            ["Recorded process GUID"] = row.ProcessGuid, ["Recorded process start UTC"] = row.ProcessStartTimeUtc?.ToString("O") ?? "Not recorded",
            ["Recorded state"] = row.CurrentState.ToString(), ["Recorded candidate count"] = row.CandidateCount.ToString(),
            ["Recorded process entity decision"] = row.CurrentProcessEntityId, ["Recorded confidence"] = row.CurrentConfidence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Decision diagnostics"] = row.CorrelationDiagnostics, ["Resolver version"] = row.ResolverVersion,
            ["Correlation method"] = row.CurrentMethod, ["Source run ID"] = row.SourceRunId }, new Dictionary<string, string>(), []);
    }

    private static AiObjectContext SourceRunContext(AiSourceRunRow row)
    {
        var reference = new AiEvidenceReference("", row.Identity, new(EvidenceReferenceKind.GenericArtifact, row.SourceRunId),
            "SourceRuns", row.SourceRunId, "", row.StartedUtc, "Recorded producer run", "", "");
        reference = reference with { ReferenceId = StableReferenceId(reference) };
        return new(reference, new Dictionary<string, string> {
            ["Source run ID"] = row.SourceRunId, ["Source type"] = row.SourceType, ["Display name"] = row.DisplayName,
            ["Recorded status"] = row.Status, ["Started UTC"] = row.StartedUtc?.ToString("O") ?? "Not recorded",
            ["Ended UTC"] = row.EndedUtc?.ToString("O") ?? "Not recorded", ["Provider"] = row.Provider,
            ["Channel"] = row.Channel, ["Tool version"] = row.ToolVersion, ["Parser version"] = row.ParserVersion,
            ["Ingestion job ID"] = row.IngestionJobId }, new Dictionary<string, string>(), []);
    }

    private static AiObjectContext StatisticsContext(ProcessStatisticsRecord row)
    {
        var identity = new EvidenceIdentity { CaseId = row.CaseId, EvidenceSessionId = row.EvidenceSessionId, CaptureId = row.CaptureId,
            SourceIdentityId = row.SourceIdentityId, HostId = row.HostId, ExecutionRootId = row.ExecutionRootId };
        var reference = new AiEvidenceReference("", identity, new(EvidenceReferenceKind.ProcessStatistic, row.SampleId),
            "ProcessStatistics", row.SourceRunId, row.SampleId, row.ObservedUtc, "Recorded process counter sample", "", "",
            new(row.ProcessEntityId, row.ProcessKey, row.CaseId, row.EvidenceSessionId, row.CaptureId, row.SourceIdentityId, row.HostId, row.ExecutionRootId));
        reference = reference with { ReferenceId = StableReferenceId(reference) };
        string Counter(long? value) => value?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "null (not recorded)";
        return new(reference, new Dictionary<string, string> { ["Sample ID"] = row.SampleId, ["Process entity ID"] = row.ProcessEntityId,
            ["Observed UTC"] = row.ObservedUtc.ToString("O"), ["Total processor time ticks"] = Counter(row.TotalProcessorTimeTicks),
            ["User processor time ticks"] = Counter(row.UserProcessorTimeTicks), ["Privileged processor time ticks"] = Counter(row.PrivilegedProcessorTimeTicks),
            ["Read bytes"] = Counter(row.ReadBytes), ["Written bytes"] = Counter(row.WrittenBytes), ["Collection error"] = row.CollectionError,
            ["Source"] = row.Source, ["Source run ID"] = row.SourceRunId }, new Dictionary<string, string>(), []);
    }

    private static AiObjectContext ProjectionContext(AiProjectionWinnerRow row)
    {
        var locator = JsonSerializer.Serialize(new[] { row.ProcessEntityId, row.Winner.FieldName, row.Winner.ObservationId,
            row.ProjectionVersion, row.UpdatedUtc?.ToString("O") ?? "" });
        var reference = new AiEvidenceReference("", row.Identity, new(EvidenceReferenceKind.GenericArtifact, locator),
            "ProcessProjectionFields", row.Winner.SourceRunId, row.Winner.ObservationId, row.UpdatedUtc, "Recorded projection field winner", "", "");
        reference = reference with { ReferenceId = StableReferenceId(reference) };
        return new(reference, new Dictionary<string, string> { ["Process entity ID"] = row.ProcessEntityId, ["Field name"] = row.Winner.FieldName,
            ["Winning observation ID"] = row.Winner.ObservationId, ["Source run ID"] = row.Winner.SourceRunId,
            ["Recorded value quality"] = row.Winner.ValueQuality.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Resolution reason"] = row.Winner.ResolutionReason, ["Projection version"] = row.ProjectionVersion,
            ["Updated UTC"] = row.UpdatedUtc?.ToString("O") ?? "Not recorded" }, new Dictionary<string, string>(), []);
    }

    private static AiObjectContext ObservationContext(AiProcessObservationRow row)
    {
        var locator = JsonSerializer.Serialize(new[] { row.ProcessEntityId, row.ObservationId });
        var reference = new AiEvidenceReference("", row.Identity, new(EvidenceReferenceKind.GenericArtifact, locator),
            "ProcessObservations", row.SourceRunId, row.ObservationId, row.ObservedUtc, "Recorded process observation", "", "");
        reference = reference with { ReferenceId = StableReferenceId(reference) };
        return new(reference, new Dictionary<string, string> {
            ["Process entity ID"] = row.ProcessEntityId, ["Observation ID"] = row.ObservationId,
            ["Adapter ID"] = row.AdapterId, ["Observation kind"] = row.ObservationKind, ["Source run ID"] = row.SourceRunId,
            ["Ingestion job ID"] = row.IngestionJobId, ["Raw record ID"] = row.RawRecordId,
            ["Native alias (source scoped)"] = row.SourceNativeAlias, ["Observed UTC"] = row.ObservedUtc?.ToString("O") ?? "Not recorded",
            ["Valid from UTC"] = row.ValidFromUtc?.ToString("O") ?? "Not recorded", ["Valid to UTC"] = row.ValidToUtc?.ToString("O") ?? "Not recorded",
            ["Status assertion"] = row.StatusAssertion, ["Correlation method"] = row.CorrelationMethod,
            ["Correlation confidence"] = row.CorrelationConfidence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Parser version"] = row.ParserVersion }, new Dictionary<string, string>(), []);
    }

    private static AiObjectContext RelationContext(EvidenceRelation row, EvidenceReference? endpoint)
    {
        var identity = new EvidenceIdentity { CaseId = row.CaseId, EvidenceSessionId = row.EvidenceSessionId,
            CaptureId = row.CaptureId, SourceIdentityId = row.SourceIdentityId, HostId = row.HostId, ExecutionRootId = row.ExecutionRootId };
        var reference = new AiEvidenceReference("", identity, new(EvidenceReferenceKind.EvidenceRelation, row.RelationId),
            "EvidenceRelations", row.SourceRunId, row.RelationId, row.ObservedFromUtc.ToUniversalTime(), "Recorded relation decision", "", "");
        reference = reference with { ReferenceId = StableReferenceId(reference) };
        var from = endpoint is not null && row.FromKind == endpoint.Kind && row.FromId == endpoint.Id;
        var to = endpoint is not null && row.ToKind == endpoint.Kind && row.ToId == endpoint.Id;
        return new(reference, new Dictionary<string, string> {
            ["Relation ID"] = row.RelationId, ["Decision key"] = row.DecisionKey,
            ["From kind"] = row.FromKind.ToString(), ["From ID"] = row.FromId,
            ["To kind"] = row.ToKind.ToString(), ["To ID"] = row.ToId,
            ["Relation type"] = row.RelationType.ToString(), ["Recorded correlation state"] = row.State.ToString(),
            ["Recorded confidence"] = row.Confidence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Candidate count"] = row.CandidateCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Correlation diagnostics"] = row.CorrelationDiagnostics, ["Correlation method"] = row.CorrelationMethod,
            ["Decision status"] = row.Status.ToString(), ["Resolver"] = row.ResolverName + " / " + row.ResolverVersion,
            ["Selected endpoint role"] = endpoint is null ? "Not evaluated" : from && to ? "From and To" : from ? "From" : to ? "To" : "Not matched",
            ["Superseded by relation ID"] = row.SupersededByRelationId }, new Dictionary<string, string>(), []);
    }

    private static AiObjectContext LineageContext(AiSourceRunLineageRow row)
    {
        var locator = JsonSerializer.Serialize(new[] { row.SourceRunId, row.LineageId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            row.ParentSourceRunId, row.InputArtifactId, row.InputPath, row.InputHash, row.RelationType, row.CreatedUtc?.ToString("O") ?? "" });
        var reference = new AiEvidenceReference("", row.Identity, new(EvidenceReferenceKind.GenericArtifact, locator),
            "SourceRunLineage", row.SourceRunId, row.LineageId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            row.CreatedUtc, "Recorded producer lineage", "", "");
        reference = reference with { ReferenceId = StableReferenceId(reference) };
        return new(reference, new Dictionary<string, string> {
            ["Source run ID"] = row.SourceRunId, ["Recorded parent source run ID"] = row.ParentSourceRunId,
            ["Recorded input artifact ID"] = row.InputArtifactId, ["Recorded input path"] = row.InputPath,
            ["Recorded input hash"] = row.InputHash, ["Recorded lineage relation type"] = row.RelationType,
            ["Created UTC"] = row.CreatedUtc?.ToString("O") ?? "Not recorded" }, new Dictionary<string, string>(), []);
    }

    private static string? NullIfEmpty(string value) => string.IsNullOrEmpty(value) ? null : value;
    private static bool EventsAvailable(FeatureAccessService access) => access.IsPublished(FeatureIds.EventsWorkspace) &&
        access.IsPublished(FeatureIds.InvestigationWorkspaces) && access.IsPublished(FeatureIds.ProcessListing) &&
        access.IsPublished(FeatureIds.SelectedProcessDetails) && EventSourceFamilyOwnershipCatalog.Definitions.Any(definition =>
            definition.Family != EventSourceFamilyKind.Runtime && access.IsPublished(definition.PresentationFeatureId));
    private static string RootFilter(AgentToolSession session) => string.IsNullOrEmpty(session.HostQueryIdentity.ExecutionRootId)
        ? "unrestricted" : session.Scope.ContextType == AiConversationContextType.Object ? "compatible" : "exact";
}
