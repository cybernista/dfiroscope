using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Analysis;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;
using static ProcInsider.Services.Ai.ProcessEvidenceAgentTools;

namespace ProcInsider.Services.Ai;

// Read adapters only: the existing snapshot query owners retain evidence access and provenance.
internal static class ArtifactEvidenceAgentTools
{
    private static readonly JsonElement InputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"reference_id":{"type":"string","minLength":1,"maxLength":160},
        "max_rows":{"type":"integer","minimum":1,"maximum":50},
        "offset":{"type":"integer","minimum":0,"maximum":2147483647}},"additionalProperties":false}
        """).RootElement.Clone();
    private static readonly JsonElement YaraInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"reference_id":{"type":"string","minLength":1,"maxLength":160},
        "scan_id":{"type":"string","minLength":1,"maxLength":160},
        "max_rows":{"type":"integer","minimum":1,"maximum":50}},"additionalProperties":false}
        """).RootElement.Clone();
    private static readonly JsonElement CurrentRiskInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"reference_id":{"type":"string","minLength":1,"maxLength":160},
        "max_rows":{"type":"integer","minimum":1,"maximum":50}},"additionalProperties":false}
        """).RootElement.Clone();
    private static readonly JsonElement ForensicInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"max_rows":{"type":"integer","minimum":1,"maximum":50},
        "offset":{"type":"integer","minimum":0,"maximum":1000000},
        "input_sha256":{"type":"string","minLength":64,"maxLength":64},
        "source_path_exact":{"type":"string","minLength":1,"maxLength":4096}},"additionalProperties":false}
        """).RootElement.Clone();
    private static readonly JsonElement PropertiesInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"reference_id":{"type":"string","minLength":1,"maxLength":160},
        "max_rows":{"type":"integer","minimum":1,"maximum":50},
        "offset":{"type":"integer","minimum":0,"maximum":1000000}},"additionalProperties":false}
        """).RootElement.Clone();
    private static readonly JsonElement OccurrencesInputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{"reference_id":{"type":"string","minLength":1,"maxLength":160},
        "max_rows":{"type":"integer","minimum":1,"maximum":50},
        "offset":{"type":"integer","minimum":0,"maximum":1000000},
        "field_offset":{"type":"integer","minimum":0,"maximum":1000000}},"additionalProperties":false}
        """).RootElement.Clone();

    internal static IEnumerable<IAgentTool> Create(TelemetryProjectionService projection, FeatureAccessService access)
    {
        foreach (var id in new[] { "GetFilesystemEvidence", "GetForensicEvidence", "GetForensicProperties", "GetForensicReadOccurrences", "GetModuleEvidence", "GetHandleEvidence", "GetPeEvidence",
            "GetSignatureEvidence", "GetDumpEvidence", "GetMemoryEvidence", "GetMemoryProcessEvidence", "GetVolatilityEvidence",
            "GetPcapEvidence", "GetZeekEvidence", "GetArtifactDetail", "GetYaraScans", "GetYaraScan", "GetReputationEvidence", "GetRiskEvidence" })
            yield return new ArtifactTool(projection, access, id);
    }

    internal static bool IsCheckedRelatedTool(IAgentTool tool, TelemetryProjectionService projection) =>
        tool is ArtifactTool adapter && ReferenceEquals(adapter.Projection, projection);

    internal static Task<AiObjectContext?> ResolveAsync(TelemetryProjectionService projection, FeatureAccessService access,
        AiEvidenceReference reference, CancellationToken token) => Task.Run(() =>
    {
        token.ThrowIfCancellationRequested();
        var owner = projection.ScopedQuery.ArtifactEvidenceQueries;
        if (reference.DataSource == "YaraAnalysisScans" && access.IsPublished(FeatureIds.AiAssistance))
        {
            var read = projection.ScopedQuery.YaraAnalysisQueries.GetExactScanForReference(reference.Identity, reference.SourceRunId, reference.Evidence.Id);
            if (read.Scan is not { } stored || read.State != YaraAnalysisReadState.Available) return null;
            var feature = stored.Result.Target.Kind switch { YaraScanTargetKind.FileArtifact => FeatureIds.FilesystemArtifacts,
                YaraScanTargetKind.MemoryDump => FeatureIds.DumpsAndPeAnalysis, _ => FeatureIds.SystemMemoryAndVolatility };
            var actual = Reference(stored.Result.Target.EvidenceIdentity, EvidenceReferenceKind.GenericArtifact,
                stored.Result.ScanId, "YaraAnalysisScans", stored.Result.Target.SourceRunId, stored.PayloadHashSha256, stored.Result.CompletedUtc);
            return access.IsPublished(feature) && Matches(actual, reference) ? Context(actual,
                new Dictionary<string, string> { ["Availability"] = stored.Result.Availability.ToString(), ["Matches"] = stored.Result.Matches.Count.ToString(CultureInfo.InvariantCulture),
                    ["Detail coverage"] = "Exact persisted scan. GetArtifactDetail pages stored normalized fields, tags and metadata. Byte matches are not persisted and unavailable." }) : null;
        }
        if (reference.DataSource == "ReputationProcessAttributions" && access.IsPublished(FeatureIds.AiAssistance))
        {
            var read = projection.ScopedQuery.ReputationAttributionQueries.GetByAttributionHash(reference.Evidence.Id);
            if (read.State != ReputationAttributionReadState.Available || read.Attributions.Count != 1) return null;
            var row = read.Attributions[0];
            var actual = Reference(row.TargetRequest.EvidenceIdentity, EvidenceReferenceKind.GenericArtifact, row.AttributionHashSha256,
                "ReputationProcessAttributions", row.TargetRequest.SourceRunId, row.AttributionHashSha256, row.Receipt.CompletedUtc);
            return Matches(actual, reference) ? Context(actual, new Dictionary<string, string> { ["Availability"] = row.Receipt.Result.Availability.ToString(),
                ["Correlation"] = row.CorrelationState.ToString(), ["Detail coverage"] = "Exact persisted attribution. GetArtifactDetail pages stored normalized provider receipt fields." }) : null;
        }
        if (reference.DataSource == "ProcessRiskProjection" && access.IsPublished(FeatureIds.ProcessRiskScore) && reference.Process is { } processAlias)
        {
            var process = projection.GetProcessByEntityId(processAlias.ProcessEntityId);
            if (process is null || ProcessReference(process).Identity != reference.Identity || process.GetUniqueKey() != processAlias.ProcessKey) return null;
            var read = projection.ScopedQuery.ProcessRiskProjectionQueries.GetCurrentProjection(process.ProcessEntityId, process.GetUniqueKey(), token);
            if (read.ReadState != ProcessRiskProjectionReadState.Available || read.Projection is null) return null;
            var actual = Reference(read.Projection.EvidenceIdentity, EvidenceReferenceKind.GenericArtifact, read.EvaluationId,
                "ProcessRiskProjection", "", read.InputIdentityHash, read.Projection.ProjectedUtc) with { Process = processAlias };
            return Matches(actual, reference) ? Context(actual, new Dictionary<string, string> { ["State"] = read.Projection.State.ToString(),
                ["Score"] = Convert.ToString(read.Projection.Score, CultureInfo.InvariantCulture) ?? "<null>", ["Detail coverage"] = "Exact current stored projection; GetArtifactDetail pages stored contributors/coverage." }) : null;
        }
        if (reference.DataSource == "ForensicArtifactResults" && access.IsPublished(FeatureIds.FilesystemArtifacts))
        {
            var detail = owner.GetForensicArtifactResultDetail(reference.Evidence.Id, token);
            if (detail.Availability != ForensicArtifactResultAvailability.Available || detail.Result is not { } result) return null;
            var canonical = Reference(result.Scope, EvidenceReferenceKind.GenericArtifact, result.ArtifactId,
                "ForensicArtifactResults", result.SourceRunId, result.ResultSha256, result.PrimaryTimeUtc);
            return Matches(canonical, reference) ? new AiObjectContext(canonical,
                new Dictionary<string, string> { ["Name"] = System.Text.Encoding.UTF8.GetByteCount(result.Name) <= 2000 ? result.Name : "Name omitted by bound",
                    ["Parser"] = result.ParserId, ["Result hash"] = result.ResultSha256,
                    ["Detail coverage"] = "GetForensicProperties pages native properties; GetForensicReadOccurrences pages validated stored read history and source-run metadata." },
                new Dictionary<string, string> { ["Exact object"] = canonical.ReferenceId }, ["Native stored properties"]) : null;
        }
        var toolId = reference.DataSource switch { "FilesystemArtifacts" => "GetFilesystemEvidence", "Modules" => "GetModuleEvidence",
            "Handles" => "GetHandleEvidence", "PeAnalyses" => "GetPeEvidence", "AuthenticodeVerifications" => "GetSignatureEvidence",
            "MemoryDumps" => "GetDumpEvidence", "MemoryImages" => "GetMemoryEvidence", "MemoryProcesses" => "GetMemoryProcessEvidence",
            "VolatilityPluginRuns" => "GetVolatilityEvidence", "NetworkCaptures" => "GetPcapEvidence", "ZeekNetworkArtifacts" => "GetZeekEvidence", _ => "" };
        if (!TryFamily(toolId, out var family) || !access.IsPublished(FamilyFeature(family))) return null;
        var page = owner.ReadPage(new(family, reference.Identity, PageSize: 2, ExactEvidenceId: reference.Evidence.Id), token);
        if (!page.Supported || page.Rows.Count != 1) return null;
        var artifactRow = page.Rows[0];
        var resolved = Reference(artifactRow.Scope, artifactRow.Evidence.Kind, artifactRow.Evidence.Id, artifactRow.DataSource, artifactRow.SourceRunId, artifactRow.SourceRevision, artifactRow.TimestampUtc);
        if (!Matches(resolved, reference)) return null;
        var fields = artifactRow.Fields.Where(field => System.Text.Encoding.UTF8.GetByteCount(field.Value) <= 2000).ToDictionary(field => field.Key, field => field.Value);
        if (string.IsNullOrWhiteSpace(artifactRow.SourceRunId)) fields["Source run provenance"] = "Not recorded; exact stored row identity/revision and admitted snapshot binding retained.";
        fields["Detail coverage"] = "Bounded native stored metadata only; oversized fields, artifact bytes and external output files omitted.";
        return new AiObjectContext(resolved, fields, new Dictionary<string, string> { ["Exact object"] = resolved.ReferenceId }, []);
    }, token);

    private static AiObjectContext Context(AiEvidenceReference reference, IReadOnlyDictionary<string, string> fields) =>
        new(reference, fields, new Dictionary<string, string> { ["Exact object"] = reference.ReferenceId }, []);

    private static bool Matches(AiEvidenceReference actual, AiEvidenceReference expected) => actual.Identity == expected.Identity &&
        actual.CanonicalObjectKey == expected.CanonicalObjectKey && actual.SourceRunId == expected.SourceRunId && actual.SourceRevision == expected.SourceRevision;
    private static bool TryFamily(string id, out ArtifactEvidenceFamily family)
    {
        var mapped = id switch { "GetFilesystemEvidence" => ArtifactEvidenceFamily.Filesystem, "GetModuleEvidence" => ArtifactEvidenceFamily.Module,
            "GetHandleEvidence" => ArtifactEvidenceFamily.Handle, "GetPeEvidence" => ArtifactEvidenceFamily.Pe, "GetSignatureEvidence" => ArtifactEvidenceFamily.Signature,
            "GetDumpEvidence" => ArtifactEvidenceFamily.Dump, "GetMemoryEvidence" => ArtifactEvidenceFamily.MemoryImage,
            "GetMemoryProcessEvidence" => ArtifactEvidenceFamily.MemoryProcess, "GetVolatilityEvidence" => ArtifactEvidenceFamily.Volatility,
            "GetPcapEvidence" => ArtifactEvidenceFamily.Pcap, "GetZeekEvidence" => ArtifactEvidenceFamily.Zeek, _ => (ArtifactEvidenceFamily?)null };
        family = mapped ?? default;
        return mapped.HasValue;
    }
    private static FeatureId FamilyFeature(ArtifactEvidenceFamily family) => family switch
    {
        ArtifactEvidenceFamily.Filesystem => FeatureIds.FilesystemArtifacts,
        ArtifactEvidenceFamily.Module or ArtifactEvidenceFamily.Handle => FeatureIds.ModulesAndHandles,
        ArtifactEvidenceFamily.Pe or ArtifactEvidenceFamily.Signature or ArtifactEvidenceFamily.Dump => FeatureIds.DumpsAndPeAnalysis,
        ArtifactEvidenceFamily.MemoryImage or ArtifactEvidenceFamily.MemoryProcess or ArtifactEvidenceFamily.Volatility => FeatureIds.SystemMemoryAndVolatility,
        _ => FeatureIds.NetworkAndZeek
    };

    private sealed class ArtifactTool : IAgentTool, IAgentToolAvailability
    {
        internal TelemetryProjectionService Projection { get; }
        private readonly FeatureAccessService _access;
        public AgentToolDescriptor Descriptor { get; }
        internal ArtifactTool(TelemetryProjectionService projection, FeatureAccessService access, string id)
        {
            Projection = projection;
            _access = access;
            Descriptor = new(id, id, id switch
                {
                    "GetYaraScan" => "Read one exact persisted YARA scan for the checked artifact and source run. scan_id selects normalized stored analysis only. No scanning or file access.",
                    "GetYaraScans" => "Discover and page persisted YARA scan references for one checked file, dump or memory image and exact source run. offset continues stored scans; no scanning or file access.",
                    "GetArtifactDetail" => "Page source-native stored columns or normalized fields for one exact checked artifact, YARA scan, reputation attribution or current risk projection. offset is native field position; maximum16 fields,2000 UTF-8 bytes each. Oversized fields omitted whole. External bytes/files unavailable.",
                    "GetRiskEvidence" => "Read the one current stored risk projection for the checked durable process. Exact current-object count; historical projection continuation unavailable in this owner. GetArtifactDetail pages native fields/contributors. No recomputation.",
                    "GetForensicEvidence" => "Count and page stored structured forensic results in the checked scope. Optional input_sha256 (hex, normalized uppercase) and source_path_exact (case-sensitive recorded spelling) filters combine with AND before count/paging. Path is metadata only; no file access. offset continues matching rows.",
                    "GetForensicProperties" => "Read a bounded page of native properties for one checked structured forensic result and revision. offset continues property rows; maximum 16 fields per page, 2000 UTF-8 bytes per value. Oversized names/values omitted whole. GetForensicReadOccurrences reads history; no file access.",
                    "GetForensicReadOccurrences" => "Read validated stored read occurrences for one checked immutable forensic result. offset selects one occurrence; field_offset pages its native read metadata, relation/receipt IDs and source-run metadata/status. Maximum 16 fields, 2000 UTF-8 bytes per value; whole-field omissions explicit. No file access.",
                    _ => $"Read stored {id[3..]} within the checked evidence boundary. Pages filter scope before exact count/paging; offset continues rows. No acquisition, analysis execution or file access."
                },
                [AgentPermission.EvidenceRead, AgentPermission.QueryLocal],
                [AgentDefinition.ExplainObjectSkillId, AgentDefinition.QueryEvidenceSkillId, AgentDefinition.InvestigateProcessSkillId],
                id switch { "GetYaraScan" => YaraInputSchema, "GetForensicEvidence" => ForensicInputSchema,
                    "GetForensicProperties" => PropertiesInputSchema, "GetForensicReadOccurrences" => OccurrencesInputSchema, "GetRiskEvidence" => CurrentRiskInputSchema, _ => InputSchema }, OutputSchema);
        }

        public Task<AgentToolResult> ExecuteAsync(AgentToolSession session, JsonElement arguments, CancellationToken token) =>
            Task.Run(() => Read(session, arguments, token), token);

        public bool IsAvailableFor(AgentToolSession session) => _access.IsPublished(OwnerFeature()) &&
            (Descriptor.Id is not ("GetYaraScan" or "GetYaraScans") || _access.IsPublished(FeatureIds.FilesystemArtifacts) ||
                _access.IsPublished(FeatureIds.DumpsAndPeAnalysis) || _access.IsPublished(FeatureIds.SystemMemoryAndVolatility));

        private FeatureId OwnerFeature() => Descriptor.Id switch
        {
            "GetFilesystemEvidence" or "GetForensicEvidence" or "GetForensicProperties" or "GetForensicReadOccurrences" => FeatureIds.FilesystemArtifacts,
            "GetModuleEvidence" or "GetHandleEvidence" => FeatureIds.ModulesAndHandles,
            "GetPeEvidence" or "GetSignatureEvidence" or "GetDumpEvidence" => FeatureIds.DumpsAndPeAnalysis,
            "GetMemoryEvidence" or "GetMemoryProcessEvidence" or "GetVolatilityEvidence" => FeatureIds.SystemMemoryAndVolatility,
            "GetPcapEvidence" or "GetZeekEvidence" => FeatureIds.NetworkAndZeek,
            "GetRiskEvidence" => FeatureIds.ProcessRiskScore,
            _ => FeatureIds.AiAssistance
        };

        private AgentToolResult Read(AgentToolSession session, JsonElement arguments, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var id = Descriptor.Id;
            if (!IsAvailableFor(session)) return State(id, "policy_unavailable");
            try
            {
                var owner = Projection.ScopedQuery;
                var target = session.ResolveCheckedReference(arguments);
                var max = Maximum(arguments);
                if (id == "GetForensicEvidence") return ForensicPage(owner.ArtifactEvidenceQueries, session, arguments, max, token);
                if (id == "GetForensicProperties") return Forensic(owner.ArtifactEvidenceQueries, session, target, arguments, max, token);
                if (id == "GetForensicReadOccurrences") return ForensicOccurrences(owner.ArtifactEvidenceQueries, session, target, arguments, max, token);
                if (id == "GetYaraScan") return Yara(owner.YaraAnalysisQueries, session, target, arguments, max);
                if (id == "GetYaraScans") return YaraPage(owner.YaraAnalysisQueries, session, target, arguments, max, token);
                if (id == "GetArtifactDetail") return Detail(owner.ArtifactEvidenceQueries, session, target, arguments, max, token);
                if (id == "GetRiskEvidence" && arguments.TryGetProperty("offset", out _))
                    return Result(id, AgentToolStatus.InvalidRequest, [], [], 0, false, false, [], "artifact.continuation-unavailable");
                if (id is "GetModuleEvidence" or "GetHandleEvidence" or "GetPeEvidence" or "GetSignatureEvidence" or "GetDumpEvidence" or "GetReputationEvidence" or "GetRiskEvidence")
                {
                    if (target?.Evidence.Kind != EvidenceReferenceKind.ProcessEntity) return State(id, "unsupported_target");
                    var process = Projection.GetProcessByEntityId(target.Evidence.Id);
                    if (process is null || ProcessReference(process).Identity != target.Identity ||
                        !session.ReadBoundaryAdmits(target.Identity) ||
                        target.Process is { ProcessKey.Length: > 0 } alias && alias.ProcessKey != process.GetUniqueKey())
                        return State(id, "original_unavailable");
                    var entity = process.ProcessEntityId;
                    if (id != "GetReputationEvidence" && id != "GetRiskEvidence")
                        return PagedFamily(owner.ArtifactEvidenceQueries, session, arguments, max, entity, token);
                    if (id == "GetReputationEvidence") return Reputation(owner.ReputationAttributionQueries, session, target.Identity, entity, arguments, max, token);
                    return Risk(owner.ProcessRiskProjectionQueries, process, token);
                }
                return PagedFamily(owner.ArtifactEvidenceQueries, session, arguments, max, "", token);
            }
            catch (OperationCanceledException) { throw; }
            catch (SqliteException error) when (error.SqliteErrorCode == 1 && error.Message.Contains("no such table", StringComparison.OrdinalIgnoreCase))
            { return State(id, "unsupported"); }
            catch (Exception) { return State(id, "read_failed"); }
        }

        private AgentToolResult PagedFamily(IArtifactEvidenceQueryService owner, AgentToolSession session, JsonElement arguments,
            int max, string entity, CancellationToken token)
        {
            if (!TryFamily(Descriptor.Id, out var family)) return State(Descriptor.Id, "unsupported");
            var offset = arguments.TryGetProperty("offset", out var value) ? value.GetInt64() : 0;
            var scope = session.HostQueryIdentity;
            var page = owner.ReadPage(new(family, scope, entity, offset, max), token);
            if (!page.Supported) return State(Descriptor.Id, "unsupported");
            if (page.Rows.Any(row => !session.ReadBoundaryAdmits(row.Scope))) return State(Descriptor.Id, "scope_mismatch");
            if (page.MatchingRows == 0) return State(Descriptor.Id, "not_collected", "No qualified stored rows in the checked scope; acquisition completeness is unknown.");
            var rows = page.Rows.Select(row => Record(Reference(row.Scope, row.Evidence.Kind, row.Evidence.Id, row.DataSource,
                row.SourceRunId, row.SourceRevision, row.TimestampUtc), row.Fields.Select(field => (field.Key, (object?)field.Value)).ToArray())).ToArray();
            var omissions = new List<string>();
            if (rows.Any(row => row.Record.Fields.Any(field => field.Name == "Context omissions"))) omissions.Add("field-omitted.snapshot");
            if (page.MissingSourceRunRows > 0) omissions.Add("source-run-provenance-not-recorded");
            if (offset > 0) omissions.Add("preceding-rows-outside-page");
            if (offset + rows.Length < page.MatchingRows) omissions.Add("following-rows-outside-page");
            var next = rows.Length > 0 && offset + rows.Length < page.MatchingRows ? offset + rows.Length : (long?)null;
            if (next > int.MaxValue) { next = null; omissions.Add("continuation-offset-limit"); }
            var result = Result(Descriptor.Id, AgentToolStatus.Available, rows.Select(row => row.Record).ToArray(), rows.Select(row => row.Reference).ToArray(),
                (int)Math.Min(int.MaxValue, page.MatchingRows), page.MatchingRows <= int.MaxValue, page.MatchingRows > rows.Length || omissions.Count > 0,
                omissions, "artifact.available", JsonSerializer.Serialize(new { count_basis = "Exact count of qualified stored rows after scope/process filtering; not acquisition completeness",
                    scope, process_entity_id = entity, offset, returned_count = rows.Length, next_offset = next, page_bound = max,
                    missing_source_run_rows = page.MissingSourceRunRows, provenance = page.MissingSourceRunRows > 0 ? "partial: source run not recorded for some scoped stored rows; no run inferred" : "recorded source run IDs",
                    detail = "Native metadata summary fields only, bounded to 2000 UTF-8 bytes; oversized fields omitted whole. GetArtifactDetail pages all native stored columns. Artifact bytes/external files unavailable." }));
            return WithEmittedContinuation(result, offset, page.MatchingRows, int.MaxValue, page.Rows.Count);
        }

        private AgentToolResult Detail(IArtifactEvidenceQueryService owner, AgentToolSession session, AiEvidenceReference? target,
            JsonElement arguments, int max, CancellationToken token)
        {
            if (target is null || !session.ReadBoundaryAdmits(target.Identity)) return State(Descriptor.Id, "unsupported_target");
            if (target.DataSource is "YaraAnalysisScans" or "ReputationProcessAttributions" or "ProcessRiskProjection")
                return NormalizedDetail(session, target, arguments, max, token);
            var id = target.DataSource switch { "FilesystemArtifacts" => "GetFilesystemEvidence", "Modules" => "GetModuleEvidence",
                "Handles" => "GetHandleEvidence", "PeAnalyses" => "GetPeEvidence", "AuthenticodeVerifications" => "GetSignatureEvidence",
                "MemoryDumps" => "GetDumpEvidence", "MemoryImages" => "GetMemoryEvidence", "MemoryProcesses" => "GetMemoryProcessEvidence",
                "VolatilityPluginRuns" => "GetVolatilityEvidence", "NetworkCaptures" => "GetPcapEvidence", "ZeekNetworkArtifacts" => "GetZeekEvidence", _ => "" };
            if (!TryFamily(id, out var family)) return State(Descriptor.Id, "unsupported_target");
            if (!_access.IsPublished(FamilyFeature(family))) return State(Descriptor.Id, "policy_unavailable");
            var offset = arguments.TryGetProperty("offset", out var value) ? value.GetInt32() : 0;
            var page = owner.ReadPage(new(family, target.Identity, PageSize: 1, ExactEvidenceId: target.Evidence.Id,
                IncludeAllStoredFields: true, FieldOffset: offset, FieldPageSize: Math.Min(max, 16)), token);
            if (!page.Supported) return State(Descriptor.Id, "unsupported");
            if (page.Rows.Count != 1) return State(Descriptor.Id, "original_unavailable");
            var row = page.Rows[0];
            var canonical = Reference(row.Scope, row.Evidence.Kind, row.Evidence.Id, row.DataSource, row.SourceRunId, row.SourceRevision, row.TimestampUtc);
            if (!Matches(canonical, target)) return State(Descriptor.Id, "original_unavailable");
            var record = Record(canonical, row.Fields.Select(field => (field.Key, (object?)field.Value)).ToArray());
            var omissions = new List<string> { "external-artifact-content-unavailable" };
            if (string.IsNullOrWhiteSpace(row.SourceRunId)) omissions.Add("source-run-provenance-not-recorded");
            if (record.Record.Fields.Any(field => field.Name == "Context omissions")) omissions.Add("stored-field-omitted-by-bound");
            if (offset > 0) omissions.Add("preceding-fields-outside-page");
            if (offset + row.Fields.Count < row.StoredFieldCount) omissions.Add("following-fields-outside-page");
            return Result(Descriptor.Id, AgentToolStatus.Available, [record.Record], [canonical], row.StoredFieldCount, true,
                row.StoredFieldCount > row.Fields.Count || omissions.Contains("stored-field-omitted-by-bound") || string.IsNullOrWhiteSpace(row.SourceRunId), omissions, "artifact.available",
                JsonSerializer.Serialize(new { count_basis = "Exact native stored column count for checked object; not record count",
                    offset, returned_field_rows = row.Fields.Count, next_offset = row.Fields.Count > 0 && offset + row.Fields.Count < row.StoredFieldCount ? offset + row.Fields.Count : (int?)null,
                    page_bound = Math.Min(max, 16), field_value_utf8_bound = 2000,
                    source_run_provenance = string.IsNullOrWhiteSpace(row.SourceRunId) ? "not_recorded; no run inferred" : "recorded",
                    detail = "All stored columns including native JSON and legacy filesystem properties are pageable. Oversized names/values omitted whole; continuation includes omitted fields. Null is <null>; empty string is <empty string>. External output files/artifact bytes unavailable; no file access." }));
        }

        private AgentToolResult NormalizedDetail(AgentToolSession session, AiEvidenceReference target, JsonElement arguments, int max, CancellationToken token)
        {
            object native; AiEvidenceReference canonical; string unavailable;
            if (target.DataSource == "YaraAnalysisScans")
            {
                var read = Projection.ScopedQuery.YaraAnalysisQueries.GetExactScanForReference(target.Identity, target.SourceRunId, target.Evidence.Id);
                if (read.State != YaraAnalysisReadState.Available || read.Scan is not { } scan) return State(Descriptor.Id,
                    read.State == YaraAnalysisReadState.Unsupported ? "unsupported" : read.State == YaraAnalysisReadState.NotFound ? "original_unavailable" : "read_failed");
                var feature = scan.Result.Target.Kind switch { YaraScanTargetKind.FileArtifact => FeatureIds.FilesystemArtifacts,
                    YaraScanTargetKind.MemoryDump => FeatureIds.DumpsAndPeAnalysis, _ => FeatureIds.SystemMemoryAndVolatility };
                if (!_access.IsPublished(feature)) return State(Descriptor.Id, "policy_unavailable");
                canonical = Reference(scan.Result.Target.EvidenceIdentity, EvidenceReferenceKind.GenericArtifact, scan.Result.ScanId,
                    "YaraAnalysisScans", scan.Result.Target.SourceRunId, scan.PayloadHashSha256, scan.Result.CompletedUtc);
                native = scan; unavailable = "StringMatches are not persisted by this schema and are unavailable; empty reconstructed arrays do not prove no byte matches. Target bytes, external output and admission profile contents unavailable.";
            }
            else if (target.DataSource == "ReputationProcessAttributions")
            {
                var read = Projection.ScopedQuery.ReputationAttributionQueries.GetByAttributionHash(target.Evidence.Id);
                if (read.State != ReputationAttributionReadState.Available || read.Attributions.Count != 1) return State(Descriptor.Id,
                    read.State == ReputationAttributionReadState.Unsupported ? "unsupported" : "original_unavailable");
                var row = read.Attributions[0];
                canonical = Reference(row.TargetRequest.EvidenceIdentity, EvidenceReferenceKind.GenericArtifact, row.AttributionHashSha256,
                    "ReputationProcessAttributions", row.TargetRequest.SourceRunId, row.AttributionHashSha256, row.Receipt.CompletedUtc);
                native = row; unavailable = "Exact persisted normalized attribution and receipt; external provider state and raw response bytes unavailable. No provider lookup.";
            }
            else
            {
                if (!_access.IsPublished(FeatureIds.ProcessRiskScore)) return State(Descriptor.Id, "policy_unavailable");
                if (target.Process is not { } alias) return State(Descriptor.Id, "original_unavailable");
                var process = Projection.GetProcessByEntityId(alias.ProcessEntityId);
                if (process is null || ProcessReference(process).Identity != target.Identity || process.GetUniqueKey() != alias.ProcessKey)
                    return State(Descriptor.Id, "original_unavailable");
                var read = Projection.ScopedQuery.ProcessRiskProjectionQueries.GetCurrentProjection(process.ProcessEntityId, process.GetUniqueKey(), token);
                if (read.ReadState != ProcessRiskProjectionReadState.Available || read.Projection is null) return State(Descriptor.Id, "original_unavailable");
                canonical = Reference(read.Projection.EvidenceIdentity, EvidenceReferenceKind.GenericArtifact, read.EvaluationId,
                    "ProcessRiskProjection", "", read.InputIdentityHash, read.Projection.ProjectedUtc) with { Process = alias };
                native = read; unavailable = "Exact stored current derived projection, including available contributors and coverage. Primary evidence remains separate. No recomputation.";
            }
            if (!Matches(canonical, target) || !session.ReadBoundaryAdmits(canonical.Identity)) return State(Descriptor.Id, "original_unavailable");
            token.ThrowIfCancellationRequested();
            var fields = NativeFields(JsonSerializer.SerializeToElement(native), "").ToArray();
            var offset = arguments.TryGetProperty("offset", out var value) ? value.GetInt32() : 0;
            var selected = fields.Skip(offset).Take(Math.Min(max, 16)).ToArray();
            var record = Record(canonical, selected);
            var omissions = new List<string> { "external-content-unavailable" };
            if (record.Record.Fields.Any(field => field.Name == "Context omissions")) omissions.Add("stored-field-omitted-by-bound");
            if (offset > 0) omissions.Add("preceding-fields-outside-page");
            if (offset + selected.Length < fields.Length) omissions.Add("following-fields-outside-page");
            return Result(Descriptor.Id, AgentToolStatus.Available, [record.Record], [canonical], fields.Length, true,
                fields.Length > selected.Length || omissions.Contains("stored-field-omitted-by-bound"), omissions, "artifact.available",
                JsonSerializer.Serialize(new { count_basis = "Exact native normalized scalar/empty-container field count; not evidence count", offset,
                    returned_field_rows = selected.Length, next_offset = selected.Length > 0 && offset + selected.Length < fields.Length ? offset + selected.Length : (int?)null,
                    page_bound = Math.Min(max, 16), field_name_bound = 80, field_value_utf8_bound = 2000,
                    detail = "Native JSON paths and array positions preserve field identity/order/types. Oversized fields omitted whole; continuation includes omitted fields. " + unavailable }));
        }

        private static IEnumerable<(string Name, object? Value)> NativeFields(JsonElement value, string path)
        {
            if (value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Any())
            {
                foreach (var field in value.EnumerateObject())
                    foreach (var row in NativeFields(field.Value, path.Length == 0 ? field.Name : path + "." + field.Name)) yield return row;
            }
            else if (value.ValueKind == JsonValueKind.Array && value.GetArrayLength() > 0)
            {
                var index = 0;
                foreach (var item in value.EnumerateArray())
                    foreach (var row in NativeFields(item, path + "[" + index++ + "]")) yield return row;
            }
            else yield return (path, value.ValueKind == JsonValueKind.String ? "String: " + (value.GetString()!.Length == 0 ? "<empty string>" : value.GetString()) :
                value.ValueKind + ": " + (value.ValueKind == JsonValueKind.Null ? "<null>" : value.GetRawText()));
        }

        private AgentToolResult Forensic(IArtifactEvidenceQueryService owner, AgentToolSession session, AiEvidenceReference? target, JsonElement arguments, int max, CancellationToken token)
        {
            if (target is null || target.Evidence.Kind is not (EvidenceReferenceKind.FileArtifact or EvidenceReferenceKind.GenericArtifact) ||
                target.DataSource != "ForensicArtifactResults" || !session.ReadBoundaryAdmits(target.Identity)) return State(Descriptor.Id, "unsupported_target");
            var detail = owner.GetForensicArtifactResultDetail(target.Evidence.Id, token);
            if (detail.Availability != ForensicArtifactResultAvailability.Available)
                return State(Descriptor.Id, detail.Availability == ForensicArtifactResultAvailability.Failed ? "read_failed" : "unsupported");
            var row = detail.Result;
            if (row is null) return State(Descriptor.Id, "not_collected");
            if (row.Scope != target.Identity || row.SourceRunId != target.SourceRunId ||
                target.SourceRevision.Length > 0 && target.SourceRevision != row.ResultSha256) return State(Descriptor.Id, "original_unavailable");
            var offset = arguments.TryGetProperty("offset", out var offsetNode) ? offsetNode.GetInt32() : 0;
            var page = owner.GetForensicArtifactResultProperties(row.ArtifactId, new(Offset: offset, PageSize: Math.Min(max, 16)), token);
            if (page.Availability != ForensicArtifactResultAvailability.Available) return State(Descriptor.Id, "read_failed");
            var reference = Reference(row.Scope, EvidenceReferenceKind.GenericArtifact, row.ArtifactId, "ForensicArtifactResults", row.SourceRunId, row.ResultSha256, row.PrimaryTimeUtc);
            var fields = new List<ToolField>(); var omissions = new List<string>();
            foreach (var property in page.Rows)
            {
                if (property.Name.Length > 80) { if (omissions.Count < 16) omissions.Add("property-name-omitted-by-bound"); continue; }
                var before = omissions.Count;
                var value = property.Value is null ? "<null>" : property.Value.Length == 0 ? "<empty string>" : property.Value;
                AddField(fields, omissions, property.Name, property.ValueType + ": " + value);
                if (omissions.Count > before) omissions[^1] = "property-value-omitted-by-bound";
            }
            if (offset > 0 && omissions.Count < 16) omissions.Add("preceding-properties-outside-page");
            if (offset + page.Rows.Count < page.MatchingRows && omissions.Count < 16) omissions.Add("following-properties-outside-page");
            if (omissions.Count < 16) omissions.Add("read-occurrence-history-omitted");
            var following = offset + page.Rows.Count < page.MatchingRows && page.Rows.Count > 0;
            var next = following && offset + page.Rows.Count <= 1000000 ? offset + page.Rows.Count : (int?)null;
            if (following && next is null && omissions.Count < 16) omissions.Add("continuation-offset-limit");
            return Result(Descriptor.Id, AgentToolStatus.Available, [new(reference.ReferenceId, "GenericArtifact", fields)], [reference],
                (int)Math.Min(int.MaxValue, page.MatchingRows), page.MatchingRows <= int.MaxValue,
                page.MatchingRows > page.Rows.Count || fields.Count < page.Rows.Count, omissions, "artifact.available",
                JsonSerializer.Serialize(new { count_basis = "Exact native property count for the checked immutable result; not artifact count",
                    offset, returned_property_rows = page.Rows.Count, returned_fields = fields.Count, next_offset = next,
                    page_bound = Math.Min(max, 16), maximum_offset = 1000000, field_name_bound = 80, field_value_utf8_bound = 2000,
                    values = "Native JSON value type prefix; explicit null/empty string markers; stored value formatting retained",
                    omissions = "Oversized names/values omitted whole; read history available through GetForensicReadOccurrences. Continuation advances native property rows, including omitted fields." }));
        }

        private AgentToolResult ForensicOccurrences(IArtifactEvidenceQueryService owner, AgentToolSession session,
            AiEvidenceReference? target, JsonElement arguments, int max, CancellationToken token)
        {
            if (target is null || target.DataSource != "ForensicArtifactResults" || !session.ReadBoundaryAdmits(target.Identity))
                return State(Descriptor.Id, "unsupported_target");
            var offset = arguments.TryGetProperty("offset", out var position) ? position.GetInt32() : 0;
            var fieldOffset = arguments.TryGetProperty("field_offset", out var fieldPosition) ? fieldPosition.GetInt32() : 0;
            var page = owner.GetForensicArtifactResultReadOccurrences(target.Evidence.Id, offset, 1, token);
            if (page.Availability != ForensicArtifactResultAvailability.Available) return State(Descriptor.Id, "read_failed");
            if (page.Result is not { } result) return State(Descriptor.Id, "not_collected");
            var reference = Reference(result.Scope, EvidenceReferenceKind.GenericArtifact, result.ArtifactId,
                "ForensicArtifactResults", result.SourceRunId, result.ResultSha256, result.PrimaryTimeUtc);
            if (!Matches(reference, target)) return State(Descriptor.Id, "original_unavailable");
            var occurrence = page.ReadOccurrences.SingleOrDefault();
            (string Name, object? Value)[] nativeFields = occurrence is null ? [] : NativeFields(JsonSerializer.SerializeToElement(new { Result = result, Occurrence = occurrence }), "").ToArray();
            var selected = nativeFields.Skip(fieldOffset).Take(Math.Min(max, 16)).ToArray();
            var omissions = new List<string> { "external-content-unavailable" };
            var fields = new List<ToolField>();
            foreach (var field in selected)
            {
                if (field.Name.Length > 80) { if (omissions.Count < 16) omissions.Add("stored-field-name-omitted-by-bound"); continue; }
                AddField(fields, omissions, field.Name, Convert.ToString(field.Value, CultureInfo.InvariantCulture));
            }
            if (fieldOffset > 0) omissions.Add("preceding-fields-outside-page");
            var moreFields = fieldOffset + selected.Length < nativeFields.Length;
            if (moreFields) omissions.Add("following-fields-outside-page");
            var following = occurrence is not null && offset + 1 < page.ReadOccurrenceCount;
            if (following) omissions.Add("following-occurrences-outside-page");
            if (following && offset == 1000000) omissions.Add("continuation-offset-limit");
            return Result(Descriptor.Id, AgentToolStatus.Available, occurrence is null ? [] : [new(reference.ReferenceId, "GenericArtifact", fields)],
                occurrence is null ? [] : [reference], (int)Math.Min(int.MaxValue, page.ReadOccurrenceCount), page.ReadOccurrenceCount <= int.MaxValue,
                moreFields || following || fields.Count < selected.Length, omissions, "artifact.available",
                JsonSerializer.Serialize(new { count_basis = "Exact stored lineage occurrence count for the checked immutable result; original and selected receipts validated; not returned-field count",
                    offset, returned_occurrences = occurrence is null ? 0 : 1,
                    next_offset = following && offset < 1000000 ? offset + 1 : (int?)null,
                    field_offset = fieldOffset, field_count = nativeFields.Length, returned_field_rows = selected.Length, returned_fields = fields.Count,
                    next_field_offset = moreFields && selected.Length > 0 ? fieldOffset + selected.Length : (int?)null,
                    maximum_offset = 1000000, page_bound = 1, field_page_bound = Math.Min(max, 16), field_name_bound = 80, field_value_utf8_bound = 2000,
                    detail = "Read all field pages before advancing occurrence offset; reset field_offset for the next occurrence. Native result/read metadata and source-run status/metadata are preserved; oversized fields omitted whole. Receipt hash and raw/relation IDs bind each validated occurrence. External original file unavailable." }));
        }

        private AgentToolResult ForensicPage(IArtifactEvidenceQueryService owner, AgentToolSession session, JsonElement arguments, int max, CancellationToken token)
        {
            var scope = session.HostQueryIdentity;
            if (string.IsNullOrWhiteSpace(scope.HostId) || string.IsNullOrWhiteSpace(scope.CaptureId)) return State(Descriptor.Id, "unsupported_target");
            var selectors = new List<ForensicArtifactResultGreenSelector>();
            foreach (var (facet, value) in new[] { (ForensicArtifactResultScopeFacet.Case, scope.CaseId),
                (ForensicArtifactResultScopeFacet.EvidenceSession, scope.EvidenceSessionId), (ForensicArtifactResultScopeFacet.Capture, scope.CaptureId),
                (ForensicArtifactResultScopeFacet.SourceIdentity, scope.SourceIdentityId), (ForensicArtifactResultScopeFacet.Host, scope.HostId),
                (ForensicArtifactResultScopeFacet.ExecutionRoot, scope.ExecutionRootId) })
                // Case/session/capture/host are exact even when empty. Only source/root have
                // policy-authorized empty wildcards; Object related reads deliberately clear source.
                if (facet is not (ForensicArtifactResultScopeFacet.SourceIdentity or ForensicArtifactResultScopeFacet.ExecutionRoot) ||
                    !string.IsNullOrEmpty(value)) selectors.Add(new(facet, value));
            var offset = arguments.TryGetProperty("offset", out var offsetNode) ? offsetNode.GetInt32() : 0;
            var hash = arguments.TryGetProperty("input_sha256", out var hashNode) ? hashNode.GetString() : null;
            if (hash is not null && (hash.Length != 64 || hash.Any(value => !char.IsAsciiHexDigit(value))))
                return Result(Descriptor.Id, AgentToolStatus.InvalidRequest, [], [], 0, false, false, [], "artifact.invalid-sha256");
            var path = arguments.TryGetProperty("source_path_exact", out var pathNode) ? pathNode.GetString() : null;
            var filters = new List<ForensicArtifactResultColumnFilter>();
            if (hash is not null) filters.Add(new(ForensicArtifactResultColumn.InputSha256, new() { AllValues = false, Values = [hash.ToUpperInvariant()] }));
            if (path is not null) filters.Add(new(ForensicArtifactResultColumn.SourcePath, new() { AllValues = false, Values = [path] }));
            var page = owner.QueryForensicArtifactResults(new(GreenSelectors: selectors, Filters: filters, Offset: offset, PageSize: max), token);
            if (page.Availability != ForensicArtifactResultAvailability.Available) return State(Descriptor.Id,
                page.Availability == ForensicArtifactResultAvailability.Failed ? "read_failed" : "unsupported");
            if (page.Rows.Any(row => !session.ReadBoundaryAdmits(row.Scope))) return State(Descriptor.Id, "scope_mismatch");
            if (page.Rows.Count == 0 && page.ViewCount == 0 && filters.Count == 0) return State(Descriptor.Id, "not_collected", "No stored structured forensic results within the checked scope; collection completeness is unknown.");
            var rows = page.Rows.Select(row => Record(Reference(row.Scope, EvidenceReferenceKind.GenericArtifact, row.ArtifactId,
                "ForensicArtifactResults", row.SourceRunId, row.ResultSha256, row.PrimaryTimeUtc),
                ("Name", row.Name), ("Type", row.ArtifactType), ("Category", row.Category), ("Summary", row.Summary),
                ("Parser", row.ParserId), ("Parser version", row.ParserVersion), ("Input hash", row.InputSha256),
                ("Source path metadata", row.SourcePath), ("Result hash", row.ResultSha256))).ToArray();
            var fieldsOmitted = rows.Any(row => row.Record.Fields.Any(field => field.Name == "Context omissions"));
            var omissions = new List<string>();
            if (fieldsOmitted) omissions.Add("field-omitted.snapshot");
            if (offset > 0) omissions.Add("preceding-results-outside-page");
            if (offset + page.Rows.Count < page.ViewCount) omissions.Add("following-results-outside-page");
            var following = offset + page.Rows.Count < page.ViewCount && page.Rows.Count > 0;
            var next = following && offset + page.Rows.Count <= 1000000 ? offset + page.Rows.Count : (int?)null;
            if (following && next is null) omissions.Add("continuation-offset-limit");
            var result = Result(Descriptor.Id, AgentToolStatus.Available, rows.Select(row => row.Record).ToArray(), rows.Select(row => row.Reference).ToArray(),
                (int)Math.Min(int.MaxValue, page.ViewCount), page.ViewCount <= int.MaxValue, fieldsOmitted || page.ViewCount > page.Rows.Count,
                omissions, "artifact.available", JsonSerializer.Serialize(new { count_basis = "Exact scoped stored structured-result count after AND selectors; not acquisition completeness",
                    input_sha256_applied = hash is not null, source_path_exact_applied = path is not null,
                    hash_semantics = "Hex normalized uppercase; exact stored input hash", path_semantics = "Exact case-sensitive recorded source path metadata; no file access",
                    offset, returned_count = page.Rows.Count, next_offset = next, page_bound = max, maximum_offset = 1000000,
                    detail = "List fields bounded to 2000 UTF-8 bytes; oversized fields omitted whole. Use checked result reference with GetForensicProperties for native property pages." }));
            return WithEmittedContinuation(result, offset, page.ViewCount, 1000000, page.Rows.Count);
        }

        private AgentToolResult Yara(IYaraAnalysisQueryService owner, AgentToolSession session, AiEvidenceReference? target, JsonElement arguments, int max)
        {
            if (target is null || !session.ReadBoundaryAdmits(target.Identity) || string.IsNullOrWhiteSpace(target.SourceRunId)) return State(Descriptor.Id, "unsupported_target");
            if (target.DataSource == "YaraAnalysisScans")
            {
                var stored = owner.GetExactScanForReference(target.Identity, target.SourceRunId, target.Evidence.Id);
                if (stored.Scan is null || stored.Scan.PayloadHashSha256 != target.SourceRevision) return State(Descriptor.Id, "original_unavailable");
                var native = stored.Scan.Result.Target;
                target = Reference(target.Identity, native.EvidenceReference.Kind, native.EvidenceReference.Id, "", target.SourceRunId, "", null);
                arguments = JsonSerializer.SerializeToElement(new { scan_id = stored.Scan.Result.ScanId });
            }
            var kind = target.Evidence.Kind switch { EvidenceReferenceKind.FileArtifact => YaraScanTargetKind.FileArtifact,
                EvidenceReferenceKind.MemoryDump => YaraScanTargetKind.MemoryDump, EvidenceReferenceKind.MemoryImage => YaraScanTargetKind.MemoryImageRegion, _ => YaraScanTargetKind.Unknown };
            if (kind == YaraScanTargetKind.Unknown) return State(Descriptor.Id, "unsupported_target");
            var targetFeature = kind switch { YaraScanTargetKind.FileArtifact => FeatureIds.FilesystemArtifacts,
                YaraScanTargetKind.MemoryDump => FeatureIds.DumpsAndPeAnalysis, _ => FeatureIds.SystemMemoryAndVolatility };
            if (!_access.IsPublished(targetFeature)) return State(Descriptor.Id, "policy_unavailable");
            if (!arguments.TryGetProperty("scan_id", out var scanId)) return State(Descriptor.Id, "scan_id_required");
            var read = owner.GetExactScan(new() { ScanId = scanId.GetString()!, EvidenceIdentity = target.Identity,
                SourceRunId = target.SourceRunId, TargetKind = kind, EvidenceReference = target.Evidence });
            if (read.State != YaraAnalysisReadState.Available || read.Scan is null) return State(Descriptor.Id,
                read.State == YaraAnalysisReadState.Unsupported ? "unsupported" : read.State == YaraAnalysisReadState.NotFound ? "not_collected" : "read_failed");
            var scan = read.Scan.Result;
            var fields = new List<ToolField>(); var omissions = new List<string>();
            AddField(fields, omissions, "Scan ID", scan.ScanId); AddField(fields, omissions, "Availability", scan.Availability.ToString());
            AddField(fields, omissions, "Matches", scan.Matches.Count.ToString(CultureInfo.InvariantCulture));
            foreach (var match in scan.Matches.Take(Math.Min(max, 12))) AddField(fields, omissions, "Rule", match.RuleNamespace + ":" + match.RuleId);
            var reference = Reference(target.Identity, EvidenceReferenceKind.GenericArtifact, scan.ScanId, "YaraAnalysisScans", target.SourceRunId, read.Scan.PayloadHashSha256, scan.CompletedUtc);
            return Result(Descriptor.Id, AgentToolStatus.Available, [new(reference.ReferenceId, "GenericArtifact", fields)], [reference], scan.Matches.Count,
                !scan.IsTruncated, scan.IsTruncated || scan.Matches.Count > Math.Min(max, 12), omissions, "artifact.available",
                "Exact persisted scan; observed_count counts persisted rule matches. Source truncation and bounded rule preview do not establish complete target coverage. GetArtifactDetail pages stored tags/metadata; byte matches are not persisted and unavailable.");
        }

        private AgentToolResult YaraPage(IYaraAnalysisQueryService owner, AgentToolSession session, AiEvidenceReference? target,
            JsonElement arguments, int max, CancellationToken token)
        {
            if (target is null || !session.ReadBoundaryAdmits(target.Identity) || string.IsNullOrWhiteSpace(target.SourceRunId)) return State(Descriptor.Id, "unsupported_target");
            var kind = target.Evidence.Kind switch { EvidenceReferenceKind.FileArtifact => YaraScanTargetKind.FileArtifact,
                EvidenceReferenceKind.MemoryDump => YaraScanTargetKind.MemoryDump, EvidenceReferenceKind.MemoryImage => YaraScanTargetKind.MemoryImageRegion, _ => YaraScanTargetKind.Unknown };
            if (kind == YaraScanTargetKind.Unknown) return State(Descriptor.Id, "unsupported_target");
            var feature = kind switch { YaraScanTargetKind.FileArtifact => FeatureIds.FilesystemArtifacts,
                YaraScanTargetKind.MemoryDump => FeatureIds.DumpsAndPeAnalysis, _ => FeatureIds.SystemMemoryAndVolatility };
            if (!_access.IsPublished(feature)) return State(Descriptor.Id, "policy_unavailable");
            var offset = arguments.TryGetProperty("offset", out var value) ? value.GetInt64() : 0;
            var page = owner.GetScanPage(new() { EvidenceIdentity = target.Identity, SourceRunId = target.SourceRunId,
                TargetKind = kind, EvidenceReference = target.Evidence }, offset, max, token);
            if (page.State != YaraAnalysisReadState.Available) return State(Descriptor.Id,
                page.State == YaraAnalysisReadState.Unsupported ? "unsupported" : "read_failed");
            if (page.MatchingRows == 0) return State(Descriptor.Id, "not_collected");
            var rows = page.Rows.Select(row => Record(Reference(target.Identity, EvidenceReferenceKind.GenericArtifact,
                row.ScanId, "YaraAnalysisScans", target.SourceRunId, row.PayloadHashSha256, row.CompletedUtc),
                ("Scan ID", row.ScanId), ("Availability", row.Availability), ("Completed UTC", row.CompletedUtc))).ToArray();
            var result = Result(Descriptor.Id, AgentToolStatus.Available, rows.Select(row => row.Record).ToArray(), rows.Select(row => row.Reference).ToArray(),
                (int)Math.Min(int.MaxValue, page.MatchingRows), page.MatchingRows <= int.MaxValue, page.MatchingRows > rows.Length,
                page.MatchingRows > rows.Length ? ["scans-outside-page"] : [], "artifact.available",
                JsonSerializer.Serialize(new { offset, returned_count = rows.Length, next_offset = (long?)null,
                    detail = "Exact stored target/run scan count, not target acquisition completeness. Use checked scan reference with GetYaraScan." }));
            return WithEmittedContinuation(result, offset, page.MatchingRows, int.MaxValue, rows.Length);
        }

        private AgentToolResult Reputation(IReputationAttributionQueryService owner, AgentToolSession session, EvidenceIdentity scope,
            string entity, JsonElement arguments, int max, CancellationToken token)
        {
            var offset = arguments.TryGetProperty("offset", out var value) ? value.GetInt64() : 0;
            var read = owner.GetProcessPage(scope, entity, offset, max, token);
            if (read.State != ReputationAttributionReadState.Available) return State(Descriptor.Id, read.State switch
                { ReputationAttributionReadState.Unsupported => "unsupported", ReputationAttributionReadState.NotFound => "not_collected", _ => "read_failed" });
            if (read.Rows.Any(row => !session.ReadBoundaryAdmits(row.TargetRequest.EvidenceIdentity))) return State(Descriptor.Id, "scope_mismatch");
            if (read.MatchingRows == 0) return State(Descriptor.Id, "not_collected");
            var rows = read.Rows.Select(row =>
            {
                var reference = Reference(row.TargetRequest.EvidenceIdentity, EvidenceReferenceKind.GenericArtifact, row.AttributionHashSha256,
                    "ReputationProcessAttributions", row.TargetRequest.SourceRunId, row.AttributionHashSha256, row.Receipt.CompletedUtc);
                return Record(reference, ("Indicator", row.TargetRequest.Indicator.Value), ("Source kind", row.SourceKind),
                    ("Provider", row.Receipt.Result.Provider.ProviderId), ("Availability", row.Receipt.Result.Availability), ("Correlation", row.CorrelationState));
            }).ToArray();
            var result = Result(Descriptor.Id, AgentToolStatus.Available, rows.Select(row => row.Record).ToArray(), rows.Select(row => row.Reference).ToArray(),
                (int)Math.Min(int.MaxValue, read.MatchingRows), read.MatchingRows <= int.MaxValue, read.MatchingRows > rows.Length,
                read.MatchingRows > rows.Length ? ["attributions-outside-page"] : [], "artifact.available",
                JsonSerializer.Serialize(new { count_basis = "Exact scoped stored attribution count for checked durable process; not provider/acquisition completeness",
                    offset, returned_count = rows.Length, next_offset = (long?)null, page_bound = max,
                    detail = "Native summary fields; GetArtifactDetail pages exact normalized attribution/provider receipt. No provider lookup." }));
            return WithEmittedContinuation(result, offset, read.MatchingRows, int.MaxValue, rows.Length);
        }

        private AgentToolResult Risk(IProcessRiskProjectionQueryService owner, ProcessInfo process, CancellationToken token)
        {
            var read = owner.GetCurrentProjection(process.ProcessEntityId, process.GetUniqueKey(), token);
            if (read.ReadState != ProcessRiskProjectionReadState.Available || read.Projection is null) return State(Descriptor.Id, read.ReadState switch
                { ProcessRiskProjectionReadState.Unsupported => "unsupported", ProcessRiskProjectionReadState.NotReady => "not_collected", ProcessRiskProjectionReadState.Stale => "stale", _ => "read_failed" });
            if (read.ProcessEntityId != process.ProcessEntityId || read.Projection.ProcessEntityId != process.ProcessEntityId ||
                read.Projection.EvidenceIdentity != ProcessReference(process).Identity || string.IsNullOrWhiteSpace(read.EvaluationId) || string.IsNullOrWhiteSpace(read.InputIdentityHash)) return State(Descriptor.Id, "read_failed");
            var reference = Reference(read.Projection.EvidenceIdentity, EvidenceReferenceKind.GenericArtifact, read.EvaluationId,
                "ProcessRiskProjection", "", read.InputIdentityHash, read.Projection.ProjectedUtc) with { Process = ProcessReference(process).Process };
            var row = Record(reference, ("State", read.Projection.State), ("Score", read.Projection.Score), ("Band", read.Projection.Band),
                ("Confidence", read.Projection.Confidence), ("Coverage", read.Projection.Coverage), ("Mapper", read.MapperId),
                ("Mapper version", read.MapperVersion), ("Aggregation version", read.AggregationVersion), ("Input hash", read.InputIdentityHash));
            return Result(Descriptor.Id, AgentToolStatus.Available, [row.Record], [reference], 1, true, false, [], "artifact.available",
                "Exact persisted rebuildable risk projection, distinct from primary evidence. Score is not a malware verdict; GetArtifactDetail pages stored contributors/coverage.");
        }
    }

    private static AgentToolResult State(string id, string state, string coverage = "")
    {
        var result = Result(id, AgentToolStatus.Unavailable, [], [], 0, false, false, [state], "artifact." + state,
            coverage.Length > 0 ? coverage : "availability=" + state + "; no acquisition or analysis execution performed.");
        var output = JsonNode.Parse(result.Output.GetRawText())!.AsObject();
        output["availability"] = state;
        return result with { Output = JsonSerializer.SerializeToElement(output) };
    }
    private static AgentToolResult WithEmittedContinuation(AgentToolResult result, long offset, long matching, long maximumOffset, int sourceRows)
    {
        var returned = result.Evidence.Count;
        var next = returned > 0 && offset + returned < matching && offset + returned <= maximumOffset ? offset + returned : (long?)null;
        var output = JsonNode.Parse(result.Output.GetRawText())!.AsObject();
        var coverage = JsonNode.Parse(output["coverage"]!.GetValue<string>())!.AsObject();
        coverage["returned_count"] = returned;
        coverage["next_offset"] = next;
        coverage["source_page_rows"] = sourceRows;
        coverage["continuation_basis"] = "Actual emitted records; whole records dropped by output bound remain reachable on the next page";
        output["coverage"] = coverage.ToJsonString();
        return result with { Output = JsonSerializer.SerializeToElement(output) };
    }
    private sealed record ArtifactRow(AiEvidenceReference Reference, ToolRecord Record);
    private static ArtifactRow Record(AiEvidenceReference reference, params (string Name, object? Value)[] values)
    {
        var fields = new List<ToolField>(); var omissions = new List<string>();
        foreach (var (name, value) in values)
        {
            if (name.Length > 80) { omissions.Add("field-name-omitted-by-bound"); continue; }
            AddField(fields, omissions, name, Convert.ToString(value, CultureInfo.InvariantCulture));
        }
        if (omissions.Count > 0)
        {
            if (fields.Count == 16) fields.RemoveAt(15);
            fields.Add(new("Context omissions", "Empty or oversized fields omitted whole."));
        }
        return new(reference, new(reference.ReferenceId, reference.Evidence.Kind.ToString(), fields));
    }
    private static AiEvidenceReference Reference(EvidenceIdentity scope, EvidenceReferenceKind kind, string key, string table,
        string run, string revision, DateTime? at)
    {
        var reference = new AiEvidenceReference("", scope, new(kind, key), table, run, revision, at?.ToUniversalTime(),
            "Recorded " + kind, "", "");
        return reference with { ReferenceId = StableReferenceId(reference) };
    }
}
