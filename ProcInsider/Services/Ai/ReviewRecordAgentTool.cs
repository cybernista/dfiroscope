using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.Features.PersistenceWorkspace;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.Ai;

// A single complete authoritative original. No display projection or related query is evidence here.
internal sealed class ReviewRecordAgentTool(TelemetryProjectionService projection, FeatureAccessService access) : IAgentTool
{
    internal const string ToolId = "GetReviewRecord";
    private static readonly JsonElement OutputSchema = JsonDocument.Parse("""
        {"type":"object","properties":{
          "availability":{"type":"string"},"count":{"type":"integer","minimum":0,"maximum":1},
          "count_exact":{"type":"boolean"},"truncated":{"type":"boolean"},
          "coverage":{"type":"string","maxLength":2000},
          "omissions":{"type":"array","maxItems":16,"items":{"type":"string","maxLength":100}},
          "records":{"type":"array","maxItems":1,"items":{"type":"object","properties":{
            "reference_id":{"type":"string","maxLength":160},"kind":{"type":"string","maxLength":80},
            "record_json":{"type":"string","maxLength":64000}},
            "required":["reference_id","kind","record_json"],"additionalProperties":false}}},
          "required":["availability","count","count_exact","truncated","coverage","omissions","records"],"additionalProperties":false}
        """).RootElement.Clone();
    public AgentToolDescriptor Descriptor { get; } = new(ToolId, ToolId,
        "Read all captured fields of only the pinned exact original. No related activity or display preview.",
        [AgentPermission.EvidenceRead, AgentPermission.QueryLocal], [AgentDefinition.ReviewRecordSkillId],
        JsonDocument.Parse("""{"type":"object","properties":{},"additionalProperties":false}""").RootElement,
        OutputSchema);

    public Task<AgentToolResult> ExecuteAsync(AgentToolSession session, JsonElement arguments, CancellationToken token) =>
        Task.Run(async () =>
        {
            if (session.Target is not { } target) return Unavailable("review.no-target");
            var query = projection.ScopedQuery;
            object? original = null;
            AiEvidenceReference? checkedReference = null;
            if (target.Evidence.Kind == EvidenceReferenceKind.ProcessEntity)
            {
                var resolution = new AiEvidenceReferenceResolver(query).ResolveProcess(target, session.Scope.Identity.EvidenceSessionId);
                if (!resolution.IsResolved) return Unavailable("review.process." + resolution.Status.ToString().ToLowerInvariant());
                ProcessRecord? record;
                if (!string.IsNullOrWhiteSpace(target.Evidence.Id)) record = query.GetProcessByEntityId(target.Evidence.Id).Process;
                else
                {
                    var matches = query.GetProcessesByExactScope(new ExplorerScope { Kind = ExplorerScopeKind.AllProcesses,
                        ProcessKey = target.Process!.ProcessKey, CaseId = target.Identity.CaseId,
                        EvidenceSessionId = target.Identity.EvidenceSessionId, CaptureId = target.Identity.CaptureId,
                        SourceIdentityId = target.Identity.SourceIdentityId, HostId = target.Identity.HostId,
                        ExecutionRootId = target.Identity.ExecutionRootId }, 2);
                    record = matches.Count == 1 ? matches[0] : null;
                }
                if (record is null || !AiEvidenceReferenceResolver.Matches(target, record.ToProcessInfo()))
                    return Unavailable("review.process.identity-mismatch");
                try { original = query.GetProcessRecordFields(record, token); }
                catch (ArgumentOutOfRangeException error) when (error.ParamName == "recordSizeBytes")
                { return Unavailable("review.record-oversize"); }
                checkedReference = target;
            }
            else if (target.Evidence.Kind == EvidenceReferenceKind.Event && long.TryParse(target.Evidence.Id, out var sequence))
            {
                var scope = target.Identity;
                await using var reader = new EventsWorkspaceQueryService(access.Catalog, query,
                    new(scope.CaseId, scope.EvidenceSessionId, scope.CaptureId, 0, 0), () => true);
                var page = await reader.QueryAsync(new EventsQuery { PageSize = 2,
                    Filter = new EventsFilter { ExactEvent = new(scope.CaseId, scope.EvidenceSessionId,
                        scope.CaptureId, scope.SourceIdentityId, scope.HostId, target.SourceRunId, sequence) } }, token);
                if (page.Rows.Count != 1) return Unavailable("review.event.original-unavailable-or-ambiguous");
                try { original = await reader.GetEventRecordFieldsAsync(page.Rows[0].Native, token); }
                catch (ArgumentOutOfRangeException error) when (error.ParamName == "recordSizeBytes")
                { return Unavailable("review.record-oversize"); }
                checkedReference = EvidenceObjectAgentTools.EventContext(page.Rows[0].Native).Reference;
            }
            else if (target.Evidence.Kind == EvidenceReferenceKind.NetworkFlow && access.IsPublished(FeatureIds.NetworkWorkspace))
            {
                var row = EvidenceObjectAgentTools.FindEndpoint(query, target, token);
                if (row is null) return Unavailable("review.network.original-unavailable-or-ambiguous");
                var native = JsonSerializer.SerializeToNode(row.Observation.Native)!.AsObject();
                foreach (var name in new[] { "IsListener", "MembershipKey", "LocalDisplay", "RemoteDisplay" }) native.Remove(name);
                original = new { row.Observation.ObservationId, row.Observation.PollId, row.Observation.EpisodeId,
                    row.Observation.Kind, Native = native, row.Observation.Provenance, row.Poll,
                    row.FirstObservedUtc, row.LastObservedUtc, row.FirstAbsentUtc, row.FirstAbsentWindowStartUtc, row.HasContinuityGap };
                checkedReference = EvidenceObjectAgentTools.NetworkContext(row).Reference;
            }
            else if (target.Evidence.Kind == EvidenceReferenceKind.GenericArtifact && target.DataSource == "PersistenceVersions" && access.IsPublished(FeatureIds.Persistence))
            {
                var locator = JsonSerializer.Deserialize<PersistenceObjectReference>(target.Evidence.Id);
                if (locator is null || locator.Scope != target.Identity) return Unavailable("review.persistence.invalid-locator");
                var row = query.PersistenceQueries.Detail(locator, token).Row;
                var collection = row.Collection;
                // Collection results may contain sibling artifacts; retain only metadata and declared coverage diagnostics.
                var collectionMetadata = new { collection.EvidenceIdentity, collection.SourceRunId, collection.IngestionJobId,
                    collection.CollectionId, collection.StateGenerationId, collection.ExpectedPredecessorCollectionId,
                    collection.CollectionSequence, collection.Reason, collection.ResetReason,
                    collection.BoundaryAcquisitionId, collection.BoundaryPreviousPeriodId, collection.DeferredBaselineGenerationId,
                    collection.StartedUtc, collection.CompletedUtc,
                    Results = collection.Results.Select(result => new { result.CollectorId, result.Coverage, result.Status,
                        result.Duration, result.DiagnosticSummary }).ToArray() };
                object? versionMetadata = row.Version is { } version
                    ? new { version.CollectionId, version.StateGenerationId, version.CollectorId, version.Coverage,
                        version.ArtifactKey, version.Kind } : null;
                original = new { row.Scope, row.PartitionKey, row.ArtifactKey, row.Artifact,
                    Collection = collectionMetadata, Version = versionMetadata,
                    row.FirstObservedUtc, row.LastChangedUtc, row.LastConfirmedUtc, row.Stale };
                checkedReference = EvidenceObjectAgentTools.PersistenceContext(row).Reference;
            }
            if (original is null || checkedReference is null) return Unavailable("review.original-unavailable");
            if (checkedReference.CanonicalObjectKey != target.CanonicalObjectKey || checkedReference.Identity != target.Identity)
                return Unavailable("review.identity-mismatch");
            token.ThrowIfCancellationRequested();
            var reference = target with { CompactSnapshot = "", SnapshotProvenance = "" };
            var output = JsonSerializer.SerializeToElement(new { availability = "Available", count = 1, count_exact = true,
                truncated = false, coverage = "Complete captured fields of the exact selected record only; related evidence was not inspected. Recorded fields do not imply complete acquisition or current machine state.",
                omissions = Array.Empty<string>(), records = new[] { new { reference_id = reference.ReferenceId,
                    kind = reference.Evidence.Kind.ToString(), record_json = JsonSerializer.Serialize(original) } } });
            if (Encoding.UTF8.GetByteCount(output.GetRawText()) + JsonSerializer.SerializeToUtf8Bytes(new[] { reference }).Length > 64_000)
                return Unavailable("review.record-oversize");
            return new AgentToolResult(ToolId, AgentToolStatus.Available, output, [reference], 1, true, false, [], "review.exact-original");
        }, token);

    private static AgentToolResult Unavailable(string code) => new(ToolId, AgentToolStatus.Unavailable,
        JsonSerializer.SerializeToElement(new { availability = "Unavailable", count = 0, count_exact = false,
            truncated = false, coverage = "The complete exact selected original could not be admitted; no assessment is available.",
            omissions = Array.Empty<string>(), records = Array.Empty<object>() }), [], 0, false, false, [], code);
}
