using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Models;

namespace ProcInsider.Services.EvidenceSources;

public sealed class NetworkEndpointEvidenceSourceAdapter : EvidenceSourceAdapterBase<NetworkEndpointSourceInput>
{
    public const string Id = "procinsider.os-network-endpoints";
    public const string Version = "2.0.0";
    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id, AdapterVersion = Version, DisplayName = "Windows OS endpoint inventory",
        Description = "Immutable IP Helper endpoint observations and complete per-family poll coverage.",
        Category = EvidenceSourceCategory.PrimaryAcquisition,
        Capabilities = EvidenceSourceCapability.ProcessObservations | EvidenceSourceCapability.IndependentArtifacts | EvidenceSourceCapability.LiveCollection | EvidenceSourceCapability.IncrementalPublication,
        MaxBatchRowCount = 256
    };
    protected override void ValidateInput(NetworkEndpointSourceInput input, List<string> errors)
    {
        if (input.Observations.Count != input.Poll.ExpectedRows || input.Observations.Any(r => r.PollId != input.Poll.PollId || r.Native.Family != input.Poll.Family))
            errors.Add("Endpoint payload does not match its family completion marker.");
        if (input.Poll.Outcome != EndpointPollOutcome.Complete && input.Observations.Count != 0)
            errors.Add("Failed coverage cannot publish endpoint observations.");
        foreach(var owner in input.FreshOwners ?? [])
            if(owner.Ownership!=EndpointOwnership.VerifiedLifetime || owner.Metadata==null || owner.ProcessStartUtc is not {Kind:DateTimeKind.Utc} start ||
                owner.Metadata.WindowStartUtc.Kind!=DateTimeKind.Utc || owner.Metadata.WindowEndUtc.Kind!=DateTimeKind.Utc ||
                start>owner.Metadata.WindowStartUtc || owner.Metadata.WindowStartUtc>owner.Metadata.WindowEndUtc || owner.Metadata.WindowEndUtc>input.Poll.WindowEndUtc ||
                owner.ProcessEntityId!=ProcessEntityIdentity.CreateExact(input.Poll.Scope.CaseId,input.Poll.Scope.EvidenceSessionId,
                    input.Poll.Scope.HostId,input.Poll.Scope.ExecutionRootId,owner.ProcessId,start))
                errors.Add("Fresh process metadata must retain its exact scoped lifetime and original valid native read window.");
    }
    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(EvidenceSourceAdapterRequest request,
        NetworkEndpointSourceInput input, IEvidenceSourcePublisher publisher, IProgress<EvidenceSourceProgress>? progress, CancellationToken token)
    {
        if (input.Poll.SourceRunId != request.SourceRunId || input.Poll.IngestionJobId != request.IngestionJobId || input.Poll.Scope != request.EvidenceIdentity)
            throw new InvalidOperationException("Endpoint poll provenance differs from its source execution.");
        var sequence = 0;
        long persisted = 0;
        var limit=GetEffectiveBatchRowLimit(Descriptor,publisher);
        var observations=new List<ProcessObservation>();var aliasesPending=new List<ProcessAlias>();
        async ValueTask FlushProcesses()
        {
            if(observations.Count+aliasesPending.Count==0)return;
            var written=await publisher.PublishAsync(new EvidenceSourceEmissionBatch {SourceRunId=request.SourceRunId,
                IngestionJobId=request.IngestionJobId,Sequence=++sequence,ProcessObservations=observations.ToArray(),ProcessAliases=aliasesPending.ToArray()},token).ConfigureAwait(false);
            persisted+=written.PersistedRowCount;observations.Clear();aliasesPending.Clear();
        }
        // Fresh native reads are independent of sparse endpoint appearance/absence records.
        // Each process/alias is durable before the endpoint visibility marker; these writes are not one atomic transaction.
        try
        {
        foreach (var owner in input.FreshOwners ?? [])
        {
            token.ThrowIfCancellationRequested();
            if (owner.Ownership != EndpointOwnership.VerifiedLifetime || owner.Metadata == null || owner.ProcessStartUtc == null)
                throw new InvalidOperationException("A fresh owner requires a verified native lifetime and metadata window.");
            var metadata = owner.Metadata;
            var record = new ProcessRecord { ProcessEntityId = owner.ProcessEntityId, ProcessId = owner.ProcessId,
                ProcessKey = $"{owner.ProcessId}_{owner.ProcessStartUtc.Value.Ticks}", StartTimeUtc = owner.ProcessStartUtc,
                ProcessName = metadata.ProcessName ?? "<not available>", ProcessPath = metadata.ImagePath ?? "<not available>",
                CommandLine = metadata.CommandLine ?? "<not available>", Status = ProcessStatus.Running,
                ParentProcessId = -1, SessionId = -1, CpuUsage = -1, MemoryUsageBytes = -1, ModuleCaptureStatus = ArtifactCaptureStatus.NotAvailable,
                HandleCaptureStatus = ArtifactCaptureStatus.NotAvailable, LastSource = "Windows OS endpoint native process read" };
            var item = ProcessObservationAdapterFactory.CreateFromProcessRecord(record, request.EvidenceIdentity,
                request.SourceRunId, request.IngestionJobId, Id, Version, metadata.WindowEndUtc,
                ProcessObservationKind.NetworkEndpointSnapshot, ProcessEntityResolutionStrategy.ExactOrSourceAlias,
                rawRecordId: owner.ProcessEntityId + "|" + metadata.WindowStartUtc.Ticks,
                metadataJson: System.Text.Json.JsonSerializer.Serialize(metadata));
            // The shared factory's ordinary adapter default must not replace this registered native source identity.
            item.Observation.Fields.SourceIdentityId=request.EvidenceIdentity.SourceIdentityId;
            var ownerAliases=item.Aliases.Select(alias=>alias with{SourceIdentityId=request.EvidenceIdentity.SourceIdentityId}).ToArray();
            if (item.Observation.ProcessEntityId != owner.ProcessEntityId) throw new InvalidOperationException("Endpoint and process identity differ.");
            foreach (var field in new[] { "ParentProcessId", "SessionId", "CpuUsage", "MemoryUsageBytes", "TreeDepth",
                "ModuleCaptureStatus", "ModuleCount", "ModuleLastCapturedUtc", "ModuleCaptureError",
                "HandleCaptureStatus", "HandleCount", "HandleLastCapturedUtc", "HandleCaptureError", "EndTimeUtc" })
                item.Observation.FieldStates[field] = ProcessObservationValueState.NotCollected;
            item.Observation.FieldStates["ProcessName"] = State(metadata.NameState);
            item.Observation.FieldStates["ProcessPath"] = State(metadata.ImageState);
            item.Observation.FieldStates["CommandLine"] = State(metadata.CommandLineState);
            // The process writer also derives this alias; keep the complete deduplicated unit in one transaction.
            if(1+ownerAliases.Length>limit)
                throw new InvalidOperationException("The publisher row limit cannot fit a process observation and its scoped aliases; no endpoint completion is published.");
            if(observations.Count+aliasesPending.Count+1+ownerAliases.Length>limit)await FlushProcesses().ConfigureAwait(false);
            observations.Add(item.Observation);
            aliasesPending.AddRange(ownerAliases);
        }
        await FlushProcesses().ConfigureAwait(false);
        foreach (var chunk in input.Observations.Chunk(GetEffectiveBatchRowLimit(Descriptor, publisher)))
        {
            var result = await publisher.PublishAsync(new EvidenceSourceEmissionBatch { SourceRunId = request.SourceRunId,
                IngestionJobId = request.IngestionJobId, Sequence = ++sequence, NetworkEndpointObservations = chunk,
                Identities=chunk.Select(r=>new EvidenceSourceEmissionIdentity { EvidenceKind=ProcInsider.Models.EvidenceReferenceKind.GenericArtifact,
                    EvidenceId=r.ObservationId,ExternalIdentity=r.PollId+"|"+r.EpisodeId,DeduplicationKey=Id+"|"+request.SourceRunId+"|"+r.ObservationId }).ToArray() }, token).ConfigureAwait(false);
            persisted += result.PersistedRowCount;
        }
        // Only this final immutable marker permits reads to treat preceding payload as complete evidence.
        var marker = await publisher.PublishAsync(new EvidenceSourceEmissionBatch { SourceRunId = request.SourceRunId,
            IngestionJobId = request.IngestionJobId, Sequence = ++sequence, IsFinalBatch = true, NetworkEndpointPolls = [input.Poll],
            Identities=[new EvidenceSourceEmissionIdentity{EvidenceKind=ProcInsider.Models.EvidenceReferenceKind.GenericArtifact,EvidenceId=input.Poll.PollId,
                ExternalIdentity=input.Poll.PollId,DeduplicationKey=Id+"|"+request.SourceRunId+"|"+input.Poll.PollId}] }, token).ConfigureAwait(false);
        return new EvidenceSourceExecutionResult { State = input.Poll.Outcome == EndpointPollOutcome.Complete ? EvidenceSourceCompletionState.Completed : EvidenceSourceCompletionState.Partial,
            ReceivedCount = input.Observations.Count, NormalizedCount = input.Observations.Count, PersistedCount = persisted + marker.PersistedRowCount };
        }
        catch(EvidenceSourcePublishException error)
        {
            return new EvidenceSourceExecutionResult {State=EvidenceSourceCompletionState.Partial,ReceivedCount=input.Observations.Count,
                NormalizedCount=input.Observations.Count,PersistedCount=persisted+error.PersistedRowCount};
        }
    }
    private static ProcessObservationValueState State(EndpointMetadataState state) => state switch
    {
        EndpointMetadataState.Available => ProcessObservationValueState.Available,
        EndpointMetadataState.AccessDenied => ProcessObservationValueState.AccessDenied,
        EndpointMetadataState.NotRecorded => ProcessObservationValueState.NotCollected,
        _ => ProcessObservationValueState.Unavailable
    };
}
