using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentImportJobHandler : IAgentJobHandler
{
    private readonly AgentStagingWriter _writer;
    private readonly TelemetryArchiveService _archiveService;
    private readonly LegacyProcessSnapshotEvidenceSourceAdapter _processAdapter;
    private readonly CaptureCompatibilityAssessment _targetCompatibility;

    public AgentImportJobHandler(
        AgentStagingWriter writer,
        TelemetryArchiveService archiveService,
        LegacyProcessSnapshotEvidenceSourceAdapter processAdapter,
        CaptureCompatibilityAssessment targetCompatibility)
    {
        _writer = writer;
        _archiveService = archiveService;
        _processAdapter = processAdapter;
        _targetCompatibility = targetCompatibility;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        CaptureCompatibilityPolicy.EnsureAllowed(
            _targetCompatibility,
            CaptureOpenCapability.WritePrimaryEvidence);
        var parameters = context.Request.ReadParameters<ImportParameters>();
        if (string.IsNullOrWhiteSpace(parameters.ArchivePath))
        {
            throw new InvalidOperationException("Import job did not include an archive path.");
        }

        await context.ReportProgressAsync(0, 1, "Reading staged telemetry archive.").ConfigureAwait(false);
        var (snapshot, result) = await _archiveService.ReadSnapshotAsync(parameters.ArchivePath, context.CancellationToken).ConfigureAwait(false);
        await context.ReportProgressAsync(0, 1, $"Importing {result.ProcessCount} processes, {result.EventCount} events, {result.ModuleCount} modules, and {result.HandleCount} handles.").ConfigureAwait(false);
        var publisher = new LegacyProcessCollectingPublisher(_processAdapter.Descriptor.MaxBatchRowCount);
        var adapterResult = await _processAdapter.ExecuteAsync(
            new EvidenceSourceAdapterRequest
            {
                SourceRunId = context.SourceRunId,
                IngestionJobId = context.Request.JobId,
                EvidenceIdentity = context.Request.EvidenceIdentity,
                InputPath = parameters.ArchivePath,
                Payload = new LegacyProcessSnapshotEvidenceSourceInput { Processes = snapshot.Processes },
                AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    LegacyProcessSnapshotEvidenceSourceAdapter.ArchivePrerequisite
                }
            },
            publisher,
            null,
            context.CancellationToken).ConfigureAwait(false);
        if (adapterResult.State == EvidenceSourceCompletionState.Failed)
        {
            throw new InvalidOperationException("Legacy archive process adapter failed.");
        }
        snapshot.Processes = publisher.Processes;
        await _writer.ReplaceWithSnapshotAsync(snapshot, context.CancellationToken).ConfigureAwait(false);
        context.SetSourceRunCompletion(adapterResult.State.ToString(), JsonSerializer.Serialize(new
        {
            adapterId = _processAdapter.Descriptor.AdapterId,
            adapterVersion = _processAdapter.Descriptor.AdapterVersion,
            completionState = adapterResult.State.ToString(),
            adapterResult.ReceivedCount,
            adapterResult.NormalizedCount,
            persistedProcessCount = publisher.Processes.Count,
            adapterResult.Diagnostics
        }));
        await context.ReportProgressAsync(1, 1, $"Imported staged telemetry from {result.ArchivePath}.").ConfigureAwait(false);
    }

    private sealed class LegacyProcessCollectingPublisher(int maxBatchRowCount) : IEvidenceSourcePublisher
    {
        private readonly List<ProcessRecord> _processes = [];

        public int MaxBatchRowCount { get; } = Math.Max(1, maxBatchRowCount);

        public IReadOnlyList<ProcessRecord> Processes => _processes;

        public ValueTask<EvidenceSourcePublishResult> PublishAsync(
            EvidenceSourceEmissionBatch batch,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AgentEvidenceSourcePublisher.ValidateBatch(batch, MaxBatchRowCount);
            if (batch.Processes.Count > 0 || batch.Events.Count > 0 || batch.FilesystemArtifacts.Count > 0 ||
                batch.VolatilityPluginRuns.Count > 0 || batch.MemoryProcesses.Count > 0 || batch.Relations.Count > 0)
            {
                throw new InvalidOperationException("The legacy archive collector accepts only normalized process observations.");
            }

            _processes.AddRange(batch.ProcessObservations.Select(observation => observation.Fields));
            return ValueTask.FromResult(new EvidenceSourcePublishResult
            {
                PersistedRowCount = batch.ProcessObservations.Count + batch.ProcessAliases.Count
            });
        }
    }

    private sealed record ImportParameters
    {
        public string ArchivePath { get; init; } = string.Empty;
    }
}
