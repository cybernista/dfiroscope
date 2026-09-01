using System.Text.Json;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentProcessMonitorImportJobHandler : IAgentJobHandler
{
    private readonly ProcessMonitorService _processMonitorService;
    private readonly ProcessMonitorEvidenceSourceAdapter _adapter;
    private readonly IEvidenceSourcePublisher _publisher;

    public AgentProcessMonitorImportJobHandler(
        ProcessMonitorService processMonitorService,
        ProcessMonitorEvidenceSourceAdapter adapter,
        IEvidenceSourcePublisher publisher)
    {
        _processMonitorService = processMonitorService;
        _adapter = adapter;
        _publisher = publisher;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = context.Request.ReadParameters<ProcessMonitorImportParameters>();
        if (string.IsNullOrWhiteSpace(parameters.InputPath))
        {
            throw new InvalidOperationException("Process Monitor import requires a CSV or PML path.");
        }

        await context.ReportProgressAsync(0, -1, $"Importing Process Monitor output from {parameters.InputPath}.").ConfigureAwait(false);
        var result = await _processMonitorService.ImportAsync(
                new ProcessMonitorImportOptions
                {
                    InputPath = parameters.InputPath,
                    ProcmonPath = parameters.ProcmonPath,
                    CaptureId = FirstNonEmpty(parameters.CaptureId, context.Request.CaptureId),
                    OutputDirectory = parameters.OutputDirectory,
                    MaxRows = parameters.MaxRows
                },
                context.Request.JobId,
                context.CancellationToken)
            .ConfigureAwait(false);

        var adapterResult = await _adapter.ExecuteAsync(
            new EvidenceSourceAdapterRequest
            {
                SourceRunId = context.SourceRunId,
                IngestionJobId = context.Request.JobId,
                EvidenceIdentity = context.Request.EvidenceIdentity,
                InputPath = parameters.InputPath,
                InputHash = context.Request.InputHash,
                Payload = new ProcessMonitorEvidenceSourceInput { Result = result },
                AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ProcessMonitorEvidenceSourceAdapter.ParserPrerequisite
                }
            },
            _publisher,
            null,
            context.CancellationToken).ConfigureAwait(false);
        context.SetSourceRunCompletion(adapterResult.State.ToString(), JsonSerializer.Serialize(new
        {
            adapterId = _adapter.Descriptor.AdapterId,
            adapterVersion = _adapter.Descriptor.AdapterVersion,
            completionState = adapterResult.State.ToString(),
            adapterResult.ReceivedCount,
            adapterResult.NormalizedCount,
            adapterResult.PersistedCount,
            adapterResult.DuplicateCount,
            adapterResult.FailedCount,
            adapterResult.Diagnostics
        }));
        await context.ReportProgressAsync(
                result.TotalRows,
                result.TotalRows,
                $"Process Monitor adapter {adapterResult.State}: {adapterResult.PersistedCount:N0} durable row(s), " +
                $"{adapterResult.DuplicateCount:N0} replay duplicate(s), {adapterResult.FailedCount:N0} failure(s).")
            .ConfigureAwait(false);
        if (adapterResult.State == EvidenceSourceCompletionState.Failed)
        {
            throw new InvalidOperationException("Process Monitor evidence adapter failed.");
        }
    }

    private static string FirstNonEmpty(params string[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private sealed record ProcessMonitorImportParameters
    {
        public string InputPath { get; init; } = string.Empty;
        public string ProcmonPath { get; init; } = string.Empty;
        public string CaptureId { get; init; } = string.Empty;
        public string OutputDirectory { get; init; } = string.Empty;
        public int MaxRows { get; init; } = 200000;
    }
}
