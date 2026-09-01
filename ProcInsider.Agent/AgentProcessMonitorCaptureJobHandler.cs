using System.Text.Json;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentProcessMonitorCaptureJobHandler : IAgentJobHandler
{
    private readonly ProcessMonitorService _processMonitorService;
    private readonly ProcessMonitorEvidenceSourceAdapter _adapter;
    private readonly IEvidenceSourcePublisher _publisher;

    public AgentProcessMonitorCaptureJobHandler(
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
        var parameters = context.Request.ReadParameters<ProcessMonitorCaptureParameters>();
        var options = new ProcessMonitorCaptureOptions
        {
            ProcmonPath = parameters.ProcmonPath,
            CaptureId = FirstNonEmpty(parameters.CaptureId, context.Request.CaptureId),
            OutputDirectory = parameters.OutputDirectory,
            BackingFilePath = parameters.BackingFilePath,
            CsvOutputPath = parameters.CsvOutputPath,
            AcceptEula = parameters.AcceptEula,
            MaxRows = parameters.MaxRows
        };

        await context.ReportProgressAsync(0, 1, "Starting Sysinternals Process Monitor capture.").ConfigureAwait(false);
        ProcessMonitorCaptureStartResult capture;
        try
        {
            capture = await _processMonitorService.StartCaptureAsync(
                    options,
                    context.Request.JobId,
                    context.CancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Process Monitor capture did not start: {ex.Message}", ex);
        }

        await context.ReportProgressAsync(
                0,
                1,
                $"Process Monitor capture running. Backing file: {capture.BackingFilePath}; transcript: {capture.TranscriptPath}")
            .ConfigureAwait(false);

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, context.CancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
        {
            try
            {
                await context.ReportProgressAsync(
                        0,
                        1,
                        "Stopping Process Monitor capture, exporting CSV, and importing rows.",
                        CancellationToken.None)
                    .ConfigureAwait(false);
                var result = await _processMonitorService.StopCaptureAndImportAsync(
                        capture,
                        parameters.MaxRows,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                var adapterResult = await PublishAsync(context, result, capture.CsvOutputPath, CancellationToken.None)
                    .ConfigureAwait(false);
                await context.ReportProgressAsync(
                        result.TotalRows,
                        result.TotalRows,
                        $"Process Monitor adapter {adapterResult.State}: {adapterResult.PersistedCount:N0} durable row(s), " +
                        $"{adapterResult.DuplicateCount:N0} replay duplicate(s). CSV: {result.CsvPath}",
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Process Monitor capture stop/import failed: {ex.Message}", ex);
            }
        }
    }

    private async Task<EvidenceSourceExecutionResult> PublishAsync(
        AgentJobContext context,
        ProcessMonitorImportResult result,
        string inputPath,
        CancellationToken cancellationToken)
    {
        var adapterResult = await _adapter.ExecuteAsync(
            new EvidenceSourceAdapterRequest
            {
                SourceRunId = context.SourceRunId,
                IngestionJobId = context.Request.JobId,
                EvidenceIdentity = context.Request.EvidenceIdentity,
                InputPath = inputPath,
                InputHash = context.Request.InputHash,
                Payload = new ProcessMonitorEvidenceSourceInput { Result = result },
                AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ProcessMonitorEvidenceSourceAdapter.ParserPrerequisite
                }
            },
            _publisher,
            null,
            cancellationToken).ConfigureAwait(false);
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
        if (adapterResult.State == EvidenceSourceCompletionState.Failed)
        {
            throw new InvalidOperationException("Process Monitor evidence adapter failed.");
        }
        return adapterResult;
    }

    private static string FirstNonEmpty(params string[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private sealed record ProcessMonitorCaptureParameters
    {
        public string ProcmonPath { get; init; } = string.Empty;
        public string CaptureId { get; init; } = string.Empty;
        public string OutputDirectory { get; init; } = string.Empty;
        public string BackingFilePath { get; init; } = string.Empty;
        public string CsvOutputPath { get; init; } = string.Empty;
        public bool AcceptEula { get; init; } = true;
        public int MaxRows { get; init; } = 200000;
    }
}
