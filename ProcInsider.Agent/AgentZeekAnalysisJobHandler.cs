using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentZeekAnalysisJobHandler : IAgentJobHandler
{
    private readonly string _databasePath;
    private readonly ZeekProcessingService _zeekProcessingService;
    private readonly ZeekNetworkEvidenceSourceAdapter _adapter;
    private readonly IEvidenceSourcePublisher _publisher;

    public AgentZeekAnalysisJobHandler(
        string databasePath,
        ZeekProcessingService zeekProcessingService,
        ZeekNetworkEvidenceSourceAdapter adapter,
        IEvidenceSourcePublisher publisher)
    {
        _databasePath = databasePath;
        _zeekProcessingService = zeekProcessingService;
        _adapter = adapter;
        _publisher = publisher;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = context.Request.ReadParameters<ZeekAnalysisParameters>();
        var captureId = parameters.CaptureId?.Trim() ?? string.Empty;
        var pcapPath = parameters.PcapPath?.Trim() ?? string.Empty;

        var queryService = new SqliteStagingQueryService(
            _databasePath,
            openContext: CaptureOpenContext.AgentWritableLive);
        if (!string.IsNullOrWhiteSpace(captureId))
        {
            var capture = queryService.GetNetworkCaptureById(captureId);
            pcapPath = string.IsNullOrWhiteSpace(pcapPath) ? capture?.FilePath ?? string.Empty : pcapPath;
        }

        if (string.IsNullOrWhiteSpace(captureId))
        {
            captureId = Path.GetFileNameWithoutExtension(pcapPath);
        }

        if (string.IsNullOrWhiteSpace(pcapPath))
        {
            throw new InvalidOperationException("Zeek analysis requires a capture id with a staged PCAPNG path or an explicit PCAP/PCAPNG path.");
        }

        await context.ReportProgressAsync(0, -1, $"Running Zeek for {pcapPath}").ConfigureAwait(false);
        ZeekProcessingResult result;
        try
        {
            result = await _zeekProcessingService.ProcessCaptureAsync(
                captureId,
                context.Request.JobId,
                pcapPath,
                parameters.OutputDirectory ?? string.Empty,
                new ZeekProcessingOptions(
                    parameters.ZeekPath ?? string.Empty,
                    parameters.WslDistributionName ?? string.Empty,
                    parameters.WslZeekCommand ?? string.Empty),
                context.CancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var diagnosticLogPath = ex is ZeekProcessingException zeekException
                ? zeekException.DiagnosticLogPath
                : string.Empty;
            await PublishAsync(
                context,
                [CreateFailedRecord(context.Request.JobId, captureId, pcapPath, diagnosticLogPath, ex.Message)],
                pcapPath,
                CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        var records = result.Records.Select(record =>
        {
            var correlation = queryService.ResolveZeekProcessCorrelation(record);
            if (!string.IsNullOrWhiteSpace(correlation.ProcessKey))
            {
                record.CorrelationMethod = correlation.Method;
                record.CorrelationConfidence = correlation.Confidence;
                if (correlation.Confidence >= 0.95)
                {
                    record.ProcessKey = correlation.ProcessKey;
                    record.ProcessId = correlation.ProcessId;
                    record.ProcessName = correlation.ProcessName;
                }
            }

            return record;
        }).ToList();
        PropagateUidCorrelations(records);

        var adapterResult = await PublishAsync(
            context,
            records,
            pcapPath,
            CancellationToken.None).ConfigureAwait(false);
        context.SetSourceRunCompletion(adapterResult.State.ToString());
        await context.ReportProgressAsync(
            records.Count,
            records.Count,
            $"Imported {records.Count} Zeek artifact(s) from {result.OutputDirectory}. Diagnostic log: {result.DiagnosticLogPath}").ConfigureAwait(false);
    }

    private static ZeekNetworkRecord CreateFailedRecord(
        Guid jobId,
        string captureId,
        string pcapPath,
        string diagnosticLogPath,
        string error)
    {
        return new ZeekNetworkRecord
        {
            ArtifactId = $"{jobId:N}-zeek-failed",
            CaptureId = captureId,
            JobId = jobId,
            Status = ZeekArtifactStatus.Failed,
            TimestampUtc = DateTime.UtcNow,
            LogType = "zeek",
            Summary = string.IsNullOrWhiteSpace(pcapPath) ? "Zeek analysis failed." : $"Zeek analysis failed for {pcapPath}.",
            RawLogPath = string.IsNullOrWhiteSpace(diagnosticLogPath) ? pcapPath : diagnosticLogPath,
            ErrorMessage = error,
            Source = "AgentZeek"
        };
    }

    private ValueTask<EvidenceSourceExecutionResult> PublishAsync(
        AgentJobContext context,
        IReadOnlyList<ZeekNetworkRecord> records,
        string pcapPath,
        CancellationToken cancellationToken)
        => _adapter.ExecuteAsync(
            new EvidenceSourceAdapterRequest
            {
                SourceRunId = context.SourceRunId,
                IngestionJobId = context.Request.JobId,
                EvidenceIdentity = context.Request.EvidenceIdentity,
                ParentSourceRunId = context.Request.ParentSourceRunId,
                InputArtifactId = records.FirstOrDefault()?.CaptureId ?? string.Empty,
                InputPath = pcapPath,
                InputHash = context.Request.InputHash,
                Payload = new ZeekNetworkEvidenceSourceInput { Artifacts = records },
                AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ZeekNetworkEvidenceSourceAdapter.ParserPrerequisite
                }
            },
            _publisher,
            null,
            cancellationToken);

    private static void PropagateUidCorrelations(IReadOnlyList<ZeekNetworkRecord> records)
    {
        var correlatedByUid = records
            .Where(record => !string.IsNullOrWhiteSpace(record.ZeekUid) &&
                             !string.IsNullOrWhiteSpace(record.ProcessKey))
            .GroupBy(record => record.ZeekUid, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group
                    .OrderByDescending(record => record.CorrelationConfidence)
                    .First(),
                StringComparer.Ordinal);

        foreach (var record in records)
        {
            if (string.IsNullOrWhiteSpace(record.ZeekUid) ||
                !string.IsNullOrWhiteSpace(record.ProcessKey) ||
                !correlatedByUid.TryGetValue(record.ZeekUid, out var correlated))
            {
                continue;
            }

            record.CorrelationMethod = $"Zeek UID propagation from {correlated.LogType}";
            record.CorrelationConfidence = Math.Min(correlated.CorrelationConfidence, 0.85);
        }
    }

    private sealed record ZeekAnalysisParameters
    {
        public string CaptureId { get; init; } = string.Empty;
        public string PcapPath { get; init; } = string.Empty;
        public string ZeekPath { get; init; } = string.Empty;
        public string WslDistributionName { get; init; } = string.Empty;
        public string WslZeekCommand { get; init; } = string.Empty;
        public string OutputDirectory { get; init; } = string.Empty;
    }
}
