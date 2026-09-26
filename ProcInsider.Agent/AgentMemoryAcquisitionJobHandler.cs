using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentMemoryAcquisitionJobHandler : IAgentJobHandler
{
    private readonly AgentMemoryAcquisitionService _acquisitionService;
    private readonly MemoryImageImportService _importService;
    private readonly MemoryImageEvidenceSourceAdapter _adapter;
    private readonly IEvidenceSourcePublisher _publisher;

    public AgentMemoryAcquisitionJobHandler(
        AgentMemoryAcquisitionService acquisitionService,
        MemoryImageImportService importService,
        MemoryImageEvidenceSourceAdapter adapter,
        IEvidenceSourcePublisher publisher)
    {
        _acquisitionService = acquisitionService;
        _importService = importService;
        _adapter = adapter;
        _publisher = publisher;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var plan = context.Request.ReadParameters<AgentMemoryAcquisitionPlan>();
        await context.ReportProgressAsync(
            0,
            3,
            $"Starting configured memory acquisition with {plan.ToolName}.").ConfigureAwait(false);

        var acquisition = await _acquisitionService.ExecuteAsync(
            plan,
            context.CancellationToken).ConfigureAwait(false);
        if (!acquisition.Succeeded)
        {
            var failedResult = BuildMemoryResult(acquisition);
            context.SetSourceRunCompletion(
                acquisition.Outcome.ToString(),
                BuildCompletionMetadata(acquisition));
            if (acquisition.Outcome == AgentMemoryAcquisitionOutcome.Canceled)
            {
                await context.ReportMemoryProgressAsync(
                    1,
                    3,
                    acquisition.Detail,
                    failedResult,
                    CancellationToken.None).ConfigureAwait(false);
                throw new OperationCanceledException(acquisition.Detail, context.CancellationToken);
            }

            await context.ReportMemoryProgressAsync(
                1,
                3,
                acquisition.Detail,
                failedResult,
                CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException(acquisition.Detail);
        }

        await context.ReportProgressAsync(
            1,
            3,
            $"Verified acquired memory image ({new FileInfo(plan.OutputPath).Length} bytes); computing metadata and hash.")
            .ConfigureAwait(false);

        var acquisitionCommandLine = $"\"{plan.ExecutablePath}\" {plan.Arguments}".Trim();
        var record = await _importService.ImportAsync(
            plan.OutputPath,
            context.Request.JobId,
            Path.GetFileName(plan.OutputPath),
            plan.ToolName,
            plan.ToolVersion,
            acquisitionCommandLine,
            Environment.MachineName,
            Environment.OSVersion.VersionString,
            Environment.IsPrivilegedProcess ? "Elevated agent" : "Agent not elevated",
            context.CancellationToken).ConfigureAwait(false);

        var adapterResult = await _adapter.ExecuteAsync(
            new EvidenceSourceAdapterRequest
            {
                SourceRunId = context.SourceRunId,
                IngestionJobId = context.Request.JobId,
                EvidenceIdentity = context.Request.EvidenceIdentity,
                InputPath = plan.OutputPath,
                InputHash = record.Sha256Hash,
                Payload = new MemoryImageEvidenceSourceInput { Images = [record] },
                AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    MemoryImageEvidenceSourceAdapter.ImageMetadataPrerequisite
                }
            },
            _publisher,
            null,
            context.CancellationToken).ConfigureAwait(false);

        context.SetSourceRunCompletion(
            adapterResult.State.ToString(),
            BuildCompletionMetadata(acquisition, record));
        if (record.Status != MemoryImageStatus.Imported)
        {
            await context.ReportProgressAsync(
                2,
                3,
                $"Acquired image metadata import failed: {record.ErrorMessage}").ConfigureAwait(false);
            throw new InvalidOperationException(record.ErrorMessage);
        }

        await context.ReportMemoryProgressAsync(
            3,
            3,
            $"Acquired and imported {record.DisplayName} ({record.FileSizeBytes} bytes, SHA256 {record.Sha256Hash}).",
            BuildMemoryResult(acquisition, record),
            context.CancellationToken)
            .ConfigureAwait(false);
    }

    private static AgentMemoryActionResult BuildMemoryResult(
        AgentMemoryAcquisitionResult acquisition,
        MemoryImageRecord? record = null) => new()
    {
        Action = "Acquire",
        Status = record?.Status.ToString() ?? acquisition.Outcome.ToString(),
        ImageId = record?.ImageId ?? string.Empty,
        Sha256Hash = record?.Sha256Hash ?? string.Empty,
        Path = acquisition.Plan.OutputPath,
        FileSizeBytes = record?.FileSizeBytes ?? 0,
        CleanupStatus = acquisition.CleanupDisposition,
        QuarantinedPath = acquisition.QuarantinedPath,
        Summary = record == null
            ? acquisition.Detail
            : $"Imported {record.FileSizeBytes} bytes with SHA256 {record.Sha256Hash}."
    };

    private static string BuildCompletionMetadata(
        AgentMemoryAcquisitionResult result,
        MemoryImageRecord? record = null) =>
        JsonSerializer.Serialize(
            new
            {
                result.Outcome,
                result.StartedAtUtc,
                result.CompletedAtUtc,
                result.ExitCode,
                result.Plan.ToolName,
                result.Plan.ToolVersion,
                result.Plan.ExecutablePath,
                result.Plan.Arguments,
                result.Plan.OutputPath,
                result.Plan.ConfigurationDiagnostic,
                result.StandardOutput,
                result.StandardError,
                result.CleanupDisposition,
                result.QuarantinedPath,
                result.Detail,
                ImageId = record?.ImageId ?? string.Empty,
                FileSizeBytes = record?.FileSizeBytes ?? 0,
                Sha256Hash = record?.Sha256Hash ?? string.Empty,
                ImportStatus = record?.Status.ToString() ?? string.Empty,
                ImportError = record?.ErrorMessage ?? string.Empty
            },
            AgentJson.JsonOptions);
}
