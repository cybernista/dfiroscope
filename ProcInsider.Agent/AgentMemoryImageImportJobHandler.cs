using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentMemoryImageImportJobHandler : IAgentJobHandler
{
    private readonly MemoryImageImportService _importService;
    private readonly MemoryImageEvidenceSourceAdapter _adapter;
    private readonly IEvidenceSourcePublisher _publisher;

    public AgentMemoryImageImportJobHandler(
        MemoryImageImportService importService,
        MemoryImageEvidenceSourceAdapter adapter,
        IEvidenceSourcePublisher publisher)
    {
        _importService = importService;
        _adapter = adapter;
        _publisher = publisher;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = context.Request.ReadParameters<MemoryImageImportParameters>();
        await context.ReportProgressAsync(0, -1, $"Importing memory image metadata for {parameters.ImagePath}.").ConfigureAwait(false);

        var record = await _importService.ImportAsync(
            parameters.ImagePath,
            context.Request.JobId,
            parameters.DisplayName,
            parameters.AcquisitionTool,
            parameters.AcquisitionToolVersion,
            parameters.AcquisitionCommandLine,
            parameters.HostName,
            parameters.OsBuild,
            parameters.PrivilegeState,
            context.CancellationToken).ConfigureAwait(false);

        var adapterResult = await _adapter.ExecuteAsync(
            new EvidenceSourceAdapterRequest
            {
                SourceRunId = context.SourceRunId,
                IngestionJobId = context.Request.JobId,
                EvidenceIdentity = context.Request.EvidenceIdentity,
                InputPath = parameters.ImagePath,
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
        context.SetSourceRunCompletion(adapterResult.State.ToString());

        if (record.Status == MemoryImageStatus.Failed)
        {
            await context.ReportMemoryProgressAsync(
                1,
                1,
                $"Memory image import failed: {record.ErrorMessage}",
                BuildMemoryResult(record),
                CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException(record.ErrorMessage);
        }

        await context.ReportMemoryProgressAsync(
            1,
            1,
            $"Imported memory image metadata for {record.DisplayName} ({record.FileSizeBytes} bytes).",
            BuildMemoryResult(record),
            context.CancellationToken).ConfigureAwait(false);
    }

    private static AgentMemoryActionResult BuildMemoryResult(MemoryImageRecord record) => new()
    {
        Action = "Import",
        Status = record.Status.ToString(),
        ImageId = record.ImageId,
        Sha256Hash = record.Sha256Hash,
        Path = record.FilePath,
        FileSizeBytes = record.FileSizeBytes,
        Summary = record.Status == MemoryImageStatus.Imported
            ? $"Imported {record.FileSizeBytes} bytes with SHA256 {record.Sha256Hash}."
            : record.ErrorMessage
    };

    private sealed record MemoryImageImportParameters
    {
        public string ImagePath { get; init; } = string.Empty;
        public string DisplayName { get; init; } = string.Empty;
        public string HostName { get; init; } = string.Empty;
        public string OsBuild { get; init; } = string.Empty;
        public string AcquisitionTool { get; init; } = "Analyst import";
        public string AcquisitionToolVersion { get; init; } = string.Empty;
        public string AcquisitionCommandLine { get; init; } = string.Empty;
        public string PrivilegeState { get; init; } = string.Empty;
    }
}
