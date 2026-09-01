using ProcInsider.Models;
using ProcInsider.Models.Agent;
using System.Text.Json;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentVolatilityAnalysisJobHandler : IAgentJobHandler
{
    private readonly string _databasePath;
    private readonly VolatilityExecutionService _volatilityExecutionService;
    private readonly VolatilityProcessEvidenceSourceAdapter _adapter;
    private readonly IEvidenceSourcePublisher _publisher;

    public AgentVolatilityAnalysisJobHandler(
        string databasePath,
        VolatilityExecutionService volatilityExecutionService,
        VolatilityProcessEvidenceSourceAdapter adapter,
        IEvidenceSourcePublisher publisher)
    {
        _databasePath = databasePath;
        _volatilityExecutionService = volatilityExecutionService;
        _adapter = adapter;
        _publisher = publisher;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = context.Request.ReadParameters<VolatilityAnalysisParameters>();
        var image = ResolveImage(parameters);
        if (image == null)
        {
            throw new InvalidOperationException("Volatility analysis requires a staged memory image id or an explicit image path.");
        }

        var plugins = parameters.PluginNames is { Length: > 0 }
            ? parameters.PluginNames
            : VolatilityExecutionService.DefaultPlugins.ToArray();
        var timeout = TimeSpan.FromSeconds(Math.Clamp(parameters.TimeoutSeconds, 30, 24 * 60 * 60));

        await context.ReportProgressAsync(0, plugins.Length, $"Running Volatility for memory image {image.DisplayName}.").ConfigureAwait(false);
        var results = await _volatilityExecutionService.RunPluginsAsync(
            image,
            context.Request.JobId,
            plugins,
            parameters.OutputDirectory,
            timeout,
            context.CancellationToken).ConfigureAwait(false);

        var runs = results.Select(result => result.Run).ToList();
        var processes = results.SelectMany(result => result.MemoryProcesses).ToList();
        var adapterResult = await _adapter.ExecuteAsync(
            new EvidenceSourceAdapterRequest
            {
                SourceRunId = context.SourceRunId,
                IngestionJobId = context.Request.JobId,
                EvidenceIdentity = context.Request.EvidenceIdentity with { CaptureId = image.CaptureId },
                ParentSourceRunId = context.Request.ParentSourceRunId,
                InputArtifactId = image.ImageId,
                InputPath = image.FilePath,
                InputHash = image.Sha256Hash,
                Payload = new VolatilityProcessEvidenceSourceInput
                {
                    PluginRuns = runs,
                    MemoryProcesses = processes
                },
                AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    VolatilityProcessEvidenceSourceAdapter.ParserPrerequisite
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
            adapterResult.UnresolvedCount,
            adapterResult.FailedCount,
            adapterResult.Diagnostics
        }));

        var failedRuns = runs.Count(run => run.Status == VolatilityPluginRunStatus.Failed);
        var completedRuns = runs.Count - failedRuns;
        await context.ReportMemoryProgressAsync(
            runs.Count,
            plugins.Length,
            $"Volatility adapter {adapterResult.State}: {completedRuns} completed run(s), {failedRuns} failed run(s), " +
            $"{adapterResult.PersistedCount:N0} durable row(s), and {adapterResult.UnresolvedCount:N0} memory-only process row(s).",
            new AgentMemoryActionResult
            {
                Action = "Volatility",
                Status = failedRuns == 0 ? "Completed" : completedRuns == 0 ? "Failed" : "Partial",
                ImageId = image.ImageId,
                RunIds = runs
                    .Select(run => run.RunId)
                    .Where(runId => !string.IsNullOrWhiteSpace(runId))
                    .Take(AgentMemoryActionPolicy.MaximumPluginCount)
                    .ToArray(),
                Path = image.FilePath,
                OutputDirectory = runs.Select(run => run.OutputDirectory)
                    .FirstOrDefault(path => !string.IsNullOrWhiteSpace(path)) ?? string.Empty,
                Summary = $"{completedRuns} completed run(s), {failedRuns} failed run(s), {adapterResult.PersistedCount} durable row(s)."
            },
            context.CancellationToken).ConfigureAwait(false);
        if (adapterResult.State == EvidenceSourceCompletionState.Failed)
        {
            throw new InvalidOperationException("Volatility process evidence adapter failed.");
        }
    }

    private MemoryImageRecord? ResolveImage(VolatilityAnalysisParameters parameters)
    {
        var queryService = new SqliteStagingQueryService(
            _databasePath,
            openContext: CaptureOpenContext.AgentWritableLive);
        if (!string.IsNullOrWhiteSpace(parameters.ImageId))
        {
            var image = queryService.GetMemoryImageById(parameters.ImageId);
            if (image != null)
            {
                return image;
            }
        }

        if (string.IsNullOrWhiteSpace(parameters.ImagePath))
        {
            return null;
        }

        var path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(parameters.ImagePath));
        return new MemoryImageRecord
        {
            ImageId = string.IsNullOrWhiteSpace(parameters.ImageId)
                ? Path.GetFileNameWithoutExtension(path)
                : parameters.ImageId,
            Status = MemoryImageStatus.Imported,
            ImportedUtc = DateTime.UtcNow,
            SourcePath = path,
            FilePath = path,
            DisplayName = Path.GetFileName(path),
            ImageFormat = Path.GetExtension(path).TrimStart('.').ToLowerInvariant(),
            Source = "AgentVolatility"
        };
    }

    private sealed record VolatilityAnalysisParameters
    {
        public string ImageId { get; init; } = string.Empty;
        public string ImagePath { get; init; } = string.Empty;
        public string[]? PluginNames { get; init; }
        public string OutputDirectory { get; init; } = string.Empty;
        public int TimeoutSeconds { get; init; } = 600;
    }
}
