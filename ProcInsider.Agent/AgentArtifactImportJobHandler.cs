using System.Text.Json;
using ProcInsider.Models.EvidenceSources;
using ProcInsider.Services.EvidenceSources;

namespace ProcInsider.Agent;

internal sealed class AgentArtifactImportJobHandler : IAgentJobHandler
{
    private readonly EvidenceSourceAdapterRegistry _adapters;
    private readonly IEvidenceSourcePublisher _publisher;

    public AgentArtifactImportJobHandler(
        EvidenceSourceAdapterRegistry adapters,
        IEvidenceSourcePublisher publisher)
    {
        _adapters = adapters ?? throw new ArgumentNullException(nameof(adapters));
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = context.Request.ReadParameters<ArtifactImportParameters>();
        var adapter = _adapters.Resolve<FilesystemArtifactEvidenceSourceAdapter>(
            FilesystemArtifactEvidenceSourceAdapter.Id,
            FilesystemArtifactEvidenceSourceAdapter.Version);
        await context.ReportProgressAsync(0, -1, $"Loading filesystem artifacts from {parameters.Path}.")
            .ConfigureAwait(false);

        var progress = new InlineProgress<EvidenceSourceProgress>(snapshot =>
            context.ReportProgressAsync(
                    snapshot.NormalizedCount,
                    snapshot.ReceivedCount,
                    snapshot.Message)
                .AsTask()
                .GetAwaiter()
                .GetResult());
        var result = await adapter.ExecuteAsync(
                new EvidenceSourceAdapterRequest
                {
                    SourceRunId = context.SourceRunId,
                    IngestionJobId = context.Request.JobId,
                    EvidenceIdentity = context.Request.EvidenceIdentity,
                    InputPath = parameters.Path,
                    Payload = new FilesystemArtifactEvidenceSourceInput
                    {
                        Path = parameters.Path,
                        Recurse = parameters.Recurse,
                        IncludeNtfs = parameters.IncludeNtfs,
                        IncludePrefetch = parameters.IncludePrefetch,
                        MaxFiles = parameters.MaxFiles
                    },
                    AvailablePrerequisiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        FilesystemArtifactEvidenceSourceAdapter.FilesystemReadPrerequisite
                    }
                },
                _publisher,
                progress,
                context.CancellationToken)
            .ConfigureAwait(false);

        var statusMetadata = JsonSerializer.Serialize(new
        {
            adapterId = adapter.Descriptor.AdapterId,
            adapterVersion = adapter.Descriptor.AdapterVersion,
            completionState = result.State.ToString(),
            result.ReceivedCount,
            result.NormalizedCount,
            result.PersistedCount,
            result.DuplicateCount,
            result.UnresolvedCount,
            result.AmbiguousCount,
            result.FailedCount,
            diagnostics = result.Diagnostics.Take(20)
        });
        context.SetSourceRunCompletion(result.State.ToString(), statusMetadata);
        await context.ReportProgressAsync(
                result.NormalizedCount,
                result.ReceivedCount,
                $"Filesystem artifact adapter {result.State}: {result.NormalizedCount:N0} normalized, " +
                $"{result.PersistedCount:N0} durable row(s), {result.FailedCount:N0} file-level failure(s).")
            .ConfigureAwait(false);

        if (result.State == EvidenceSourceCompletionState.Failed)
        {
            var error = result.Diagnostics.FirstOrDefault(diagnostic =>
                diagnostic.Severity == EvidenceSourceDiagnosticSeverity.Error)?.Message;
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(error)
                    ? "Filesystem artifact adapter failed without diagnostic detail."
                    : error);
        }
    }

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    private sealed class ArtifactImportParameters
    {
        public string Path { get; set; } = string.Empty;
        public bool Recurse { get; set; } = true;
        public bool IncludeNtfs { get; set; } = true;
        public bool IncludePrefetch { get; set; } = true;
        public int MaxFiles { get; set; } = 10000;
    }
}
