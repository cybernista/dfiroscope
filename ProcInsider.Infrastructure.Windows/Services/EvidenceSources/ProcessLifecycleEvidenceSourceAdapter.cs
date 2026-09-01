using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

public enum ProcessLifecycleProducer
{
    Runtime,
    Wmi,
    Etw
}

public sealed record ProcessLifecycleEvidenceSourceInput
{
    public string CaptureId { get; init; } = string.Empty;

    public string Source { get; init; } = "RuntimeProcessLifecycle";

    public DateTime ObservedUtc { get; init; } = DateTime.UtcNow;

    public ProcessLifecycleProducer Producer { get; init; }

    public IReadOnlyList<ProcessInfo> Processes { get; init; } = Array.Empty<ProcessInfo>();
}

public sealed class ProcessLifecycleEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<ProcessLifecycleEvidenceSourceInput>
{
    public const string Id = "procinsider.process-lifecycle";
    public const string Version = "1.0.0";
    public const string LifecyclePrerequisite = "windows.process-lifecycle";

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Process lifecycle observations",
        Description = "Normalizes runtime, WMI, and ETW process lifecycle assertions without owning watchers or ETW sessions.",
        Category = EvidenceSourceCategory.PrimaryAcquisition,
        Capabilities =
            EvidenceSourceCapability.ProcessObservations |
            EvidenceSourceCapability.IncrementalPublication |
            EvidenceSourceCapability.LiveCollection,
        MaxBatchRowCount = 1024,
        RawPreservation = new EvidenceRawPreservationPolicy { Mode = EvidenceRawPreservationMode.None },
        Prerequisites =
        [
            new EvidenceSourcePrerequisite
            {
                PrerequisiteId = LifecyclePrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.Capability,
                Description = "A scheduler-owned process lifecycle watcher or ETW event source is available."
            }
        ]
    };

    protected override void ValidateInput(ProcessLifecycleEvidenceSourceInput input, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(input.Source))
        {
            errors.Add("A lifecycle source name is required.");
        }

        if (input.ObservedUtc == default)
        {
            errors.Add("ObservedUtc is required.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        ProcessLifecycleEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var identity = ProcessObservationAdapterFactory.CloneIdentity(
            request.EvidenceIdentity,
            input.CaptureId,
            Id);
        var observationKind = input.Producer switch
        {
            ProcessLifecycleProducer.Wmi => ProcessObservationKind.WmiLifecycle,
            ProcessLifecycleProducer.Etw => ProcessObservationKind.EtwLifecycle,
            _ => ProcessObservationKind.RuntimeLifecycle
        };
        var metadata = JsonSerializer.Serialize(new { producer = input.Producer.ToString() });
        var items = input.Processes.Select(process =>
        {
            var observedUtc = process.Status == ProcessStatus.Exited
                ? process.EndTime?.ToUniversalTime() ?? input.ObservedUtc
                : process.StartTime?.ToUniversalTime() ?? input.ObservedUtc;
            return ProcessObservationAdapterFactory.CreateFromProcessInfo(
                process,
                identity,
                identity.CaptureId,
                request.SourceRunId,
                request.IngestionJobId,
                Id,
                Version,
                input.Source,
                observedUtc,
                observationKind,
                ProcessEntityResolutionStrategy.ExactOrSourceAlias,
                includeStatistics: false,
                metadataJson: metadata);
        }).ToArray();

        return await PublishAsync(request, items, publisher, progress, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<EvidenceSourceExecutionResult> PublishAsync(
        EvidenceSourceAdapterRequest request,
        IReadOnlyList<ProcessObservationAdapterItem> items,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var rowsPerItem = 1 + Math.Max(1, items.Select(item => item.Aliases.Count).DefaultIfEmpty(1).Max());
        var batchSize = Math.Max(1, GetEffectiveBatchRowLimit(Descriptor, publisher) / rowsPerItem);
        var persisted = 0L;
        var duplicate = 0L;
        var sequence = 0;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        try
        {
            foreach (var chunk in items.Chunk(batchSize))
            {
                cancellationToken.ThrowIfCancellationRequested();
                sequence++;
                var batch = new EvidenceSourceEmissionBatch
                {
                    SourceRunId = request.SourceRunId,
                    IngestionJobId = request.IngestionJobId,
                    Sequence = sequence,
                    IsFinalBatch = sequence * batchSize >= items.Count,
                    ProcessObservations = chunk.Select(item => item.Observation).ToArray(),
                    ProcessAliases = chunk.SelectMany(item => item.Aliases).ToArray(),
                    Identities = chunk.Select(item => new EvidenceSourceEmissionIdentity
                    {
                        EvidenceKind = EvidenceReferenceKind.ProcessObservation,
                        EvidenceId = item.Observation.ObservationId,
                        ExternalIdentity = item.Observation.SourceNativeAlias,
                        DeduplicationKey = item.Observation.ObservationId
                    }).ToArray()
                };
                var result = await publisher.PublishAsync(batch, cancellationToken).ConfigureAwait(false);
                persisted += result.PersistedRowCount;
                duplicate += result.DuplicateRowCount;
                diagnostics.AddRange(result.Diagnostics);
                progress?.Report(new EvidenceSourceProgress
                {
                    AdapterId = Id,
                    SourceRunId = request.SourceRunId,
                    ReceivedCount = items.Count,
                    NormalizedCount = Math.Min(items.Count, sequence * batchSize),
                    PersistedCount = persisted,
                    DuplicateCount = duplicate,
                    Message = "Process lifecycle observations normalized."
                });
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (ex is EvidenceSourcePublishException publishException)
            {
                persisted += publishException.PersistedRowCount;
            }

            diagnostics.Add(new EvidenceSourceDiagnostic
            {
                Code = "ProcessLifecyclePublishFailed",
                Severity = EvidenceSourceDiagnosticSeverity.Error,
                Message = ex.Message,
                IsRetryable = true
            });
            return new EvidenceSourceExecutionResult
            {
                State = persisted > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Failed,
                ReceivedCount = items.Count,
                NormalizedCount = items.Count,
                PersistedCount = persisted,
                DuplicateCount = duplicate,
                FailedCount = Math.Max(1, items.Count - persisted),
                Diagnostics = diagnostics
            };
        }

        return new EvidenceSourceExecutionResult
        {
            State = EvidenceSourceCompletionState.Completed,
            ReceivedCount = items.Count,
            NormalizedCount = items.Count,
            PersistedCount = persisted,
            DuplicateCount = duplicate,
            Diagnostics = diagnostics
        };
    }
}
