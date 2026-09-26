using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

public sealed record RuntimeProcessSnapshotInput
{
    public string CaptureId { get; init; } = string.Empty;

    public string Source { get; init; } = "AgentLiveCaptureProcessRefresh";

    public DateTime ObservedUtc { get; init; } = DateTime.UtcNow;

    public bool IsFullSnapshot { get; init; }

    public IReadOnlyList<ProcessInfo> Processes { get; init; } = Array.Empty<ProcessInfo>();
}

/// <summary>
/// Normalizes scheduler-owned periodic process snapshots into immutable process
/// observations and statistics. Polling, coalescing, and write priority remain
/// outside the adapter.
/// </summary>
public sealed class RuntimeProcessSnapshotEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<RuntimeProcessSnapshotInput>
{
    public const string Id = "procinsider.runtime-process-snapshot";
    public const string Version = "2.0.0";
    public const string ProcessApiPrerequisite = "windows.process-api";

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Runtime process snapshots",
        Description = "Normalizes periodic PID/start-time snapshots into immutable observations and statistics.",
        Category = EvidenceSourceCategory.PrimaryAcquisition,
        Capabilities =
            EvidenceSourceCapability.ProcessObservations |
            EvidenceSourceCapability.ProcessStatistics |
            EvidenceSourceCapability.IncrementalPublication |
            EvidenceSourceCapability.LiveCollection,
        MaxBatchRowCount = 2048,
        RawPreservation = new EvidenceRawPreservationPolicy
        {
            Mode = EvidenceRawPreservationMode.None
        },
        Prerequisites =
        [
            new EvidenceSourcePrerequisite
            {
                PrerequisiteId = ProcessApiPrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.Capability,
                Description = "Windows process enumeration is available to the scheduler-owned live collector."
            }
        ]
    };

    protected override void ValidateInput(RuntimeProcessSnapshotInput input, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(input.Source))
        {
            errors.Add("A runtime process source name is required.");
        }

        if (input.ObservedUtc == default)
        {
            errors.Add("ObservedUtc is required.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        RuntimeProcessSnapshotInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var effectiveIdentity = ProcessObservationAdapterFactory.CloneIdentity(
            request.EvidenceIdentity,
            input.CaptureId,
            Id);
        var metadataJson = JsonSerializer.Serialize(new
        {
            input.IsFullSnapshot,
            producer = "RuntimeProcessPolling"
        });
        var normalized = input.Processes
            .Select(process => ProcessObservationAdapterFactory.CreateFromProcessInfo(
                process,
                effectiveIdentity,
                effectiveIdentity.CaptureId,
                request.SourceRunId,
                request.IngestionJobId,
                Id,
                Version,
                input.Source,
                input.ObservedUtc,
                ProcessObservationKind.PeriodicSnapshot,
                ProcessEntityResolutionStrategy.ExactOrSourceAlias,
                includeStatistics: true,
                metadataJson: metadataJson))
            .ToArray();
        return await PublishAsync(request, normalized, publisher, progress, cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<EvidenceSourceExecutionResult> PublishAsync(
        EvidenceSourceAdapterRequest request,
        IReadOnlyList<ProcessObservationAdapterItem> normalized,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var maxAliases = Math.Max(1, normalized.Select(item => item.Aliases.Count).DefaultIfEmpty(1).Max());
        var rowsPerProcess = 2 + maxAliases;
        var processBatchSize = Math.Max(1, GetEffectiveBatchRowLimit(Descriptor, publisher) / rowsPerProcess);
        var persisted = 0L;
        var duplicate = 0L;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        var sequence = 0;

        try
        {
            foreach (var chunk in normalized.Chunk(processBatchSize))
            {
                cancellationToken.ThrowIfCancellationRequested();
                sequence++;
                var batch = new EvidenceSourceEmissionBatch
                {
                    SourceRunId = request.SourceRunId,
                    IngestionJobId = request.IngestionJobId,
                    Sequence = sequence,
                    IsFinalBatch = sequence * processBatchSize >= normalized.Count,
                    ProcessObservations = chunk.Select(item => item.Observation).ToArray(),
                    ProcessAliases = chunk.SelectMany(item => item.Aliases).ToArray(),
                    ProcessStatistics = chunk
                        .Where(item => item.Statistics != null)
                        .Select(item => item.Statistics!)
                        .ToArray(),
                    Identities = chunk.Select(item => new EvidenceSourceEmissionIdentity
                    {
                        EvidenceKind = EvidenceReferenceKind.ProcessObservation,
                        EvidenceId = item.Observation.ObservationId,
                        ExternalIdentity = item.Observation.SourceNativeAlias,
                        DeduplicationKey = item.Observation.ObservationId,
                        RawReference = item.Observation.RawRecordId
                    }).ToArray()
                };
                var published = await publisher.PublishAsync(batch, cancellationToken).ConfigureAwait(false);
                persisted += published.PersistedRowCount;
                duplicate += published.DuplicateRowCount;
                diagnostics.AddRange(published.Diagnostics);
                progress?.Report(new EvidenceSourceProgress
                {
                    AdapterId = Id,
                    SourceRunId = request.SourceRunId,
                    ReceivedCount = normalized.Count,
                    NormalizedCount = Math.Min(normalized.Count, sequence * processBatchSize),
                    PersistedCount = persisted,
                    DuplicateCount = duplicate,
                    Message = "Runtime process snapshot normalized into immutable observations."
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
                Code = "RuntimeProcessPublishFailed",
                Severity = EvidenceSourceDiagnosticSeverity.Error,
                Message = ex.Message,
                IsRetryable = true
            });
            return new EvidenceSourceExecutionResult
            {
                State = persisted > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Failed,
                ReceivedCount = normalized.Count,
                NormalizedCount = normalized.Count,
                DuplicateCount = duplicate,
                PersistedCount = persisted,
                FailedCount = Math.Max(1, normalized.Count - persisted),
                Diagnostics = diagnostics
            };
        }

        return new EvidenceSourceExecutionResult
        {
            State = EvidenceSourceCompletionState.Completed,
            ReceivedCount = normalized.Count,
            NormalizedCount = normalized.Count,
            DuplicateCount = duplicate,
            PersistedCount = persisted,
            Diagnostics = diagnostics
        };
    }
}
