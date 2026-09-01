using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

public sealed record LegacyProcessSnapshotEvidenceSourceInput
{
    public IReadOnlyList<ProcessRecord> Processes { get; init; } = Array.Empty<ProcessRecord>();
}

/// <summary>
/// Bounded compatibility adapter for legacy archive process rows. New live,
/// import, and analyzer producers must use their dedicated adapters.
/// </summary>
public sealed class LegacyProcessSnapshotEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<LegacyProcessSnapshotEvidenceSourceInput>
{
    public const string Id = "procinsider.legacy-process-snapshot";
    public const string Version = "1.0.0";
    public const string ArchivePrerequisite = "legacy.archive-processes";

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Legacy process snapshot compatibility",
        Description = "Normalizes bounded legacy archive process rows while preserving ProcessKey compatibility.",
        Category = EvidenceSourceCategory.CompatibilityOnly,
        Capabilities = EvidenceSourceCapability.ProcessObservations,
        MaxBatchRowCount = 1024,
        IsPublished = false,
        RawPreservation = new EvidenceRawPreservationPolicy { Mode = EvidenceRawPreservationMode.None },
        Prerequisites =
        [
            new EvidenceSourcePrerequisite
            {
                PrerequisiteId = ArchivePrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.File,
                Description = "A validated legacy ProcInsider archive has been loaded."
            }
        ]
    };

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        LegacyProcessSnapshotEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var identity = ProcessObservationAdapterFactory.CloneIdentity(
            request.EvidenceIdentity,
            request.EvidenceIdentity.CaptureId,
            Id);
        var items = input.Processes.Select(process =>
            ProcessObservationAdapterFactory.CreateFromProcessRecord(
                process,
                identity,
                request.SourceRunId,
                request.IngestionJobId,
                Id,
                Version,
                process.LastObservedUtc == default ? DateTime.UtcNow : process.LastObservedUtc,
                ProcessObservationKind.LegacyCompatibility,
                ProcessEntityResolutionStrategy.LegacyCompatibility,
                rawRecordId: process.ProcessKey,
                metadataJson: "{\"compatibilityOnly\":true}"))
            .ToArray();
        var rowsPerItem = 1 + Math.Max(1, items.Select(item => item.Aliases.Count).DefaultIfEmpty(1).Max());
        var batchSize = Math.Max(1, GetEffectiveBatchRowLimit(Descriptor, publisher) / rowsPerItem);
        var persisted = 0L;
        var duplicate = 0L;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        var sequence = 0;
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
                    IsFinalBatch = sequence * batchSize >= items.Length,
                    ProcessObservations = chunk.Select(item => item.Observation).ToArray(),
                    ProcessAliases = chunk.SelectMany(item => item.Aliases).ToArray(),
                    Identities = chunk.Select(item => new EvidenceSourceEmissionIdentity
                    {
                        EvidenceKind = EvidenceReferenceKind.ProcessObservation,
                        EvidenceId = item.Observation.ObservationId,
                        ExternalIdentity = item.Observation.SourceNativeAlias,
                        DeduplicationKey = item.Observation.ObservationId,
                        RawReference = item.Observation.RawRecordId
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
                    ReceivedCount = items.Length,
                    NormalizedCount = Math.Min(items.Length, sequence * batchSize),
                    PersistedCount = persisted,
                    DuplicateCount = duplicate,
                    Message = "Legacy process rows normalized through the compatibility adapter."
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
                Code = "LegacyProcessPublishFailed",
                Severity = EvidenceSourceDiagnosticSeverity.Error,
                Message = ex.Message,
                IsRetryable = false
            });
            return new EvidenceSourceExecutionResult
            {
                State = persisted > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Failed,
                ReceivedCount = items.Length,
                NormalizedCount = items.Length,
                PersistedCount = persisted,
                DuplicateCount = duplicate,
                FailedCount = Math.Max(1, items.Length - persisted),
                Diagnostics = diagnostics
            };
        }

        return new EvidenceSourceExecutionResult
        {
            State = EvidenceSourceCompletionState.Completed,
            ReceivedCount = items.Length,
            NormalizedCount = items.Length,
            PersistedCount = persisted,
            DuplicateCount = duplicate,
            Diagnostics = diagnostics
        };
    }
}
