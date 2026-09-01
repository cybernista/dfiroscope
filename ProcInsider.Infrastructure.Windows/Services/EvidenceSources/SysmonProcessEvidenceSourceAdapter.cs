using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

public sealed record SysmonProcessEvidenceSourceInput
{
    public string CaptureId { get; init; } = string.Empty;

    public DateTime ObservedUtc { get; init; } = DateTime.UtcNow;

    public bool IsTermination { get; init; }

    public IReadOnlyList<ProcessInfo> Processes { get; init; } = Array.Empty<ProcessInfo>();
}

public sealed class SysmonProcessEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<SysmonProcessEvidenceSourceInput>
{
    public const string Id = "procinsider.sysmon-process";
    public const string Version = "1.0.0";
    public const string SysmonPrerequisite = "windows.sysmon-eventlog";

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Sysmon process lifecycle",
        Description = "Preserves Sysmon ProcessGuid assertions as scoped aliases and immutable process observations.",
        Category = EvidenceSourceCategory.PrimaryAcquisition,
        Capabilities =
            EvidenceSourceCapability.ProcessObservations |
            EvidenceSourceCapability.RawReferences |
            EvidenceSourceCapability.IncrementalPublication |
            EvidenceSourceCapability.LiveCollection,
        MaxBatchRowCount = 1024,
        RawPreservation = new EvidenceRawPreservationPolicy
        {
            Mode = EvidenceRawPreservationMode.BoundedInlineAndFileReference,
            MaxInlineBytes = 4096
        },
        Prerequisites =
        [
            new EvidenceSourcePrerequisite
            {
                PrerequisiteId = SysmonPrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.Capability,
                Description = "The Sysmon Operational event channel is available to the live collector."
            }
        ]
    };

    protected override void ValidateInput(SysmonProcessEvidenceSourceInput input, List<string> errors)
    {
        if (input.ObservedUtc == default)
        {
            errors.Add("ObservedUtc is required.");
        }

        if (input.Processes.Any(process => string.IsNullOrWhiteSpace(process.ProcessGuid)))
        {
            errors.Add("Every Sysmon process observation requires ProcessGuid.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        SysmonProcessEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var identity = ProcessObservationAdapterFactory.CloneIdentity(
            request.EvidenceIdentity,
            input.CaptureId,
            Id);
        var kind = input.IsTermination
            ? ProcessObservationKind.SysmonProcessTerminate
            : ProcessObservationKind.SysmonProcessCreate;
        var metadata = JsonSerializer.Serialize(new { eventId = input.IsTermination ? 5 : 1 });
        var items = input.Processes.Select(process =>
            ProcessObservationAdapterFactory.CreateFromProcessInfo(
                process,
                identity,
                identity.CaptureId,
                request.SourceRunId,
                request.IngestionJobId,
                Id,
                Version,
                input.IsTermination ? "SysmonProcessTerminate" : "SysmonProcessCreate",
                input.ObservedUtc,
                kind,
                ProcessEntityResolutionStrategy.SysmonGuid,
                includeStatistics: false,
                rawRecordId: process.ProcessGuid,
                metadataJson: metadata)).ToArray();
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
                    Message = "Sysmon ProcessGuid observations normalized."
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
                Code = "SysmonProcessPublishFailed",
                Severity = EvidenceSourceDiagnosticSeverity.Error,
                Message = ex.Message,
                IsRetryable = true
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
