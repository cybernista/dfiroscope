using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

public sealed record ProcessMonitorEvidenceSourceInput
{
    public ProcessMonitorImportResult? Result { get; init; }
}

public sealed class ProcessMonitorEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<ProcessMonitorEvidenceSourceInput>
{
    public const string Id = "procinsider.process-monitor";
    public const string Version = "1.0.0";
    public const string ParserPrerequisite = "sysinternals.procmon-output";

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Sysinternals Process Monitor",
        Description = "Normalizes Process Monitor synthetic processes and event rows without merging them into live processes by PID.",
        Category = EvidenceSourceCategory.Importer,
        Capabilities =
            EvidenceSourceCapability.ProcessObservations |
            EvidenceSourceCapability.Events |
            EvidenceSourceCapability.RawReferences |
            EvidenceSourceCapability.IncrementalPublication,
        MaxBatchRowCount = 2048,
        RawPreservation = new EvidenceRawPreservationPolicy
        {
            Mode = EvidenceRawPreservationMode.HashAndFileReference,
            RequireContentHash = true
        },
        Prerequisites =
        [
            new EvidenceSourcePrerequisite
            {
                PrerequisiteId = ParserPrerequisite,
                Kind = EvidenceSourcePrerequisiteKind.File,
                Description = "A Process Monitor CSV export or successfully exported PML input is available."
            }
        ]
    };

    protected override void ValidateInput(ProcessMonitorEvidenceSourceInput input, List<string> errors)
    {
        if (input.Result == null)
        {
            errors.Add("A normalized Process Monitor import result is required.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        ProcessMonitorEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var result = input.Result!;
        var identity = ProcessObservationAdapterFactory.CloneIdentity(
            request.EvidenceIdentity,
            result.Processes.FirstOrDefault()?.CaptureId ?? request.EvidenceIdentity.CaptureId,
            Id);
        var nativeKeyByProjectedKey = new Dictionary<string, string>(StringComparer.Ordinal);
        var items = result.Processes.Select(process =>
        {
            var nativeProcessKey = process.ProcessKey;
            var projectedProcess = JsonSerializer.Deserialize<ProcessRecord>(
                JsonSerializer.Serialize(process)) ?? throw new InvalidOperationException(
                "Process Monitor process normalization could not clone its source row.");
            var runKey = ProcessObservationAdapterFactory.CreateStableId(
                "procmon-run",
                request.SourceRunId,
                nativeProcessKey);
            projectedProcess.ProcessKey = $"{nativeProcessKey}:run:{runKey[12..]}";
            nativeKeyByProjectedKey[projectedProcess.ProcessKey] = nativeProcessKey;
            return ProcessObservationAdapterFactory.CreateFromProcessRecord(
                projectedProcess,
                identity,
                request.SourceRunId,
                request.IngestionJobId,
                Id,
                Version,
                process.LastObservedUtc == default ? DateTime.UtcNow : process.LastObservedUtc,
                ProcessObservationKind.ProcmonSyntheticProcess,
                ProcessEntityResolutionStrategy.SourceRunAlias,
                rawRecordId: nativeProcessKey,
                metadataJson: "{\"identityPolicy\":\"source-run-scoped-synthetic\"}");
        }).ToArray();
        var entityByProcessKey = items
            .GroupBy(
                item => nativeKeyByProjectedKey[item.Observation.Fields.ProcessKey],
                StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.First().Observation,
                StringComparer.Ordinal);
        var eventRows = result.Events
            .Select(processEvent => JsonSerializer.Deserialize<TelemetryEventRecord>(
                JsonSerializer.Serialize(processEvent)) ?? throw new InvalidOperationException(
                "Process Monitor event normalization could not clone its source row."))
            .ToArray();
        foreach (var processEvent in eventRows)
        {
            ProcessObservationAdapterFactory.ApplyIdentity(processEvent, identity, Id);
            if (entityByProcessKey.TryGetValue(processEvent.ProcessKey, out var processObservation))
            {
                processEvent.ProcessKey = processObservation.Fields.ProcessKey;
                processEvent.ProcessEntityId = processObservation.ProcessEntityId;
                processEvent.CorrelationState = EvidenceCorrelationState.Asserted;
                processEvent.CorrelationMethod = "ProcmonSyntheticAlias";
                processEvent.CorrelationCandidateCount = 1;
                processEvent.CorrelationDiagnostics = "Attached to the source-run-scoped Procmon synthetic process entity.";
            }
        }

        var planned = PlanBatches(request, items, eventRows, publisher);
        var persisted = 0L;
        var duplicate = 0L;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        try
        {
            foreach (var batch in planned)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var published = await publisher.PublishAsync(batch, cancellationToken).ConfigureAwait(false);
                persisted += published.PersistedRowCount;
                duplicate += published.DuplicateRowCount;
                diagnostics.AddRange(published.Diagnostics);
                progress?.Report(new EvidenceSourceProgress
                {
                    AdapterId = Id,
                    SourceRunId = request.SourceRunId,
                    ReceivedCount = result.TotalRows,
                    NormalizedCount = Math.Min(result.TotalRows, persisted + duplicate),
                    PersistedCount = persisted,
                    DuplicateCount = duplicate,
                    FailedCount = result.FailedRows,
                    Message = "Process Monitor processes and events normalized."
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
                Code = "ProcessMonitorPublishFailed",
                Severity = EvidenceSourceDiagnosticSeverity.Error,
                Message = ex.Message,
                IsRetryable = true
            });
            return CreateResult(
                persisted > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Failed,
                result,
                persisted,
                duplicate,
                diagnostics,
                Math.Max(1, result.FailedRows));
        }

        return CreateResult(
            result.FailedRows > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Completed,
            result,
            persisted,
            duplicate,
            diagnostics,
            result.FailedRows);
    }

    private IReadOnlyList<EvidenceSourceEmissionBatch> PlanBatches(
        EvidenceSourceAdapterRequest request,
        IReadOnlyList<ProcessObservationAdapterItem> items,
        IReadOnlyList<TelemetryEventRecord> events,
        IEvidenceSourcePublisher publisher)
    {
        var batches = new List<EvidenceSourceEmissionBatch>();
        var maxRows = GetEffectiveBatchRowLimit(Descriptor, publisher);
        var processRows = 1 + Math.Max(1, items.Select(item => item.Aliases.Count).DefaultIfEmpty(1).Max());
        var processBatchSize = Math.Max(1, maxRows / processRows);
        foreach (var chunk in items.Chunk(processBatchSize))
        {
            batches.Add(new EvidenceSourceEmissionBatch
            {
                SourceRunId = request.SourceRunId,
                IngestionJobId = request.IngestionJobId,
                Sequence = batches.Count + 1,
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
            });
        }

        foreach (var chunk in events.Chunk(maxRows))
        {
            var eventRows = chunk.ToArray();
            batches.Add(new EvidenceSourceEmissionBatch
            {
                SourceRunId = request.SourceRunId,
                IngestionJobId = request.IngestionJobId,
                Sequence = batches.Count + 1,
                Events = eventRows,
                Identities = eventRows.Select(processEvent =>
                {
                    var external = $"{processEvent.RawLogName}|{processEvent.RawRecordId}";
                    var id = ProcessObservationAdapterFactory.CreateStableId(
                        "procmon-event",
                        request.SourceRunId,
                        external,
                        processEvent.TimestampUtc.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    return new EvidenceSourceEmissionIdentity
                    {
                        EvidenceKind = EvidenceReferenceKind.Event,
                        EvidenceId = id,
                        ExternalIdentity = external,
                        DeduplicationKey = id,
                        RawReference = external
                    };
                }).ToArray()
            });
        }

        if (batches.Count > 0)
        {
            batches[^1] = batches[^1] with { IsFinalBatch = true };
        }

        return batches;
    }

    private static EvidenceSourceExecutionResult CreateResult(
        EvidenceSourceCompletionState state,
        ProcessMonitorImportResult input,
        long persisted,
        long duplicate,
        IReadOnlyList<EvidenceSourceDiagnostic> diagnostics,
        long failed)
        => new()
        {
            State = state,
            ReceivedCount = input.TotalRows,
            NormalizedCount = input.Events.Count + input.Processes.Count,
            PersistedCount = persisted,
            DuplicateCount = duplicate,
            FailedCount = failed,
            Diagnostics = diagnostics
        };
}
