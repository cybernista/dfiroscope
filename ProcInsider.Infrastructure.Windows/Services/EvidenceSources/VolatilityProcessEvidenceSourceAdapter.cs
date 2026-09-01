using ProcInsider.Models;
using ProcInsider.Models.EvidenceSources;

namespace ProcInsider.Services.EvidenceSources;

public sealed record VolatilityProcessEvidenceSourceInput
{
    public IReadOnlyList<VolatilityPluginRunRecord> PluginRuns { get; init; } =
        Array.Empty<VolatilityPluginRunRecord>();

    public IReadOnlyList<MemoryProcessRecord> MemoryProcesses { get; init; } =
        Array.Empty<MemoryProcessRecord>();
}

public sealed class VolatilityProcessEvidenceSourceAdapter
    : EvidenceSourceAdapterBase<VolatilityProcessEvidenceSourceInput>
{
    public const string Id = "procinsider.volatility-process";
    public const string Version = "1.0.0";
    public const string ParserPrerequisite = "volatility.normalized-output";

    private readonly EvidenceRelationService _relationService;

    public VolatilityProcessEvidenceSourceAdapter(EvidenceRelationService? relationService = null)
    {
        _relationService = relationService ?? new EvidenceRelationService();
    }

    public override EvidenceSourceAdapterDescriptor Descriptor { get; } = new()
    {
        AdapterId = Id,
        AdapterVersion = Version,
        DisplayName = "Volatility memory processes",
        Description = "Preserves memory-process rows and emits canonical process observations only for exact scoped PID/create-time identities.",
        Category = EvidenceSourceCategory.DerivedAnalyzer,
        Capabilities =
            EvidenceSourceCapability.ProcessObservations |
            EvidenceSourceCapability.IndependentArtifacts |
            EvidenceSourceCapability.Relationships |
            EvidenceSourceCapability.RawReferences |
            EvidenceSourceCapability.DerivationLineage,
        MaxBatchRowCount = 1024,
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
                Kind = EvidenceSourcePrerequisiteKind.SourceRun,
                Description = "Volatility plugin output has been normalized by the scheduler-owned execution service."
            }
        ]
    };

    protected override void ValidateInput(VolatilityProcessEvidenceSourceInput input, List<string> errors)
    {
        if (input.PluginRuns.Count == 0 && input.MemoryProcesses.Count == 0)
        {
            errors.Add("At least one Volatility run or memory-process row is required.");
        }
    }

    protected override async ValueTask<EvidenceSourceExecutionResult> ExecuteCoreAsync(
        EvidenceSourceAdapterRequest request,
        VolatilityProcessEvidenceSourceInput input,
        IEvidenceSourcePublisher publisher,
        IProgress<EvidenceSourceProgress>? progress,
        CancellationToken cancellationToken)
    {
        var identity = ProcessObservationAdapterFactory.CloneIdentity(
            request.EvidenceIdentity,
            request.EvidenceIdentity.CaptureId,
            Id);
        foreach (var run in input.PluginRuns)
        {
            ProcessObservationAdapterFactory.ApplyIdentity(run, identity, Id);
            run.JobId = request.IngestionJobId;
            run.SourceRunId = request.SourceRunId;
            run.IngestionJobId = request.IngestionJobId.ToString("D");
        }

        var exactItems = new Dictionary<string, ProcessObservationAdapterItem>(StringComparer.Ordinal);
        var unresolved = 0;
        foreach (var memoryProcess in input.MemoryProcesses)
        {
            ProcessObservationAdapterFactory.ApplyIdentity(memoryProcess, identity, Id);
            memoryProcess.SourceRunId = request.SourceRunId;
            memoryProcess.IngestionJobId = request.IngestionJobId.ToString("D");
            if (memoryProcess.ProcessId > 0 && memoryProcess.CreateTimeUtc.HasValue)
            {
                var processKey = $"memory:{memoryProcess.ArtifactId}";
                var record = new ProcessRecord
                {
                    CaseId = identity.CaseId,
                    EvidenceSessionId = identity.EvidenceSessionId,
                    CaptureId = identity.CaptureId,
                    SourceIdentityId = Id,
                    HostId = identity.HostId,
                    ExecutionRootId = identity.ExecutionRootId,
                    ProcessKey = processKey,
                    ProcessId = memoryProcess.ProcessId,
                    StartTimeUtc = memoryProcess.CreateTimeUtc,
                    EndTimeUtc = memoryProcess.ExitTimeUtc,
                    Status = memoryProcess.ExitTimeUtc.HasValue ? ProcessStatus.Exited : ProcessStatus.NotFound,
                    ParentProcessId = memoryProcess.ParentProcessId,
                    ProcessName = string.IsNullOrWhiteSpace(memoryProcess.ProcessName) ? "<unknown>" : memoryProcess.ProcessName,
                    ProcessPath = string.IsNullOrWhiteSpace(memoryProcess.ImagePath) ? "<not available>" : memoryProcess.ImagePath,
                    CommandLine = string.IsNullOrWhiteSpace(memoryProcess.CommandLine) ? "<not available>" : memoryProcess.CommandLine,
                    SessionId = memoryProcess.SessionId,
                    Architecture = string.Equals(memoryProcess.Wow64, "True", StringComparison.OrdinalIgnoreCase) ? "x86" : "<not available>",
                    FirstObservedUtc = memoryProcess.CreateTimeUtc.Value,
                    LastObservedUtc = memoryProcess.ExitTimeUtc ?? memoryProcess.CreateTimeUtc.Value,
                    LastSource = "VolatilityMemoryProcess"
                };
                var item = ProcessObservationAdapterFactory.CreateFromProcessRecord(
                    record,
                    identity,
                    request.SourceRunId,
                    request.IngestionJobId,
                    Id,
                    Version,
                    record.LastObservedUtc,
                    ProcessObservationKind.VolatilityMemoryProcess,
                    ProcessEntityResolutionStrategy.ExactOrSourceAlias,
                    rawRecordId: memoryProcess.RawRowHash,
                    metadataJson: "{\"identityPolicy\":\"exact-scoped-pid-create-time\"}");
                item.Observation.CorrelationMethod = ProcessCorrelationMethod.ExactMemoryPidCreateTime;
                memoryProcess.ProcessKey = processKey;
                memoryProcess.CorrelationState = MemoryProcessCorrelationState.Correlated;
                memoryProcess.CorrelationMethod = "Exact scoped PID and memory create time";
                memoryProcess.CorrelationConfidence = 1.0;
                exactItems[memoryProcess.ArtifactId] = item;
            }
            else
            {
                memoryProcess.ProcessKey = string.Empty;
                memoryProcess.CorrelationState = MemoryProcessCorrelationState.MemoryOnly;
                memoryProcess.CorrelationMethod = memoryProcess.ProcessId <= 0
                    ? "Memory row has no usable PID"
                    : "Memory row has no exact process create time; PID-only correlation is forbidden";
                memoryProcess.CorrelationConfidence = 0;
                unresolved++;
            }
        }

        var batches = PlanBatches(request, input, exactItems, publisher);
        var persisted = 0L;
        var duplicate = 0L;
        var diagnostics = new List<EvidenceSourceDiagnostic>();
        try
        {
            foreach (var batch in batches)
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
                    ReceivedCount = input.MemoryProcesses.Count,
                    NormalizedCount = Math.Min(input.MemoryProcesses.Count, persisted + duplicate),
                    UnresolvedCount = unresolved,
                    PersistedCount = persisted,
                    DuplicateCount = duplicate,
                    Message = "Volatility memory-process evidence normalized."
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
                Code = "VolatilityProcessPublishFailed",
                Severity = EvidenceSourceDiagnosticSeverity.Error,
                Message = ex.Message,
                IsRetryable = true
            });
            return CreateResult(
                persisted > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Failed,
                input,
                unresolved,
                persisted,
                duplicate,
                diagnostics,
                Math.Max(1, input.MemoryProcesses.Count - exactItems.Count));
        }

        var failedRuns = input.PluginRuns.Count(run => run.Status == VolatilityPluginRunStatus.Failed);
        return CreateResult(
            failedRuns > 0 ? EvidenceSourceCompletionState.Partial : EvidenceSourceCompletionState.Completed,
            input,
            unresolved,
            persisted,
            duplicate,
            diagnostics,
            failedRuns);
    }

    private IReadOnlyList<EvidenceSourceEmissionBatch> PlanBatches(
        EvidenceSourceAdapterRequest request,
        VolatilityProcessEvidenceSourceInput input,
        IReadOnlyDictionary<string, ProcessObservationAdapterItem> exactItems,
        IEvidenceSourcePublisher publisher)
    {
        var batches = new List<EvidenceSourceEmissionBatch>();
        var maxRows = GetEffectiveBatchRowLimit(Descriptor, publisher);
        foreach (var chunk in input.PluginRuns.Chunk(maxRows))
        {
            var runs = chunk.ToArray();
            var relations = runs.SelectMany(run => CreatePluginRunRelations(request, run)).ToArray();
            batches.Add(new EvidenceSourceEmissionBatch
            {
                SourceRunId = request.SourceRunId,
                IngestionJobId = request.IngestionJobId,
                Sequence = batches.Count + 1,
                VolatilityPluginRuns = runs,
                Relations = relations,
                Identities = runs.SelectMany(run =>
                    new[]
                    {
                        new EvidenceSourceEmissionIdentity
                        {
                            EvidenceKind = EvidenceReferenceKind.VolatilityPluginRun,
                            EvidenceId = run.RunId,
                            ExternalIdentity = $"{run.ImageId}|{run.PluginName}|{run.RunId}",
                            DeduplicationKey = $"{Id}|run|{request.SourceRunId}|{run.RunId}",
                            RawReference = run.StdoutPath
                        },
                        new EvidenceSourceEmissionIdentity
                        {
                            EvidenceKind = EvidenceReferenceKind.RawRecord,
                            EvidenceId = BuildPluginRawId(run.RunId),
                            ExternalIdentity = string.IsNullOrWhiteSpace(run.RawOutputHash)
                                ? run.StdoutPath
                                : run.RawOutputHash,
                            DeduplicationKey = $"{Id}|raw|{request.SourceRunId}|{run.RunId}",
                            RawReference = run.StdoutPath
                        }
                    }.Concat(CreatePluginRunRelations(request, run).Select(relation =>
                        new EvidenceSourceEmissionIdentity
                        {
                            EvidenceKind = EvidenceReferenceKind.GenericArtifact,
                            EvidenceId = relation.RelationId,
                            ExternalIdentity = relation.DecisionKey,
                            DeduplicationKey = $"{Id}|relation|{relation.RelationId}"
                        }))).ToArray()
            });
        }

        const int rowsPerMemory = 8;
        var memoryBatchSize = Math.Max(1, maxRows / rowsPerMemory);
        foreach (var chunk in input.MemoryProcesses.Chunk(memoryBatchSize))
        {
            var memoryRows = chunk.ToArray();
            var items = memoryRows
                .Where(row => exactItems.ContainsKey(row.ArtifactId))
                .Select(row => exactItems[row.ArtifactId])
                .ToArray();
            var relations = memoryRows
                .Select(row => CreateMemoryProcessRelation(request, row))
                .ToArray();
            batches.Add(new EvidenceSourceEmissionBatch
            {
                SourceRunId = request.SourceRunId,
                IngestionJobId = request.IngestionJobId,
                Sequence = batches.Count + 1,
                MemoryProcesses = memoryRows,
                ProcessObservations = items.Select(item => item.Observation).ToArray(),
                ProcessAliases = items.SelectMany(item => item.Aliases).ToArray(),
                Relations = relations,
                Identities = memoryRows.SelectMany(row =>
                {
                    var identities = new List<EvidenceSourceEmissionIdentity>
                    {
                        new()
                        {
                            EvidenceKind = EvidenceReferenceKind.MemoryProcess,
                            EvidenceId = row.ArtifactId,
                            ExternalIdentity = $"{row.PluginRunId}|{row.RowNumber}|{row.ObjectOffset}",
                            DeduplicationKey = $"{Id}|memory|{row.ArtifactId}",
                            RawReference = row.RawRowHash
                        },
                        new()
                        {
                            EvidenceKind = EvidenceReferenceKind.GenericArtifact,
                            EvidenceId = CreateMemoryProcessRelation(request, row).RelationId,
                            ExternalIdentity = CreateMemoryProcessRelation(request, row).DecisionKey,
                            DeduplicationKey = $"{Id}|relation|{CreateMemoryProcessRelation(request, row).RelationId}"
                        }
                    };
                    if (exactItems.TryGetValue(row.ArtifactId, out var item))
                    {
                        identities.Add(new EvidenceSourceEmissionIdentity
                        {
                            EvidenceKind = EvidenceReferenceKind.ProcessObservation,
                            EvidenceId = item.Observation.ObservationId,
                            ExternalIdentity = item.Observation.SourceNativeAlias,
                            DeduplicationKey = item.Observation.ObservationId,
                            RawReference = item.Observation.RawRecordId
                        });
                    }

                    return identities;
                }).ToArray()
            });
        }

        if (batches.Count > 0)
        {
            batches[^1] = batches[^1] with { IsFinalBatch = true };
        }

        return batches;
    }

    private IReadOnlyList<EvidenceRelation> CreatePluginRunRelations(
        EvidenceSourceAdapterRequest request,
        VolatilityPluginRunRecord run)
    {
        var identity = request.EvidenceIdentity with
        {
            CaptureId = string.IsNullOrWhiteSpace(run.CaptureId)
                ? request.EvidenceIdentity.CaptureId
                : run.CaptureId
        };
        return
        [
            _relationService.CreateDecision(
                new EvidenceReference(EvidenceReferenceKind.MemoryImage, run.ImageId),
                new EvidenceReference(EvidenceReferenceKind.SourceRun, request.SourceRunId),
                EvidenceRelationType.DerivedFrom,
                EvidenceCorrelationState.Exact,
                "VolatilityRunInput",
                1.0,
                identity,
                Id,
                decisionKey: $"volatility:{run.ImageId}:source-run:{request.SourceRunId}",
                observedUtc: run.RequestedUtc,
                sourceRunId: request.SourceRunId,
                ingestionJobId: request.IngestionJobId.ToString("D"),
                rawInputId: request.InputHash,
                resolverVersion: Version),
            _relationService.CreateDecision(
                new EvidenceReference(EvidenceReferenceKind.SourceRun, request.SourceRunId),
                new EvidenceReference(EvidenceReferenceKind.VolatilityPluginRun, run.RunId),
                EvidenceRelationType.DerivedFrom,
                EvidenceCorrelationState.Exact,
                "VolatilityPluginExecution",
                1.0,
                identity,
                Id,
                decisionKey: $"volatility:{run.RunId}:execution",
                observedUtc: run.RequestedUtc,
                sourceRunId: request.SourceRunId,
                ingestionJobId: request.IngestionJobId.ToString("D"),
                rawInputId: run.ImageId,
                resolverVersion: Version),
            _relationService.CreateDecision(
                new EvidenceReference(EvidenceReferenceKind.VolatilityPluginRun, run.RunId),
                new EvidenceReference(EvidenceReferenceKind.RawRecord, BuildPluginRawId(run.RunId)),
                EvidenceRelationType.ExtractedFrom,
                EvidenceCorrelationState.Exact,
                "VolatilityRawSidecar",
                1.0,
                identity,
                Id,
                decisionKey: $"volatility:{run.RunId}:raw",
                observedUtc: run.CompletedUtc ?? run.RequestedUtc,
                sourceRunId: request.SourceRunId,
                ingestionJobId: request.IngestionJobId.ToString("D"),
                rawInputId: run.RawOutputHash,
                resolverVersion: Version)
        ];
    }

    private EvidenceRelation CreateMemoryProcessRelation(
        EvidenceSourceAdapterRequest request,
        MemoryProcessRecord row)
        => _relationService.CreateDecision(
            new EvidenceReference(EvidenceReferenceKind.RawRecord, BuildPluginRawId(row.PluginRunId)),
            new EvidenceReference(EvidenceReferenceKind.MemoryProcess, row.ArtifactId),
            EvidenceRelationType.DerivedFrom,
            EvidenceCorrelationState.Exact,
            "VolatilityNormalization",
            1.0,
            request.EvidenceIdentity with
            {
                CaptureId = string.IsNullOrWhiteSpace(row.CaptureId)
                    ? request.EvidenceIdentity.CaptureId
                    : row.CaptureId
            },
            Id,
            decisionKey: $"volatility:{row.ArtifactId}:normalized",
            observedUtc: row.CreateTimeUtc ?? DateTime.UtcNow,
            sourceRunId: request.SourceRunId,
            ingestionJobId: request.IngestionJobId.ToString("D"),
            rawInputId: row.RawRowHash,
            resolverVersion: Version);

    private static string BuildPluginRawId(string pluginRunId)
        => $"volatility-raw:{pluginRunId}";

    private static EvidenceSourceExecutionResult CreateResult(
        EvidenceSourceCompletionState state,
        VolatilityProcessEvidenceSourceInput input,
        long unresolved,
        long persisted,
        long duplicate,
        IReadOnlyList<EvidenceSourceDiagnostic> diagnostics,
        long failed)
        => new()
        {
            State = state,
            ReceivedCount = input.MemoryProcesses.Count,
            NormalizedCount = input.MemoryProcesses.Count,
            UnresolvedCount = unresolved,
            PersistedCount = persisted,
            DuplicateCount = duplicate,
            FailedCount = failed,
            Diagnostics = diagnostics
        };
}
