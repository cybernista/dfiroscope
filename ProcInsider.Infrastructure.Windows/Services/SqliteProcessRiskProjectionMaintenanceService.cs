using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum ProcessRiskProjectionRebuildState
{
    Completed = 0,
    Unsupported = 1
}

public sealed record ProcessRiskProjectionRebuildProgress(
    int EvaluatedProcesses,
    int TotalProcesses,
    string ProcessEntityId,
    int ReadyProjections,
    int FailedProjections);

public sealed record ProcessRiskProjectionRebuildResult(
    ProcessRiskProjectionRebuildState State,
    int EvaluatedProcesses,
    int ReadyProjections,
    int FailedProjections,
    string InputSetHash,
    string Diagnostic);

internal interface ISqliteProcessRiskProjectionMaintenanceService
{
    ProcessRiskProjectionRebuildResult Rebuild(
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken);

    ProcessRiskProjectionRebuildResult ReplaceSigmaEvidenceAndRebuild(
        IReadOnlyList<LocalProcessSigmaEvidence> evidence,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken);

    ProcessRiskProjectionRebuildResult ReplaceBaselineEvidenceAndRebuild(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> evidence,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken);

    ProcessRiskProjectionRebuildResult ReplaceYaraAttributionsAndRebuild(
        IReadOnlyList<YaraProcessAttributionResult> attributions,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken);
}

internal sealed class UnavailableSqliteProcessRiskProjectionMaintenanceService
    : ISqliteProcessRiskProjectionMaintenanceService
{
    public ProcessRiskProjectionRebuildResult Rebuild(
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "Process-risk projection maintenance requires the viewer-owned SqliteAnalysisIndexMaintenanceStoreFactory.");

    public ProcessRiskProjectionRebuildResult ReplaceSigmaEvidenceAndRebuild(
        IReadOnlyList<LocalProcessSigmaEvidence> evidence,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "Sigma process-risk maintenance requires the viewer-owned SqliteAnalysisIndexMaintenanceStoreFactory.");

    public ProcessRiskProjectionRebuildResult ReplaceBaselineEvidenceAndRebuild(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> evidence,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "Baseline process-risk maintenance requires the viewer-owned SqliteAnalysisIndexMaintenanceStoreFactory.");

    public ProcessRiskProjectionRebuildResult ReplaceYaraAttributionsAndRebuild(
        IReadOnlyList<YaraProcessAttributionResult> attributions,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "YARA process-risk maintenance requires the viewer-owned SqliteAnalysisIndexMaintenanceStoreFactory.");
}

/// <summary>
/// Rebuilds process-risk derived state through one store-authorized SQLite
/// transaction. It cannot open, select, migrate, or independently commit a database.
/// </summary>
internal sealed class SqliteProcessRiskProjectionMaintenanceService
    : ISqliteProcessRiskProjectionMaintenanceService
{
    private const int BatchSize = 256;
    private const int MaximumPersistedSigmaEvidence = SigmaRiskEvidenceMaterializer.MaximumFindings;
    private const int MaximumPersistedBaselineEvidence = 1_000;
    private const int MaximumPersistedYaraAttributions = 1_000;
    private const int MaximumIdentityLength = 512;
    private const int MaximumSerializedEvidenceLength = 131_072;
    private const string AggregationVersion = "1";
    private readonly SqliteProcessRiskProjectionMaintenanceContext _context;

    internal SqliteProcessRiskProjectionMaintenanceService(
        SqliteProcessRiskProjectionMaintenanceContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public ProcessRiskProjectionRebuildResult Rebuild(
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_context.TableExists("ProcessRiskBaselineInputs") ||
            !_context.TableExists("ProcessRiskProjections") ||
            !_context.TableExists("ProcessObservations"))
        {
            return new ProcessRiskProjectionRebuildResult(
                ProcessRiskProjectionRebuildState.Unsupported,
                0,
                0,
                0,
                string.Empty,
                "This supported capture revision does not contain the complete cataloged process-risk analysis-input schema.");
        }

        var totalProcesses = CountProcessEntities();
        var yaraGeneration = ReadPersistedYaraGeneration();
        return _context.ExecuteTransactionWithRetry(
            () => RebuildCore(
                totalProcesses,
                ReadPersistedSigmaEvidence(),
                ReadPersistedBaselineEvidence(),
                yaraGeneration,
                progress,
                cancellationToken),
            cancellationToken);
    }

    public ProcessRiskProjectionRebuildResult ReplaceSigmaEvidenceAndRebuild(
        IReadOnlyList<LocalProcessSigmaEvidence> evidence,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        cancellationToken.ThrowIfCancellationRequested();
        if (!_context.TableExists("ProcessRiskSigmaInputs") ||
            !_context.TableExists("ProcessRiskBaselineInputs") ||
            !_context.TableExists("ProcessRiskProjections") ||
            !_context.TableExists("ProcessObservations"))
        {
            return new ProcessRiskProjectionRebuildResult(
                ProcessRiskProjectionRebuildState.Unsupported,
                0,
                0,
                0,
                string.Empty,
                "This supported capture revision does not contain the cataloged Sigma risk-input schema.");
        }

        var ordered = ValidateAndOrderSigmaEvidence(evidence);
        var baselineByEntity = ReadPersistedBaselineEvidence();
        var yaraGeneration = ReadPersistedYaraGeneration();
        var totalProcesses = CountProcessEntities();
        return _context.ExecuteTransactionWithRetry(() =>
        {
            ReplacePersistedSigmaEvidence(ordered);
            return RebuildCore(
                totalProcesses,
                GroupSigmaEvidence(ordered),
                baselineByEntity,
                yaraGeneration,
                progress,
                cancellationToken);
        }, cancellationToken);
    }

    public ProcessRiskProjectionRebuildResult ReplaceBaselineEvidenceAndRebuild(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> evidence,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        cancellationToken.ThrowIfCancellationRequested();
        if (!_context.TableExists("ProcessRiskBaselineInputs") ||
            !_context.TableExists("ProcessRiskSigmaInputs") ||
            !_context.TableExists("ProcessRiskProjections") ||
            !_context.TableExists("ProcessObservations"))
        {
            return new ProcessRiskProjectionRebuildResult(
                ProcessRiskProjectionRebuildState.Unsupported,
                0,
                0,
                0,
                string.Empty,
                "This supported capture revision does not contain the cataloged Baseline risk-input schema.");
        }

        var ordered = ValidateAndOrderBaselineEvidence(evidence);
        ValidateBaselineEvidenceAgainstCurrentObservations(ordered);
        var sigmaByEntity = ReadPersistedSigmaEvidence();
        var yaraGeneration = ReadPersistedYaraGeneration();
        var totalProcesses = CountProcessEntities();
        return _context.ExecuteTransactionWithRetry(() =>
        {
            ReplacePersistedBaselineEvidence(ordered);
            return RebuildCore(
                totalProcesses,
                sigmaByEntity,
                GroupBaselineEvidence(ordered),
                yaraGeneration,
                progress,
                cancellationToken);
        }, cancellationToken);
    }

    public ProcessRiskProjectionRebuildResult ReplaceYaraAttributionsAndRebuild(
        IReadOnlyList<YaraProcessAttributionResult> attributions,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attributions);
        cancellationToken.ThrowIfCancellationRequested();
        if (!_context.TableExists("ProcessRiskYaraInputs") ||
            !_context.TableExists("YaraAnalysisScans") ||
            !_context.TableExists("EvidenceRelations") ||
            !_context.TableExists("ProcessRiskBaselineInputs") ||
            !_context.TableExists("ProcessRiskSigmaInputs") ||
            !_context.TableExists("ProcessRiskProjections") ||
            !_context.TableExists("ProcessObservations"))
        {
            return new ProcessRiskProjectionRebuildResult(
                ProcessRiskProjectionRebuildState.Unsupported,
                0,
                0,
                0,
                string.Empty,
                "This supported capture revision does not contain the cataloged YARA risk-input schema.");
        }

        var generation = ValidateAndBuildYaraGeneration(attributions);
        var sigmaByEntity = ReadPersistedSigmaEvidence();
        var baselineByEntity = ReadPersistedBaselineEvidence();
        var totalProcesses = CountProcessEntities();
        return _context.ExecuteTransactionWithRetry(() =>
        {
            ReplacePersistedYaraGeneration(generation);
            return RebuildCore(
                totalProcesses,
                sigmaByEntity,
                baselineByEntity,
                generation,
                progress,
                cancellationToken);
        }, cancellationToken);
    }

    private ProcessRiskProjectionRebuildResult RebuildCore(
        int totalProcesses,
        IReadOnlyDictionary<string, IReadOnlyList<LocalProcessSigmaEvidence>> sigmaByEntity,
        IReadOnlyDictionary<string, IReadOnlyList<LocalProcessBaselineComparisonEvidence>> baselineByEntity,
        PersistedYaraGeneration? yaraGeneration,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress,
        CancellationToken cancellationToken)
    {
        using (var deleteContributors = _context.CreateCommand(
                   "DELETE FROM ProcessRiskProjectionContributors;"))
        {
            deleteContributors.ExecuteNonQuery();
        }

        using (var deleteSources = _context.CreateCommand(
                   "DELETE FROM ProcessRiskProjectionSources;"))
        {
            deleteSources.ExecuteNonQuery();
        }

        using (var deleteProjections = _context.CreateCommand(
                   "DELETE FROM ProcessRiskProjections;"))
        {
            deleteProjections.ExecuteNonQuery();
        }

        var evaluated = 0;
        var ready = 0;
        var failed = 0;
        using var inputSetHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var afterEntityId = string.Empty;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var observations = ReadObservationBatch(afterEntityId);
            if (observations.Count == 0)
            {
                break;
            }

            var entityIds = observations.Select(item => item.ProcessEntityId).ToArray();
            var peByEntity = ReadLatestPeAnalyses(entityIds);
            AttachLatestAuthenticode(peByEntity.Values);
            var eventsByEntity = ReadLatestProcessEvents(entityIds, networkOnly: false);
            var networkEventsByEntity = ReadLatestProcessEvents(entityIds, networkOnly: true);
            var filesystemByEntity = ReadLatestFilesystemEvidence(entityIds);
            var memoryByEntity = ReadLatestMemoryEvidence(entityIds);
            foreach (var selected in observations)
            {
                cancellationToken.ThrowIfCancellationRequested();
                peByEntity.TryGetValue(selected.ProcessEntityId, out var pe);
                var processEvents = eventsByEntity.TryGetValue(selected.ProcessEntityId, out var exactEvents)
                    ? exactEvents
                    : Array.Empty<TelemetryEventRecord>();
                var networkEvents = networkEventsByEntity.TryGetValue(
                    selected.ProcessEntityId,
                    out var exactNetworkEvents)
                    ? exactNetworkEvents
                    : Array.Empty<TelemetryEventRecord>();
                var filesystemEvidence = filesystemByEntity.TryGetValue(
                    selected.ProcessEntityId,
                    out var exactFilesystemEvidence)
                    ? exactFilesystemEvidence
                    : Array.Empty<LocalProcessFilesystemEvidence>();
                var memoryEvidence = memoryByEntity.TryGetValue(
                    selected.ProcessEntityId,
                    out var exactMemoryEvidence)
                    ? exactMemoryEvidence
                    : Array.Empty<LocalProcessMemoryEvidence>();
                var sigmaEvidence = sigmaByEntity.TryGetValue(
                    selected.ProcessEntityId,
                    out var exactSigmaEvidence)
                    ? exactSigmaEvidence
                    : Array.Empty<LocalProcessSigmaEvidence>();
                var baselineEvidence = baselineByEntity.TryGetValue(
                    selected.ProcessEntityId,
                    out var exactBaselineEvidence)
                    ? exactBaselineEvidence
                    : Array.Empty<LocalProcessBaselineComparisonEvidence>();
                var yaraInput = yaraGeneration != null &&
                                yaraGeneration.ByEntity.TryGetValue(
                                    selected.ProcessEntityId,
                                    out var exactYaraInput)
                    ? exactYaraInput
                    : null;
                var policy = yaraGeneration == null
                    ? ProcessRiskAggregationPolicy.LocalFirstVersion1
                    : ProcessRiskAggregationPolicy.LocalFirstVersion2;
                var inputHash = ComputeInputHash(
                    selected,
                    pe,
                    processEvents,
                    networkEvents,
                    filesystemEvidence,
                    memoryEvidence,
                    sigmaEvidence,
                    baselineEvidence,
                    yaraGeneration?.GenerationId,
                    yaraInput?.Attribution);
                inputSetHasher.AppendData(Encoding.UTF8.GetBytes(inputHash));
                inputSetHasher.AppendData("\n"u8);
                if (string.IsNullOrWhiteSpace(selected.MaterializationFailure))
                {
                    if (TryBuildProjection(
                            selected.Observation,
                            pe,
                            processEvents,
                            networkEvents,
                            filesystemEvidence,
                            memoryEvidence,
                            sigmaEvidence,
                            baselineEvidence,
                            yaraInput,
                            policy,
                            inputHash,
                            out var projection,
                            out var diagnostic))
                    {
                        InsertReadyProjection(
                            selected,
                            pe,
                            policy,
                            inputHash,
                            projection!,
                            diagnostic);
                        ready++;
                    }
                    else
                    {
                        InsertFailedProjection(
                            selected,
                            pe,
                            processEvents,
                            networkEvents,
                            filesystemEvidence,
                            memoryEvidence,
                            sigmaEvidence,
                            baselineEvidence,
                            yaraInput,
                            policy,
                            inputHash,
                            diagnostic);
                        failed++;
                    }
                }
                else
                {
                    InsertFailedProjection(
                        selected,
                        pe,
                        processEvents,
                        networkEvents,
                        filesystemEvidence,
                        memoryEvidence,
                        sigmaEvidence,
                        baselineEvidence,
                        yaraInput,
                        policy,
                        inputHash,
                        selected.MaterializationFailure);
                    failed++;
                }

                evaluated++;
                progress?.Report(new ProcessRiskProjectionRebuildProgress(
                    evaluated,
                    totalProcesses,
                    selected.ProcessEntityId,
                    ready,
                    failed));
            }

            afterEntityId = observations[^1].ProcessEntityId;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var inputSetHash = Convert.ToHexString(inputSetHasher.GetHashAndReset()).ToLowerInvariant();
        return new ProcessRiskProjectionRebuildResult(
            ProcessRiskProjectionRebuildState.Completed,
            evaluated,
            ready,
            failed,
            inputSetHash,
            $"Rebuilt {ready} ready and {failed} failed process-risk projections atomically from {evaluated} exact process entities.");
    }

    private static bool TryBuildProjection(
        ProcessObservation observation,
        PeAnalysisRecord? pe,
        IReadOnlyList<TelemetryEventRecord> processEvents,
        IReadOnlyList<TelemetryEventRecord> networkEvents,
        IReadOnlyList<LocalProcessFilesystemEvidence> filesystemEvidence,
        IReadOnlyList<LocalProcessMemoryEvidence> memoryEvidence,
        IReadOnlyList<LocalProcessSigmaEvidence> sigmaEvidence,
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> baselineEvidence,
        PersistedYaraInput? yaraInput,
        ProcessRiskAggregationPolicy policy,
        string inputHash,
        out ProcessRiskScoreProjection? projection,
        out string diagnostic)
    {
        var verification = pe?.AuthenticodeVerification;
        var evaluatedUtc = new[]
            {
                observation.ObservedUtc,
                pe?.AnalyzedUtc ?? DateTime.MinValue,
                verification?.VerificationTimeUtc ?? DateTime.MinValue,
                processEvents.Count == 0
                    ? DateTime.MinValue
                    : processEvents.Max(item => item.TimestampUtc),
                networkEvents.Count == 0
                    ? DateTime.MinValue
                    : networkEvents.Max(item => item.TimestampUtc),
                LatestFilesystemUtc(filesystemEvidence) ?? DateTime.MinValue,
                LatestMemoryUtc(memoryEvidence) ?? DateTime.MinValue,
                LatestSigmaUtc(sigmaEvidence) ?? DateTime.MinValue,
                LatestBaselineUtc(baselineEvidence) ?? DateTime.MinValue,
                yaraInput?.CompletedUtc ?? DateTime.MinValue
            }
            .Max();
        if (evaluatedUtc.Kind != DateTimeKind.Utc)
        {
            projection = null;
            diagnostic = "The selected evidence carries a non-UTC or malformed evaluation timestamp.";
            return false;
        }

        var mapping = LocalProcessRiskMapper.Map(new LocalProcessRiskMappingRequest
        {
            ProcessObservation = observation,
            PeAnalysis = pe,
            PePropertiesAvailability = IsPeStale(observation, pe)
                ? AnalysisSourceAvailability.Stale
                : null,
            AuthenticodeAvailability = IsAuthenticodeStale(pe, verification)
                ? AnalysisSourceAvailability.Stale
                : null,
            NetworkEventRecords = networkEvents,
            EventRecords = processEvents,
            FilesystemEvidence = filesystemEvidence,
            MemoryEvidence = memoryEvidence,
            SigmaEvidence = sigmaEvidence,
            BaselineComparisonEvidence = baselineEvidence,
            YaraAttribution = yaraInput?.Attribution,
            EvaluatedUtc = evaluatedUtc,
            Policy = policy
        });
        if (!mapping.Accepted || mapping.Result == null)
        {
            if (memoryEvidence.Count > 0 &&
                mapping.Failure is LocalProcessRiskMappingFailure.InvalidMemoryEvidence
                    or LocalProcessRiskMappingFailure.DuplicateMemoryEvidence
                    or LocalProcessRiskMappingFailure.MemoryInputLimitExceeded)
            {
                throw new InvalidDataException(
                    $"The selected exact memory evidence failed closed and the risk projection generation was not replaced: {mapping.Failure}: {mapping.Diagnostic}");
            }

            if (sigmaEvidence.Count > 0 &&
                mapping.Failure is LocalProcessRiskMappingFailure.InvalidSigmaEvidence
                    or LocalProcessRiskMappingFailure.DuplicateSigmaEvidence
                    or LocalProcessRiskMappingFailure.SigmaInputLimitExceeded)
            {
                throw new InvalidDataException(
                    $"The selected exact Sigma evidence failed closed and the risk projection generation was not replaced: {mapping.Failure}: {mapping.Diagnostic}");
            }

            if (baselineEvidence.Count > 0 &&
                mapping.Failure is LocalProcessRiskMappingFailure.InvalidBaselineComparisonEvidence
                    or LocalProcessRiskMappingFailure.DuplicateBaselineComparisonEvidence
                    or LocalProcessRiskMappingFailure.BaselineInputLimitExceeded)
            {
                throw new InvalidDataException(
                    $"The selected exact Baseline evidence failed closed and the risk projection generation was not replaced: {mapping.Failure}: {mapping.Diagnostic}");
            }

            if (yaraInput != null &&
                mapping.Failure is LocalProcessRiskMappingFailure.InvalidYaraAttribution
                    or LocalProcessRiskMappingFailure.DuplicateYaraEvidence
                    or LocalProcessRiskMappingFailure.YaraInputLimitExceeded)
            {
                throw new InvalidDataException(
                    $"The selected exact YARA attribution failed closed and the risk projection generation was not replaced: {mapping.Failure}: {mapping.Diagnostic}");
            }

            projection = null;
            diagnostic = $"Local mapper rejected the selected exact evidence: {mapping.Failure}: {mapping.Diagnostic}";
            return false;
        }

        var process = observation.Fields;
        var aggregation = ProcessRiskAggregationPolicyEngine.Aggregate(new ProcessRiskAggregationRequest
        {
            EvidenceIdentity = new EvidenceIdentity
            {
                CaseId = process.CaseId,
                EvidenceSessionId = process.EvidenceSessionId,
                CaptureId = process.CaptureId,
                SourceIdentityId = process.SourceIdentityId,
                HostId = process.HostId,
                ExecutionRootId = process.ExecutionRootId
            },
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ProjectedUtc = evaluatedUtc,
            Policy = policy,
            Findings = mapping.Result.Findings,
            Signals = mapping.Result.Signals
        });
        if (!aggregation.Accepted || aggregation.Projection == null)
        {
            projection = null;
            diagnostic = $"Risk aggregation rejected mapper output for input {inputHash}: {aggregation.Failure}: {aggregation.Diagnostic}";
            return false;
        }

        projection = aggregation.Projection;
        diagnostic = aggregation.Diagnostic;
        return true;
    }

    private void InsertReadyProjection(
        SelectedObservation selected,
        PeAnalysisRecord? pe,
        ProcessRiskAggregationPolicy policy,
        string inputHash,
        ProcessRiskScoreProjection projection,
        string diagnostic)
    {
        InsertProjectionRow(
            selected,
            pe,
            policy,
            inputHash,
            rebuildStatus: "Ready",
            diagnostic,
            projection.State,
            projection.Score,
            projection.Band,
            projection.Confidence,
            projection.Coverage,
            projection.ProjectedUtc,
            JsonSerializer.Serialize(projection));

        var sourceOrder = 0;
        foreach (var source in projection.Sources.OrderBy(item => item.SourceKind))
        {
            InsertSource(selected.ProcessEntityId, sourceOrder++, source);
        }

        for (var index = 0; index < projection.Contributors.Count; index++)
        {
            InsertContributor(selected.ProcessEntityId, index, projection.Contributors[index]);
        }
    }

    private void InsertFailedProjection(
        SelectedObservation selected,
        PeAnalysisRecord? pe,
        IReadOnlyList<TelemetryEventRecord> processEvents,
        IReadOnlyList<TelemetryEventRecord> networkEvents,
        IReadOnlyList<LocalProcessFilesystemEvidence> filesystemEvidence,
        IReadOnlyList<LocalProcessMemoryEvidence> memoryEvidence,
        IReadOnlyList<LocalProcessSigmaEvidence> sigmaEvidence,
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> baselineEvidence,
        PersistedYaraInput? yaraInput,
        ProcessRiskAggregationPolicy policy,
        string inputHash,
        string diagnostic)
    {
        var projectedUtc = MaxUtc(
            selected.Observation.ObservedUtc,
            pe?.AnalyzedUtc,
            pe?.AuthenticodeVerification?.VerificationTimeUtc,
            processEvents.Count == 0 ? null : processEvents.Max(item => item.TimestampUtc),
            networkEvents.Count == 0 ? null : networkEvents.Max(item => item.TimestampUtc),
            LatestFilesystemUtc(filesystemEvidence),
            LatestMemoryUtc(memoryEvidence),
            LatestSigmaUtc(sigmaEvidence),
            LatestBaselineUtc(baselineEvidence),
            yaraInput?.CompletedUtc);
        InsertProjectionRow(
            selected,
            pe,
            policy,
            inputHash,
            rebuildStatus: "Failed",
            diagnostic,
            ProcessRiskProjectionState.Unknown,
            null,
            ProcessRiskBand.Unknown,
            0,
            0,
            projectedUtc,
            string.Empty);

        var sourceOrder = 0;
        foreach (var policySource in policy.Sources
                     .OrderBy(item => item.SourceKind))
        {
            InsertSource(selected.ProcessEntityId, sourceOrder++, new ProcessRiskSourceCoverage
            {
                SourceKind = policySource.SourceKind,
                SourceId = policySource.SourceId,
                Availability = policySource.SourceKind == ProcessRiskSourceKind.ProcessMetadata
                    ? AnalysisSourceAvailability.Failed
                    : AnalysisSourceAvailability.NotCollected,
                ConfidenceWeight = policySource.ConfidenceWeight,
                Diagnostic = policySource.SourceKind == ProcessRiskSourceKind.ProcessMetadata
                    ? diagnostic
                    : "The process-scoped rebuild failed before this source could be evaluated."
            });
        }
    }

    private void InsertProjectionRow(
        SelectedObservation selected,
        PeAnalysisRecord? pe,
        ProcessRiskAggregationPolicy policy,
        string inputHash,
        string rebuildStatus,
        string diagnostic,
        ProcessRiskProjectionState projectionState,
        int? score,
        ProcessRiskBand band,
        double confidence,
        double coverage,
        DateTime projectedUtc,
        string projectionJson)
    {
        var process = selected.Observation.Fields ?? new ProcessRecord();
        var verification = pe?.AuthenticodeVerification;
        using var command = _context.CreateCommand("""
            INSERT INTO ProcessRiskProjections(
                ProcessEntityId, ProcessKey, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                HostId, ExecutionRootId, RebuildStatus, Diagnostic, ProjectionState, Score, Band,
                Confidence, Coverage, PolicyId, PolicyVersion, MapperId, MapperVersion,
                AggregationVersion, EvaluationId, InputIdentityHash, ProjectedUtc, ObservationId,
                PeAnalysisId, AuthenticodeVerificationId, ProjectionJson)
            VALUES(
                $ProcessEntityId, $ProcessKey, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId,
                $HostId, $ExecutionRootId, $RebuildStatus, $Diagnostic, $ProjectionState, $Score, $Band,
                $Confidence, $Coverage, $PolicyId, $PolicyVersion, $MapperId, $MapperVersion,
                $AggregationVersion, $EvaluationId, $InputIdentityHash, $ProjectedUtc, $ObservationId,
                $PeAnalysisId, $AuthenticodeVerificationId, $ProjectionJson);
            """);
        Add(command, "$ProcessEntityId", selected.ProcessEntityId);
        Add(command, "$ProcessKey", process.ProcessKey);
        Add(command, "$CaseId", process.CaseId);
        Add(command, "$EvidenceSessionId", process.EvidenceSessionId);
        Add(command, "$CaptureId", process.CaptureId);
        Add(command, "$SourceIdentityId", process.SourceIdentityId);
        Add(command, "$HostId", process.HostId);
        Add(command, "$ExecutionRootId", process.ExecutionRootId);
        Add(command, "$RebuildStatus", rebuildStatus);
        Add(command, "$Diagnostic", diagnostic);
        Add(command, "$ProjectionState", projectionState.ToString());
        Add(command, "$Score", score);
        Add(command, "$Band", band.ToString());
        Add(command, "$Confidence", confidence);
        Add(command, "$Coverage", coverage);
        Add(command, "$PolicyId", policy.PolicyId);
        Add(command, "$PolicyVersion", policy.PolicyVersion);
        Add(command, "$MapperId", LocalProcessRiskMapper.MapperId);
        Add(command, "$MapperVersion", LocalProcessRiskMapper.MapperVersion);
        Add(command, "$AggregationVersion", AggregationVersion);
        Add(command, "$EvaluationId", ComputeEvaluationId(inputHash, policy));
        Add(command, "$InputIdentityHash", inputHash);
        Add(command, "$ProjectedUtc", FormatUtc(projectedUtc));
        Add(command, "$ObservationId", selected.Observation.ObservationId);
        Add(command, "$PeAnalysisId", pe?.AnalysisId);
        Add(command, "$AuthenticodeVerificationId", verification?.VerificationId);
        Add(command, "$ProjectionJson", projectionJson);
        command.ExecuteNonQuery();
    }

    private void InsertSource(
        string processEntityId,
        int sourceOrder,
        ProcessRiskSourceCoverage source)
    {
        using var command = _context.CreateCommand("""
            INSERT INTO ProcessRiskProjectionSources(
                ProcessEntityId, SourceOrder, SourceKind, SourceId, Availability,
                ConfidenceWeight, Confidence, FindingCount, SignalCount, Diagnostic)
            VALUES(
                $ProcessEntityId, $SourceOrder, $SourceKind, $SourceId, $Availability,
                $ConfidenceWeight, $Confidence, $FindingCount, $SignalCount, $Diagnostic);
            """);
        Add(command, "$ProcessEntityId", processEntityId);
        Add(command, "$SourceOrder", sourceOrder);
        Add(command, "$SourceKind", source.SourceKind.ToString());
        Add(command, "$SourceId", source.SourceId);
        Add(command, "$Availability", source.Availability.ToString());
        Add(command, "$ConfidenceWeight", source.ConfidenceWeight);
        Add(command, "$Confidence", source.Confidence);
        Add(command, "$FindingCount", source.FindingCount);
        Add(command, "$SignalCount", source.SignalCount);
        Add(command, "$Diagnostic", source.Diagnostic);
        command.ExecuteNonQuery();
    }

    private void InsertContributor(
        string processEntityId,
        int contributorOrder,
        ProcessRiskContribution contribution)
    {
        using var command = _context.CreateCommand("""
            INSERT INTO ProcessRiskProjectionContributors(
                ProcessEntityId, ContributorOrder, SourceKind, SourceId, FindingId, SignalId,
                InputSnapshotId, ScoreDelta, Severity, Confidence, EvidenceReferencesJson, ContributionJson)
            VALUES(
                $ProcessEntityId, $ContributorOrder, $SourceKind, $SourceId, $FindingId, $SignalId,
                $InputSnapshotId, $ScoreDelta, $Severity, $Confidence, $EvidenceReferencesJson, $ContributionJson);
            """);
        Add(command, "$ProcessEntityId", processEntityId);
        Add(command, "$ContributorOrder", contributorOrder);
        Add(command, "$SourceKind", contribution.SourceKind.ToString());
        Add(command, "$SourceId", contribution.SourceId);
        Add(command, "$FindingId", contribution.Finding.FindingId);
        Add(command, "$SignalId", contribution.Signal.SignalId);
        Add(command, "$InputSnapshotId", contribution.Signal.InputSnapshotId);
        Add(command, "$ScoreDelta", contribution.Signal.ScoreDelta);
        Add(command, "$Severity", contribution.Signal.Severity.ToString());
        Add(command, "$Confidence", contribution.Signal.Confidence);
        Add(command, "$EvidenceReferencesJson", JsonSerializer.Serialize(contribution.Signal.EvidenceReferences));
        Add(command, "$ContributionJson", JsonSerializer.Serialize(contribution));
        command.ExecuteNonQuery();
    }

    private static LocalProcessSigmaEvidence[] ValidateAndOrderSigmaEvidence(
        IReadOnlyList<LocalProcessSigmaEvidence> evidence)
    {
        if (evidence.Count > MaximumPersistedSigmaEvidence)
        {
            throw new InvalidDataException(
                $"Sigma risk input exceeds the bounded maximum of {MaximumPersistedSigmaEvidence} rows.");
        }

        var copied = new List<LocalProcessSigmaEvidence>(evidence.Count);
        foreach (var item in evidence)
        {
            if (item == null ||
                string.IsNullOrWhiteSpace(item.ProcessEntityId) ||
                string.IsNullOrWhiteSpace(item.MatchId) ||
                string.IsNullOrWhiteSpace(item.RuleId) ||
                string.IsNullOrWhiteSpace(item.RuleVersion) ||
                item.MatchedUtc.Kind != DateTimeKind.Utc)
            {
                throw new InvalidDataException(
                    "Every persisted Sigma risk input requires bounded process, match, rule, version, and UTC identity.");
            }

            var json = JsonSerializer.Serialize(item);
            if (json.Length > 131_072)
            {
                throw new InvalidDataException(
                    "A normalized Sigma risk input exceeds the bounded serialized-row limit.");
            }

            copied.Add(JsonSerializer.Deserialize<LocalProcessSigmaEvidence>(json) ??
                       throw new InvalidDataException(
                           "A normalized Sigma risk input could not be defensively copied."));
        }

        var ordered = copied
            .OrderBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ThenBy(item => item.MatchId, StringComparer.Ordinal)
            .ToArray();
        foreach (var group in ordered.GroupBy(item => item.ProcessEntityId, StringComparer.Ordinal))
        {
            if (group.Count() > LocalProcessRiskMapper.MaximumSigmaEvidence)
            {
                throw new InvalidDataException(
                    $"Process {group.Key} exceeds the bounded normalized Sigma input limit.");
            }

            if (group.Select(item => item.MatchId).Distinct(StringComparer.Ordinal).Count() !=
                group.Count())
            {
                throw new InvalidDataException(
                    $"Process {group.Key} contains duplicate normalized Sigma match identities.");
            }
        }

        return ordered;
    }

    private void ReplacePersistedSigmaEvidence(
        IReadOnlyList<LocalProcessSigmaEvidence> evidence)
    {
        using (var delete = _context.CreateCommand("DELETE FROM ProcessRiskSigmaInputs;"))
        {
            delete.ExecuteNonQuery();
        }

        var canonicalRows = evidence
            .Select(item => JsonSerializer.Serialize(item))
            .ToArray();
        var generationId = $"sigma-input-{Sha256(string.Join('\n', canonicalRows))[..32]}";
        for (var index = 0; index < evidence.Count; index++)
        {
            var item = evidence[index];
            using var command = _context.CreateCommand("""
                INSERT INTO ProcessRiskSigmaInputs(
                    GenerationId, ProcessEntityId, MatchId, RuleId, RuleVersion,
                    MatchContentHashSha256, MatchedUtc, EvidenceJson)
                VALUES(
                    $GenerationId, $ProcessEntityId, $MatchId, $RuleId, $RuleVersion,
                    $MatchContentHashSha256, $MatchedUtc, $EvidenceJson);
                """);
            Add(command, "$GenerationId", generationId);
            Add(command, "$ProcessEntityId", item.ProcessEntityId);
            Add(command, "$MatchId", item.MatchId);
            Add(command, "$RuleId", item.RuleId);
            Add(command, "$RuleVersion", item.RuleVersion);
            Add(command, "$MatchContentHashSha256", item.MatchContentHashSha256.ToLowerInvariant());
            Add(command, "$MatchedUtc", FormatUtc(item.MatchedUtc));
            Add(command, "$EvidenceJson", canonicalRows[index]);
            command.ExecuteNonQuery();
        }
    }

    private IReadOnlyDictionary<string, IReadOnlyList<LocalProcessSigmaEvidence>>
        ReadPersistedSigmaEvidence()
    {
        if (!_context.TableExists("ProcessRiskSigmaInputs"))
        {
            return new Dictionary<string, IReadOnlyList<LocalProcessSigmaEvidence>>(
                StringComparer.Ordinal);
        }

        using var command = _context.CreateCommand("""
            SELECT ProcessEntityId, MatchId, RuleId, RuleVersion,
                   MatchContentHashSha256, MatchedUtc, EvidenceJson
            FROM ProcessRiskSigmaInputs
            ORDER BY ProcessEntityId, MatchId
            LIMIT $MaximumRows;
            """);
        Add(command, "$MaximumRows", MaximumPersistedSigmaEvidence + 1);
        var rows = new List<LocalProcessSigmaEvidence>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (rows.Count >= MaximumPersistedSigmaEvidence)
            {
                throw new InvalidDataException(
                    "Persisted Sigma risk input exceeds the bounded row limit.");
            }

            var json = GetString(reader, 6);
            LocalProcessSigmaEvidence item;
            try
            {
                item = JsonSerializer.Deserialize<LocalProcessSigmaEvidence>(json) ??
                       throw new JsonException("The normalized Sigma row is null.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException(
                    $"A persisted Sigma risk input is malformed: {ex.GetType().Name}.",
                    ex);
            }

            if (!string.Equals(item.ProcessEntityId, GetString(reader, 0), StringComparison.Ordinal) ||
                !string.Equals(item.MatchId, GetString(reader, 1), StringComparison.Ordinal) ||
                !string.Equals(item.RuleId, GetString(reader, 2), StringComparison.Ordinal) ||
                !string.Equals(item.RuleVersion, GetString(reader, 3), StringComparison.Ordinal) ||
                !string.Equals(
                    item.MatchContentHashSha256,
                    GetString(reader, 4),
                    StringComparison.OrdinalIgnoreCase) ||
                item.MatchedUtc != GetDateTime(reader, 5))
            {
                throw new InvalidDataException(
                    "A persisted Sigma risk input disagrees with its indexed identity columns.");
            }

            rows.Add(item);
        }

        return GroupSigmaEvidence(ValidateAndOrderSigmaEvidence(rows));
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<LocalProcessSigmaEvidence>>
        GroupSigmaEvidence(IEnumerable<LocalProcessSigmaEvidence> evidence) =>
        evidence
            .GroupBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<LocalProcessSigmaEvidence>)group
                    .OrderBy(item => item.MatchId, StringComparer.Ordinal)
                    .ToArray(),
                StringComparer.Ordinal);

    private static LocalProcessBaselineComparisonEvidence[] ValidateAndOrderBaselineEvidence(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> evidence)
    {
        if (evidence.Count > MaximumPersistedBaselineEvidence)
        {
            throw new InvalidDataException(
                $"Baseline risk input exceeds the bounded maximum of {MaximumPersistedBaselineEvidence} rows.");
        }

        var copied = new List<LocalProcessBaselineComparisonEvidence>(evidence.Count);
        var findingIds = new HashSet<string>(StringComparer.Ordinal);
        var canonicalInputs = new HashSet<string>(StringComparer.Ordinal);
        var nowUtc = DateTime.UtcNow;
        foreach (var candidate in evidence)
        {
            if (candidate == null)
            {
                throw new InvalidDataException(
                    "Every persisted Baseline risk input must be a concrete normalized row.");
            }

            var json = JsonSerializer.Serialize(candidate);
            if (json.Length > MaximumSerializedEvidenceLength)
            {
                throw new InvalidDataException(
                    "A normalized Baseline risk input exceeds the bounded serialized-row limit.");
            }

            var item = JsonSerializer.Deserialize<LocalProcessBaselineComparisonEvidence>(json) ??
                       throw new InvalidDataException(
                           "A normalized Baseline risk input could not be defensively copied.");
            item = CanonicalizeBaselineEvidence(item);
            ValidateBaselineEvidenceStructure(item, nowUtc);
            if (!findingIds.Add(item.FindingId))
            {
                throw new InvalidDataException(
                    $"Baseline risk input contains duplicate finding identity {item.FindingId}.");
            }

            var canonicalInput = JsonSerializer.Serialize(item with { FindingId = string.Empty });
            if (!canonicalInputs.Add(canonicalInput))
            {
                throw new InvalidDataException(
                    "Baseline risk input contains duplicate canonical normalized evidence.");
            }

            copied.Add(item);
        }

        var ordered = copied
            .OrderBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ThenBy(item => item.FindingId, StringComparer.Ordinal)
            .ToArray();
        foreach (var group in ordered.GroupBy(item => item.ProcessEntityId, StringComparer.Ordinal))
        {
            if (group.Count() > LocalProcessRiskMapper.MaximumBaselineComparisonEvidence)
            {
                throw new InvalidDataException(
                    $"Process {group.Key} exceeds the bounded normalized Baseline input limit.");
            }
        }

        return ordered;
    }

    private static LocalProcessBaselineComparisonEvidence CanonicalizeBaselineEvidence(
        LocalProcessBaselineComparisonEvidence item) =>
        item with
        {
            BaselineSnapshotHashSha256 = item.BaselineSnapshotHashSha256?.ToLowerInvariant() ?? string.Empty,
            CurrentSnapshotHashSha256 = item.CurrentSnapshotHashSha256?.ToLowerInvariant() ?? string.Empty,
            StableKeyHashSha256 = item.StableKeyHashSha256?.ToLowerInvariant() ?? string.Empty,
            BaselineFingerprintSha256 = item.BaselineFingerprintSha256?.ToLowerInvariant() ?? string.Empty,
            CurrentFingerprintSha256 = item.CurrentFingerprintSha256?.ToLowerInvariant() ?? string.Empty,
            EvidenceReferences = item.EvidenceReferences?
                .OrderBy(reference => reference?.Kind)
                .ThenBy(reference => reference?.Id, StringComparer.Ordinal)
                .Select(reference => reference == null
                    ? null!
                    : new EvidenceReference(reference.Kind, reference.Id))
                .ToArray() ?? Array.Empty<EvidenceReference>()
        };

    private static void ValidateBaselineEvidenceStructure(
        LocalProcessBaselineComparisonEvidence item,
        DateTime nowUtc)
    {
        if (item.EvidenceIdentity == null || item.EvidenceReferences == null ||
            item.PolicyRuleId == null || item.BaselineFingerprintSha256 == null ||
            item.CurrentFingerprintSha256 == null ||
            !RequiredIdentity(item.FindingId) || !RequiredIdentity(item.ComparisonId) ||
            !RequiredIdentity(item.ComparisonVersion) || !RequiredIdentity(item.BaselineId) ||
            !ValidSha256(item.BaselineSnapshotHashSha256) ||
            !ValidSha256(item.CurrentSnapshotHashSha256) ||
            !ValidSha256(item.StableKeyHashSha256) ||
            item.ArtifactKind != LocalProcessBaselineArtifactKind.Process ||
            !Enum.IsDefined(item.Verdict) ||
            item.Verdict is LocalProcessBaselineVerdict.Unknown or LocalProcessBaselineVerdict.Missing ||
            !RequiredIdentity(item.ProcessEntityId) || !OptionalIdentity(item.ProcessKey) ||
            item.ComparedUtc.Kind != DateTimeKind.Utc || item.ComparedUtc > nowUtc ||
            item.CorrelationState != EvidenceCorrelationState.Exact ||
            item.CorrelationCandidateCount != 1 || !RequiredIdentity(item.CorrelationMethod) ||
            !ValidScope(item.EvidenceIdentity) ||
            item.EvidenceReferences.Count < 3 ||
            item.EvidenceReferences.Count > LocalProcessRiskMapper.MaximumBaselineEvidenceReferences ||
            !ValidBaselineVerdictShape(item))
        {
            throw new InvalidDataException(
                $"Baseline risk input {item.FindingId} has malformed, unsupported, future, weak, incomplete, or contradictory normalized identity.");
        }

        var referenceKeys = new HashSet<string>(StringComparer.Ordinal);
        var processEntityReferences = 0;
        foreach (var reference in item.EvidenceReferences)
        {
            if (reference == null || !Enum.IsDefined(reference.Kind) ||
                !RequiredIdentity(reference.Id) ||
                !referenceKeys.Add($"{(int)reference.Kind}:{reference.Id}"))
            {
                throw new InvalidDataException(
                    $"Baseline risk input {item.FindingId} contains a malformed or duplicate evidence reference.");
            }

            if (reference.Kind == EvidenceReferenceKind.ProcessEntity)
            {
                processEntityReferences++;
                if (!string.Equals(reference.Id, item.ProcessEntityId, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"Baseline risk input {item.FindingId} references the wrong durable process.");
                }
            }
        }

        if (processEntityReferences != 1)
        {
            throw new InvalidDataException(
                $"Baseline risk input {item.FindingId} must cite exactly one matching durable process.");
        }
    }

    private void ValidateBaselineEvidenceAgainstCurrentObservations(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> evidence)
    {
        if (evidence.Count == 0)
        {
            return;
        }

        var byEntity = GroupBaselineEvidence(evidence);
        var observations = ReadLatestObservations(byEntity.Keys.ToArray());
        foreach (var pair in byEntity)
        {
            if (!observations.TryGetValue(pair.Key, out var selected) ||
                !string.IsNullOrWhiteSpace(selected.MaterializationFailure))
            {
                throw new InvalidDataException(
                    $"Baseline risk input targets missing or malformed current process observation {pair.Key}.");
            }

            foreach (var item in pair.Value)
            {
                if (item.EvidenceReferences.Count(reference =>
                        reference.Kind == EvidenceReferenceKind.ProcessObservation &&
                        string.Equals(reference.Id, selected.Observation.ObservationId,
                            StringComparison.Ordinal)) != 1 ||
                    item.EvidenceReferences.Count(reference =>
                        reference.Kind == EvidenceReferenceKind.SourceRun &&
                        string.Equals(reference.Id, selected.Observation.SourceRunId,
                            StringComparison.Ordinal)) != 1)
                {
                    throw new InvalidDataException(
                        $"Baseline risk input {item.FindingId} does not cite the selected exact process observation and source run.");
                }
            }

            var evaluatedUtc = new[]
            {
                selected.Observation.ObservedUtc,
                pair.Value.Max(item => item.ComparedUtc)
            }.Max();
            var mapping = LocalProcessRiskMapper.Map(new LocalProcessRiskMappingRequest
            {
                ProcessObservation = selected.Observation,
                BaselineComparisonEvidence = pair.Value,
                BaselineComparisonAvailability = AnalysisSourceAvailability.Available,
                EvaluatedUtc = evaluatedUtc,
                Policy = ProcessRiskAggregationPolicy.LocalFirstVersion1
            });
            if (!mapping.Accepted || mapping.Result == null)
            {
                throw new InvalidDataException(
                    $"Baseline risk input for process {pair.Key} failed exact mapper validation before replacement: {mapping.Failure}: {mapping.Diagnostic}");
            }
        }
    }

    private void ReplacePersistedBaselineEvidence(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> evidence)
    {
        using (var delete = _context.CreateCommand("DELETE FROM ProcessRiskBaselineInputs;"))
        {
            delete.ExecuteNonQuery();
        }

        var canonicalRows = evidence.Select(item => JsonSerializer.Serialize(item)).ToArray();
        var generationId = ComputeBaselineGenerationId(canonicalRows);
        for (var index = 0; index < evidence.Count; index++)
        {
            var item = evidence[index];
            using var command = _context.CreateCommand("""
                INSERT INTO ProcessRiskBaselineInputs(
                    GenerationId, ProcessEntityId, FindingId, ComparisonId, ComparisonVersion,
                    BaselineId, BaselineSnapshotHashSha256, CurrentSnapshotHashSha256,
                    StableKeyHashSha256, BaselineFingerprintSha256, CurrentFingerprintSha256,
                    ArtifactKind, Verdict, PolicyRuleId, ComparedUtc, EvidenceJson)
                VALUES(
                    $GenerationId, $ProcessEntityId, $FindingId, $ComparisonId, $ComparisonVersion,
                    $BaselineId, $BaselineSnapshotHashSha256, $CurrentSnapshotHashSha256,
                    $StableKeyHashSha256, $BaselineFingerprintSha256, $CurrentFingerprintSha256,
                    $ArtifactKind, $Verdict, $PolicyRuleId, $ComparedUtc, $EvidenceJson);
                """);
            Add(command, "$GenerationId", generationId);
            Add(command, "$ProcessEntityId", item.ProcessEntityId);
            Add(command, "$FindingId", item.FindingId);
            Add(command, "$ComparisonId", item.ComparisonId);
            Add(command, "$ComparisonVersion", item.ComparisonVersion);
            Add(command, "$BaselineId", item.BaselineId);
            Add(command, "$BaselineSnapshotHashSha256", item.BaselineSnapshotHashSha256);
            Add(command, "$CurrentSnapshotHashSha256", item.CurrentSnapshotHashSha256);
            Add(command, "$StableKeyHashSha256", item.StableKeyHashSha256);
            Add(command, "$BaselineFingerprintSha256", item.BaselineFingerprintSha256);
            Add(command, "$CurrentFingerprintSha256", item.CurrentFingerprintSha256);
            Add(command, "$ArtifactKind", item.ArtifactKind.ToString());
            Add(command, "$Verdict", item.Verdict.ToString());
            Add(command, "$PolicyRuleId", item.PolicyRuleId);
            Add(command, "$ComparedUtc", FormatUtc(item.ComparedUtc));
            Add(command, "$EvidenceJson", canonicalRows[index]);
            command.ExecuteNonQuery();
        }
    }

    private IReadOnlyDictionary<string, IReadOnlyList<LocalProcessBaselineComparisonEvidence>>
        ReadPersistedBaselineEvidence()
    {
        using var command = _context.CreateCommand("""
            SELECT GenerationId, ProcessEntityId, FindingId, ComparisonId, ComparisonVersion,
                   BaselineId, BaselineSnapshotHashSha256, CurrentSnapshotHashSha256,
                   StableKeyHashSha256, BaselineFingerprintSha256, CurrentFingerprintSha256,
                   ArtifactKind, Verdict, PolicyRuleId, ComparedUtc, EvidenceJson
            FROM ProcessRiskBaselineInputs
            ORDER BY ProcessEntityId, FindingId
            LIMIT $MaximumRows;
            """);
        Add(command, "$MaximumRows", MaximumPersistedBaselineEvidence + 1);
        var rows = new List<LocalProcessBaselineComparisonEvidence>();
        var generationIds = new List<string>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (rows.Count >= MaximumPersistedBaselineEvidence)
            {
                throw new InvalidDataException(
                    "Persisted Baseline risk input exceeds the bounded row limit.");
            }

            var json = GetString(reader, 15);
            LocalProcessBaselineComparisonEvidence item;
            try
            {
                item = JsonSerializer.Deserialize<LocalProcessBaselineComparisonEvidence>(json) ??
                       throw new JsonException("The normalized Baseline row is null.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException(
                    $"A persisted Baseline risk input is malformed: {ex.GetType().Name}.", ex);
            }

            if (!string.Equals(item.ProcessEntityId, GetString(reader, 1), StringComparison.Ordinal) ||
                !string.Equals(item.FindingId, GetString(reader, 2), StringComparison.Ordinal) ||
                !string.Equals(item.ComparisonId, GetString(reader, 3), StringComparison.Ordinal) ||
                !string.Equals(item.ComparisonVersion, GetString(reader, 4), StringComparison.Ordinal) ||
                !string.Equals(item.BaselineId, GetString(reader, 5), StringComparison.Ordinal) ||
                !string.Equals(item.BaselineSnapshotHashSha256, GetString(reader, 6), StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(item.CurrentSnapshotHashSha256, GetString(reader, 7), StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(item.StableKeyHashSha256, GetString(reader, 8), StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(item.BaselineFingerprintSha256, GetString(reader, 9), StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(item.CurrentFingerprintSha256, GetString(reader, 10), StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(item.ArtifactKind.ToString(), GetString(reader, 11), StringComparison.Ordinal) ||
                !string.Equals(item.Verdict.ToString(), GetString(reader, 12), StringComparison.Ordinal) ||
                !string.Equals(item.PolicyRuleId, GetString(reader, 13), StringComparison.Ordinal) ||
                item.ComparedUtc != GetDateTime(reader, 14))
            {
                throw new InvalidDataException(
                    "A persisted Baseline risk input disagrees with its indexed identity columns.");
            }

            generationIds.Add(GetString(reader, 0));
            rows.Add(item);
        }

        var ordered = ValidateAndOrderBaselineEvidence(rows);
        var canonicalRows = ordered.Select(item => JsonSerializer.Serialize(item)).ToArray();
        var expectedGenerationId = ComputeBaselineGenerationId(canonicalRows);
        if (generationIds.Any(id => !string.Equals(id, expectedGenerationId, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "Persisted Baseline risk inputs disagree with their deterministic generation identity.");
        }

        ValidateBaselineEvidenceAgainstCurrentObservations(ordered);
        return GroupBaselineEvidence(ordered);
    }

    private static string ComputeBaselineGenerationId(IReadOnlyList<string> canonicalRows) =>
        $"baseline-input-{Sha256(string.Join('\n', canonicalRows))[..32]}";

    private static IReadOnlyDictionary<string, IReadOnlyList<LocalProcessBaselineComparisonEvidence>>
        GroupBaselineEvidence(IEnumerable<LocalProcessBaselineComparisonEvidence> evidence) =>
        evidence
            .GroupBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<LocalProcessBaselineComparisonEvidence>)group
                    .OrderBy(item => item.FindingId, StringComparer.Ordinal)
                    .ToArray(),
                StringComparer.Ordinal);

    private PersistedYaraGeneration ValidateAndBuildYaraGeneration(
        IReadOnlyList<YaraProcessAttributionResult> attributions)
    {
        if (attributions.Count == 0)
        {
            throw new InvalidDataException(
                "A YARA risk-input replacement requires one nonempty complete attribution generation.");
        }

        if (attributions.Count > MaximumPersistedYaraAttributions)
        {
            throw new InvalidDataException(
                $"YARA risk input exceeds the bounded maximum of {MaximumPersistedYaraAttributions} process attributions.");
        }

        var copied = new List<YaraProcessAttributionResult>(attributions.Count);
        foreach (var attribution in attributions)
        {
            if (attribution == null)
            {
                throw new InvalidDataException("A YARA process attribution is null.");
            }

            var json = JsonSerializer.Serialize(attribution);
            if (json.Length > MaximumSerializedEvidenceLength)
            {
                throw new InvalidDataException(
                    "A normalized YARA process attribution exceeds the bounded serialized-row limit.");
            }

            copied.Add(JsonSerializer.Deserialize<YaraProcessAttributionResult>(json) ??
                       throw new InvalidDataException(
                           "A normalized YARA process attribution could not be defensively copied."));
        }

        var ordered = copied
            .OrderBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ThenBy(item => item.ScanId, StringComparer.Ordinal)
            .ToArray();
        if (ordered.Select(item => item.ProcessEntityId).Distinct(StringComparer.Ordinal).Count() !=
            ordered.Length ||
            ordered.Select(item => item.ScanId).Distinct(StringComparer.Ordinal).Count() != ordered.Length)
        {
            throw new InvalidDataException(
                "A YARA risk-input generation contains a duplicate process or scan identity.");
        }

        var policyIdentity = JsonSerializer.Serialize(ordered[0].Policy);
        var rulesetIdentity = JsonSerializer.Serialize(ordered[0].Ruleset);
        if (ordered.Any(item =>
                !string.Equals(JsonSerializer.Serialize(item.Policy), policyIdentity,
                    StringComparison.Ordinal) ||
                !string.Equals(JsonSerializer.Serialize(item.Ruleset), rulesetIdentity,
                    StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "A YARA risk-input generation must use one coherent reviewed policy and ruleset identity.");
        }

        var observations = ReadLatestObservations(
            ordered.Select(item => item.ProcessEntityId).ToArray());
        var inputs = new List<PersistedYaraInput>(ordered.Length);
        var canonicalAttributions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var attribution in ordered)
        {
            if (!observations.TryGetValue(attribution.ProcessEntityId, out var selected) ||
                !string.IsNullOrWhiteSpace(selected.MaterializationFailure))
            {
                throw new InvalidDataException(
                    $"YARA risk input targets missing or malformed current process observation {attribution.ProcessEntityId}.");
            }

            var relationReferences = attribution.EvidenceReferences
                .Where(reference => reference.Kind == EvidenceReferenceKind.EvidenceRelation)
                .ToArray();
            if (relationReferences.Length != 1)
            {
                throw new InvalidDataException(
                    $"YARA risk input {attribution.ScanId} must cite exactly one persisted evidence relation.");
            }

            var scanRead = _context.ReadExactYaraScan(new YaraAnalysisScanQuery
            {
                ScanId = attribution.ScanId,
                EvidenceIdentity = attribution.Target.EvidenceIdentity with { },
                SourceRunId = attribution.Target.SourceRunId,
                TargetKind = attribution.Target.Kind,
                EvidenceReference = attribution.Target.EvidenceReference with { }
            });
            if (scanRead.State != YaraAnalysisReadState.Available || scanRead.Scan == null)
            {
                throw new InvalidDataException(
                    $"YARA risk input {attribution.ScanId} cannot re-read its exact payload-verified migration-029 scan ({scanRead.State}).");
            }

            var relation = ReadExactEvidenceRelation(relationReferences[0].Id);
            if (relation == null)
            {
                throw new InvalidDataException(
                    $"YARA risk input {attribution.ScanId} cannot re-read its exact persisted evidence relation.");
            }

            var normalized = YaraProcessAttributionNormalizer.Normalize(
                new YaraProcessAttributionNormalizationRequest
                {
                    Policy = attribution.Policy,
                    PersistedScan = scanRead.Scan,
                    Process = selected.Observation.Fields,
                    Relation = relation
                });
            if (!normalized.Accepted || normalized.Result == null)
            {
                throw new InvalidDataException(
                    $"YARA risk input {attribution.ScanId} failed persisted-evidence attribution reconstruction: {normalized.Failure}: {normalized.Diagnostic}");
            }

            var offeredJson = JsonSerializer.Serialize(attribution);
            var reconstructedJson = JsonSerializer.Serialize(normalized.Result);
            if (!string.Equals(offeredJson, reconstructedJson, StringComparison.Ordinal) ||
                !canonicalAttributions.Add(offeredJson))
            {
                throw new InvalidDataException(
                    $"YARA risk input {attribution.ScanId} disagrees with its canonical reconstructed attribution.");
            }

            var mapping = LocalProcessRiskMapper.Map(new LocalProcessRiskMappingRequest
            {
                ProcessObservation = selected.Observation,
                YaraAttribution = normalized.Result,
                EvaluatedUtc = new[]
                {
                    selected.Observation.ObservedUtc,
                    scanRead.Scan.Result.CompletedUtc
                }.Max(),
                Policy = ProcessRiskAggregationPolicy.LocalFirstVersion2
            });
            if (!mapping.Accepted || mapping.Result == null)
            {
                throw new InvalidDataException(
                    $"YARA risk input {attribution.ScanId} failed version-2 mapper validation before replacement: {mapping.Failure}: {mapping.Diagnostic}");
            }

            inputs.Add(new PersistedYaraInput(
                normalized.Result,
                scanRead.Scan.Result.CompletedUtc,
                scanRead.Scan.PayloadHashSha256,
                Sha256(reconstructedJson),
                relation.RelationId));
        }

        var generationId = ComputeYaraGenerationId(inputs);
        return new PersistedYaraGeneration(
            generationId,
            inputs.ToDictionary(item => item.Attribution.ProcessEntityId, StringComparer.Ordinal));
    }

    private void ReplacePersistedYaraGeneration(PersistedYaraGeneration generation)
    {
        using (var delete = _context.CreateCommand("DELETE FROM ProcessRiskYaraInputs;"))
        {
            delete.ExecuteNonQuery();
        }

        foreach (var input in generation.ByEntity.Values
                     .OrderBy(item => item.Attribution.ProcessEntityId, StringComparer.Ordinal))
        {
            var item = input.Attribution;
            using var command = _context.CreateCommand("""
                INSERT INTO ProcessRiskYaraInputs(
                    GenerationId, ProcessEntityId, ScanId, PolicyId, PolicyVersion,
                    ReviewerId, ReviewPolicyId, ReviewPolicyVersion, ReviewedUtc,
                    RulesetId, RulesetVersion, RulesetHashSha256, TargetKind,
                    TargetReferenceKind, TargetReferenceId, SourceRunId, RelationId,
                    Availability, CompletedUtc, ScanPayloadHashSha256,
                    AttributionPayloadHashSha256, AttributionJson)
                VALUES(
                    $GenerationId, $ProcessEntityId, $ScanId, $PolicyId, $PolicyVersion,
                    $ReviewerId, $ReviewPolicyId, $ReviewPolicyVersion, $ReviewedUtc,
                    $RulesetId, $RulesetVersion, $RulesetHashSha256, $TargetKind,
                    $TargetReferenceKind, $TargetReferenceId, $SourceRunId, $RelationId,
                    $Availability, $CompletedUtc, $ScanPayloadHashSha256,
                    $AttributionPayloadHashSha256, $AttributionJson);
                """);
            Add(command, "$GenerationId", generation.GenerationId);
            Add(command, "$ProcessEntityId", item.ProcessEntityId);
            Add(command, "$ScanId", item.ScanId);
            Add(command, "$PolicyId", item.Policy.PolicyId);
            Add(command, "$PolicyVersion", item.Policy.PolicyVersion);
            Add(command, "$ReviewerId", item.Policy.ReviewerId);
            Add(command, "$ReviewPolicyId", item.Policy.ReviewPolicyId);
            Add(command, "$ReviewPolicyVersion", item.Policy.ReviewPolicyVersion);
            Add(command, "$ReviewedUtc", FormatUtc(item.Policy.ReviewedUtc));
            Add(command, "$RulesetId", item.Ruleset.RulesetId);
            Add(command, "$RulesetVersion", item.Ruleset.RulesetVersion);
            Add(command, "$RulesetHashSha256", item.Ruleset.RulesetHashSha256);
            Add(command, "$TargetKind", (int)item.Target.Kind);
            Add(command, "$TargetReferenceKind", (int)item.Target.EvidenceReference.Kind);
            Add(command, "$TargetReferenceId", item.Target.EvidenceReference.Id);
            Add(command, "$SourceRunId", item.Target.SourceRunId);
            Add(command, "$RelationId", input.RelationId);
            Add(command, "$Availability", (int)item.Availability);
            Add(command, "$CompletedUtc", FormatUtc(input.CompletedUtc));
            Add(command, "$ScanPayloadHashSha256", input.ScanPayloadHashSha256);
            Add(command, "$AttributionPayloadHashSha256", input.AttributionPayloadHashSha256);
            Add(command, "$AttributionJson", JsonSerializer.Serialize(item));
            command.ExecuteNonQuery();
        }
    }

    private PersistedYaraGeneration? ReadPersistedYaraGeneration()
    {
        if (!_context.TableExists("ProcessRiskYaraInputs"))
        {
            return null;
        }

        using var command = _context.CreateCommand("""
            SELECT GenerationId, ProcessEntityId, ScanId, PolicyId, PolicyVersion,
                   ReviewerId, ReviewPolicyId, ReviewPolicyVersion, ReviewedUtc,
                   RulesetId, RulesetVersion, RulesetHashSha256, TargetKind,
                   TargetReferenceKind, TargetReferenceId, SourceRunId, RelationId,
                   Availability, CompletedUtc, ScanPayloadHashSha256,
                   AttributionPayloadHashSha256, AttributionJson
            FROM ProcessRiskYaraInputs
            ORDER BY ProcessEntityId, ScanId
            LIMIT $MaximumRows;
            """);
        Add(command, "$MaximumRows", MaximumPersistedYaraAttributions + 1);
        var stored = new List<(string GenerationId, PersistedYaraInput Input)>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (stored.Count >= MaximumPersistedYaraAttributions)
            {
                throw new InvalidDataException(
                    "Persisted YARA risk input exceeds the bounded row limit.");
            }

            var json = GetString(reader, 21);
            YaraProcessAttributionResult attribution;
            try
            {
                attribution = JsonSerializer.Deserialize<YaraProcessAttributionResult>(json) ??
                              throw new JsonException("The normalized YARA attribution is null.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException(
                    $"A persisted YARA risk input is malformed: {ex.GetType().Name}.", ex);
            }

            var completedUtc = GetDateTime(reader, 18) ?? DateTime.MinValue;
            var scanPayloadHash = GetString(reader, 19);
            var attributionPayloadHash = GetString(reader, 20);
            var relationId = GetString(reader, 16);
            if (!string.Equals(attribution.ProcessEntityId, GetString(reader, 1), StringComparison.Ordinal) ||
                !string.Equals(attribution.ScanId, GetString(reader, 2), StringComparison.Ordinal) ||
                !string.Equals(attribution.Policy.PolicyId, GetString(reader, 3), StringComparison.Ordinal) ||
                !string.Equals(attribution.Policy.PolicyVersion, GetString(reader, 4), StringComparison.Ordinal) ||
                !string.Equals(attribution.Policy.ReviewerId, GetString(reader, 5), StringComparison.Ordinal) ||
                !string.Equals(attribution.Policy.ReviewPolicyId, GetString(reader, 6), StringComparison.Ordinal) ||
                !string.Equals(attribution.Policy.ReviewPolicyVersion, GetString(reader, 7), StringComparison.Ordinal) ||
                attribution.Policy.ReviewedUtc != GetDateTime(reader, 8) ||
                !string.Equals(attribution.Ruleset.RulesetId, GetString(reader, 9), StringComparison.Ordinal) ||
                !string.Equals(attribution.Ruleset.RulesetVersion, GetString(reader, 10), StringComparison.Ordinal) ||
                !string.Equals(attribution.Ruleset.RulesetHashSha256, GetString(reader, 11), StringComparison.OrdinalIgnoreCase) ||
                (int)attribution.Target.Kind != GetInt(reader, 12) ||
                (int)attribution.Target.EvidenceReference.Kind != GetInt(reader, 13) ||
                !string.Equals(attribution.Target.EvidenceReference.Id, GetString(reader, 14), StringComparison.Ordinal) ||
                !string.Equals(attribution.Target.SourceRunId, GetString(reader, 15), StringComparison.Ordinal) ||
                (int)attribution.Availability != GetInt(reader, 17) ||
                completedUtc.Kind != DateTimeKind.Utc ||
                !ValidSha256(scanPayloadHash) || !ValidSha256(attributionPayloadHash) ||
                !string.Equals(attributionPayloadHash, Sha256(json), StringComparison.OrdinalIgnoreCase) ||
                attribution.EvidenceReferences.Count(reference =>
                    reference.Kind == EvidenceReferenceKind.EvidenceRelation &&
                    string.Equals(reference.Id, relationId, StringComparison.Ordinal)) != 1)
            {
                throw new InvalidDataException(
                    "A persisted YARA risk input disagrees with its indexed identity columns.");
            }

            stored.Add((
                GetString(reader, 0),
                new PersistedYaraInput(
                    attribution,
                    completedUtc,
                    scanPayloadHash,
                    attributionPayloadHash,
                    relationId)));
        }

        if (stored.Count == 0)
        {
            return null;
        }

        var rebuilt = ValidateAndBuildYaraGeneration(
            stored.Select(item => item.Input.Attribution).ToArray());
        foreach (var row in stored)
        {
            if (!string.Equals(row.GenerationId, rebuilt.GenerationId, StringComparison.Ordinal) ||
                !rebuilt.ByEntity.TryGetValue(
                    row.Input.Attribution.ProcessEntityId,
                    out var reconstructed) ||
                reconstructed.CompletedUtc != row.Input.CompletedUtc ||
                !string.Equals(reconstructed.ScanPayloadHashSha256,
                    row.Input.ScanPayloadHashSha256, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(reconstructed.AttributionPayloadHashSha256,
                    row.Input.AttributionPayloadHashSha256, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(reconstructed.RelationId, row.Input.RelationId,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Persisted YARA risk inputs disagree with their deterministic generation or source identity.");
            }
        }

        return rebuilt;
    }

    private EvidenceRelation? ReadExactEvidenceRelation(string relationId)
    {
        using var command = _context.CreateCommand("""
            SELECT RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                   CorrelationState, CorrelationMethod, Confidence, CandidateCount,
                   CorrelationDiagnostics, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                   RawInputId, ObservedFromUtc, ObservedToUtc, ValidFromUtc, ValidToUtc,
                   ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                   SupersededByRelationId, AnalystAnnotationId
            FROM EvidenceRelations
            WHERE RelationId = $RelationId
            LIMIT 2;
            """);
        Add(command, "$RelationId", relationId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var relation = new EvidenceRelation
        {
            RelationId = GetString(reader, 0),
            DecisionKey = GetString(reader, 1),
            FromKind = GetEnum(reader, 2, (EvidenceReferenceKind)(-1)),
            FromId = GetString(reader, 3),
            ToKind = GetEnum(reader, 4, (EvidenceReferenceKind)(-1)),
            ToId = GetString(reader, 5),
            RelationType = GetEnum(reader, 6, (EvidenceRelationType)(-1)),
            State = GetEnum(reader, 7, (EvidenceCorrelationState)(-1)),
            CorrelationMethod = GetString(reader, 8),
            Confidence = GetDouble(reader, 9),
            CandidateCount = GetInt(reader, 10),
            CorrelationDiagnostics = GetString(reader, 11),
            CaseId = GetString(reader, 12),
            EvidenceSessionId = GetString(reader, 13),
            CaptureId = GetString(reader, 14),
            SourceIdentityId = GetString(reader, 15),
            HostId = GetString(reader, 16),
            ExecutionRootId = GetString(reader, 17),
            SourceRunId = GetString(reader, 18),
            IngestionJobId = GetString(reader, 19),
            RawInputId = GetString(reader, 20),
            ObservedFromUtc = GetDateTime(reader, 21) ?? DateTime.MinValue,
            ObservedToUtc = GetDateTime(reader, 22),
            ValidFromUtc = GetDateTime(reader, 23),
            ValidToUtc = GetDateTime(reader, 24),
            ResolverName = GetString(reader, 25),
            ResolverVersion = GetString(reader, 26),
            CreatedUtc = GetDateTime(reader, 27) ?? DateTime.MinValue,
            UpdatedUtc = GetDateTime(reader, 28) ?? DateTime.MinValue,
            Status = GetEnum(reader, 29, (EvidenceRelationStatus)(-1)),
            SupersededByRelationId = GetString(reader, 30),
            AnalystAnnotationId = GetString(reader, 31)
        };
        if (reader.Read())
        {
            throw new InvalidDataException("The exact YARA evidence relation is ambiguous.");
        }

        return relation;
    }

    private static string ComputeYaraGenerationId(
        IReadOnlyCollection<PersistedYaraInput> inputs)
    {
        var canonical = inputs
            .OrderBy(item => item.Attribution.ProcessEntityId, StringComparer.Ordinal)
            .ThenBy(item => item.Attribution.ScanId, StringComparer.Ordinal)
            .Select(item => string.Join('|',
                item.Attribution.ProcessEntityId,
                item.Attribution.ScanId,
                FormatUtc(item.CompletedUtc),
                item.ScanPayloadHashSha256,
                item.AttributionPayloadHashSha256,
                item.RelationId));
        return $"yara-input-{Sha256(string.Join('\n', canonical))[..32]}";
    }

    private static bool ValidBaselineVerdictShape(LocalProcessBaselineComparisonEvidence item)
    {
        var hasBaseline = ValidSha256(item.BaselineFingerprintSha256);
        var hasCurrent = ValidSha256(item.CurrentFingerprintSha256);
        var hasPolicy = RequiredIdentity(item.PolicyRuleId);
        var hasNoPolicy = item.PolicyRuleId.Length == 0;
        return item.Verdict switch
        {
            LocalProcessBaselineVerdict.New =>
                item.BaselineFingerprintSha256.Length == 0 && hasCurrent && hasNoPolicy,
            LocalProcessBaselineVerdict.Changed =>
                hasBaseline && hasCurrent && hasNoPolicy &&
                !string.Equals(item.BaselineFingerprintSha256, item.CurrentFingerprintSha256,
                    StringComparison.OrdinalIgnoreCase),
            LocalProcessBaselineVerdict.Known or LocalProcessBaselineVerdict.Noisy =>
                hasBaseline && hasCurrent && hasNoPolicy &&
                string.Equals(item.BaselineFingerprintSha256, item.CurrentFingerprintSha256,
                    StringComparison.OrdinalIgnoreCase),
            LocalProcessBaselineVerdict.Accepted =>
                hasBaseline && hasCurrent && hasPolicy &&
                !string.Equals(item.BaselineFingerprintSha256, item.CurrentFingerprintSha256,
                    StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool ValidScope(EvidenceIdentity scope) =>
        OptionalIdentity(scope.CaseId) && RequiredIdentity(scope.EvidenceSessionId) &&
        OptionalIdentity(scope.CaptureId) && RequiredIdentity(scope.SourceIdentityId) &&
        RequiredIdentity(scope.HostId) && RequiredIdentity(scope.ExecutionRootId);

    private static bool RequiredIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaximumIdentityLength;

    private static bool OptionalIdentity(string? value) =>
        value != null && value.Length <= MaximumIdentityLength;

    private static bool ValidSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private int CountProcessEntities()
    {
        using var command = _context.CreateCommand("""
            SELECT COUNT(DISTINCT ProcessEntityId)
            FROM ProcessObservations
            WHERE ProcessEntityId <> '';
            """);
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private IReadOnlyDictionary<string, SelectedObservation> ReadLatestObservations(
        IReadOnlyList<string> processEntityIds)
    {
        if (processEntityIds.Count == 0)
        {
            return new Dictionary<string, SelectedObservation>(StringComparer.Ordinal);
        }

        using var command = _context.CreateCommand("""
            WITH Ranked AS (
                SELECT ProcessEntityId, ObservationId, AdapterId, ObservationKind, SourceRunId,
                       IngestionJobId, RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc,
                       ValidToUtc, StatusAssertion, CorrelationMethod, CorrelationConfidence,
                       ParserVersion, FieldStatesJson, MetadataJson, PayloadJson,
                       ROW_NUMBER() OVER (
                           PARTITION BY ProcessEntityId
                           ORDER BY ObservedUtc DESC, ObservationId DESC) AS RowNumber
                FROM ProcessObservations
                WHERE ProcessEntityId IN (SELECT value FROM json_each($ProcessEntityIdsJson))
                  AND ProcessEntityId <> ''
            )
            SELECT ProcessEntityId, ObservationId, AdapterId, ObservationKind, SourceRunId,
                   IngestionJobId, RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc,
                   ValidToUtc, StatusAssertion, CorrelationMethod, CorrelationConfidence,
                   ParserVersion, FieldStatesJson, MetadataJson, PayloadJson
            FROM Ranked
            WHERE RowNumber = 1
            ORDER BY ProcessEntityId;
            """);
        Add(command, "$ProcessEntityIdsJson", JsonSerializer.Serialize(processEntityIds));
        var results = new Dictionary<string, SelectedObservation>(StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var selected = ReadSelectedObservation(reader);
            results.Add(selected.ProcessEntityId, selected);
        }

        return results;
    }

    private IReadOnlyList<SelectedObservation> ReadObservationBatch(string afterEntityId)
    {
        using var command = _context.CreateCommand("""
            WITH Ranked AS (
                SELECT ProcessEntityId, ObservationId, AdapterId, ObservationKind, SourceRunId,
                       IngestionJobId, RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc,
                       ValidToUtc, StatusAssertion, CorrelationMethod, CorrelationConfidence,
                       ParserVersion, FieldStatesJson, MetadataJson, PayloadJson,
                       ROW_NUMBER() OVER (
                           PARTITION BY ProcessEntityId
                           ORDER BY ObservedUtc DESC, ObservationId DESC) AS RowNumber
                FROM ProcessObservations
                WHERE ProcessEntityId > $AfterEntityId
                  AND ProcessEntityId <> ''
            )
            SELECT ProcessEntityId, ObservationId, AdapterId, ObservationKind, SourceRunId,
                   IngestionJobId, RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc,
                   ValidToUtc, StatusAssertion, CorrelationMethod, CorrelationConfidence,
                   ParserVersion, FieldStatesJson, MetadataJson, PayloadJson
            FROM Ranked
            WHERE RowNumber = 1
            ORDER BY ProcessEntityId
            LIMIT $BatchSize;
            """);
        Add(command, "$AfterEntityId", afterEntityId);
        Add(command, "$BatchSize", BatchSize);
        var results = new List<SelectedObservation>(BatchSize);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            results.Add(ReadSelectedObservation(reader));
        }

        return results;
    }

    private static SelectedObservation ReadSelectedObservation(SqliteDataReader reader)
    {
        var entityId = GetString(reader, 0);
        var payloadJson = GetString(reader, 17);
        var fieldStatesJson = GetString(reader, 15);
        var failure = string.Empty;
        ProcessRecord fields;
        Dictionary<string, ProcessObservationValueState> fieldStates;
        try
        {
            fields = JsonSerializer.Deserialize<ProcessRecord>(payloadJson) ?? new ProcessRecord();
            fieldStates = JsonSerializer.Deserialize<Dictionary<string, ProcessObservationValueState>>(
                              fieldStatesJson) ?? new(StringComparer.Ordinal);
        }
        catch (JsonException ex)
        {
            fields = new ProcessRecord { ProcessEntityId = entityId };
            fieldStates = new(StringComparer.Ordinal);
            failure = $"The selected process observation JSON is malformed: {ex.GetType().Name}.";
        }

        var observation = new ProcessObservation
        {
            ProcessEntityId = entityId,
            ObservationId = GetString(reader, 1),
            AdapterId = GetString(reader, 2),
            ObservationKind = GetEnum(reader, 3, (ProcessObservationKind)(-1)),
            SourceRunId = GetString(reader, 4),
            IngestionJobId = Guid.TryParse(GetString(reader, 5), out var jobId) ? jobId : null,
            RawRecordId = GetString(reader, 6),
            SourceNativeAlias = GetString(reader, 7),
            ObservedUtc = GetDateTime(reader, 8) ?? DateTime.MinValue,
            ValidFromUtc = GetDateTime(reader, 9),
            ValidToUtc = GetDateTime(reader, 10),
            StatusAssertion = GetEnum(reader, 11, (ProcessStatus)(-1)),
            CorrelationMethod = GetEnum(reader, 12, (ProcessCorrelationMethod)(-1)),
            CorrelationConfidence = GetDouble(reader, 13),
            ParserVersion = GetString(reader, 14),
            FieldStates = fieldStates,
            MetadataJson = GetString(reader, 16),
            Fields = fields
        };
        return new SelectedObservation(
            entityId,
            observation,
            payloadJson,
            fieldStatesJson,
            failure);
    }

    private Dictionary<string, PeAnalysisRecord> ReadLatestPeAnalyses(
        IReadOnlyList<string> processEntityIds)
    {
        var results = new Dictionary<string, PeAnalysisRecord>(StringComparer.Ordinal);
        if (processEntityIds.Count == 0 || !_context.TableExists("PeAnalyses"))
        {
            return results;
        }

        using var command = _context.CreateCommand("""
            WITH Ranked AS (
                SELECT AnalysisId, ProcessKey, ProcessId, ProcessGuid, ProcessName, SourceKind,
                       SourceArtifactId, FilePath, Status, AnalyzedUtc, FileSizeBytes, FileLastWriteUtc,
                       Sha256Hash, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                       ExecutionRootId, ProcessEntityId, SourceRunId, IngestionJobId,
                       ROW_NUMBER() OVER (
                           PARTITION BY ProcessEntityId
                           ORDER BY AnalyzedUtc DESC, AnalysisId DESC) AS RowNumber
                FROM PeAnalyses
                WHERE SourceKind = 'ProcessImage'
                  AND ProcessEntityId IN (SELECT value FROM json_each($ProcessEntityIdsJson))
            )
            SELECT AnalysisId, ProcessKey, ProcessId, ProcessGuid, ProcessName, SourceKind,
                   SourceArtifactId, FilePath, Status, AnalyzedUtc, FileSizeBytes, FileLastWriteUtc,
                   Sha256Hash, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                   ExecutionRootId, ProcessEntityId, SourceRunId, IngestionJobId
            FROM Ranked
            WHERE RowNumber = 1
            ORDER BY ProcessEntityId;
            """);
        Add(command, "$ProcessEntityIdsJson", JsonSerializer.Serialize(processEntityIds));
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var pe = new PeAnalysisRecord
            {
                AnalysisId = GetString(reader, 0),
                ProcessKey = GetString(reader, 1),
                ProcessId = GetInt(reader, 2),
                ProcessGuid = GetString(reader, 3),
                ProcessName = GetString(reader, 4),
                SourceKind = GetEnum(reader, 5, (PeAnalysisSourceKind)(-1)),
                SourceArtifactId = GetString(reader, 6),
                FilePath = GetString(reader, 7),
                Status = GetEnum(reader, 8, (PeAnalysisStatus)(-1)),
                AnalyzedUtc = GetDateTime(reader, 9) ?? DateTime.MinValue,
                FileSizeBytes = GetLong(reader, 10),
                FileLastWriteUtc = GetDateTime(reader, 11),
                Sha256Hash = GetString(reader, 12),
                CaseId = GetString(reader, 13),
                EvidenceSessionId = GetString(reader, 14),
                CaptureId = GetString(reader, 15),
                SourceIdentityId = GetString(reader, 16),
                HostId = GetString(reader, 17),
                ExecutionRootId = GetString(reader, 18),
                ProcessEntityId = GetString(reader, 19),
                SourceRunId = GetString(reader, 20),
                IngestionJobId = GetString(reader, 21)
            };
            results[pe.ProcessEntityId] = pe;
        }

        return results;
    }

    private Dictionary<string, IReadOnlyList<TelemetryEventRecord>> ReadLatestProcessEvents(
        IReadOnlyList<string> processEntityIds,
        bool networkOnly)
    {
        var mutable = new Dictionary<string, List<TelemetryEventRecord>>(StringComparer.Ordinal);
        if (processEntityIds.Count == 0 || !_context.TableExists("ProcessEvents") ||
            !_context.TableExists("EvidenceRelations") ||
            !_context.ColumnExists("ProcessEvents", "ProcessEntityId") ||
            !_context.ColumnExists("ProcessEvents", "SourceRunId") ||
            !_context.ColumnExists("ProcessEvents", "IngestionJobId"))
        {
            return new Dictionary<string, IReadOnlyList<TelemetryEventRecord>>(StringComparer.Ordinal);
        }

        using var command = _context.CreateCommand("""
            WITH LatestRelations AS (
                SELECT FromId, ToId, CorrelationState, CorrelationMethod, CandidateCount,
                       CorrelationDiagnostics,
                       ROW_NUMBER() OVER (
                           PARTITION BY FromId
                           ORDER BY UpdatedUtc DESC, RelationId DESC) AS RelationNumber
                FROM EvidenceRelations
                WHERE FromKind = 'Event'
                  AND ToKind = 'ProcessEntity'
                  AND RelationType = 'OwnedBy'
                  AND Status = 'Active'
            ),
            Ranked AS (
                SELECT CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                       ExecutionRootId, SequenceId, TimestampUtc, Source, ProcessKey, ProcessId,
                       ProcessGuid, ProcessStartTimeUtc, ProcessName, ParentProcessId, EventCode,
                       Category, Action, RepeatCount, RawProvider, RawLogName, RawRecordIdText,
                       relation.CorrelationMethod AS ExactCorrelationMethod,
                       relation.CandidateCount AS ExactCandidateCount,
                       relation.CorrelationDiagnostics AS ExactCorrelationDiagnostics,
                       ProcessEntityId, SourceRunId, IngestionJobId,
                       ROW_NUMBER() OVER (
                           PARTITION BY ProcessEntityId
                           ORDER BY TimestampUtc DESC, SequenceId DESC) AS RowNumber
                FROM ProcessEvents event
                INNER JOIN LatestRelations relation
                    ON relation.RelationNumber = 1
                   AND relation.FromId = CAST(event.SequenceId AS TEXT)
                   AND relation.ToId = event.ProcessEntityId
                   AND relation.CorrelationState = 'Exact'
                   AND relation.CandidateCount = 1
                WHERE ProcessEntityId IN (SELECT value FROM json_each($ProcessEntityIdsJson))
                  AND ProcessEntityId <> ''
                  AND SourceRunId <> ''
                  AND relation.CorrelationMethod <> ''
                  AND ($NetworkOnly = 0 OR Action IN ('Connect', 'DnsQuery'))
            )
            SELECT CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                   ExecutionRootId, SequenceId, TimestampUtc, Source, ProcessKey, ProcessId,
                   ProcessGuid, ProcessStartTimeUtc, ProcessName, ParentProcessId, EventCode,
                   Category, Action, RepeatCount, RawProvider, RawLogName, RawRecordIdText,
                   ExactCorrelationMethod, ExactCandidateCount, ExactCorrelationDiagnostics,
                   ProcessEntityId, SourceRunId, IngestionJobId
            FROM Ranked
            WHERE RowNumber <= $MaximumEventRecords
            ORDER BY ProcessEntityId, TimestampUtc, SequenceId;
            """);
        Add(command, "$ProcessEntityIdsJson", JsonSerializer.Serialize(processEntityIds));
        Add(command, "$NetworkOnly", networkOnly ? 1 : 0);
        Add(
            command,
            "$MaximumEventRecords",
            networkOnly
                ? LocalProcessRiskMapper.MaximumNetworkEventRecords
                : LocalProcessRiskMapper.MaximumEventRecords);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var processEvent = new TelemetryEventRecord
            {
                CaseId = GetString(reader, 0),
                EvidenceSessionId = GetString(reader, 1),
                CaptureId = GetString(reader, 2),
                SourceIdentityId = GetString(reader, 3),
                HostId = GetString(reader, 4),
                ExecutionRootId = GetString(reader, 5),
                SequenceId = GetLong(reader, 6),
                TimestampUtc = GetDateTime(reader, 7) ?? DateTime.MinValue,
                Source = GetString(reader, 8),
                ProcessKey = GetString(reader, 9),
                ProcessId = GetInt(reader, 10),
                ProcessGuid = GetString(reader, 11),
                ProcessStartTimeUtc = GetDateTime(reader, 12),
                ProcessName = GetString(reader, 13),
                ParentProcessId = GetInt(reader, 14),
                EventCode = reader.IsDBNull(15) ? null : reader.GetInt32(15),
                Category = GetEnum(reader, 16, (ProcessEventCategory)(-1)),
                Action = GetEnum(reader, 17, (ProcessEventAction)(-1)),
                RepeatCount = GetInt(reader, 18),
                RawProvider = GetString(reader, 19),
                RawLogName = GetString(reader, 20),
                RawRecordId = GetString(reader, 21),
                CorrelationMethod = GetString(reader, 22),
                CorrelationCandidateCount = GetInt(reader, 23),
                CorrelationDiagnostics = GetString(reader, 24),
                ProcessEntityId = GetString(reader, 25),
                SourceRunId = GetString(reader, 26),
                IngestionJobId = GetString(reader, 27),
                CorrelationState = EvidenceCorrelationState.Exact,
            };
            if (!mutable.TryGetValue(processEvent.ProcessEntityId, out var rows))
            {
                rows = new List<TelemetryEventRecord>();
                mutable.Add(processEvent.ProcessEntityId, rows);
            }

            rows.Add(processEvent);
        }

        return mutable.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<TelemetryEventRecord>)pair.Value.ToArray(),
            StringComparer.Ordinal);
    }

    private Dictionary<string, IReadOnlyList<LocalProcessFilesystemEvidence>>
        ReadLatestFilesystemEvidence(IReadOnlyList<string> processEntityIds)
    {
        var mutable = new Dictionary<string, List<LocalProcessFilesystemEvidence>>(
            StringComparer.Ordinal);
        if (processEntityIds.Count == 0 || !_context.TableExists("Artifacts") ||
            !_context.TableExists("ArtifactProperties") ||
            !_context.TableExists("EvidenceRelations") ||
            !_context.ColumnExists("Artifacts", "SourceRunId") ||
            !_context.ColumnExists("Artifacts", "IngestionJobId") ||
            !_context.ColumnExists("EvidenceRelations", "CandidateCount") ||
            !_context.ColumnExists("EvidenceRelations", "Status"))
        {
            return new Dictionary<string, IReadOnlyList<LocalProcessFilesystemEvidence>>(
                StringComparer.Ordinal);
        }

        using var command = _context.CreateCommand("""
            WITH LatestRelations AS (
                SELECT RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                       CorrelationState, CorrelationMethod, Confidence, CandidateCount,
                       CorrelationDiagnostics, CaseId, EvidenceSessionId, CaptureId,
                       SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                       RawInputId, ObservedFromUtc, ObservedToUtc, ValidFromUtc, ValidToUtc,
                       ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                       SupersededByRelationId, AnalystAnnotationId,
                       ROW_NUMBER() OVER (
                           PARTITION BY FromId, ToId
                           ORDER BY UpdatedUtc DESC, RelationId DESC) AS RelationNumber
                FROM EvidenceRelations
                WHERE FromKind = 'ProcessEntity'
                  AND ToKind = 'FileArtifact'
                  AND Status = 'Active'
                  AND FromId IN (SELECT value FROM json_each($ProcessEntityIdsJson))
            ),
            Ranked AS (
                SELECT relation.FromId AS ProcessEntityId,
                       artifact.ArtifactId, artifact.ArtifactType, artifact.TimestampUtc,
                       artifact.Name, artifact.Path, artifact.Hash, artifact.CaseId,
                       artifact.EvidenceSessionId, artifact.CaptureId,
                       artifact.SourceIdentityId, artifact.HostId, artifact.ExecutionRootId,
                       artifact.SourceRunId, artifact.IngestionJobId,
                       relation.RelationId, relation.DecisionKey, relation.FromKind,
                       relation.FromId, relation.ToKind, relation.ToId, relation.RelationType,
                       relation.CorrelationState, relation.CorrelationMethod,
                       relation.Confidence, relation.CandidateCount,
                       relation.CorrelationDiagnostics, relation.CaseId AS RelationCaseId,
                       relation.EvidenceSessionId AS RelationEvidenceSessionId,
                       relation.CaptureId AS RelationCaptureId,
                       relation.SourceIdentityId AS RelationSourceIdentityId,
                       relation.HostId AS RelationHostId,
                       relation.ExecutionRootId AS RelationExecutionRootId,
                       relation.SourceRunId AS RelationSourceRunId,
                       relation.IngestionJobId AS RelationIngestionJobId,
                       relation.RawInputId, relation.ObservedFromUtc, relation.ObservedToUtc,
                       relation.ValidFromUtc, relation.ValidToUtc, relation.ResolverName,
                       relation.ResolverVersion, relation.CreatedUtc AS RelationCreatedUtc,
                       relation.UpdatedUtc AS RelationUpdatedUtc,
                       relation.Status AS RelationStatus,
                       relation.SupersededByRelationId, relation.AnalystAnnotationId,
                       ROW_NUMBER() OVER (
                           PARTITION BY relation.FromId
                           ORDER BY artifact.TimestampUtc DESC, artifact.ArtifactId,
                                    relation.RelationId) AS EvidenceNumber
                FROM LatestRelations relation
                INNER JOIN Artifacts artifact
                    ON artifact.ArtifactId = relation.ToId
                WHERE relation.RelationNumber = 1
                  AND relation.CorrelationState = 'Exact'
                  AND relation.CandidateCount = 1
                  AND relation.Confidence = 1.0
                  AND artifact.ArtifactType IN (
                      'NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata')
                  AND COALESCE((
                      SELECT property.Value
                      FROM ArtifactProperties property
                      WHERE property.ArtifactId = artifact.ArtifactId
                        AND property.Name = 'Status'
                      LIMIT 1), 'Imported') = 'Imported'
            )
            SELECT ProcessEntityId, ArtifactId, ArtifactType, TimestampUtc, Name, Path, Hash,
                   CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                   ExecutionRootId, SourceRunId, IngestionJobId,
                   RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                   CorrelationState, CorrelationMethod, Confidence, CandidateCount,
                   CorrelationDiagnostics, RelationCaseId, RelationEvidenceSessionId,
                   RelationCaptureId, RelationSourceIdentityId, RelationHostId,
                   RelationExecutionRootId, RelationSourceRunId, RelationIngestionJobId,
                   RawInputId, ObservedFromUtc, ObservedToUtc, ValidFromUtc, ValidToUtc,
                   ResolverName, ResolverVersion, RelationCreatedUtc, RelationUpdatedUtc,
                   RelationStatus, SupersededByRelationId, AnalystAnnotationId
            FROM Ranked
            WHERE EvidenceNumber <= $MaximumFilesystemEvidence
            ORDER BY ProcessEntityId, TimestampUtc, ArtifactId, RelationId;
            """);
        Add(command, "$ProcessEntityIdsJson", JsonSerializer.Serialize(processEntityIds));
        Add(command, "$MaximumFilesystemEvidence", LocalProcessRiskMapper.MaximumFilesystemEvidence);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var processEntityId = GetString(reader, 0);
            var artifact = new FilesystemArtifactRecord
            {
                ArtifactId = GetString(reader, 1),
                Kind = GetEnum(reader, 2, (FilesystemArtifactKind)(-1)),
                TimestampUtc = GetDateTime(reader, 3) ?? DateTime.MinValue,
                Name = GetString(reader, 4),
                SourcePath = GetString(reader, 5),
                Sha256Hash = GetString(reader, 6),
                CaseId = GetString(reader, 7),
                EvidenceSessionId = GetString(reader, 8),
                CaptureId = GetString(reader, 9),
                SourceIdentityId = GetString(reader, 10),
                HostId = GetString(reader, 11),
                ExecutionRootId = GetString(reader, 12),
                SourceRunId = GetString(reader, 13),
                IngestionJobId = GetString(reader, 14),
                Source = "AgentArtifactImport",
                Status = FilesystemArtifactStatus.Imported
            };
            var relation = new EvidenceRelation
            {
                RelationId = GetString(reader, 15),
                DecisionKey = GetString(reader, 16),
                FromKind = GetEnum(reader, 17, (EvidenceReferenceKind)(-1)),
                FromId = GetString(reader, 18),
                ToKind = GetEnum(reader, 19, (EvidenceReferenceKind)(-1)),
                ToId = GetString(reader, 20),
                RelationType = GetEnum(reader, 21, (EvidenceRelationType)(-1)),
                State = GetEnum(reader, 22, (EvidenceCorrelationState)(-1)),
                CorrelationMethod = GetString(reader, 23),
                Confidence = GetDouble(reader, 24),
                CandidateCount = GetInt(reader, 25),
                CorrelationDiagnostics = GetString(reader, 26),
                CaseId = GetString(reader, 27),
                EvidenceSessionId = GetString(reader, 28),
                CaptureId = GetString(reader, 29),
                SourceIdentityId = GetString(reader, 30),
                HostId = GetString(reader, 31),
                ExecutionRootId = GetString(reader, 32),
                SourceRunId = GetString(reader, 33),
                IngestionJobId = GetString(reader, 34),
                RawInputId = GetString(reader, 35),
                ObservedFromUtc = GetDateTime(reader, 36) ?? DateTime.MinValue,
                ObservedToUtc = GetDateTime(reader, 37),
                ValidFromUtc = GetDateTime(reader, 38),
                ValidToUtc = GetDateTime(reader, 39),
                ResolverName = GetString(reader, 40),
                ResolverVersion = GetString(reader, 41),
                CreatedUtc = GetDateTime(reader, 42) ?? DateTime.MinValue,
                UpdatedUtc = GetDateTime(reader, 43) ?? DateTime.MinValue,
                Status = GetEnum(reader, 44, (EvidenceRelationStatus)(-1)),
                SupersededByRelationId = GetString(reader, 45),
                AnalystAnnotationId = GetString(reader, 46)
            };
            if (!mutable.TryGetValue(processEntityId, out var rows))
            {
                rows = new List<LocalProcessFilesystemEvidence>();
                mutable.Add(processEntityId, rows);
            }

            rows.Add(new LocalProcessFilesystemEvidence
            {
                Artifact = artifact,
                Relation = relation
            });
        }

        return mutable.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<LocalProcessFilesystemEvidence>)pair.Value.ToArray(),
            StringComparer.Ordinal);
    }

    private Dictionary<string, IReadOnlyList<LocalProcessMemoryEvidence>>
        ReadLatestMemoryEvidence(IReadOnlyList<string> processEntityIds)
    {
        var mutable = new Dictionary<string, List<LocalProcessMemoryEvidence>>(
            StringComparer.Ordinal);
        if (processEntityIds.Count == 0 || !_context.TableExists("MemoryProcesses") ||
            !_context.TableExists("EvidenceRelations") ||
            !_context.ColumnExists("MemoryProcesses", "SourceRunId") ||
            !_context.ColumnExists("MemoryProcesses", "IngestionJobId") ||
            !_context.ColumnExists("EvidenceRelations", "CandidateCount") ||
            !_context.ColumnExists("EvidenceRelations", "Status"))
        {
            return new Dictionary<string, IReadOnlyList<LocalProcessMemoryEvidence>>(
                StringComparer.Ordinal);
        }

        using var command = _context.CreateCommand("""
            WITH LatestRelations AS (
                SELECT RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                       CorrelationState, CorrelationMethod, Confidence, CandidateCount,
                       CorrelationDiagnostics, CaseId, EvidenceSessionId, CaptureId,
                       SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                       RawInputId, ObservedFromUtc, ObservedToUtc, ValidFromUtc, ValidToUtc,
                       ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                       SupersededByRelationId, AnalystAnnotationId,
                       ROW_NUMBER() OVER (
                           PARTITION BY FromId
                           ORDER BY UpdatedUtc DESC, ObservedFromUtc DESC, RelationId DESC)
                           AS RelationNumber
                FROM EvidenceRelations
                WHERE FromKind = 'MemoryProcess'
                  AND ToKind = 'ProcessEntity'
                  AND Status = 'Active'
                  AND FromId IN (
                      SELECT candidate.FromId
                      FROM EvidenceRelations candidate
                      WHERE candidate.FromKind = 'MemoryProcess'
                        AND candidate.ToKind = 'ProcessEntity'
                        AND candidate.Status = 'Active'
                        AND candidate.ToId IN (
                            SELECT value FROM json_each($ProcessEntityIdsJson)))
            ),
            Ranked AS (
                SELECT relation.ToId AS ProcessEntityId,
                       memory.ArtifactId, memory.ImageId, memory.PluginRunId, memory.CaseId,
                       memory.EvidenceSessionId, memory.CaptureId, memory.SourceIdentityId,
                       memory.HostId, memory.ExecutionRootId, memory.SourceRunId,
                       memory.IngestionJobId, memory.PluginName, memory.EvidenceKind,
                       memory.RowNumber, memory.ObjectOffset, memory.ProcessId,
                       memory.ParentProcessId, memory.ProcessName, memory.ImagePath,
                       memory.CommandLine, memory.CreateTimeUtc, memory.ExitTimeUtc,
                       memory.SessionId, memory.ThreadCount, memory.HandleCount, memory.Wow64,
                       memory.ProcessKey, memory.CorrelationState, memory.CorrelationMethod,
                       memory.CorrelationConfidence, memory.RawRowHash, memory.RawJson,
                       relation.RelationId, relation.DecisionKey, relation.FromKind,
                       relation.FromId, relation.ToKind, relation.ToId, relation.RelationType,
                       relation.CorrelationState AS RelationCorrelationState,
                       relation.CorrelationMethod AS RelationCorrelationMethod,
                       relation.Confidence AS RelationConfidence,
                       relation.CandidateCount AS RelationCandidateCount,
                       relation.CorrelationDiagnostics, relation.CaseId AS RelationCaseId,
                       relation.EvidenceSessionId AS RelationEvidenceSessionId,
                       relation.CaptureId AS RelationCaptureId,
                       relation.SourceIdentityId AS RelationSourceIdentityId,
                       relation.HostId AS RelationHostId,
                       relation.ExecutionRootId AS RelationExecutionRootId,
                       relation.SourceRunId AS RelationSourceRunId,
                       relation.IngestionJobId AS RelationIngestionJobId,
                       relation.RawInputId, relation.ObservedFromUtc, relation.ObservedToUtc,
                       relation.ValidFromUtc, relation.ValidToUtc, relation.ResolverName,
                       relation.ResolverVersion, relation.CreatedUtc AS RelationCreatedUtc,
                       relation.UpdatedUtc AS RelationUpdatedUtc,
                       relation.Status AS RelationStatus,
                       relation.SupersededByRelationId, relation.AnalystAnnotationId,
                       ROW_NUMBER() OVER (
                           PARTITION BY relation.ToId
                           ORDER BY relation.ObservedFromUtc DESC, memory.ArtifactId,
                                    relation.RelationId) AS EvidenceNumber
                FROM LatestRelations relation
                INNER JOIN MemoryProcesses memory
                    ON memory.ArtifactId = relation.FromId
                WHERE relation.RelationNumber = 1
                  AND relation.ToId IN (SELECT value FROM json_each($ProcessEntityIdsJson))
                  AND relation.RelationType = 'CorrelatesWith'
                  AND relation.CorrelationState = 'Exact'
                  AND relation.CandidateCount = 1
                  AND relation.Confidence = 1.0
            )
            SELECT ProcessEntityId, ArtifactId, ImageId, PluginRunId, CaseId,
                   EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                   SourceRunId, IngestionJobId, PluginName, EvidenceKind, RowNumber,
                   ObjectOffset, ProcessId, ParentProcessId, ProcessName, ImagePath,
                   CommandLine, CreateTimeUtc, ExitTimeUtc, SessionId, ThreadCount,
                   HandleCount, Wow64, ProcessKey, CorrelationState, CorrelationMethod,
                   CorrelationConfidence, RawRowHash, RawJson,
                   RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                   RelationCorrelationState, RelationCorrelationMethod, RelationConfidence,
                   RelationCandidateCount, CorrelationDiagnostics, RelationCaseId,
                   RelationEvidenceSessionId, RelationCaptureId, RelationSourceIdentityId,
                   RelationHostId, RelationExecutionRootId, RelationSourceRunId,
                   RelationIngestionJobId, RawInputId, ObservedFromUtc, ObservedToUtc,
                   ValidFromUtc, ValidToUtc, ResolverName, ResolverVersion,
                   RelationCreatedUtc, RelationUpdatedUtc, RelationStatus,
                   SupersededByRelationId, AnalystAnnotationId
            FROM Ranked
            WHERE EvidenceNumber <= $MaximumMemoryEvidence
            ORDER BY ProcessEntityId, ObservedFromUtc, ArtifactId, RelationId;
            """);
        Add(command, "$ProcessEntityIdsJson", JsonSerializer.Serialize(processEntityIds));
        Add(command, "$MaximumMemoryEvidence", LocalProcessRiskMapper.MaximumMemoryEvidence);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var processEntityId = GetString(reader, 0);
            var memoryProcess = new MemoryProcessRecord
            {
                ArtifactId = GetString(reader, 1),
                ImageId = GetString(reader, 2),
                PluginRunId = GetString(reader, 3),
                CaseId = GetString(reader, 4),
                EvidenceSessionId = GetString(reader, 5),
                CaptureId = GetString(reader, 6),
                SourceIdentityId = GetString(reader, 7),
                HostId = GetString(reader, 8),
                ExecutionRootId = GetString(reader, 9),
                SourceRunId = GetString(reader, 10),
                IngestionJobId = GetString(reader, 11),
                PluginName = GetString(reader, 12),
                EvidenceKind = GetEnum(reader, 13, (MemoryProcessEvidenceKind)(-1)),
                RowNumber = GetInt(reader, 14),
                ObjectOffset = GetString(reader, 15),
                ProcessId = GetInt(reader, 16),
                ParentProcessId = GetInt(reader, 17),
                ProcessName = GetString(reader, 18),
                ImagePath = GetString(reader, 19),
                CommandLine = GetString(reader, 20),
                CreateTimeUtc = GetDateTime(reader, 21),
                ExitTimeUtc = GetDateTime(reader, 22),
                SessionId = GetInt(reader, 23),
                ThreadCount = GetInt(reader, 24),
                HandleCount = GetInt(reader, 25),
                Wow64 = GetString(reader, 26),
                ProcessKey = GetString(reader, 27),
                CorrelationState = GetEnum(
                    reader,
                    28,
                    (MemoryProcessCorrelationState)(-1)),
                CorrelationMethod = GetString(reader, 29),
                CorrelationConfidence = GetDouble(reader, 30),
                RawRowHash = GetString(reader, 31),
                RawJson = GetString(reader, 32),
                Source = "AgentVolatility"
            };
            var relation = new EvidenceRelation
            {
                RelationId = GetString(reader, 33),
                DecisionKey = GetString(reader, 34),
                FromKind = GetEnum(reader, 35, (EvidenceReferenceKind)(-1)),
                FromId = GetString(reader, 36),
                ToKind = GetEnum(reader, 37, (EvidenceReferenceKind)(-1)),
                ToId = GetString(reader, 38),
                RelationType = GetEnum(reader, 39, (EvidenceRelationType)(-1)),
                State = GetEnum(reader, 40, (EvidenceCorrelationState)(-1)),
                CorrelationMethod = GetString(reader, 41),
                Confidence = GetDouble(reader, 42),
                CandidateCount = GetInt(reader, 43),
                CorrelationDiagnostics = GetString(reader, 44),
                CaseId = GetString(reader, 45),
                EvidenceSessionId = GetString(reader, 46),
                CaptureId = GetString(reader, 47),
                SourceIdentityId = GetString(reader, 48),
                HostId = GetString(reader, 49),
                ExecutionRootId = GetString(reader, 50),
                SourceRunId = GetString(reader, 51),
                IngestionJobId = GetString(reader, 52),
                RawInputId = GetString(reader, 53),
                ObservedFromUtc = GetDateTime(reader, 54) ?? DateTime.MinValue,
                ObservedToUtc = GetDateTime(reader, 55),
                ValidFromUtc = GetDateTime(reader, 56),
                ValidToUtc = GetDateTime(reader, 57),
                ResolverName = GetString(reader, 58),
                ResolverVersion = GetString(reader, 59),
                CreatedUtc = GetDateTime(reader, 60) ?? DateTime.MinValue,
                UpdatedUtc = GetDateTime(reader, 61) ?? DateTime.MinValue,
                Status = GetEnum(reader, 62, (EvidenceRelationStatus)(-1)),
                SupersededByRelationId = GetString(reader, 63),
                AnalystAnnotationId = GetString(reader, 64)
            };
            if (!mutable.TryGetValue(processEntityId, out var rows))
            {
                rows = new List<LocalProcessMemoryEvidence>();
                mutable.Add(processEntityId, rows);
            }

            rows.Add(new LocalProcessMemoryEvidence
            {
                MemoryProcess = memoryProcess,
                Relation = relation
            });
        }

        return mutable.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<LocalProcessMemoryEvidence>)pair.Value.ToArray(),
            StringComparer.Ordinal);
    }

    private void AttachLatestAuthenticode(IEnumerable<PeAnalysisRecord> analyses)
    {
        var byAnalysisId = analyses
            .Where(item => !string.IsNullOrWhiteSpace(item.AnalysisId))
            .ToDictionary(item => item.AnalysisId, StringComparer.Ordinal);
        if (byAnalysisId.Count == 0 || !_context.TableExists("AuthenticodeVerifications"))
        {
            return;
        }

        using var command = _context.CreateCommand("""
            WITH Ranked AS (
                SELECT VerificationId, AnalysisId, CaseId, EvidenceSessionId, CaptureId,
                       SourceIdentityId, HostId, ExecutionRootId, ProcessEntityId, SourceRunId,
                       IngestionJobId, ProcessKey, ProcessId, ProcessGuid, ProcessName, FilePath,
                       Sha256Hash, SignatureKind, VerificationStatus, SignerSubject, Publisher,
                       CertificateThumbprint, Issuer, HasTimestamp, TimestampSubject, TimestampUtc,
                       VerificationPolicy, VerificationTimeUtc, RevocationMode, RevocationStatus,
                       NativeStatusCode, DiagnosticCode, DiagnosticText,
                       ROW_NUMBER() OVER (
                           PARTITION BY AnalysisId
                           ORDER BY VerificationTimeUtc DESC, VerificationId DESC) AS RowNumber
                FROM AuthenticodeVerifications
                WHERE AnalysisId IN (SELECT value FROM json_each($AnalysisIdsJson))
            )
            SELECT VerificationId, AnalysisId, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, ProcessEntityId, SourceRunId,
                   IngestionJobId, ProcessKey, ProcessId, ProcessGuid, ProcessName, FilePath,
                   Sha256Hash, SignatureKind, VerificationStatus, SignerSubject, Publisher,
                   CertificateThumbprint, Issuer, HasTimestamp, TimestampSubject, TimestampUtc,
                   VerificationPolicy, VerificationTimeUtc, RevocationMode, RevocationStatus,
                   NativeStatusCode, DiagnosticCode, DiagnosticText
            FROM Ranked
            WHERE RowNumber = 1
            ORDER BY AnalysisId;
            """);
        Add(command, "$AnalysisIdsJson", JsonSerializer.Serialize(byAnalysisId.Keys));
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var verification = new AuthenticodeVerificationRecord
            {
                VerificationId = GetString(reader, 0),
                AnalysisId = GetString(reader, 1),
                CaseId = GetString(reader, 2),
                EvidenceSessionId = GetString(reader, 3),
                CaptureId = GetString(reader, 4),
                SourceIdentityId = GetString(reader, 5),
                HostId = GetString(reader, 6),
                ExecutionRootId = GetString(reader, 7),
                ProcessEntityId = GetString(reader, 8),
                SourceRunId = GetString(reader, 9),
                IngestionJobId = GetString(reader, 10),
                ProcessKey = GetString(reader, 11),
                ProcessId = GetInt(reader, 12),
                ProcessGuid = GetString(reader, 13),
                ProcessName = GetString(reader, 14),
                FilePath = GetString(reader, 15),
                Sha256Hash = GetString(reader, 16),
                SignatureKind = GetEnum(reader, 17, (AuthenticodeSignatureKind)(-1)),
                VerificationStatus = GetEnum(reader, 18, (AuthenticodeVerificationStatus)(-1)),
                SignerSubject = GetString(reader, 19),
                Publisher = GetString(reader, 20),
                CertificateThumbprint = GetString(reader, 21),
                Issuer = GetString(reader, 22),
                HasTimestamp = GetInt(reader, 23) != 0,
                TimestampSubject = GetString(reader, 24),
                TimestampUtc = GetDateTime(reader, 25),
                VerificationPolicy = GetString(reader, 26),
                VerificationTimeUtc = GetDateTime(reader, 27) ?? DateTime.MinValue,
                RevocationMode = GetEnum(reader, 28, (AuthenticodeRevocationMode)(-1)),
                RevocationStatus = GetEnum(reader, 29, (AuthenticodeRevocationStatus)(-1)),
                NativeStatusCode = GetString(reader, 30),
                DiagnosticCode = GetString(reader, 31),
                DiagnosticText = GetString(reader, 32)
            };
            if (byAnalysisId.TryGetValue(verification.AnalysisId, out var pe))
            {
                pe.AuthenticodeVerification = verification;
            }
        }
    }

    private static bool IsPeStale(ProcessObservation observation, PeAnalysisRecord? pe)
    {
        if (pe == null || pe.AnalyzedUtc >= observation.ObservedUtc)
        {
            return false;
        }

        var observedHash = ConcreteHash(observation.Fields.Sha256Hash);
        var peHash = ConcreteHash(pe.Sha256Hash);
        return observedHash == null || peHash == null ||
               !string.Equals(observedHash, peHash, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAuthenticodeStale(
        PeAnalysisRecord? pe,
        AuthenticodeVerificationRecord? verification) =>
        pe != null && verification != null && verification.VerificationTimeUtc < pe.AnalyzedUtc;

    private static string? ConcreteHash(string? value) =>
        string.IsNullOrWhiteSpace(value) ||
        value.Equals("<not available>", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("<unknown>", StringComparison.OrdinalIgnoreCase)
            ? null
            : value.Trim();

    private static string ComputeInputHash(
        SelectedObservation selected,
        PeAnalysisRecord? pe,
        IReadOnlyList<TelemetryEventRecord> processEvents,
        IReadOnlyList<TelemetryEventRecord> networkEvents,
        IReadOnlyList<LocalProcessFilesystemEvidence> filesystemEvidence,
        IReadOnlyList<LocalProcessMemoryEvidence> memoryEvidence,
        IReadOnlyList<LocalProcessSigmaEvidence> sigmaEvidence,
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> baselineEvidence,
        string? yaraGenerationId,
        YaraProcessAttributionResult? yaraAttribution)
    {
        var verification = pe?.AuthenticodeVerification;
        var eventInputs = processEvents
            .OrderBy(item => item.TimestampUtc)
            .ThenBy(item => item.SequenceId)
            .Select(item => string.Join('|',
                item.SequenceId.ToString(CultureInfo.InvariantCulture),
                FormatUtc(item.TimestampUtc),
                item.CaseId,
                item.EvidenceSessionId,
                item.CaptureId,
                item.SourceIdentityId,
                item.HostId,
                item.ExecutionRootId,
                item.ProcessEntityId,
                item.ProcessKey,
                item.SourceRunId,
                item.Category.ToString(),
                item.Action.ToString(),
                item.EventCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                item.RepeatCount.ToString(CultureInfo.InvariantCulture),
                item.CorrelationMethod));
        var networkInputs = networkEvents
            .OrderBy(item => item.TimestampUtc)
            .ThenBy(item => item.SequenceId)
            .Select(item => string.Join('|',
                item.SequenceId.ToString(CultureInfo.InvariantCulture),
                FormatUtc(item.TimestampUtc),
                item.CaseId,
                item.EvidenceSessionId,
                item.CaptureId,
                item.SourceIdentityId,
                item.HostId,
                item.ExecutionRootId,
                item.ProcessEntityId,
                item.ProcessKey,
                item.SourceRunId,
                item.Category.ToString(),
                item.Action.ToString(),
                item.EventCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                item.RepeatCount.ToString(CultureInfo.InvariantCulture),
                item.CorrelationMethod));
        var filesystemInputs = filesystemEvidence
            .OrderBy(item => item.Artifact.TimestampUtc)
            .ThenBy(item => item.Artifact.ArtifactId, StringComparer.Ordinal)
            .Select(item => string.Join('|',
                item.Artifact.ArtifactId,
                item.Artifact.CaseId,
                item.Artifact.EvidenceSessionId,
                item.Artifact.CaptureId,
                item.Artifact.SourceIdentityId,
                item.Artifact.HostId,
                item.Artifact.ExecutionRootId,
                item.Artifact.SourceRunId,
                item.Artifact.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                item.Artifact.Kind.ToString(),
                item.Relation.RelationId,
                item.Relation.CaseId,
                item.Relation.EvidenceSessionId,
                item.Relation.CaptureId,
                item.Relation.SourceIdentityId,
                item.Relation.HostId,
                item.Relation.ExecutionRootId,
                item.Relation.FromKind.ToString(),
                item.Relation.FromId,
                item.Relation.ToKind.ToString(),
                item.Relation.ToId,
                item.Relation.RelationType.ToString(),
                item.Relation.State.ToString(),
                item.Relation.Status.ToString(),
                item.Relation.SourceRunId,
                item.Relation.ObservedFromUtc.ToString("O", CultureInfo.InvariantCulture)));
        var memoryInputs = memoryEvidence
            .OrderBy(item => item.Relation.ObservedFromUtc)
            .ThenBy(item => item.MemoryProcess.ArtifactId, StringComparer.Ordinal)
            .ThenBy(item => item.Relation.RelationId, StringComparer.Ordinal)
            .Select(item => string.Join('|',
                item.MemoryProcess.ArtifactId,
                item.MemoryProcess.ImageId,
                item.MemoryProcess.PluginRunId,
                item.MemoryProcess.CaseId,
                item.MemoryProcess.EvidenceSessionId,
                item.MemoryProcess.CaptureId,
                item.MemoryProcess.SourceIdentityId,
                item.MemoryProcess.HostId,
                item.MemoryProcess.ExecutionRootId,
                item.MemoryProcess.SourceRunId,
                item.MemoryProcess.EvidenceKind.ToString(),
                item.MemoryProcess.RawRowHash,
                item.Relation.RelationId,
                item.Relation.DecisionKey,
                item.Relation.CaseId,
                item.Relation.EvidenceSessionId,
                item.Relation.CaptureId,
                item.Relation.SourceIdentityId,
                item.Relation.HostId,
                item.Relation.ExecutionRootId,
                item.Relation.SourceRunId,
                item.Relation.FromKind.ToString(),
                item.Relation.FromId,
                item.Relation.ToKind.ToString(),
                item.Relation.ToId,
                item.Relation.RelationType.ToString(),
                item.Relation.State.ToString(),
                item.Relation.Status.ToString(),
                item.Relation.ObservedFromUtc.ToString("O", CultureInfo.InvariantCulture),
                item.Relation.ResolverName,
                item.Relation.ResolverVersion));
        var sigmaInputs = sigmaEvidence
            .OrderBy(item => item.MatchedUtc)
            .ThenBy(item => item.MatchId, StringComparer.Ordinal)
            .Select(item => JsonSerializer.Serialize(item));
        var baselineInputs = baselineEvidence
            .OrderBy(item => item.ComparedUtc)
            .ThenBy(item => item.FindingId, StringComparer.Ordinal)
            .Select(item => JsonSerializer.Serialize(item));
        var canonical = string.Join('\n',
            selected.ProcessEntityId,
            selected.Observation.ObservationId,
            selected.Observation.SourceRunId,
            selected.FieldStatesJson,
            selected.PayloadJson,
            pe == null ? string.Empty : JsonSerializer.Serialize(pe),
            verification == null ? string.Empty : JsonSerializer.Serialize(verification),
            "events",
            string.Join('\n', eventInputs),
            "network-dns-events",
            string.Join('\n', networkInputs),
            "filesystem-evidence",
            string.Join('\n', filesystemInputs),
            "memory-evidence",
            string.Join('\n', memoryInputs),
            "sigma-evidence",
            string.Join('\n', sigmaInputs),
            "baseline-evidence",
            string.Join('\n', baselineInputs),
            "yara-generation",
            yaraGenerationId ?? string.Empty,
            "yara-attribution",
            yaraAttribution == null ? string.Empty : JsonSerializer.Serialize(yaraAttribution));
        return Sha256(canonical);
    }

    private static DateTime? LatestSigmaUtc(
        IReadOnlyList<LocalProcessSigmaEvidence> sigmaEvidence) =>
        sigmaEvidence.Count == 0 ? null : sigmaEvidence.Max(item => item.MatchedUtc);

    private static DateTime? LatestBaselineUtc(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> baselineEvidence) =>
        baselineEvidence.Count == 0 ? null : baselineEvidence.Max(item => item.ComparedUtc);

    private static DateTime? LatestFilesystemUtc(
        IReadOnlyList<LocalProcessFilesystemEvidence> filesystemEvidence)
    {
        if (filesystemEvidence.Count == 0)
        {
            return null;
        }

        var timestamps = new List<DateTime>(filesystemEvidence.Count * 9);
        foreach (var item in filesystemEvidence)
        {
            timestamps.Add(item.Artifact.TimestampUtc);
            timestamps.Add(item.Relation.ObservedFromUtc);
            timestamps.Add(item.Relation.CreatedUtc);
            timestamps.Add(item.Relation.UpdatedUtc);
            if (item.Artifact.CreatedUtc is { } artifactCreatedUtc)
            {
                timestamps.Add(artifactCreatedUtc);
            }

            if (item.Artifact.LastModifiedUtc is { } lastModifiedUtc)
            {
                timestamps.Add(lastModifiedUtc);
            }

            if (item.Artifact.LastRunUtc is { } lastRunUtc)
            {
                timestamps.Add(lastRunUtc);
            }

            if (item.Relation.ObservedToUtc is { } observedToUtc)
            {
                timestamps.Add(observedToUtc);
            }

            if (item.Relation.ValidFromUtc is { } validFromUtc)
            {
                timestamps.Add(validFromUtc);
            }

            if (item.Relation.ValidToUtc is { } validToUtc)
            {
                timestamps.Add(validToUtc);
            }
        }

        return timestamps.Max();
    }

    private static DateTime? LatestMemoryUtc(
        IReadOnlyList<LocalProcessMemoryEvidence> memoryEvidence)
    {
        if (memoryEvidence.Count == 0)
        {
            return null;
        }

        var timestamps = new List<DateTime>(memoryEvidence.Count * 8);
        foreach (var item in memoryEvidence)
        {
            timestamps.Add(item.Relation.ObservedFromUtc);
            timestamps.Add(item.Relation.CreatedUtc);
            timestamps.Add(item.Relation.UpdatedUtc);
            if (item.MemoryProcess.CreateTimeUtc is { } createTimeUtc)
            {
                timestamps.Add(createTimeUtc);
            }

            if (item.MemoryProcess.ExitTimeUtc is { } exitTimeUtc)
            {
                timestamps.Add(exitTimeUtc);
            }

            if (item.Relation.ObservedToUtc is { } observedToUtc)
            {
                timestamps.Add(observedToUtc);
            }

            if (item.Relation.ValidFromUtc is { } validFromUtc)
            {
                timestamps.Add(validFromUtc);
            }

            if (item.Relation.ValidToUtc is { } validToUtc)
            {
                timestamps.Add(validToUtc);
            }
        }

        return timestamps.Max();
    }

    private static string ComputeEvaluationId(
        string inputHash,
        ProcessRiskAggregationPolicy policy)
    {
        var evaluationIdentity = Sha256(string.Join('\n',
            inputHash,
            LocalProcessRiskMapper.MapperId,
            LocalProcessRiskMapper.MapperVersion,
            policy.PolicyId,
            policy.PolicyVersion,
            AggregationVersion));
        return $"risk-evaluation-{evaluationIdentity[..32]}";
    }

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static DateTime MaxUtc(
        DateTime first,
        DateTime? second,
        DateTime? third,
        DateTime? fourth = null,
        DateTime? fifth = null,
        DateTime? sixth = null,
        DateTime? seventh = null,
        DateTime? eighth = null,
        DateTime? ninth = null,
        DateTime? tenth = null)
    {
        var value = new[]
        {
            first,
            second ?? DateTime.MinValue,
            third ?? DateTime.MinValue,
            fourth ?? DateTime.MinValue,
            fifth ?? DateTime.MinValue,
            sixth ?? DateTime.MinValue,
            seventh ?? DateTime.MinValue,
            eighth ?? DateTime.MinValue,
            ninth ?? DateTime.MinValue,
            tenth ?? DateTime.MinValue
        }.Max();
        return value.Kind == DateTimeKind.Utc ? value : DateTime.UnixEpoch;
    }

    private static string FormatUtc(DateTime value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static void Add(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    private static string GetString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static int GetInt(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? 0 : reader.GetInt32(ordinal);

    private static long GetLong(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? 0 : reader.GetInt64(ordinal);

    private static double GetDouble(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? 0 : reader.GetDouble(ordinal);

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ||
        !DateTimeOffset.TryParse(
            reader.GetString(ordinal),
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var value)
            ? null
            : value.UtcDateTime;

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum invalid)
        where TEnum : struct, Enum =>
        !reader.IsDBNull(ordinal) &&
        Enum.TryParse<TEnum>(reader.GetString(ordinal), out var value) &&
        Enum.IsDefined(value)
            ? value
            : invalid;

    private sealed record SelectedObservation(
        string ProcessEntityId,
        ProcessObservation Observation,
        string PayloadJson,
        string FieldStatesJson,
        string MaterializationFailure);

    private sealed record PersistedYaraInput(
        YaraProcessAttributionResult Attribution,
        DateTime CompletedUtc,
        string ScanPayloadHashSha256,
        string AttributionPayloadHashSha256,
        string RelationId);

    private sealed record PersistedYaraGeneration(
        string GenerationId,
        IReadOnlyDictionary<string, PersistedYaraInput> ByEntity);
}

internal sealed class SqliteProcessRiskProjectionMaintenanceContext
{
    private readonly SqliteStagingStore _owner;

    internal SqliteProcessRiskProjectionMaintenanceContext(SqliteStagingStore owner)
    {
        _owner = owner ?? throw new ArgumentNullException(nameof(owner));
    }

    internal SqliteCommand CreateCommand(string sql)
        => _owner.CreateAnalysisMaintenanceCommand(sql);

    internal bool TableExists(string tableName)
        => _owner.AnalysisMaintenanceTableExists(tableName);

    internal bool ColumnExists(string tableName, string columnName)
        => _owner.AnalysisMaintenanceColumnExists(tableName, columnName);

    internal YaraAnalysisReadResult ReadExactYaraScan(YaraAnalysisScanQuery query)
    {
        var readContext = new SqliteReadQueryContext(
            _owner.DatabasePath,
            annotationDatabasePath: null,
            SqlitePerformanceProfileName.Conservative);
        return new YaraAnalysisQueryService(readContext).GetExactScan(query);
    }

    internal T ExecuteTransactionWithRetry<T>(Func<T> action, CancellationToken cancellationToken)
        => _owner.ExecuteAnalysisMaintenanceTransactionWithRetry(action, cancellationToken);
}
