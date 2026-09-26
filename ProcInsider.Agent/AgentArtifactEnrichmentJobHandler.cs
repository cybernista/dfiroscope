using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentArtifactEnrichmentJobHandler : IAgentJobHandler
{
    private static readonly TimeSpan NewProcessPriorityWindow = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ModuleFreshnessWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan HandleFreshnessWindow = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan FailureThrottleWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan WriterPressureDelay = TimeSpan.FromMilliseconds(250);
    private const int WriterPressurePendingWorkItems = 32;
    private const double WriterPressureQueueDelayMilliseconds = 2000;

    private readonly string _databasePath;
    private readonly AgentStagingWriter _writer;
    private readonly ModuleInspector _moduleInspector;
    private readonly HandleInspector _handleInspector;
    private readonly PeAnalysisService _peAnalysisService;
    private readonly int _peAnalysisWorkers;
    private readonly TextWriter _log;
    private readonly AgentArtifactEnrichmentStatistics _statistics;

    public AgentArtifactEnrichmentJobHandler(
        string databasePath,
        AgentStagingWriter writer,
        ModuleInspector moduleInspector,
        HandleInspector handleInspector,
        PeAnalysisService peAnalysisService,
        int peAnalysisWorkers,
        TextWriter log,
        AgentArtifactEnrichmentStatistics statistics)
    {
        _databasePath = databasePath;
        _writer = writer;
        _moduleInspector = moduleInspector;
        _handleInspector = handleInspector;
        _peAnalysisService = peAnalysisService;
        _peAnalysisWorkers = Math.Clamp(peAnalysisWorkers, 1, PeAnalysisBatch.MaximumConcurrency);
        _log = log;
        _statistics = statistics;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = context.Request.ReadParameters<EnrichmentParameters>();
        var captureModules = parameters.CaptureModules || context.Request.JobKind == ProcInsider.Models.Agent.JobKind.ModuleEnrichment;
        var captureHandles = parameters.CaptureHandles || context.Request.JobKind == ProcInsider.Models.Agent.JobKind.HandleEnrichment;
        var capturePe = parameters.CapturePe || context.Request.JobKind == ProcInsider.Models.Agent.JobKind.PeAnalysis;
        var peStringExtractionMode = parameters.PeStringExtractionMode;
        var force = (parameters.ProcessEntityIds is { Length: > 0 } || parameters.ProcessKeys is { Length: > 0 }) && !parameters.Sweep;
        var targets = LoadTargets(parameters.ProcessEntityIds, parameters.ProcessKeys, force, capturePe, peStringExtractionMode).ToList();
        var peAnalysisBatch = capturePe ? new PeAnalysisBatch(_peAnalysisService, _peAnalysisWorkers, peStringExtractionMode) : null;

        if (targets.Count == 0)
        {
            await context.ReportProgressAsync(0, 0, "No staged processes matched the enrichment request.").ConfigureAwait(false);
            return;
        }

        await context.ReportProgressAsync(0, targets.Count, $"Enriching {targets.Count} process(es).").ConfigureAwait(false);
        var processed = 0;
        var peTargets = new List<ProcessRecord>();
        var peFreshnessSkipCount = 0;
        foreach (var target in targets)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            if (!force)
            {
                await WaitForWriterBreathingRoomAsync(context.CancellationToken).ConfigureAwait(false);
            }

            var isLiveMatch = await CaptureNonPeArtifactsAsync(target.Process, captureModules, captureHandles, force, context.CancellationToken).ConfigureAwait(false);
            if (isLiveMatch && capturePe && ShouldCapturePe(target.Process, target.LatestProcessImagePeAnalysis, force, peStringExtractionMode))
            {
                peTargets.Add(target.Process);
            }
            else if (isLiveMatch && capturePe)
            {
                peFreshnessSkipCount++;
            }
            processed++;
            if (!force)
            {
                await WaitForWriterBreathingRoomAsync(context.CancellationToken).ConfigureAwait(false);
            }

            await context.ReportProgressAsync(processed, targets.Count, $"Enriched {processed} of {targets.Count} process(es).").ConfigureAwait(false);
        }

        if (capturePe && peFreshnessSkipCount > 0)
        {
            _statistics.PeFreshnessSkipped(peFreshnessSkipCount);
        }

        if (peTargets.Count > 0)
        {
            await AnalyzeAndPersistPeAsync(peTargets, peAnalysisBatch!, peFreshnessSkipCount, force, context).ConfigureAwait(false);
        }
        else if (capturePe && peFreshnessSkipCount > 0)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] PE timing: analyzed=0, freshnessSkipped={peFreshnessSkipCount}, physical=0, completedCacheHits=0, inFlightReuse=0.");
            await context.ReportProgressAsync(
                targets.Count,
                targets.Count,
                $"PE analysis complete: analyzed 0, freshness skipped {peFreshnessSkipCount}, written 0, failed 0.").ConfigureAwait(false);
        }
    }

    private async Task WaitForWriterBreathingRoomAsync(CancellationToken cancellationToken)
    {
        var logged = false;
        while (true)
        {
            var snapshot = _writer.GetSnapshot();
            var pending = snapshot.PendingWorkItemCount;
            var queueDelayPressure = pending > 0 &&
                                     snapshot.LastQueueDelayMilliseconds >= WriterPressureQueueDelayMilliseconds;
            if (!snapshot.IsBackpressureActive &&
                pending < WriterPressurePendingWorkItems &&
                !queueDelayPressure)
            {
                return;
            }

            if (!logged)
            {
                _log.WriteLine(
                    $"[{DateTimeOffset.Now:O}] Pausing background enrichment while SQLite writer catches up. " +
                    $"Queue: {pending}/{snapshot.QueueCapacity}; last queue delay {snapshot.LastQueueDelayMilliseconds:F1} ms; " +
                    $"last operation {snapshot.LastOperationName}.");
                logged = true;
            }

            await Task.Delay(WriterPressureDelay, cancellationToken).ConfigureAwait(false);
        }
    }

    private IEnumerable<EnrichmentTarget> LoadTargets(
        string[]? processEntityIds,
        string[]? processKeys,
        bool force,
        bool capturePe,
        PeStringExtractionMode peStringExtractionMode)
    {
        var queryService = new SqliteStagingQueryService(
            _databasePath,
            openContext: CaptureOpenContext.AgentWritableLive);
        var allProcesses = queryService.GetProcesses(new ProcessProjectionQuery
        {
            IncludeExited = false,
            MaxCount = 100000
        });
        var latestPeAnalyses = capturePe
            ? queryService.GetLatestProcessImagePeAnalysesByProcessKey()
            : new Dictionary<string, PeAnalysisRecord>(StringComparer.Ordinal);

        if (processEntityIds is { Length: > 0 })
        {
            var requestedEntities = processEntityIds
                .Where(id => !string.IsNullOrWhiteSpace(id))
                .Select((id, index) => new { Id = id, Index = index })
                .GroupBy(item => item.Id, StringComparer.Ordinal)
                .ToDictionary(group => group.Key, group => group.Min(item => item.Index), StringComparer.Ordinal);
            return allProcesses
                .Where(process => requestedEntities.ContainsKey(process.ProcessEntityId))
                .OrderBy(process => requestedEntities[process.ProcessEntityId])
                .Select(process => new EnrichmentTarget(process, GetLatestProcessImagePeAnalysis(process, latestPeAnalyses)));
        }

        if (processKeys is not { Length: > 0 })
        {
            return PrioritizeTargets(allProcesses.Where(process => process.Status == ProcessStatus.Running), force, capturePe, peStringExtractionMode, latestPeAnalyses)
                .Select(process => new EnrichmentTarget(process, GetLatestProcessImagePeAnalysis(process, latestPeAnalyses)));
        }

        var requestedOrder = processKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select((key, index) => new { Key = key, Index = index })
            .GroupBy(item => item.Key, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Min(item => item.Index), StringComparer.Ordinal);
        return allProcesses
            .Where(process => requestedOrder.ContainsKey(process.ProcessKey))
            .OrderBy(process => requestedOrder[process.ProcessKey])
            .Select(process => new EnrichmentTarget(process, GetLatestProcessImagePeAnalysis(process, latestPeAnalyses)));
    }

    private async Task<bool> CaptureNonPeArtifactsAsync(
        ProcessRecord process,
        bool captureModules,
        bool captureHandles,
        bool force,
        CancellationToken cancellationToken)
    {
        var liveMatch = TryOpenMatchingLiveProcess(process, out var liveProcess);
        using (liveProcess)
        {
            if (!liveMatch || liveProcess is null)
            {
                await MarkNotFoundAsync(process, captureModules, captureHandles, "Process was not found or PID was reused during agent enrichment.", cancellationToken).ConfigureAwait(false);
                if (captureModules)
                {
                    _statistics.ModuleStarted();
                    _statistics.ModuleFailed("Process was not found or PID was reused during agent enrichment.");
                }
                if (captureHandles)
                {
                    _statistics.HandleStarted();
                    _statistics.HandleFailed("Process was not found or PID was reused during agent enrichment.");
                }
                return false;
            }

            var now = DateTime.UtcNow;
            if (captureModules && ShouldCaptureArtifact(process.ModuleCaptureStatus, process.ModuleLastCapturedUtc, process.LastObservedUtc, ModuleFreshnessWindow, now, force))
            {
                _statistics.ModuleStarted();
                try
                {
                    await CaptureModulesAsync(process, liveProcess, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    await MarkModuleFailureAsync(process, ex.Message, cancellationToken).ConfigureAwait(false);
                    _statistics.ModuleFailed(ex.Message);
                }
            }

            if (captureHandles && ShouldCaptureArtifact(process.HandleCaptureStatus, process.HandleLastCapturedUtc, process.LastObservedUtc, HandleFreshnessWindow, now, force))
            {
                _statistics.HandleStarted();
                try
                {
                    await CaptureHandlesAsync(process, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    await MarkHandleFailureAsync(process, ex.Message, cancellationToken).ConfigureAwait(false);
                    _statistics.HandleFailed(ex.Message);
                }
            }

            return true;
        }
    }

    private async Task CaptureModulesAsync(ProcessRecord process, Process liveProcess, CancellationToken cancellationToken)
    {
        var capturing = Clone(process);
        capturing.ModuleCaptureStatus = ArtifactCaptureStatus.Capturing;
        capturing.ModuleCaptureError = string.Empty;
        capturing.LastSource = "AgentModuleEnrichment";
        capturing.LastObservedUtc = DateTime.UtcNow;

        try
        {
            await _writer.UpsertProcessesAsync(new[] { capturing }, cancellationToken).ConfigureAwait(false);
            var result = await _moduleInspector.GetModulesAsync(liveProcess, cancellationToken).ConfigureAwait(false);
            if (!result.Success)
            {
                var error = result.ErrorMessage ?? "Unable to capture modules.";
                await MarkModuleFailureAsync(process, error, cancellationToken).ConfigureAwait(false);
                _statistics.ModuleFailed(error);
                return;
            }

            var capturedUtc = DateTime.UtcNow;
            var records = result.Modules.Select(module => CreateModuleRecord(process, module, capturedUtc)).ToList();
            var updated = Clone(process);
            updated.ModuleCaptureStatus = ArtifactCaptureStatus.Captured;
            updated.ModuleCount = records.Count;
            updated.ModuleLastCapturedUtc = capturedUtc;
            updated.ModuleCaptureError = string.Empty;
            updated.LastSource = "AgentModuleEnrichment";
            updated.LastObservedUtc = capturedUtc;
            await _writer.UpsertProcessesAsync(new[] { updated }, cancellationToken).ConfigureAwait(false);
            await _writer.UpsertModuleSnapshotAsync(
                process.ProcessKey,
                records,
                capturedUtc,
                "AgentModuleEnrichment",
                cancellationToken).ConfigureAwait(false);
            _statistics.ModuleSucceeded(records.Count);
        }
        catch (OperationCanceledException)
        {
            _statistics.ModuleCancelled();
            throw;
        }
        catch (Exception ex)
        {
            await MarkModuleFailureAsync(process, ex.Message, cancellationToken).ConfigureAwait(false);
            _statistics.ModuleFailed(ex.Message);
        }
    }

    private async Task CaptureHandlesAsync(ProcessRecord process, CancellationToken cancellationToken)
    {
        var capturing = Clone(process);
        capturing.HandleCaptureStatus = ArtifactCaptureStatus.Capturing;
        capturing.HandleCaptureError = string.Empty;
        capturing.LastSource = "AgentHandleEnrichment";
        capturing.LastObservedUtc = DateTime.UtcNow;

        try
        {
            await _writer.UpsertProcessesAsync(new[] { capturing }, cancellationToken).ConfigureAwait(false);
            var result = await _handleInspector.GetHandlesAsync(process.ProcessId, cancellationToken).ConfigureAwait(false);
            if (!result.Success)
            {
                var error = result.ErrorMessage ?? "Unable to capture handles.";
                await MarkHandleFailureAsync(process, error, cancellationToken).ConfigureAwait(false);
                _statistics.HandleFailed(error);
                return;
            }

            var capturedUtc = DateTime.UtcNow;
            var records = result.Handles.Select(handle => CreateHandleRecord(process, handle, capturedUtc)).ToList();
            var updated = Clone(process);
            updated.HandleCaptureStatus = ArtifactCaptureStatus.Captured;
            updated.HandleCount = records.Count;
            updated.HandleLastCapturedUtc = capturedUtc;
            updated.HandleCaptureError = string.Empty;
            updated.LastSource = "AgentHandleEnrichment";
            updated.LastObservedUtc = capturedUtc;
            await _writer.UpsertProcessesAsync(new[] { updated }, cancellationToken).ConfigureAwait(false);
            await _writer.UpsertHandleSnapshotAsync(
                process.ProcessKey,
                records,
                capturedUtc,
                "AgentHandleEnrichment",
                cancellationToken).ConfigureAwait(false);
            _statistics.HandleSucceeded(records.Count);
        }
        catch (OperationCanceledException)
        {
            _statistics.HandleCancelled();
            throw;
        }
        catch (Exception ex)
        {
            await MarkHandleFailureAsync(process, ex.Message, cancellationToken).ConfigureAwait(false);
            _statistics.HandleFailed(ex.Message);
        }
    }

    private async Task AnalyzeAndPersistPeAsync(
        IReadOnlyList<ProcessRecord> processes,
        PeAnalysisBatch analysisBatch,
        int freshnessSkipCount,
        bool force,
        AgentJobContext context)
    {
        var totalTimer = Stopwatch.StartNew();
        var analysisTimer = Stopwatch.StartNew();
        var analyses = new PeAnalysisRecord[processes.Count];
        var completed = 0;
        var succeeded = 0;
        var failed = 0;
        var reused = 0;
        var lastReportedCount = 0;
        long lastProgressTimestamp = 0;
        using var progressReportGate = new SemaphoreSlim(1, 1);
        await context.ReportProgressAsync(0, processes.Count, $"PE analysis starting for {processes.Count} process image(s) with up to {analysisBatch.MaxConcurrency} worker(s).").ConfigureAwait(false);

        await Parallel.ForEachAsync(
            Enumerable.Range(0, processes.Count),
            new ParallelOptions
            {
                CancellationToken = context.CancellationToken,
                MaxDegreeOfParallelism = analysisBatch.MaxConcurrency
            },
            async (index, cancellationToken) =>
            {
                if (!force)
                {
                    await WaitForWriterBreathingRoomAsync(cancellationToken).ConfigureAwait(false);
                }

                _statistics.PeStarted();
                try
                {
                    var analysis = await AnalyzePeAsync(processes[index], analysisBatch, cancellationToken).ConfigureAwait(false);
                    analyses[index] = analysis;
                    var wasReused = IsReusedPeAnalysis(analysis);
                    if (wasReused)
                    {
                        Interlocked.Increment(ref reused);
                    }

                    if (analysis.Status == PeAnalysisStatus.Completed)
                    {
                        Interlocked.Increment(ref succeeded);
                        _statistics.PeSucceeded(wasReused);
                    }
                    else
                    {
                        Interlocked.Increment(ref failed);
                        _statistics.PeFailed(analysis.ErrorMessage, wasReused);
                    }
                }
                catch (OperationCanceledException)
                {
                    _statistics.PeCancelled();
                    throw;
                }

                var current = Interlocked.Increment(ref completed);
                if (ShouldReportPeProgress(current, processes.Count, ref lastProgressTimestamp))
                {
                    await progressReportGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        var latest = Volatile.Read(ref completed);
                        if (latest > lastReportedCount)
                        {
                            lastReportedCount = latest;
                            await context.ReportProgressAsync(
                                latest,
                                processes.Count,
                                $"PE analysis {latest} of {processes.Count}: successful {Volatile.Read(ref succeeded)}, failed {Volatile.Read(ref failed)}, reused {Volatile.Read(ref reused)}, freshness skipped {freshnessSkipCount}.").ConfigureAwait(false);
                        }
                    }
                    finally
                    {
                        progressReportGate.Release();
                    }
                }
            }).ConfigureAwait(false);

        var analysisMilliseconds = analysisTimer.Elapsed.TotalMilliseconds;
        context.CancellationToken.ThrowIfCancellationRequested();
        await context.ReportProgressAsync(
            completed,
            processes.Count,
            $"PE analysis finished: successful {succeeded}, failed {failed}, reused {reused}; writing {analyses.Length} durable row(s).").ConfigureAwait(false);
        var persistenceTimer = Stopwatch.StartNew();
        try
        {
            await _writer.UpsertPeAnalysesAsync(analyses, context.CancellationToken).ConfigureAwait(false);
            _statistics.PeRowsWritten(analyses.Length);
            var authenticodeVerifications = analyses
                .Select(analysis => analysis.AuthenticodeVerification)
                .Where(verification => verification != null)
                .Cast<AuthenticodeVerificationRecord>()
                .ToArray();
            await _writer.InsertAuthenticodeVerificationsAsync(
                authenticodeVerifications,
                context.CancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _statistics.PePersistenceFailed(ex.Message);
            throw;
        }
        var persistenceMilliseconds = persistenceTimer.Elapsed.TotalMilliseconds;
        var phaseTotals = SummarizePePerformance(analyses);
        _log.WriteLine(
            $"[{DateTimeOffset.Now:O}] PE timing: analyzed={analyses.Length}, freshnessSkipped={freshnessSkipCount}, " +
            $"physical={analysisBatch.PhysicalAnalysisCount}, completedCacheHits={analysisBatch.CompletedCacheHitCount}, " +
            $"inFlightReuse={analysisBatch.InFlightReuseCount}, maxConcurrency={analysisBatch.MaxObservedConcurrentAnalyses}/{analysisBatch.MaxConcurrency}, " +
            $"openMs={phaseTotals.FileOpenMilliseconds:F1}, scanMs={phaseTotals.StreamScanMilliseconds:F1}, " +
            $"hashFinalizeMs={phaseTotals.HashFinalizationMilliseconds:F1}, stringsMs={phaseTotals.StringExtractionMilliseconds:F1}, " +
            $"parseMs={phaseTotals.PeParsingMilliseconds:F1}, versionMs={phaseTotals.VersionMetadataMilliseconds:F1}, " +
            $"queueMs={phaseTotals.QueueDelayMilliseconds:F1}, analysisWallMs={analysisMilliseconds:F1}, " +
            $"persistenceMs={persistenceMilliseconds:F1}, totalMs={totalTimer.Elapsed.TotalMilliseconds:F1}.");
        await context.ReportProgressAsync(
            completed,
            processes.Count,
            $"PE analysis complete: successful {succeeded}, failed {failed}, reused {reused}, freshness skipped {freshnessSkipCount}, written {analyses.Length}.").ConfigureAwait(false);
    }

    private static bool ShouldReportPeProgress(int completed, int total, ref long lastProgressTimestamp)
    {
        if (completed <= 3 || completed >= total)
        {
            return true;
        }

        var now = Stopwatch.GetTimestamp();
        while (true)
        {
            var previous = Volatile.Read(ref lastProgressTimestamp);
            if (previous != 0 && Stopwatch.GetElapsedTime(previous, now) < TimeSpan.FromMilliseconds(250))
            {
                return false;
            }

            if (Interlocked.CompareExchange(ref lastProgressTimestamp, now, previous) == previous)
            {
                return true;
            }
        }
    }

    private static bool IsReusedPeAnalysis(PeAnalysisRecord analysis)
    {
        try
        {
            return JsonSerializer.Deserialize<PeAnalysisPerformance>(analysis.PerformanceJson)?.ReusedAnalysis == true;
        }
        catch
        {
            return false;
        }
    }

    private static PeAnalysisPerformance SummarizePePerformance(IEnumerable<PeAnalysisRecord> analyses)
    {
        var total = new PeAnalysisPerformance();
        foreach (var analysis in analyses)
        {
            PeAnalysisPerformance? timing;
            try
            {
                timing = JsonSerializer.Deserialize<PeAnalysisPerformance>(analysis.PerformanceJson);
            }
            catch
            {
                timing = null;
            }

            if (timing == null || timing.ReusedAnalysis)
            {
                continue;
            }

            total.FileOpenMilliseconds += timing.FileOpenMilliseconds;
            total.StreamScanMilliseconds += timing.StreamScanMilliseconds;
            total.HashFinalizationMilliseconds += timing.HashFinalizationMilliseconds;
            total.StringExtractionMilliseconds += timing.StringExtractionMilliseconds;
            total.PeParsingMilliseconds += timing.PeParsingMilliseconds;
            total.VersionMetadataMilliseconds += timing.VersionMetadataMilliseconds;
            total.QueueDelayMilliseconds += timing.QueueDelayMilliseconds;
            total.TotalMilliseconds += timing.TotalMilliseconds;
        }

        return total;
    }

    private async Task<PeAnalysisRecord> AnalyzePeAsync(
        ProcessRecord process,
        PeAnalysisBatch analysisBatch,
        CancellationToken cancellationToken)
    {
        try
        {
            var processInfo = ToProcessInfo(process);
            var analysis = await analysisBatch.AnalyzeProcessImageAsync(processInfo, cancellationToken).ConfigureAwait(false);
            analysis.CaseId = process.CaseId;
            analysis.EvidenceSessionId = process.EvidenceSessionId;
            analysis.CaptureId = process.CaptureId;
            analysis.SourceIdentityId = process.SourceIdentityId;
            analysis.HostId = process.HostId;
            analysis.ExecutionRootId = process.ExecutionRootId;
            analysis.ProcessEntityId = process.ProcessEntityId;
            analysis.Source = "AgentPeEnrichment";
            if (analysis.Status == PeAnalysisStatus.Failed)
            {
                _log.WriteLine($"[{DateTimeOffset.Now:O}] PE enrichment failed for {process.ProcessKey}: {analysis.ErrorMessage}");
            }
            return analysis;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var failed = CreateFailedPeAnalysis(process, ex.Message, analysisBatch.StringExtractionMode);
            _log.WriteLine($"[{DateTimeOffset.Now:O}] PE enrichment failed for {process.ProcessKey}: {ex.Message}");
            return failed;
        }
    }

    private async Task MarkNotFoundAsync(
        ProcessRecord process,
        bool captureModules,
        bool captureHandles,
        string error,
        CancellationToken cancellationToken)
    {
        var updated = Clone(process);
        if (updated.Status != ProcessStatus.Exited)
        {
            updated.Status = ProcessStatus.NotFound;
        }

        if (captureModules)
        {
            updated.ModuleCaptureStatus = ArtifactCaptureStatus.NotFound;
            updated.ModuleCaptureError = error;
        }

        if (captureHandles)
        {
            updated.HandleCaptureStatus = ArtifactCaptureStatus.NotFound;
            updated.HandleCaptureError = error;
        }

        updated.LastSource = "AgentArtifactEnrichment";
        updated.LastObservedUtc = DateTime.UtcNow;
        await _writer.UpsertProcessesAsync(new[] { updated }, cancellationToken).ConfigureAwait(false);
    }

    private async Task MarkModuleFailureAsync(ProcessRecord process, string error, CancellationToken cancellationToken)
    {
        var updated = Clone(process);
        updated.ModuleCaptureStatus = IsProcessNotFoundError(error) ? ArtifactCaptureStatus.NotFound : ArtifactCaptureStatus.Failed;
        updated.ModuleCaptureError = error;
        updated.LastSource = "AgentModuleEnrichment";
        updated.LastObservedUtc = DateTime.UtcNow;
        await _writer.UpsertProcessesAsync(new[] { updated }, cancellationToken).ConfigureAwait(false);
        _log.WriteLine($"[{DateTimeOffset.Now:O}] Module enrichment failed for {process.ProcessKey}: {error}");
    }

    private async Task MarkHandleFailureAsync(ProcessRecord process, string error, CancellationToken cancellationToken)
    {
        var updated = Clone(process);
        updated.HandleCaptureStatus = IsProcessNotFoundError(error) ? ArtifactCaptureStatus.NotFound : ArtifactCaptureStatus.Failed;
        updated.HandleCaptureError = error;
        updated.LastSource = "AgentHandleEnrichment";
        updated.LastObservedUtc = DateTime.UtcNow;
        await _writer.UpsertProcessesAsync(new[] { updated }, cancellationToken).ConfigureAwait(false);
        _log.WriteLine($"[{DateTimeOffset.Now:O}] Handle enrichment failed for {process.ProcessKey}: {error}");
    }

    private static bool TryOpenMatchingLiveProcess(ProcessRecord process, out Process? liveProcess)
    {
        liveProcess = null;
        try
        {
            liveProcess = Process.GetProcessById(process.ProcessId);
            if (process.StartTimeUtc.HasValue)
            {
                return Math.Abs((liveProcess.StartTime.ToUniversalTime() - process.StartTimeUtc.Value).TotalSeconds) <= 2;
            }

            return string.Equals(liveProcess.ProcessName, process.ProcessName, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals($"{liveProcess.ProcessName}.exe", process.ProcessName, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            liveProcess?.Dispose();
            liveProcess = null;
            return false;
        }
    }

    private static ModuleObservationRecord CreateModuleRecord(ProcessRecord process, ModuleInfo module, DateTime observedUtc)
    {
        var input = new ModuleObservationInput
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ProcessId = process.ProcessId,
            ProcessGuid = process.ProcessGuid,
            ModuleName = module.ModuleName,
            FullPath = module.FullPath,
            BaseAddress = module.BaseAddress,
            ModuleMemorySize = module.ModuleMemorySize,
            FileVersion = module.FileVersion,
            CompanyName = module.CompanyName,
            Description = module.Description,
            Sha256Hash = module.Sha256Hash,
            ObservedUtc = observedUtc,
            Source = "AgentModuleEnrichment"
        };

        return new ModuleObservationRecord
        {
            CaseId = input.CaseId,
            EvidenceSessionId = input.EvidenceSessionId,
            CaptureId = input.CaptureId,
            SourceIdentityId = input.SourceIdentityId,
            HostId = input.HostId,
            ExecutionRootId = input.ExecutionRootId,
            ProcessEntityId = input.ProcessEntityId,
            ProcessKey = input.ProcessKey,
            ProcessId = input.ProcessId,
            ProcessGuid = input.ProcessGuid,
            ModuleKey = BuildModuleKey(input),
            ModuleName = PreferKnownValue(input.ModuleName, "<unknown>"),
            FullPath = PreferKnownValue(input.FullPath, "<not available>"),
            BaseAddress = PreferKnownValue(input.BaseAddress, "<not available>"),
            ModuleMemorySize = input.ModuleMemorySize,
            FileVersion = PreferKnownValue(input.FileVersion, "<not available>"),
            CompanyName = PreferKnownValue(input.CompanyName, "<not available>"),
            Description = PreferKnownValue(input.Description, "<not available>"),
            Sha256Hash = PreferKnownValue(input.Sha256Hash, "<not available>"),
            FirstSeenUtc = observedUtc,
            LastSeenUtc = observedUtc,
            State = ModuleObservationState.Loaded,
            Sources = input.Source,
            LastSource = input.Source
        };
    }

    private static HandleObservationRecord CreateHandleRecord(ProcessRecord process, HandleInfo handle, DateTime observedUtc)
    {
        return new HandleObservationRecord
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ProcessId = process.ProcessId,
            HandleKey = BuildHandleKey(
                string.IsNullOrWhiteSpace(process.ProcessEntityId) ? process.ProcessKey : process.ProcessEntityId,
                handle),
            HandleValue = handle.HandleValue,
            HandleValueNumeric = handle.HandleValueNumeric,
            ObjectType = handle.ObjectType,
            ObjectName = handle.ObjectName,
            GrantedAccess = handle.GrantedAccess,
            GrantedAccessValue = handle.GrantedAccessValue,
            HandleAttributes = handle.HandleAttributes,
            HandleAttributesValue = handle.HandleAttributesValue,
            ObjectAddress = handle.ObjectAddress,
            FirstSeenUtc = observedUtc,
            LastSeenUtc = observedUtc,
            State = HandleObservationState.Open,
            LastSource = "AgentHandleEnrichment"
        };
    }

    private static string BuildModuleKey(ModuleObservationInput input)
    {
        var processIdentity = string.IsNullOrWhiteSpace(input.ProcessEntityId)
            ? input.ProcessKey
            : input.ProcessEntityId;
        var path = NormalizeKeyPart(input.FullPath);
        var baseAddress = NormalizeKeyPart(input.BaseAddress);
        return string.IsNullOrWhiteSpace(baseAddress) || baseAddress == "<not available>"
            ? $"{processIdentity}|{path}"
            : $"{processIdentity}|{path}|{baseAddress}";
    }

    private static string BuildHandleKey(string processKey, HandleInfo handle)
    {
        var objectIdentity = !string.IsNullOrWhiteSpace(handle.ObjectAddress) && handle.ObjectAddress != "<not available>"
            ? handle.ObjectAddress
            : handle.ObjectName;
        return $"{processKey}|{handle.HandleValueNumeric}|{NormalizeKeyPart(handle.ObjectType)}|{NormalizeKeyPart(objectIdentity)}";
    }

    private static string NormalizeKeyPart(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToLowerInvariant();

    private static string PreferKnownValue(string? incoming, string fallback)
        => string.IsNullOrWhiteSpace(incoming) ? fallback : incoming;

    private static bool IsProcessNotFoundError(string error)
        => error.Contains("has exited", StringComparison.OrdinalIgnoreCase) ||
           error.Contains("no longer available", StringComparison.OrdinalIgnoreCase) ||
           error.Contains("invalid process state", StringComparison.OrdinalIgnoreCase);

    private IEnumerable<ProcessRecord> PrioritizeTargets(
        IEnumerable<ProcessRecord> targets,
        bool force,
        bool capturePe,
        PeStringExtractionMode peStringExtractionMode,
        IReadOnlyDictionary<string, PeAnalysisRecord> latestPeAnalyses)
    {
        var now = DateTime.UtcNow;
        var candidates = force
            ? targets
            : targets.Where(process =>
                ShouldCaptureArtifact(process.ModuleCaptureStatus, process.ModuleLastCapturedUtc, process.LastObservedUtc, ModuleFreshnessWindow, now, force: false) ||
                ShouldCaptureArtifact(process.HandleCaptureStatus, process.HandleLastCapturedUtc, process.LastObservedUtc, HandleFreshnessWindow, now, force: false) ||
                (capturePe && ShouldCapturePe(process, GetLatestProcessImagePeAnalysis(process, latestPeAnalyses), force: false, peStringExtractionMode)));

        return candidates
            .OrderByDescending(process => GetPriority(process, GetLatestProcessImagePeAnalysis(process, latestPeAnalyses), now, peStringExtractionMode))
            .ThenBy(process => GetOldestArtifactTimestamp(process, GetLatestProcessImagePeAnalysis(process, latestPeAnalyses)) ?? DateTime.MinValue);
    }

    private static bool ShouldCapturePe(
        ProcessRecord process,
        PeAnalysisRecord? latest,
        bool force,
        PeStringExtractionMode peStringExtractionMode = PeStringExtractionMode.Deferred)
        => PeAnalysisFreshnessPolicy.ShouldAnalyzeProcessImage(process, latest, force, DateTime.UtcNow, peStringExtractionMode);

    private static bool ShouldCaptureArtifact(
        ArtifactCaptureStatus status,
        DateTime? lastCapturedUtc,
        DateTime lastObservedUtc,
        TimeSpan freshnessWindow,
        DateTime now,
        bool force)
    {
        if (force)
        {
            return true;
        }

        return status switch
        {
            ArtifactCaptureStatus.Pending => true,
            ArtifactCaptureStatus.Capturing => false,
            ArtifactCaptureStatus.Captured => !lastCapturedUtc.HasValue || now - lastCapturedUtc.Value > freshnessWindow,
            ArtifactCaptureStatus.Failed or ArtifactCaptureStatus.NotFound or ArtifactCaptureStatus.NotAvailable => now - lastObservedUtc > FailureThrottleWindow,
            _ => true
        };
    }

    private static int GetPriority(
        ProcessRecord process,
        PeAnalysisRecord? latestPeAnalysis,
        DateTime now,
        PeStringExtractionMode peStringExtractionMode)
    {
        var priority = 0;
        if (now - process.FirstObservedUtc <= NewProcessPriorityWindow ||
            now - process.LastObservedUtc <= NewProcessPriorityWindow ||
            process.LastSource.Contains("Delta", StringComparison.OrdinalIgnoreCase))
        {
            priority += 1000;
        }

        if (process.ModuleCaptureStatus == ArtifactCaptureStatus.Pending)
        {
            priority += 300;
        }

        if (process.HandleCaptureStatus == ArtifactCaptureStatus.Pending)
        {
            priority += 300;
        }

        if (ShouldCapturePe(process, latestPeAnalysis, force: false, peStringExtractionMode))
        {
            priority += 150;
        }

        if (process.ModuleCaptureStatus is ArtifactCaptureStatus.Failed or ArtifactCaptureStatus.NotFound or ArtifactCaptureStatus.NotAvailable ||
            process.HandleCaptureStatus is ArtifactCaptureStatus.Failed or ArtifactCaptureStatus.NotFound or ArtifactCaptureStatus.NotAvailable)
        {
            priority -= 200;
        }

        return priority;
    }

    private static DateTime? GetOldestArtifactTimestamp(ProcessRecord process, PeAnalysisRecord? latestPeAnalysis)
    {
        var timestamps = new[]
            {
                process.ModuleLastCapturedUtc,
                process.HandleLastCapturedUtc,
                latestPeAnalysis?.AnalyzedUtc
            }
            .Where(timestamp => timestamp.HasValue)
            .Select(timestamp => timestamp!.Value)
            .ToList();
        if (timestamps.Count == 0)
        {
            return null;
        }

        return timestamps.Min();
    }

    private static PeAnalysisRecord? GetLatestProcessImagePeAnalysis(
        ProcessRecord process,
        IReadOnlyDictionary<string, PeAnalysisRecord> latestPeAnalyses)
    {
        var identityKey = string.IsNullOrWhiteSpace(process.ProcessEntityId)
            ? process.ProcessKey
            : process.ProcessEntityId;
        return latestPeAnalyses.TryGetValue(identityKey, out var latest)
            ? latest
            : null;
    }

    private static ProcessInfo ToProcessInfo(ProcessRecord process)
    {
        return new ProcessInfo
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ProcessId = process.ProcessId,
            ProcessGuid = process.ProcessGuid,
            StartTime = process.StartTimeUtc?.ToLocalTime(),
            EndTime = process.EndTimeUtc?.ToLocalTime(),
            Status = process.Status,
            ParentProcessId = process.ParentProcessId,
            ParentProcessKey = process.ParentProcessKey,
            ParentProcessName = process.ParentProcessName,
            ProcessName = process.ProcessName,
            ProcessPath = process.ProcessPath,
            CommandLine = process.CommandLine,
            UserName = process.UserName,
            SessionId = process.SessionId,
            Architecture = process.Architecture,
            CpuUsage = process.CpuUsage,
            MemoryUsageBytes = process.MemoryUsageBytes,
            CompanyName = process.CompanyName,
            FileDescription = process.FileDescription,
            Sha256Hash = process.Sha256Hash,
            TreeDepth = process.TreeDepth,
            ModuleCaptureStatus = process.ModuleCaptureStatus,
            ModuleCount = process.ModuleCount,
            ModuleLastCaptured = process.ModuleLastCapturedUtc?.ToLocalTime(),
            ModuleCaptureError = process.ModuleCaptureError,
            HandleCaptureStatus = process.HandleCaptureStatus,
            HandleCount = process.HandleCount,
            HandleLastCaptured = process.HandleLastCapturedUtc?.ToLocalTime(),
            HandleCaptureError = process.HandleCaptureError
        };
    }

    private static PeAnalysisRecord CreateFailedPeAnalysis(
        ProcessRecord process,
        string error,
        PeStringExtractionMode stringExtractionMode)
    {
        return new PeAnalysisRecord
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            AnalysisId = BuildPeAnalysisId(process),
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ProcessId = process.ProcessId,
            ProcessGuid = process.ProcessGuid,
            ProcessName = process.ProcessName,
            SourceKind = PeAnalysisSourceKind.ProcessImage,
            FilePath = process.ProcessPath,
            Status = PeAnalysisStatus.Failed,
            StringAnalysisStatus = stringExtractionMode == PeStringExtractionMode.Immediate
                ? PeStringAnalysisStatus.Failed
                : PeStringAnalysisStatus.Deferred,
            AnalyzedUtc = DateTime.UtcNow,
            ErrorMessage = error,
            Source = "AgentPeEnrichment"
        };
    }

    private static string BuildPeAnalysisId(ProcessRecord process)
    {
        var processIdentity = string.IsNullOrWhiteSpace(process.ProcessEntityId)
            ? process.ProcessKey
            : process.ProcessEntityId;
        var input = $"{processIdentity}|ProcessImage||{process.ProcessPath}".ToLowerInvariant();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant()[..32];
    }

    private static ProcessRecord Clone(ProcessRecord process)
    {
        return new ProcessRecord
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ProcessId = process.ProcessId,
            ProcessGuid = process.ProcessGuid,
            StartTimeUtc = process.StartTimeUtc,
            EndTimeUtc = process.EndTimeUtc,
            Status = process.Status,
            ModuleCaptureStatus = process.ModuleCaptureStatus,
            ModuleCount = process.ModuleCount,
            ModuleLastCapturedUtc = process.ModuleLastCapturedUtc,
            ModuleCaptureError = process.ModuleCaptureError,
            HandleCaptureStatus = process.HandleCaptureStatus,
            HandleCount = process.HandleCount,
            HandleLastCapturedUtc = process.HandleLastCapturedUtc,
            HandleCaptureError = process.HandleCaptureError,
            ParentProcessId = process.ParentProcessId,
            ParentProcessKey = process.ParentProcessKey,
            ParentProcessName = process.ParentProcessName,
            ProcessName = process.ProcessName,
            ProcessPath = process.ProcessPath,
            CommandLine = process.CommandLine,
            UserName = process.UserName,
            SessionId = process.SessionId,
            Architecture = process.Architecture,
            CpuUsage = process.CpuUsage,
            MemoryUsageBytes = process.MemoryUsageBytes,
            CompanyName = process.CompanyName,
            FileDescription = process.FileDescription,
            Sha256Hash = process.Sha256Hash,
            TreeDepth = process.TreeDepth,
            FirstObservedUtc = process.FirstObservedUtc,
            LastObservedUtc = process.LastObservedUtc,
            LastSource = process.LastSource
        };
    }

    private sealed record EnrichmentParameters
    {
        public string[]? ProcessEntityIds { get; init; }

        public string[]? ProcessKeys { get; init; }

        public bool CaptureModules { get; init; }

        public bool CaptureHandles { get; init; }

        public bool CapturePe { get; init; }

        public PeStringExtractionMode PeStringExtractionMode { get; init; } = PeStringExtractionMode.Deferred;

        public bool Sweep { get; init; }
    }

    private sealed record EnrichmentTarget(
        ProcessRecord Process,
        PeAnalysisRecord? LatestProcessImagePeAnalysis);
}

internal static class AgentJobRequestParameterExtensions
{
    public static T ReadParameters<T>(this AgentJobRequest request)
        where T : new()
    {
        if (request.Parameters is null)
        {
            return new T();
        }

        if (request.Parameters is JsonElement jsonElement)
        {
            return jsonElement.Deserialize<T>(AgentJson.JsonOptions) ?? new T();
        }

        var json = JsonSerializer.Serialize(request.Parameters, AgentJson.JsonOptions);
        return JsonSerializer.Deserialize<T>(json, AgentJson.JsonOptions) ?? new T();
    }
}
