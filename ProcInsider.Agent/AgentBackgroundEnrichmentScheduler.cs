using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services;
using System.Collections.Concurrent;

namespace ProcInsider.Agent;

internal sealed class AgentBackgroundEnrichmentScheduler : IAsyncDisposable
{
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ImmediateBatchDelay = TimeSpan.FromMilliseconds(150);
    private static readonly TimeSpan NewProcessPriorityWindow = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ModuleFreshnessWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan HandleFreshnessWindow = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan FailureThrottleWindow = TimeSpan.FromMinutes(10);
    private const int MaxProcessScan = 100000;
    private const int MaxBatchSize = 8;

    private readonly string _databasePath;
    private readonly AgentJobQueue _jobQueue;
    private readonly TextWriter _log;
    private readonly Func<AgentArtifactCapturePolicy> _capturePolicyProvider;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ConcurrentDictionary<string, byte> _immediateProcessEntityIds = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _immediateSignal = new(0, 1);
    private readonly Task _worker;
    private int _immediateSignalPending;

    public AgentBackgroundEnrichmentScheduler(
        string databasePath,
        AgentJobQueue jobQueue,
        TextWriter log,
        Func<AgentArtifactCapturePolicy> capturePolicyProvider,
        bool enableAutomaticScheduling = true)
    {
        _databasePath = databasePath;
        _jobQueue = jobQueue;
        _log = log;
        _capturePolicyProvider = capturePolicyProvider;
        _worker = enableAutomaticScheduling ? Task.Run(RunAsync) : Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        try
        {
            await _worker.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }
        finally
        {
            _shutdown.Dispose();
            _immediateSignal.Dispose();
        }
    }

    /// <summary>
    /// Schedules a newly committed live process without waiting for the periodic sweep.
    /// The keys are deduplicated and picked up only after their process rows are durable.
    /// </summary>
    public void NotifyProcessRecordsPersisted(IReadOnlyList<ProcessRecord> records)
    {
        var added = false;
        foreach (var record in records)
        {
            if (record.Status == ProcessStatus.Running && !string.IsNullOrWhiteSpace(record.ProcessEntityId))
            {
                added |= _immediateProcessEntityIds.TryAdd(record.ProcessEntityId, 0);
            }
        }

        if (added && Interlocked.Exchange(ref _immediateSignalPending, 1) == 0)
        {
            _immediateSignal.Release();
        }
    }

    private async Task RunAsync()
    {
        try
        {
            var nextSweepUtc = DateTime.UtcNow + InitialDelay;
            while (!_shutdown.IsCancellationRequested)
            {
                var delay = nextSweepUtc - DateTime.UtcNow;
                if (delay < TimeSpan.Zero)
                {
                    delay = TimeSpan.Zero;
                }

                using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
                waitCancellation.CancelAfter(delay);
                try
                {
                    await _immediateSignal.WaitAsync(waitCancellation.Token).ConfigureAwait(false);
                    Interlocked.Exchange(ref _immediateSignalPending, 0);
                    await Task.Delay(ImmediateBatchDelay, _shutdown.Token).ConfigureAwait(false);
                    await QueueImmediateTargetsAsync(_shutdown.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!_shutdown.IsCancellationRequested)
                {
                    await QueueSweepIfNeededAsync(_shutdown.Token).ConfigureAwait(false);
                    nextSweepUtc = DateTime.UtcNow + SweepInterval;
                }
            }
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Background enrichment scheduler stopped after failure: {ex.Message}");
        }
    }

    private async Task QueueSweepIfNeededAsync(CancellationToken cancellationToken)
    {
        var policy = _capturePolicyProvider();
        var targets = SelectTargets(policy);
        await QueueTargetsAsync(targets, policy, "AgentBackgroundEnrichment", "Agent background enrichment sweep", cancellationToken).ConfigureAwait(false);
    }

    private async Task QueueImmediateTargetsAsync(CancellationToken cancellationToken)
    {
        var entityIds = _immediateProcessEntityIds.Keys.ToArray();
        _immediateProcessEntityIds.Clear();
        if (entityIds.Length == 0)
        {
            return;
        }

        var policy = _capturePolicyProvider();
        var targets = SelectTargets(policy, entityIds);
        await QueueTargetsAsync(targets, policy, "AgentLiveProcessEnrichment", "Live process artifact enrichment", cancellationToken).ConfigureAwait(false);
    }

    private async Task QueueTargetsAsync(
        IReadOnlyList<string> targets,
        AgentArtifactCapturePolicy policy,
        string sourceType,
        string sourceDisplayName,
        CancellationToken cancellationToken)
    {
        if (!_jobQueue.TryGetAcceptingConfiguredCapture(out var captureId))
        {
            return;
        }

        var jobKind = AgentEnrichmentPlanning.GetJobKind(
            policy.CaptureModules,
            policy.CaptureHandles,
            policy.CapturePeMetadata);
        if (targets.Count == 0 || jobKind == JobKind.Unknown)
        {
            return;
        }

        var request = new AgentJobRequest
        {
            JobKind = jobKind,
            SourceType = sourceType,
            SourceDisplayName = sourceDisplayName,
            CaptureId = captureId,
            IsCaptureScoped = true,
            Ownership = AgentJobOwnership.ConfiguredCapture,
            RequestedWorkloads = AgentRequestedWorkloads.ForEnrichment(
                policy.CaptureModules,
                policy.CaptureHandles,
                policy.CapturePeMetadata),
            Parameters = new
            {
                ProcessEntityIds = targets.ToArray(),
                policy.CaptureModules,
                policy.CaptureHandles,
                CapturePe = policy.CapturePeMetadata,
                PeStringExtractionMode = PeStringExtractionMode.Deferred,
                Sweep = true
            }
        };

        if (!_jobQueue.TryGetAcceptingConfiguredCapture(out var currentCaptureId) ||
            !string.Equals(currentCaptureId, captureId, StringComparison.Ordinal))
        {
            return;
        }

        try
        {
            var jobId = await _jobQueue.EnqueueAsync(request, cancellationToken).ConfigureAwait(false);
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Queued {sourceDisplayName} {jobId} for {targets.Count} process(es).");
        }
        catch (AgentConfiguredCaptureStoppingException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Skipped {sourceDisplayName}; configured capture {captureId} is stopping.");
        }
    }

    private IReadOnlyList<string> SelectTargets(
        AgentArtifactCapturePolicy policy,
        IReadOnlyCollection<string>? requestedProcessEntityIds = null)
    {
        try
        {
            var now = DateTime.UtcNow;
            var queryService = new SqliteStagingQueryService(
                _databasePath,
                openContext: CaptureOpenContext.AgentWritableLive);
            var latestPeAnalyses = queryService.GetLatestProcessImagePeAnalysesByProcessKey();
            return queryService.GetProcesses(new ProcessProjectionQuery
                {
                    IncludeExited = false,
                    MaxCount = MaxProcessScan
                })
                .Where(process => process.Status == ProcessStatus.Running)
                .Where(process => requestedProcessEntityIds is null || requestedProcessEntityIds.Contains(process.ProcessEntityId, StringComparer.Ordinal))
                .Where(process => NeedsSweep(process, latestPeAnalyses, policy, now))
                .OrderByDescending(process => GetPriority(process, latestPeAnalyses, policy, now))
                .ThenBy(process => GetOldestArtifactTimestamp(process, latestPeAnalyses, policy) ?? DateTime.MinValue)
                .Take(MaxBatchSize)
                .Select(process => process.ProcessEntityId)
                .Where(processEntityId => !string.IsNullOrWhiteSpace(processEntityId))
                .ToList();
        }
        catch (Exception ex)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Background enrichment target selection failed: {ex.Message}");
            return Array.Empty<string>();
        }
    }

    private static bool NeedsSweep(
        ProcessRecord process,
        IReadOnlyDictionary<string, PeAnalysisRecord> latestPeAnalyses,
        AgentArtifactCapturePolicy policy,
        DateTime now)
    {
        return (policy.CaptureModules && NeedsArtifactCapture(process.ModuleCaptureStatus, process.ModuleLastCapturedUtc, process.LastObservedUtc, ModuleFreshnessWindow, now)) ||
               (policy.CaptureHandles && NeedsArtifactCapture(process.HandleCaptureStatus, process.HandleLastCapturedUtc, process.LastObservedUtc, HandleFreshnessWindow, now)) ||
               (policy.CapturePeMetadata && NeedsPeAnalysis(process, latestPeAnalyses, now));
    }

    private static bool NeedsArtifactCapture(
        ArtifactCaptureStatus status,
        DateTime? lastCapturedUtc,
        DateTime lastObservedUtc,
        TimeSpan freshnessWindow,
        DateTime now)
    {
        return status switch
        {
            ArtifactCaptureStatus.Pending => true,
            ArtifactCaptureStatus.Capturing => false,
            ArtifactCaptureStatus.Captured => !lastCapturedUtc.HasValue || now - lastCapturedUtc.Value > freshnessWindow,
            ArtifactCaptureStatus.Failed or ArtifactCaptureStatus.NotFound or ArtifactCaptureStatus.NotAvailable => now - lastObservedUtc > FailureThrottleWindow,
            _ => true
        };
    }

    private static bool NeedsPeAnalysis(
        ProcessRecord process,
        IReadOnlyDictionary<string, PeAnalysisRecord> latestPeAnalyses,
        DateTime now)
    {
        var identityKey = string.IsNullOrWhiteSpace(process.ProcessEntityId)
            ? process.ProcessKey
            : process.ProcessEntityId;
        latestPeAnalyses.TryGetValue(identityKey, out var latest);
        return PeAnalysisFreshnessPolicy.ShouldAnalyzeProcessImage(
            process,
            latest,
            force: false,
            now,
            PeStringExtractionMode.Deferred);
    }

    private static int GetPriority(
        ProcessRecord process,
        IReadOnlyDictionary<string, PeAnalysisRecord> latestPeAnalyses,
        AgentArtifactCapturePolicy policy,
        DateTime now)
    {
        var priority = 0;
        if (now - process.FirstObservedUtc <= NewProcessPriorityWindow ||
            now - process.LastObservedUtc <= NewProcessPriorityWindow ||
            process.LastSource.Contains("Delta", StringComparison.OrdinalIgnoreCase))
        {
            priority += 1000;
        }

        if (policy.CaptureModules && process.ModuleCaptureStatus == ArtifactCaptureStatus.Pending)
        {
            priority += 300;
        }

        if (policy.CaptureHandles && process.HandleCaptureStatus == ArtifactCaptureStatus.Pending)
        {
            priority += 300;
        }

        if (policy.CapturePeMetadata && NeedsPeAnalysis(process, latestPeAnalyses, now))
        {
            priority += 150;
        }

        if ((policy.CaptureModules && process.ModuleCaptureStatus is ArtifactCaptureStatus.Failed or ArtifactCaptureStatus.NotFound or ArtifactCaptureStatus.NotAvailable) ||
            (policy.CaptureHandles && process.HandleCaptureStatus is ArtifactCaptureStatus.Failed or ArtifactCaptureStatus.NotFound or ArtifactCaptureStatus.NotAvailable))
        {
            priority -= 200;
        }

        return priority;
    }

    private static DateTime? GetOldestArtifactTimestamp(
        ProcessRecord process,
        IReadOnlyDictionary<string, PeAnalysisRecord> latestPeAnalyses,
        AgentArtifactCapturePolicy policy)
    {
        var timestamps = new[]
            {
                policy.CaptureModules ? process.ModuleLastCapturedUtc : null,
                policy.CaptureHandles ? process.HandleLastCapturedUtc : null,
                policy.CapturePeMetadata && latestPeAnalyses.TryGetValue(process.ProcessKey, out var latest)
                    ? latest.AnalyzedUtc
                    : (DateTime?)null
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
}
