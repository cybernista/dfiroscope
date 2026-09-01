using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Reuses one completed physical process-image analysis for every process that
/// references the same unchanged file snapshot during a single enrichment job.
/// </summary>
public sealed class PeAnalysisBatch
{
    public const int DefaultMaxConcurrency = 2;
    public const int MaximumConcurrency = 8;

    private readonly IPeProcessImageAnalyzer _service;
    private readonly ConcurrentDictionary<string, CachedAnalysis> _completedByPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Lazy<Task<PeAnalysisRecord>>> _inFlightByPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _analysisSlots;
    private readonly PeStringExtractionMode _stringExtractionMode;
    private int _physicalAnalysisCount;
    private int _activeAnalysisCount;
    private int _maxObservedConcurrentAnalyses;
    private int _completedCacheHitCount;
    private int _inFlightReuseCount;

    public PeAnalysisBatch(
        IPeProcessImageAnalyzer service,
        int maxConcurrency = DefaultMaxConcurrency,
        PeStringExtractionMode stringExtractionMode = PeStringExtractionMode.Immediate)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        MaxConcurrency = Math.Clamp(maxConcurrency, 1, MaximumConcurrency);
        _analysisSlots = new SemaphoreSlim(MaxConcurrency, MaxConcurrency);
        _stringExtractionMode = stringExtractionMode;
    }

    public int MaxConcurrency { get; }

    public PeStringExtractionMode StringExtractionMode => _stringExtractionMode;

    public int PhysicalAnalysisCount => Volatile.Read(ref _physicalAnalysisCount);

    public int MaxObservedConcurrentAnalyses => Volatile.Read(ref _maxObservedConcurrentAnalyses);

    public int CompletedCacheHitCount => Volatile.Read(ref _completedCacheHitCount);

    public int InFlightReuseCount => Volatile.Read(ref _inFlightReuseCount);

    public async Task<PeAnalysisRecord> AnalyzeProcessImageAsync(
        ProcessInfo process,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(process);
        var cacheKey = NormalizePath(process.ProcessPath);
        if (cacheKey != null &&
            _completedByPath.TryGetValue(cacheKey, out var cached) &&
            TryGetSnapshot(process.ProcessPath, out var currentSnapshot) &&
            currentSnapshot == cached.Snapshot)
        {
            Interlocked.Increment(ref _completedCacheHitCount);
            return MarkReused(_service.CreateProcessImageRecordFromTemplate(process, cached.Template));
        }

        if (cacheKey == null)
        {
            return await AnalyzePhysicalAsync(process, cancellationToken).ConfigureAwait(false);
        }

        var candidate = new Lazy<Task<PeAnalysisRecord>>(
                () => AnalyzePhysicalAsync(process, cancellationToken),
                LazyThreadSafetyMode.ExecutionAndPublication);
        var pending = _inFlightByPath.GetOrAdd(cacheKey, candidate);
        var reusedInFlight = !ReferenceEquals(candidate, pending);
        if (reusedInFlight)
        {
            Interlocked.Increment(ref _inFlightReuseCount);
        }

        PeAnalysisRecord template;
        try
        {
            template = await pending.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (template.Status == PeAnalysisStatus.Completed &&
                TryGetSnapshot(template.FilePath, out var analyzedSnapshot) &&
                analyzedSnapshot.Length == template.FileSizeBytes)
            {
                _completedByPath[cacheKey] = new CachedAnalysis(template, analyzedSnapshot);
            }
        }
        finally
        {
            if (pending.IsValueCreated && pending.Value.IsCompleted)
            {
                _inFlightByPath.TryRemove(new KeyValuePair<string, Lazy<Task<PeAnalysisRecord>>>(cacheKey, pending));
            }
        }

        if (string.Equals(template.ProcessKey, process.GetUniqueKey(), StringComparison.Ordinal))
        {
            return template;
        }

        var cloned = _service.CreateProcessImageRecordFromTemplate(process, template);
        return reusedInFlight ? MarkReused(cloned) : cloned;
    }

    private async Task<PeAnalysisRecord> AnalyzePhysicalAsync(
        ProcessInfo process,
        CancellationToken cancellationToken)
    {
        var queueTimer = System.Diagnostics.Stopwatch.StartNew();
        await _analysisSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
        var queueDelayMilliseconds = queueTimer.Elapsed.TotalMilliseconds;
        var active = Interlocked.Increment(ref _activeAnalysisCount);
        UpdateMaximum(ref _maxObservedConcurrentAnalyses, active);
        Interlocked.Increment(ref _physicalAnalysisCount);
        try
        {
            var result = await _service.AnalyzeProcessImageAsync(process, _stringExtractionMode, cancellationToken).ConfigureAwait(false);
            UpdatePerformance(result, performance => performance.QueueDelayMilliseconds += queueDelayMilliseconds);
            return result;
        }
        finally
        {
            Interlocked.Decrement(ref _activeAnalysisCount);
            _analysisSlots.Release();
        }
    }

    private static PeAnalysisRecord MarkReused(PeAnalysisRecord record)
    {
        UpdatePerformance(record, performance => performance.ReusedAnalysis = true);
        return record;
    }

    private static void UpdatePerformance(PeAnalysisRecord record, Action<PeAnalysisPerformance> update)
    {
        PeAnalysisPerformance performance;
        try
        {
            performance = JsonSerializer.Deserialize<PeAnalysisPerformance>(record.PerformanceJson) ?? new PeAnalysisPerformance();
        }
        catch
        {
            performance = new PeAnalysisPerformance();
        }

        update(performance);
        record.PerformanceJson = JsonSerializer.Serialize(performance);
    }

    private static void UpdateMaximum(ref int target, int candidate)
    {
        var observed = Volatile.Read(ref target);
        while (candidate > observed)
        {
            var previous = Interlocked.CompareExchange(ref target, candidate, observed);
            if (previous == observed)
            {
                return;
            }

            observed = previous;
        }
    }

    private static string? NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path == "<not available>")
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch
        {
            return null;
        }
    }

    private static bool TryGetSnapshot(string path, out FileSnapshot snapshot)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                snapshot = default;
                return false;
            }

            snapshot = new FileSnapshot(info.Length, info.LastWriteTimeUtc);
            return true;
        }
        catch
        {
            snapshot = default;
            return false;
        }
    }

    private sealed record CachedAnalysis(PeAnalysisRecord Template, FileSnapshot Snapshot);

    private readonly record struct FileSnapshot(long Length, DateTime LastWriteTimeUtc);
}
