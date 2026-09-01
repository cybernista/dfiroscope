using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

/// <summary>
/// Thread-safe target lifecycle counters for module, handle, and PE enrichment. These are
/// independent of generic job counters and are returned as constant-time health snapshots.
/// </summary>
public sealed class AgentArtifactEnrichmentStatistics
{
    private readonly object _metadataLock = new();
    private long _moduleActive;
    private long _moduleAttempts;
    private long _moduleCompleted;
    private long _moduleRecords;
    private long _moduleFailures;
    private long _handleActive;
    private long _handleAttempts;
    private long _handleCompleted;
    private long _handleRecords;
    private long _handleFailures;
    private long _peActive;
    private long _peAttempts;
    private long _peCompleted;
    private long _peRecords;
    private long _peFreshnessSkips;
    private long _peReused;
    private long _peFailures;
    private long _peCancellations;
    private string _moduleLastError = string.Empty;
    private string _handleLastError = string.Empty;
    private string _peLastError = string.Empty;
    private DateTime? _moduleLastCompletedUtc;
    private DateTime? _handleLastCompletedUtc;
    private DateTime? _peLastCompletedUtc;

    public void ModuleStarted()
    {
        Interlocked.Increment(ref _moduleActive);
        Interlocked.Increment(ref _moduleAttempts);
    }

    public void ModuleSucceeded(int recordCount)
    {
        DecrementNonNegative(ref _moduleActive);
        Interlocked.Increment(ref _moduleCompleted);
        Interlocked.Add(ref _moduleRecords, Math.Max(0, recordCount));
        SetModuleCompletion(string.Empty);
    }

    public void ModuleFailed(string error)
    {
        DecrementNonNegative(ref _moduleActive);
        Interlocked.Increment(ref _moduleFailures);
        SetModuleCompletion(error);
    }

    public void ModuleCancelled() => DecrementNonNegative(ref _moduleActive);

    public void HandleStarted()
    {
        Interlocked.Increment(ref _handleActive);
        Interlocked.Increment(ref _handleAttempts);
    }

    public void HandleSucceeded(int recordCount)
    {
        DecrementNonNegative(ref _handleActive);
        Interlocked.Increment(ref _handleCompleted);
        Interlocked.Add(ref _handleRecords, Math.Max(0, recordCount));
        SetHandleCompletion(string.Empty);
    }

    public void HandleFailed(string error)
    {
        DecrementNonNegative(ref _handleActive);
        Interlocked.Increment(ref _handleFailures);
        SetHandleCompletion(error);
    }

    public void HandleCancelled() => DecrementNonNegative(ref _handleActive);

    /// <summary>Marks one target-level PE attempt after freshness planning and before analysis begins.</summary>
    public void PeStarted()
    {
        Interlocked.Increment(ref _peActive);
        Interlocked.Increment(ref _peAttempts);
    }

    /// <summary>Closes one successful target attempt. Reuse is counted at target level, not as a physical file read.</summary>
    public void PeSucceeded(bool reused)
    {
        DecrementNonNegative(ref _peActive);
        Interlocked.Increment(ref _peCompleted);
        if (reused)
        {
            Interlocked.Increment(ref _peReused);
        }
        SetPeCompletion(string.Empty);
    }

    /// <summary>Closes one failed target attempt. A subsequently persisted failed row is not a success.</summary>
    public void PeFailed(string error, bool reused = false)
    {
        DecrementNonNegative(ref _peActive);
        Interlocked.Increment(ref _peFailures);
        if (reused)
        {
            Interlocked.Increment(ref _peReused);
        }
        SetPeCompletion(error);
    }

    public void PeCancelled()
    {
        DecrementNonNegative(ref _peActive);
        Interlocked.Increment(ref _peCancellations);
        SetPeCompletion(string.Empty);
    }

    public void PeFreshnessSkipped(int count)
        => Interlocked.Add(ref _peFreshnessSkips, Math.Max(0, count));

    /// <summary>Adds rows only after the serialized SQLite writer confirms the batch commit.</summary>
    public void PeRowsWritten(int count)
        => Interlocked.Add(ref _peRecords, Math.Max(0, count));

    public void PePersistenceFailed(string error) => SetPeError(error);

    public AgentArtifactEnrichmentSnapshot GetSnapshot()
    {
        string moduleLastError;
        string handleLastError;
        string peLastError;
        DateTime? moduleLastCompletedUtc;
        DateTime? handleLastCompletedUtc;
        DateTime? peLastCompletedUtc;
        lock (_metadataLock)
        {
            moduleLastError = _moduleLastError;
            handleLastError = _handleLastError;
            peLastError = _peLastError;
            moduleLastCompletedUtc = _moduleLastCompletedUtc;
            handleLastCompletedUtc = _handleLastCompletedUtc;
            peLastCompletedUtc = _peLastCompletedUtc;
        }

        return new AgentArtifactEnrichmentSnapshot
        {
            ModuleActiveCount = Interlocked.Read(ref _moduleActive),
            ModuleAttemptCount = Interlocked.Read(ref _moduleAttempts),
            ModuleCompletedCount = Interlocked.Read(ref _moduleCompleted),
            ModuleRecordCount = Interlocked.Read(ref _moduleRecords),
            ModuleFailureCount = Interlocked.Read(ref _moduleFailures),
            ModuleLastError = moduleLastError,
            ModuleLastCompletedUtc = moduleLastCompletedUtc,
            HandleActiveCount = Interlocked.Read(ref _handleActive),
            HandleAttemptCount = Interlocked.Read(ref _handleAttempts),
            HandleCompletedCount = Interlocked.Read(ref _handleCompleted),
            HandleRecordCount = Interlocked.Read(ref _handleRecords),
            HandleFailureCount = Interlocked.Read(ref _handleFailures),
            HandleLastError = handleLastError,
            HandleLastCompletedUtc = handleLastCompletedUtc,
            PeActiveCount = Interlocked.Read(ref _peActive),
            PeAttemptCount = Interlocked.Read(ref _peAttempts),
            PeCompletedCount = Interlocked.Read(ref _peCompleted),
            PeRecordCount = Interlocked.Read(ref _peRecords),
            PeFreshnessSkipCount = Interlocked.Read(ref _peFreshnessSkips),
            PeReuseCount = Interlocked.Read(ref _peReused),
            PeFailureCount = Interlocked.Read(ref _peFailures),
            PeCancellationCount = Interlocked.Read(ref _peCancellations),
            PeLastError = peLastError,
            PeLastCompletedUtc = peLastCompletedUtc
        };
    }

    private void SetModuleCompletion(string error)
    {
        lock (_metadataLock)
        {
            if (!string.IsNullOrWhiteSpace(error))
            {
                _moduleLastError = error;
            }
            _moduleLastCompletedUtc = DateTime.UtcNow;
        }
    }

    private void SetHandleCompletion(string error)
    {
        lock (_metadataLock)
        {
            if (!string.IsNullOrWhiteSpace(error))
            {
                _handleLastError = error;
            }
            _handleLastCompletedUtc = DateTime.UtcNow;
        }
    }

    private void SetPeCompletion(string error)
    {
        lock (_metadataLock)
        {
            if (!string.IsNullOrWhiteSpace(error))
            {
                _peLastError = error;
            }
            _peLastCompletedUtc = DateTime.UtcNow;
        }
    }

    private void SetPeError(string error)
    {
        lock (_metadataLock)
        {
            _peLastError = error;
        }
    }

    private static void DecrementNonNegative(ref long value)
    {
        while (true)
        {
            var current = Interlocked.Read(ref value);
            if (current <= 0)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref value, current - 1, current) == current)
            {
                return;
            }
        }
    }
}
