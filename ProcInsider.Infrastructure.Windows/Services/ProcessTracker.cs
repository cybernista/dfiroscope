using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Tracks processes over time, preserving history of exited processes.
/// Uses PID + StartTime as unique identity since Windows can reuse PIDs.
/// </summary>
public class ProcessTracker
{
    private const int MaxExitedProcessHistory = 10000;
    private static readonly TimeSpan ExitedProcessRetentionPeriod = TimeSpan.FromHours(1);
    private static readonly TimeSpan RealtimeNotificationDelay = TimeSpan.FromMilliseconds(750);

    private readonly ProcessDataCollector _collector;
    private readonly Dictionary<string, ProcessInfo> _processHistory = new();
    private readonly Dictionary<string, string> _processGuidIndex = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ProcessInfo> _pendingNewProcesses = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ProcessInfo> _pendingExitedProcesses = new(StringComparer.Ordinal);
    private readonly object _lock = new();
    private ManagementEventWatcher? _processStartWatcher;
    private ManagementEventWatcher? _processStopWatcher;
    private Timer? _realtimeNotificationTimer;
    private bool _realtimeTrackingStarted;
    private bool _realtimeNotificationPending;

    public event EventHandler<ProcessUpdateEventArgs>? ProcessesUpdated;
    public event EventHandler<ProcessChangesEventArgs>? ProcessChangesDetected;
    public event EventHandler<ExternalProcessObservationEventArgs>? ExternalProcessObserved;

    public ProcessTracker(ProcessDataCollector collector)
    {
        _collector = collector;
    }

    /// <summary>
    /// Starts process lifecycle watchers so short-lived processes can enter history immediately.
    /// </summary>
    public void StartRealtimeTracking()
    {
        if (_realtimeTrackingStarted)
        {
            return;
        }

        try
        {
            _processStartWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _processStartWatcher.EventArrived += OnProcessStarted;
            _processStartWatcher.Start();

            _processStopWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
            _processStopWatcher.EventArrived += OnProcessStopped;
            _processStopWatcher.Start();

            _realtimeTrackingStarted = true;
        }
        catch
        {
            StopRealtimeTracking();
        }
    }

    /// <summary>
    /// Stops process lifecycle watchers.
    /// </summary>
    public void StopRealtimeTracking()
    {
        if (_processStartWatcher != null)
        {
            _processStartWatcher.EventArrived -= OnProcessStarted;
            _processStartWatcher.Stop();
            _processStartWatcher.Dispose();
            _processStartWatcher = null;
        }

        if (_processStopWatcher != null)
        {
            _processStopWatcher.EventArrived -= OnProcessStopped;
            _processStopWatcher.Stop();
            _processStopWatcher.Dispose();
            _processStopWatcher = null;
        }

        _realtimeTrackingStarted = false;

        lock (_lock)
        {
            _realtimeNotificationTimer?.Dispose();
            _realtimeNotificationTimer = null;
            _realtimeNotificationPending = false;
            _pendingNewProcesses.Clear();
            _pendingExitedProcesses.Clear();
        }
    }

    /// <summary>
    /// Refreshes the process list, updating existing entries and detecting exits.
    /// </summary>
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        var currentProcesses = await _collector.CollectAllProcessesAsync(cancellationToken);
        var currentKeys = new HashSet<string>();
        var newProcesses = new List<ProcessInfo>();
        var exitedProcesses = new List<ProcessInfo>();

        lock (_lock)
        {
            // Process each currently running process
            foreach (var proc in currentProcesses)
            {
                var key = proc.GetUniqueKey();
                if (TryGetTrackedProcessForRefresh(proc, out var existingKey, out var existing))
                {
                    if (!string.Equals(existingKey, key, StringComparison.Ordinal))
                    {
                        ReKeyProcess(existingKey, key, existing);
                    }

                    MergeProcessData(existing, proc);
                }
                else
                {
                    proc.Status = ProcessStatus.Running;
                    _processHistory[key] = proc;
                    newProcesses.Add(proc);
                }

                currentKeys.Add(key);
            }

            // Mark processes that are no longer running as exited
            foreach (var kvp in _processHistory)
            {
                if (!currentKeys.Contains(kvp.Key) && kvp.Value.Status == ProcessStatus.Running)
                {
                    kvp.Value.Status = ProcessStatus.Exited;
                    kvp.Value.EndTime = DateTime.Now;
                    exitedProcesses.Add(kvp.Value);
                }
            }

            // Resolve parent process names and tree depths
            PruneExitedProcessHistory();
            ResolveParentNames();
            CalculateTreeDepths();
        }

        PublishProcessUpdate();

        if (newProcesses.Count > 0 || exitedProcesses.Count > 0)
        {
            ProcessChangesDetected?.Invoke(this, new ProcessChangesEventArgs(
                newProcesses,
                exitedProcesses,
                "RuntimeProcessPollingDelta",
                ProcessObservationKind.RuntimeLifecycle));
        }
    }

    /// <summary>
    /// Gets all tracked processes (running and exited).
    /// </summary>
    public List<ProcessInfo> GetAllProcesses()
    {
        lock (_lock)
        {
            return _processHistory.Values.ToList();
        }
    }

    /// <summary>
    /// Gets a process by its unique key.
    /// </summary>
    public ProcessInfo? GetProcess(string uniqueKey)
    {
        lock (_lock)
        {
            return _processHistory.GetValueOrDefault(uniqueKey);
        }
    }

    /// <summary>
    /// Gets the current running process for a PID, if tracked.
    /// </summary>
    public ProcessInfo? GetRunningProcessById(int processId)
    {
        lock (_lock)
        {
            return _processHistory.Values
                .Where(p => p.ProcessId == processId && p.Status == ProcessStatus.Running)
                .OrderByDescending(p => p.StartTime)
                .FirstOrDefault();
        }
    }

    /// <summary>
    /// Gets the most recently tracked process instance for a PID, including exited processes.
    /// </summary>
    public ProcessInfo? GetLatestProcessById(int processId)
    {
        lock (_lock)
        {
            return _processHistory.Values
                .Where(p => p.ProcessId == processId)
                .OrderByDescending(p => p.StartTime ?? DateTime.MinValue)
                .ThenBy(p => p.Status == ProcessStatus.Running ? 0 : 1)
                .FirstOrDefault();
        }
    }

    public ProcessInfo? GetBestProcessMatch(
        int processId,
        string? processName = null,
        DateTime? eventTimeUtc = null,
        string? processGuid = null)
    {
        lock (_lock)
        {
            return GetBestProcessMatchUnlocked(processId, processName, eventTimeUtc, processGuid);
        }
    }

    public ProcessInfo? CorrelateSysmonProcess(
        string? processGuid,
        int processId,
        string? processName,
        DateTime? eventTimeUtc,
        string? processPath,
        string? commandLine)
    {
        if (processId <= 0)
        {
            return null;
        }

        lock (_lock)
        {
            var process = GetBestProcessMatchUnlocked(processId, processName, eventTimeUtc, processGuid);
            if (process == null)
            {
                return null;
            }

            if (!string.IsNullOrWhiteSpace(processGuid))
            {
                process.ProcessGuid = processGuid;
                _processGuidIndex[processGuid] = process.GetUniqueKey();
            }

            process.ProcessPath = PreferKnownValue(processPath ?? string.Empty, process.ProcessPath, "<not available>", "<access denied>");
            process.CommandLine = PreferKnownValue(commandLine ?? string.Empty, process.CommandLine, "<not available>");
            return process;
        }
    }

    public ProcessInfo TrackExternalProcess(
        ProcessInfo observedProcess,
        string source = "ExternalProcessObservation",
        ProcessObservationKind observationKind = ProcessObservationKind.RuntimeLifecycle)
    {
        ProcessInfo trackedProcess;
        var created = false;

        lock (_lock)
        {
            var existing = GetBestProcessMatchUnlocked(
                observedProcess.ProcessId,
                observedProcess.ProcessName,
                observedProcess.StartTime?.ToUniversalTime(),
                observedProcess.ProcessGuid);

            if (existing != null)
            {
                var existingKey = existing.GetUniqueKey();
                MergeProcessData(existing, observedProcess, observedProcess.Status == ProcessStatus.Running);
                var newKey = existing.GetUniqueKey();
                if (!string.Equals(existingKey, newKey, StringComparison.Ordinal))
                {
                    ReKeyProcess(existingKey, newKey, existing);
                }

                trackedProcess = existing;
            }
            else
            {
                trackedProcess = observedProcess;
                _processHistory[trackedProcess.GetUniqueKey()] = trackedProcess;
                created = true;
            }

            if (!string.IsNullOrWhiteSpace(trackedProcess.ProcessGuid))
            {
                _processGuidIndex[trackedProcess.ProcessGuid] = trackedProcess.GetUniqueKey();
            }

            if (created && trackedProcess.Status == ProcessStatus.Running)
            {
                QueueNewProcess(trackedProcess);
            }
        }

        ScheduleRealtimeNotification();
        ExternalProcessObserved?.Invoke(
            this,
            new ExternalProcessObservationEventArgs(trackedProcess, source, observationKind));
        return trackedProcess;
    }

    /// <summary>
    /// Resolves parent process names for all tracked processes.
    /// </summary>
    private void ResolveParentNames()
    {
        var processes = _processHistory.Values.ToList();
        var processesByPid = BuildProcessPidIndex(processes);

        foreach (var proc in processes)
        {
            var parent = ResolveParentProcess(proc, processesByPid);
            if (parent != null)
            {
                proc.ParentProcessKey = parent.GetUniqueKey();
                proc.ParentProcessName = parent.ProcessName;
            }
            else
            {
                proc.ParentProcessKey = string.Empty;
                proc.ParentProcessName = proc.ParentProcessId > 0 ? "<exited>" : "<none>";
            }
        }
    }

    /// <summary>
    /// Calculates tree depths for all processes based on parent-child relationships.
    /// </summary>
    private void CalculateTreeDepths()
    {
        var processes = _processHistory.Values.ToList();
        var processesByPid = BuildProcessPidIndex(processes);
        var children = new Dictionary<string, List<ProcessInfo>>(StringComparer.Ordinal);
        var rootProcesses = new List<ProcessInfo>();

        foreach (var proc in processes)
        {
            proc.TreeDepth = 0;

            var parent = ResolveParentProcess(proc, processesByPid);
            if (parent == null)
            {
                rootProcesses.Add(proc);
            }
            else
            {
                var parentKey = parent.GetUniqueKey();
                if (!children.TryGetValue(parentKey, out var childList))
                {
                    childList = new List<ProcessInfo>();
                    children[parentKey] = childList;
                }
                childList.Add(proc);
            }
        }

        var visited = new HashSet<string>(StringComparer.Ordinal);
        var activePath = new HashSet<string>(StringComparer.Ordinal);

        void SetDepth(ProcessInfo root, int rootDepth)
        {
            var stack = new Stack<(ProcessInfo Process, int Depth, bool Exit)>();
            stack.Push((root, rootDepth, false));

            while (stack.Count > 0)
            {
                var (proc, depth, exit) = stack.Pop();
                var key = proc.GetUniqueKey();

                if (exit)
                {
                    activePath.Remove(key);
                    continue;
                }

                if (!activePath.Add(key))
                {
                    continue;
                }

                proc.TreeDepth = depth;
                visited.Add(key);
                stack.Push((proc, depth, true));

                if (!children.TryGetValue(key, out var childList))
                {
                    continue;
                }

                for (var index = childList.Count - 1; index >= 0; index--)
                {
                    stack.Push((childList[index], depth + 1, false));
                }
            }
        }

        foreach (var root in rootProcesses)
        {
            SetDepth(root, 0);
        }

        foreach (var proc in processes)
        {
            if (!visited.Contains(proc.GetUniqueKey()))
            {
                SetDepth(proc, 0);
            }
        }
    }

    private void PublishProcessUpdate()
    {
        ProcessesUpdated?.Invoke(this, new ProcessUpdateEventArgs(GetAllProcesses(), isFullSnapshot: true));
    }

    private void QueueNewProcess(ProcessInfo process)
    {
        var key = process.GetUniqueKey();
        _pendingNewProcesses[key] = process;
        _pendingExitedProcesses.Remove(key);
    }

    private void QueueExitedProcess(ProcessInfo process)
    {
        var key = process.GetUniqueKey();
        _pendingExitedProcesses[key] = process;
        _pendingNewProcesses.Remove(key);
    }

    private void ReKeyProcess(string oldKey, string newKey, ProcessInfo process)
    {
        _processHistory.Remove(oldKey);
        _processHistory[newKey] = process;

        if (_pendingNewProcesses.Remove(oldKey))
        {
            _pendingNewProcesses[newKey] = process;
        }

        if (_pendingExitedProcesses.Remove(oldKey))
        {
            _pendingExitedProcesses[newKey] = process;
        }

        foreach (var guid in _processGuidIndex
                     .Where(kvp => string.Equals(kvp.Value, oldKey, StringComparison.Ordinal))
                     .Select(kvp => kvp.Key)
                     .ToList())
        {
            _processGuidIndex[guid] = newKey;
        }
    }

    private void ScheduleRealtimeNotification()
    {
        lock (_lock)
        {
            _realtimeNotificationPending = true;
            _realtimeNotificationTimer ??= new Timer(FlushRealtimeNotifications, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _realtimeNotificationTimer.Change(RealtimeNotificationDelay, Timeout.InfiniteTimeSpan);
        }
    }

    private void FlushRealtimeNotifications(object? state)
    {
        List<ProcessInfo> allProcesses;
        List<ProcessInfo> newProcesses;
        List<ProcessInfo> exitedProcesses;

        lock (_lock)
        {
            if (!_realtimeNotificationPending)
            {
                return;
            }

            _realtimeNotificationPending = false;
            PruneExitedProcessHistory();
            ResolveParentNames();
            CalculateTreeDepths();

            allProcesses = _processHistory.Values.ToList();
            newProcesses = _pendingNewProcesses.Values.ToList();
            exitedProcesses = _pendingExitedProcesses.Values.ToList();
            _pendingNewProcesses.Clear();
            _pendingExitedProcesses.Clear();
        }

        ProcessesUpdated?.Invoke(this, new ProcessUpdateEventArgs(allProcesses, isFullSnapshot: false));
        if (newProcesses.Count > 0 || exitedProcesses.Count > 0)
        {
            ProcessChangesDetected?.Invoke(this, new ProcessChangesEventArgs(
                newProcesses,
                exitedProcesses,
                "WmiProcessLifecycle",
                ProcessObservationKind.WmiLifecycle));
        }
    }

    private void PruneExitedProcessHistory()
    {
        var cutoff = DateTime.Now.Subtract(ExitedProcessRetentionPeriod);
        var expiredExited = _processHistory
            .Where(kvp => kvp.Value.Status == ProcessStatus.Exited)
            .Where(kvp => (kvp.Value.EndTime ?? kvp.Value.StartTime ?? DateTime.MinValue) < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredExited)
        {
            _processHistory.Remove(key);
            RemoveGuidIndexForKey(key);
            _pendingNewProcesses.Remove(key);
            _pendingExitedProcesses.Remove(key);
        }

        var exitedToRemove = _processHistory
            .Where(kvp => kvp.Value.Status == ProcessStatus.Exited)
            .OrderByDescending(kvp => kvp.Value.EndTime ?? kvp.Value.StartTime ?? DateTime.MinValue)
            .Skip(MaxExitedProcessHistory)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in exitedToRemove)
        {
            _processHistory.Remove(key);
            RemoveGuidIndexForKey(key);
            _pendingNewProcesses.Remove(key);
            _pendingExitedProcesses.Remove(key);
        }
    }

    private ProcessInfo? GetBestProcessMatchUnlocked(
        int processId,
        string? processName,
        DateTime? eventTimeUtc,
        string? processGuid)
    {
        if (!string.IsNullOrWhiteSpace(processGuid) &&
            _processGuidIndex.TryGetValue(processGuid, out var processKey) &&
            _processHistory.TryGetValue(processKey, out var guidProcess))
        {
            return guidProcess;
        }

        var candidates = _processHistory.Values
            .Where(p => p.ProcessId == processId)
            .Where(p => IsProcessNameCompatible(p, processName))
            .ToList();

        if (candidates.Count == 0)
        {
            return null;
        }

        var eventTimeLocal = eventTimeUtc?.ToLocalTime();
        if (eventTimeLocal.HasValue)
        {
            var timeMatched = candidates
                .Where(p => ProcessLifetimeContains(p, eventTimeLocal.Value))
                .OrderByDescending(p => p.StartTime ?? DateTime.MinValue)
                .ThenBy(p => p.Status == ProcessStatus.Running ? 0 : 1)
                .FirstOrDefault();

            if (timeMatched != null)
            {
                return timeMatched;
            }
        }

        return candidates
            .OrderByDescending(p => p.Status == ProcessStatus.Running ? 1 : 0)
            .ThenByDescending(p => p.StartTime ?? p.EndTime ?? DateTime.MinValue)
            .FirstOrDefault();
    }

    private static bool ProcessLifetimeContains(ProcessInfo process, DateTime eventTimeLocal)
    {
        var startsBeforeEvent = !process.StartTime.HasValue || process.StartTime.Value <= eventTimeLocal.AddSeconds(2);
        var endsAfterEvent = !process.EndTime.HasValue || process.EndTime.Value >= eventTimeLocal.AddSeconds(-2);
        return startsBeforeEvent && endsAfterEvent;
    }

    private static bool IsProcessNameCompatible(ProcessInfo process, string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName) ||
            string.Equals(process.ProcessName, "<unknown>", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var trackedName = process.ProcessName;
        var observedName = Path.GetFileNameWithoutExtension(processName);
        var trackedNameWithoutExtension = Path.GetFileNameWithoutExtension(trackedName);
        return string.Equals(trackedName, processName, StringComparison.OrdinalIgnoreCase)
            || string.Equals(trackedNameWithoutExtension, observedName, StringComparison.OrdinalIgnoreCase);
    }

    private void RemoveGuidIndexForKey(string processKey)
    {
        foreach (var guid in _processGuidIndex
                     .Where(kvp => string.Equals(kvp.Value, processKey, StringComparison.Ordinal))
                     .Select(kvp => kvp.Key)
                     .ToList())
        {
            _processGuidIndex.Remove(guid);
        }
    }

    /// <summary>
    /// Clears all tracked processes.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _processHistory.Clear();
            _processGuidIndex.Clear();
            _pendingNewProcesses.Clear();
            _pendingExitedProcesses.Clear();
        }
    }

    private async void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
            if (processId <= 0)
            {
                return;
            }

            var fallbackProcess = BuildProcessInfoFromStartEvent(e.NewEvent);
            var collected = await _collector.TryCollectProcessByIdAsync(processId);
            var observedProcess = collected ?? fallbackProcess;
            observedProcess.Status = ProcessStatus.Running;

            ProcessInfo trackedProcess;
            var created = false;

            lock (_lock)
            {
                var key = observedProcess.GetUniqueKey();
                if (TryGetTrackedProcessForRefresh(observedProcess, out var existingKey, out var existing))
                {
                    if (!string.Equals(existingKey, key, StringComparison.Ordinal))
                    {
                        ReKeyProcess(existingKey, key, existing);
                    }

                    var markRunning = existing.Status != ProcessStatus.Exited;
                    MergeProcessData(existing, observedProcess, markRunning);
                    trackedProcess = existing;
                }
                else
                {
                    _processHistory[key] = observedProcess;
                    trackedProcess = observedProcess;
                    created = true;
                }

                if (created)
                {
                    QueueNewProcess(trackedProcess);
                }
            }

            ScheduleRealtimeNotification();
        }
        catch
        {
            // Ignore process start notifications we cannot materialize.
        }
    }

    private void OnProcessStopped(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
            if (processId <= 0)
            {
                return;
            }

            var exitTime = ConvertEventTime(e.NewEvent.Properties["TIME_CREATED"]?.Value) ?? DateTime.UtcNow;
            ProcessInfo? exitedProcess = null;

            lock (_lock)
            {
                var trackedProcess = _processHistory.Values
                    .Where(p => p.ProcessId == processId && p.Status == ProcessStatus.Running)
                    .OrderByDescending(p => p.StartTime ?? DateTime.MinValue)
                    .FirstOrDefault();

                if (trackedProcess == null)
                {
                    trackedProcess = BuildProcessInfoFromStopEvent(e.NewEvent);
                    trackedProcess.Status = ProcessStatus.Exited;
                    trackedProcess.EndTime = exitTime.ToLocalTime();
                    _processHistory[trackedProcess.GetUniqueKey()] = trackedProcess;
                }
                else
                {
                    trackedProcess.Status = ProcessStatus.Exited;
                    trackedProcess.EndTime = exitTime.ToLocalTime();
                }

                exitedProcess = trackedProcess;
                QueueExitedProcess(trackedProcess);
            }

            ScheduleRealtimeNotification();
        }
        catch
        {
            // Ignore process stop notifications we cannot materialize.
        }
    }

    private bool TryGetTrackedProcessForRefresh(ProcessInfo process, out string existingKey, out ProcessInfo existingProcess)
    {
        var desiredKey = process.GetUniqueKey();
        if (_processHistory.TryGetValue(desiredKey, out existingProcess!))
        {
            existingKey = desiredKey;
            return true;
        }

        var placeholderMatch = _processHistory
            .FirstOrDefault(kvp =>
                kvp.Value.ProcessId == process.ProcessId &&
                IsProcessNameCompatible(kvp.Value, process.ProcessName) &&
                IsLikelySameObservedProcess(kvp.Value, process));

        if (!string.IsNullOrEmpty(placeholderMatch.Key))
        {
            existingKey = placeholderMatch.Key;
            existingProcess = placeholderMatch.Value;
            return true;
        }

        existingKey = string.Empty;
        existingProcess = null!;
        return false;
    }

    private static bool IsLikelySameObservedProcess(ProcessInfo tracked, ProcessInfo observed)
    {
        if (tracked.StartTime.HasValue && observed.StartTime.HasValue)
        {
            return tracked.StartTime.Value == observed.StartTime.Value;
        }

        if (tracked.Status == ProcessStatus.Running)
        {
            return tracked.StartTime == null || observed.StartTime == null;
        }

        if (tracked.Status == ProcessStatus.Exited && tracked.StartTime == null && tracked.EndTime.HasValue)
        {
            var observedStart = observed.StartTime ?? tracked.EndTime.Value;
            return observedStart <= tracked.EndTime.Value.AddSeconds(10);
        }

        return false;
    }

    private static void MergeProcessData(ProcessInfo target, ProcessInfo source, bool markRunning = true)
    {
        target.ProcessId = source.ProcessId;
        target.StartTime = source.StartTime ?? target.StartTime;
        target.ParentProcessId = source.ParentProcessId > 0 ? source.ParentProcessId : target.ParentProcessId;
        target.ParentProcessKey = PreferKnownValue(source.ParentProcessKey, target.ParentProcessKey);
        target.ProcessName = PreferKnownValue(source.ProcessName, target.ProcessName, "<unknown>", "<access denied>");
        target.ProcessGuid = PreferKnownValue(source.ProcessGuid, target.ProcessGuid);
        target.ProcessPath = PreferKnownValue(source.ProcessPath, target.ProcessPath, "<not available>", "<access denied>");
        target.CommandLine = PreferKnownValue(source.CommandLine, target.CommandLine, "<not available>");
        target.UserName = PreferKnownValue(source.UserName, target.UserName, "<not available>", "<access denied>");
        target.SessionId = source.SessionId >= 0 ? source.SessionId : target.SessionId;
        target.Architecture = PreferKnownValue(source.Architecture, target.Architecture, "<not available>");
        target.MemoryUsageBytes = source.MemoryUsageBytes;
        target.CpuUsage = source.CpuUsage;
        target.TotalProcessorTime = source.TotalProcessorTime ?? target.TotalProcessorTime;
        target.UserProcessorTime = source.UserProcessorTime ?? target.UserProcessorTime;
        target.PrivilegedProcessorTime = source.PrivilegedProcessorTime ?? target.PrivilegedProcessorTime;
        target.ReadBytes = source.ReadBytes ?? target.ReadBytes;
        target.WrittenBytes = source.WrittenBytes ?? target.WrittenBytes;
        target.StatisticsCollectionError = PreferKnownValue(source.StatisticsCollectionError, target.StatisticsCollectionError);
        target.CompanyName = PreferKnownValue(source.CompanyName, target.CompanyName, "<not available>");
        target.FileDescription = PreferKnownValue(source.FileDescription, target.FileDescription, "<not available>");
        target.Sha256Hash = PreferKnownValue(source.Sha256Hash, target.Sha256Hash, "<not available>", "<access denied>");
        if (markRunning)
        {
            target.Status = ProcessStatus.Running;
            target.EndTime = null;
        }
        else if (source.Status == ProcessStatus.Exited || source.EndTime.HasValue)
        {
            target.Status = ProcessStatus.Exited;
            target.EndTime = source.EndTime ?? target.EndTime ?? DateTime.Now;
        }
    }

    private static string PreferKnownValue(string incoming, string current, params string[] placeholderValues)
    {
        if (string.IsNullOrWhiteSpace(incoming))
        {
            return current;
        }

        foreach (var placeholder in placeholderValues)
        {
            if (string.Equals(incoming, placeholder, StringComparison.OrdinalIgnoreCase))
            {
                return string.IsNullOrWhiteSpace(current) ? incoming : current;
            }
        }

        return incoming;
    }

    private static Dictionary<int, List<ProcessInfo>> BuildProcessPidIndex(List<ProcessInfo> processes)
    {
        var index = new Dictionary<int, List<ProcessInfo>>();
        foreach (var process in processes)
        {
            if (!index.TryGetValue(process.ProcessId, out var processList))
            {
                processList = new List<ProcessInfo>();
                index[process.ProcessId] = processList;
            }

            processList.Add(process);
        }

        return index;
    }

    private static ProcessInfo? ResolveParentProcess(ProcessInfo process, Dictionary<int, List<ProcessInfo>> processesByPid)
    {
        if (process.ParentProcessId <= 0)
        {
            return null;
        }

        var processKey = process.GetUniqueKey();
        if (!processesByPid.TryGetValue(process.ParentProcessId, out var parentCandidates))
        {
            return null;
        }

        var candidates = parentCandidates
            .Where(p => !string.Equals(p.GetUniqueKey(), processKey, StringComparison.Ordinal))
            .ToList();

        if (candidates.Count == 0)
        {
            return null;
        }

        var childObservedTime = process.StartTime ?? process.EndTime;
        if (childObservedTime.HasValue)
        {
            var matchingCandidate = candidates
                .Where(p => (p.StartTime ?? DateTime.MinValue) <= childObservedTime.Value)
                .OrderByDescending(p => p.StartTime ?? DateTime.MinValue)
                .ThenBy(p => p.Status == ProcessStatus.Running ? 0 : 1)
                .FirstOrDefault();

            if (matchingCandidate != null)
            {
                return matchingCandidate;
            }
        }

        return candidates
            .OrderByDescending(p => p.StartTime ?? DateTime.MinValue)
            .ThenBy(p => p.Status == ProcessStatus.Running ? 0 : 1)
            .FirstOrDefault();
    }

    private static ProcessInfo BuildProcessInfoFromStartEvent(ManagementBaseObject eventObject)
    {
        var startTimeUtc = ConvertEventTime(eventObject.Properties["TIME_CREATED"]?.Value);

        return new ProcessInfo
        {
            ProcessId = Convert.ToInt32(eventObject.Properties["ProcessID"]?.Value ?? 0),
            ParentProcessId = Convert.ToInt32(eventObject.Properties["ParentProcessID"]?.Value ?? 0),
            ProcessName = eventObject.Properties["ProcessName"]?.Value?.ToString() ?? "<unknown>",
            SessionId = Convert.ToInt32(eventObject.Properties["SessionID"]?.Value ?? 0),
            StartTime = startTimeUtc?.ToLocalTime(),
            Status = ProcessStatus.Running
        };
    }

    private static ProcessInfo BuildProcessInfoFromStopEvent(ManagementBaseObject eventObject)
    {
        var endTimeUtc = ConvertEventTime(eventObject.Properties["TIME_CREATED"]?.Value);

        return new ProcessInfo
        {
            ProcessId = Convert.ToInt32(eventObject.Properties["ProcessID"]?.Value ?? 0),
            ProcessName = eventObject.Properties["ProcessName"]?.Value?.ToString() ?? "<unknown>",
            SessionId = Convert.ToInt32(eventObject.Properties["SessionID"]?.Value ?? 0),
            EndTime = endTimeUtc?.ToLocalTime(),
            Status = ProcessStatus.Exited
        };
    }

    private static DateTime? ConvertEventTime(object? rawTimeCreated)
    {
        if (rawTimeCreated is not ulong timeCreated || timeCreated == 0)
        {
            return null;
        }

        try
        {
            return DateTime.FromFileTimeUtc((long)timeCreated);
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// Event args for process updates.
/// </summary>
public class ProcessUpdateEventArgs : EventArgs
{
    public List<ProcessInfo> AllProcesses { get; }
    public bool IsFullSnapshot { get; }

    public ProcessUpdateEventArgs(List<ProcessInfo> allProcesses, bool isFullSnapshot)
    {
        AllProcesses = allProcesses;
        IsFullSnapshot = isFullSnapshot;
    }
}

/// <summary>
/// Event args for newly started and exited processes detected during a refresh.
/// </summary>
public class ProcessChangesEventArgs : EventArgs
{
    public List<ProcessInfo> NewProcesses { get; }
    public List<ProcessInfo> ExitedProcesses { get; }
    public string Source { get; }
    public ProcessObservationKind ObservationKind { get; }

    public ProcessChangesEventArgs(
        List<ProcessInfo> newProcesses,
        List<ProcessInfo> exitedProcesses,
        string source = "RuntimeProcessLifecycle",
        ProcessObservationKind observationKind = ProcessObservationKind.RuntimeLifecycle)
    {
        NewProcesses = newProcesses;
        ExitedProcesses = exitedProcesses;
        Source = source;
        ObservationKind = observationKind;
    }
}

public sealed class ExternalProcessObservationEventArgs : EventArgs
{
    public ExternalProcessObservationEventArgs(
        ProcessInfo process,
        string source,
        ProcessObservationKind observationKind)
    {
        Process = process;
        Source = source;
        ObservationKind = observationKind;
    }

    public ProcessInfo Process { get; }
    public string Source { get; }
    public ProcessObservationKind ObservationKind { get; }
}
