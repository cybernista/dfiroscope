using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentProcessEventContext : IProcessEventContext, IDisposable
{
    private readonly ProcessTracker _processTracker;
    private bool _disposed;

    public AgentProcessEventContext(ProcessTracker processTracker)
    {
        _processTracker = processTracker;
        _processTracker.ProcessChangesDetected += OnProcessChangesDetected;
    }

    public event Action<IReadOnlyList<ProcessInfo>, IReadOnlyList<ProcessInfo>>? ProcessChangesDetected;

    public List<ProcessInfo> GetAllProcesses() => _processTracker.GetAllProcesses();

    public ProcessInfo? GetProcess(string uniqueKey) => _processTracker.GetProcess(uniqueKey);

    public ProcessInfo? GetRunningProcessById(int processId) =>
        _processTracker.GetRunningProcessById(processId);

    public ProcessInfo? GetLatestProcessById(int processId) =>
        _processTracker.GetLatestProcessById(processId);

    public ProcessInfo? GetBestProcessMatch(
        int processId,
        string? processName = null,
        DateTime? eventTimeUtc = null,
        string? processGuid = null) =>
        _processTracker.GetBestProcessMatch(processId, processName, eventTimeUtc, processGuid);

    public ProcessInfo? CorrelateSysmonProcess(
        string? processGuid,
        int processId,
        string? processName,
        DateTime? eventTimeUtc,
        string? processPath,
        string? commandLine) =>
        _processTracker.CorrelateSysmonProcess(
            processGuid,
            processId,
            processName,
            eventTimeUtc,
            processPath,
            commandLine);

    public ProcessInfo TrackExternalProcess(
        ProcessInfo observedProcess,
        string source = "ExternalProcessObservation",
        ProcessObservationKind observationKind = ProcessObservationKind.RuntimeLifecycle) =>
        _processTracker.TrackExternalProcess(observedProcess, source, observationKind);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _processTracker.ProcessChangesDetected -= OnProcessChangesDetected;
        _disposed = true;
    }

    private void OnProcessChangesDetected(object? sender, ProcessChangesEventArgs e)
    {
        ProcessChangesDetected?.Invoke(e.NewProcesses, e.ExitedProcesses);
    }
}
