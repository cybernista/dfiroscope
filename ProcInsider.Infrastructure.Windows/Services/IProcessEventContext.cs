using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Supplies the process identity and lifecycle context required by event collectors
/// without coupling the shared collectors to the current process-tracker implementation.
/// </summary>
public interface IProcessEventContext
{
    event Action<IReadOnlyList<ProcessInfo>, IReadOnlyList<ProcessInfo>>? ProcessChangesDetected;

    List<ProcessInfo> GetAllProcesses();

    ProcessInfo? GetProcess(string uniqueKey);

    ProcessInfo? GetRunningProcessById(int processId);

    ProcessInfo? GetLatestProcessById(int processId);

    ProcessInfo? GetBestProcessMatch(
        int processId,
        string? processName = null,
        DateTime? eventTimeUtc = null,
        string? processGuid = null);

    ProcessInfo? CorrelateSysmonProcess(
        string? processGuid,
        int processId,
        string? processName,
        DateTime? eventTimeUtc,
        string? processPath,
        string? commandLine);

    ProcessInfo TrackExternalProcess(
        ProcessInfo observedProcess,
        string source = "ExternalProcessObservation",
        ProcessObservationKind observationKind = ProcessObservationKind.RuntimeLifecycle);
}
