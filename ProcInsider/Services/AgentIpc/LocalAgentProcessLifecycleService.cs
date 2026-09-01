using ProcInsider.Models;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProcInsider.Services.AgentIpc;

public enum LocalAgentProcessOutcome
{
    Started,
    AlreadyRunning,
    VerifiedRunning,
    AlreadyExited,
    Exited,
    VerificationRejected,
    GracefulWaitTimedOut,
    ObservationCanceled,
    ForcedStopCompleted,
    ForcedStopTimedOut,
    InspectionFailure,
    ElevationCanceled,
    CredentialsUnavailable,
    ExecutableNotFound,
    ElevationDenied,
    StartFailed,
    Disposed
}

public sealed record LocalAgentProcessResult(
    LocalAgentProcessOutcome Outcome,
    int ProcessId,
    bool IsRunning,
    bool IsStopped,
    bool Forced,
    string Detail,
    bool ExactIdentityMismatchProved = false)
{
    public bool IsConfirmedExactExit => Outcome is
        LocalAgentProcessOutcome.AlreadyExited or
        LocalAgentProcessOutcome.Exited or
        LocalAgentProcessOutcome.ForcedStopCompleted;
}

public sealed record LocalAgentProcessIdentity(
    int ProcessId,
    DateTime StartedAtUtc,
    IReadOnlyList<string> SupportedExecutablePaths,
    string ExpectedExecutableName = "");

public sealed record LocalAgentLaunchTargetValidation(
    bool IsValid,
    string DatabasePath,
    string Detail);

public static class LocalAgentLaunchTargetPolicy
{
    public static LocalAgentLaunchTargetValidation Validate(
        CaptureWorkspaceMode workspaceMode,
        string? sessionRoot,
        string? databasePath)
    {
        if (workspaceMode != CaptureWorkspaceMode.LiveCapture)
        {
            return Invalid("The local agent can be started only for an active live capture workspace.");
        }

        if (string.IsNullOrWhiteSpace(sessionRoot) ||
            string.IsNullOrWhiteSpace(databasePath))
        {
            return Invalid("The active live session root or evidence database path is unavailable.");
        }

        try
        {
            var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(sessionRoot));
            var normalizedDatabase = Path.GetFullPath(databasePath);
            if (!Directory.Exists(normalizedRoot))
            {
                return Invalid("The active live session root does not exist.");
            }

            var relativeDatabase = Path.GetRelativePath(normalizedRoot, normalizedDatabase);
            if (Path.IsPathRooted(relativeDatabase) ||
                string.Equals(relativeDatabase, "..", StringComparison.Ordinal) ||
                relativeDatabase.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
                relativeDatabase.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal) ||
                Directory.Exists(normalizedDatabase))
            {
                return Invalid("The active evidence database path is not a contained file in the live session root.");
            }

            // A fresh workspace intentionally has no evidence database yet. The
            // elevated agent owns first creation and schema initialization.
            return new LocalAgentLaunchTargetValidation(
                IsValid: true,
                DatabasePath: normalizedDatabase,
                Detail: File.Exists(normalizedDatabase)
                    ? "The contained live evidence database is available for agent startup."
                    : "The contained live evidence database will be created by the agent.");
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return Invalid($"The active live session path is invalid: {ex.Message}");
        }
    }

    private static LocalAgentLaunchTargetValidation Invalid(string detail) =>
        new(IsValid: false, DatabasePath: string.Empty, Detail: detail);
}

public enum LocalAgentLaunchMode
{
    ExplicitUserConsent = 1
}

public sealed record LocalAgentProcessStartRequest(
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    LocalAgentLaunchMode LaunchMode = LocalAgentLaunchMode.ExplicitUserConsent);

public interface ILocalAgentProcessRuntime
{
    string CurrentUserSid { get; }

    ILocalAgentProcessHandle? Start(LocalAgentProcessStartRequest request);

    ILocalAgentProcessHandle GetProcessById(int processId);
}

public interface ILocalAgentProcessHandle : IDisposable
{
    int Id { get; }

    bool HasExited { get; }

    string ProcessName { get; }

    string ExecutablePath { get; }

    DateTime StartedAtUtc { get; }

    string OwnerSid { get; }

    bool? IsElevated { get; }

    bool IsRunningQueryOnly { get; }

    void Kill(bool entireProcessTree);

    Task WaitForExitAsync(CancellationToken cancellationToken);
}

public sealed class LocalAgentProcessLifecycleService : IDisposable
{
    private static readonly TimeSpan ExactStartTimeTolerance = TimeSpan.FromSeconds(1);

    private readonly object _sync = new();
    private readonly ILocalAgentProcessRuntime _runtime;
    private ILocalAgentProcessHandle? _startedProcess;
    private bool _disposed;

    public LocalAgentProcessLifecycleService(ILocalAgentProcessRuntime? runtime = null)
    {
        _runtime = runtime ?? new SystemLocalAgentProcessRuntime();
    }

    public LocalAgentProcessResult Start(LocalAgentProcessStartRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        lock (_sync)
        {
            if (_disposed)
            {
                return Result(
                    LocalAgentProcessOutcome.Disposed,
                    detail: "The local-agent process lifecycle is already disposed.");
            }

            if (!HasSupportedAgentExecutableName(request.ExecutablePath))
            {
                return Result(
                    LocalAgentProcessOutcome.VerificationRejected,
                    detail: "The requested executable path does not identify a supported local-agent executable.");
            }

            if (request.LaunchMode != LocalAgentLaunchMode.ExplicitUserConsent)
            {
                return Result(
                    LocalAgentProcessOutcome.VerificationRejected,
                    detail: "The local agent can be started only through the explicit user-consent elevation contract.");
            }

            if (_startedProcess != null)
            {
                try
                {
                    if (!_startedProcess.HasExited)
                    {
                        if (!IsVerifiedLaunchIdentity(_startedProcess, request.ExecutablePath))
                        {
                            return Result(
                                LocalAgentProcessOutcome.VerificationRejected,
                                processId: _startedProcess.Id,
                                detail: "The retained local-agent process does not match the requested executable, current user, and elevated identity.");
                        }

                        return Result(
                            LocalAgentProcessOutcome.AlreadyRunning,
                            processId: _startedProcess.Id,
                            isRunning: true,
                            detail: "The viewer-started local agent is already running.");
                    }

                    DisposeTrackedProcessNoThrow();
                }
                catch (InvalidOperationException)
                {
                    DisposeTrackedProcessNoThrow();
                }
                catch (Exception ex)
                {
                    return Result(
                        LocalAgentProcessOutcome.InspectionFailure,
                        processId: TryGetProcessId(_startedProcess),
                        detail: $"The previous local-agent process could not be inspected: {ex.Message}");
                }
            }

            try
            {
                var process = _runtime.Start(request);
                if (process == null)
                {
                    return Result(
                        LocalAgentProcessOutcome.StartFailed,
                        detail: "The local-agent executable did not return a process handle.");
                }

                _startedProcess = process;
                return Result(
                    LocalAgentProcessOutcome.Started,
                    processId: process.Id,
                    isRunning: true,
                    detail: "The local-agent process was started.");
            }
            catch (Win32Exception ex)
            {
                return MapLaunchFailure(ex);
            }
            catch (FileNotFoundException ex)
            {
                return Result(
                    LocalAgentProcessOutcome.ExecutableNotFound,
                    detail: $"The local-agent executable could not be found: {ex.Message}");
            }
            catch (Exception ex)
            {
                return Result(
                    LocalAgentProcessOutcome.StartFailed,
                    detail: $"The local-agent process could not be started: {ex.Message}");
            }
        }
    }

    public LocalAgentProcessResult VerifyRunning(LocalAgentProcessIdentity identity)
    {
        var lease = AcquireVerifiedProcess(identity, VerificationMode.Reuse);
        if (lease.Result != null)
        {
            return lease.Result;
        }

        var process = lease.Process!;
        try
        {
            if (process.HasExited)
            {
                ReleaseTrackedProcessIfSame(process);
                return Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    processId: identity.ProcessId,
                    isStopped: true,
                    detail: "The verified local-agent process has already exited.");
            }

            return Result(
                LocalAgentProcessOutcome.VerifiedRunning,
                processId: identity.ProcessId,
                isRunning: true,
                detail: "The local-agent PID, start time, executable path, current-user ownership, and elevation were verified.");
        }
        catch (InvalidOperationException)
        {
            ReleaseTrackedProcessIfSame(process);
            return Result(
                LocalAgentProcessOutcome.AlreadyExited,
                processId: identity.ProcessId,
                isStopped: true,
                detail: "The verified local-agent process exited during identity verification.");
        }
        catch (Exception ex)
        {
            return Result(
                LocalAgentProcessOutcome.InspectionFailure,
                processId: identity.ProcessId,
                detail: $"The local-agent process could not be inspected for reuse: {ex.Message}");
        }
        finally
        {
            if (lease.DisposeProcess)
            {
                process.Dispose();
            }
        }
    }

    public async Task<LocalAgentProcessResult> WaitForExitAsync(
        LocalAgentProcessIdentity identity,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var lease = AcquireVerifiedProcess(identity, VerificationMode.GracefulWait);
        if (lease.Result != null)
        {
            return lease.Result;
        }

        var process = lease.Process!;
        try
        {
            if (process.HasExited)
            {
                ReleaseTrackedProcessIfSame(process);
                return Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    processId: identity.ProcessId,
                    isStopped: true,
                    detail: "The verified local-agent process has already exited.");
            }

            using var timeoutCancellation = new CancellationTokenSource(timeout);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
                timeoutCancellation.Token,
                cancellationToken);
            try
            {
                await process.WaitForExitAsync(cancellation.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsSynchronizationAccessDenied(ex))
            {
                if (!await WaitForExitQueryOnlyAsync(
                        process,
                        timeout,
                        cancellationToken).ConfigureAwait(false))
                {
                    return Result(
                        LocalAgentProcessOutcome.GracefulWaitTimedOut,
                        processId: identity.ProcessId,
                        detail: "The elevated verified local-agent process did not exit during the query-only graceful wait.");
                }
            }
            ReleaseTrackedProcessIfSame(process);
            return Result(
                LocalAgentProcessOutcome.Exited,
                processId: identity.ProcessId,
                isStopped: true,
                detail: "The verified local-agent process exited.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Result(
                LocalAgentProcessOutcome.ObservationCanceled,
                processId: identity.ProcessId,
                detail: "The exact local-agent exit observation was canceled before completion.");
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (process.HasExited)
                {
                    ReleaseTrackedProcessIfSame(process);
                    return Result(
                        LocalAgentProcessOutcome.Exited,
                        processId: identity.ProcessId,
                        isStopped: true,
                        detail: "The verified local-agent process exited at the graceful wait boundary.");
                }
            }
            catch (InvalidOperationException)
            {
                ReleaseTrackedProcessIfSame(process);
                return Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    processId: identity.ProcessId,
                    isStopped: true,
                    detail: "The verified local-agent process exited during the graceful wait.");
            }

            return Result(
                LocalAgentProcessOutcome.GracefulWaitTimedOut,
                processId: identity.ProcessId,
                detail: "The verified local-agent process did not exit during the graceful wait.");
        }
        catch (InvalidOperationException)
        {
            ReleaseTrackedProcessIfSame(process);
            return Result(
                LocalAgentProcessOutcome.AlreadyExited,
                processId: identity.ProcessId,
                isStopped: true,
                detail: "The verified local-agent process exited during the graceful wait.");
        }
        catch (Exception ex)
        {
            return Result(
                LocalAgentProcessOutcome.InspectionFailure,
                processId: identity.ProcessId,
                detail: $"The verified local-agent process could not be observed during shutdown: {ex.Message}");
        }
        finally
        {
            if (lease.DisposeProcess)
            {
                process.Dispose();
            }
        }
    }

    private static bool IsSynchronizationAccessDenied(Exception exception) =>
        exception is UnauthorizedAccessException ||
        exception is Win32Exception { NativeErrorCode: 5 };

    private static async Task<bool> WaitForExitQueryOnlyAsync(
        ILocalAgentProcessHandle process,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (process.IsRunningQueryOnly)
        {
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                return false;
            }

            await Task.Delay(remaining < TimeSpan.FromMilliseconds(100)
                    ? remaining
                    : TimeSpan.FromMilliseconds(100),
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return true;
    }

    public async Task<LocalAgentProcessResult> ForceStopAsync(
        LocalAgentProcessIdentity identity,
        TimeSpan timeout)
    {
        var lease = AcquireVerifiedProcess(identity, VerificationMode.ForcedStop);
        if (lease.Result != null)
        {
            return lease.Result;
        }

        var process = lease.Process!;
        try
        {
            if (process.HasExited)
            {
                ReleaseTrackedProcessIfSame(process);
                return Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    processId: identity.ProcessId,
                    isStopped: true,
                    detail: "The verified local-agent process exited before forced stop.");
            }

            process.Kill(entireProcessTree: true);
            using var cancellation = new CancellationTokenSource(timeout);
            await process.WaitForExitAsync(cancellation.Token).ConfigureAwait(false);
            ReleaseTrackedProcessIfSame(process);
            return Result(
                LocalAgentProcessOutcome.ForcedStopCompleted,
                processId: identity.ProcessId,
                isStopped: true,
                forced: true,
                detail: "The verified local-agent process tree was terminated.");
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (process.HasExited)
                {
                    ReleaseTrackedProcessIfSame(process);
                    return Result(
                        LocalAgentProcessOutcome.ForcedStopCompleted,
                        processId: identity.ProcessId,
                        isStopped: true,
                        forced: true,
                        detail: "The verified local-agent process exited after forced stop was requested.");
                }
            }
            catch (InvalidOperationException)
            {
                ReleaseTrackedProcessIfSame(process);
                return Result(
                    LocalAgentProcessOutcome.ForcedStopCompleted,
                    processId: identity.ProcessId,
                    isStopped: true,
                    forced: true,
                    detail: "The verified local-agent process exited after forced stop was requested.");
            }

            return Result(
                LocalAgentProcessOutcome.ForcedStopTimedOut,
                processId: identity.ProcessId,
                detail: "The verified local-agent process did not exit after forced stop was requested.");
        }
        catch (InvalidOperationException)
        {
            ReleaseTrackedProcessIfSame(process);
            return Result(
                LocalAgentProcessOutcome.ForcedStopCompleted,
                processId: identity.ProcessId,
                isStopped: true,
                forced: true,
                detail: "The verified local-agent process exited during forced stop.");
        }
        catch (Exception ex)
        {
            return Result(
                LocalAgentProcessOutcome.InspectionFailure,
                processId: identity.ProcessId,
                detail: $"The verified local-agent process could not be terminated: {ex.Message}");
        }
        finally
        {
            if (lease.DisposeProcess)
            {
                process.Dispose();
            }
        }
    }

    public LocalAgentProcessResult CleanupExited()
    {
        lock (_sync)
        {
            if (_startedProcess == null)
            {
                return Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    isStopped: true,
                    detail: "No viewer-started local-agent process handle is retained.");
            }

            try
            {
                if (!_startedProcess.HasExited)
                {
                    return Result(
                        LocalAgentProcessOutcome.AlreadyRunning,
                        processId: _startedProcess.Id,
                        isRunning: true,
                        detail: "The viewer-started local-agent process is still running.");
                }

                var processId = _startedProcess.Id;
                DisposeTrackedProcessNoThrow();
                return Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    processId: processId,
                    isStopped: true,
                    detail: "The exited local-agent process handle was released.");
            }
            catch (InvalidOperationException)
            {
                DisposeTrackedProcessNoThrow();
                return Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    isStopped: true,
                    detail: "The invalid exited local-agent process handle was released.");
            }
            catch (Exception ex)
            {
                return Result(
                    LocalAgentProcessOutcome.InspectionFailure,
                    processId: TryGetProcessId(_startedProcess),
                    detail: $"The viewer-started local-agent process could not be cleaned up: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            DisposeTrackedProcessNoThrow();
        }
    }

    private ProcessLease AcquireVerifiedProcess(
        LocalAgentProcessIdentity identity,
        VerificationMode mode)
    {
        if (identity.ProcessId <= 0 || identity.StartedAtUtc == default)
        {
            return ProcessLease.FromResult(Result(
                LocalAgentProcessOutcome.VerificationRejected,
                processId: identity.ProcessId,
                detail: "The local-agent process identity is incomplete."));
        }

        ILocalAgentProcessHandle? tracked;
        var reacquireTrackedProcess = false;
        var trackedIdentityFailure = string.Empty;
        lock (_sync)
        {
            if (_disposed)
            {
                return ProcessLease.FromResult(Result(
                    LocalAgentProcessOutcome.Disposed,
                    processId: identity.ProcessId,
                    detail: "The local-agent process lifecycle is already disposed."));
            }

            tracked = _startedProcess;
        }

        if (tracked != null)
        {
            try
            {
                if (tracked.Id == identity.ProcessId)
                {
                    if (tracked.HasExited)
                    {
                        ReleaseTrackedProcessIfSame(tracked);
                        return ProcessLease.FromResult(Result(
                            LocalAgentProcessOutcome.AlreadyExited,
                            processId: identity.ProcessId,
                            isStopped: true,
                            detail: "The viewer-started local-agent process has already exited."));
                    }

                    var trackedAssessment = AssessIdentity(tracked, identity);
                    trackedIdentityFailure = trackedAssessment.Detail;
                    if (trackedAssessment.State == IdentityVerificationState.Verified)
                    {
                        return new ProcessLease(tracked, DisposeProcess: false, Result: null);
                    }

                    // A retained Process handle can outlive the identity snapshot captured
                    // when the viewer launched the elevated agent. Re-open the same PID once
                    // and require the complete authenticated-health identity again before
                    // replacing the stale handle. The fresh path remains query-only here.
                    reacquireTrackedProcess = true;
                }
            }
            catch (InvalidOperationException)
            {
                ReleaseTrackedProcessIfSame(tracked);
                return ProcessLease.FromResult(Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    processId: identity.ProcessId,
                    isStopped: true,
                    detail: "The viewer-started local-agent process has already exited."));
            }
            catch (Exception ex)
            {
                return ProcessLease.FromResult(Result(
                    LocalAgentProcessOutcome.InspectionFailure,
                    processId: identity.ProcessId,
                    detail: $"The tracked local-agent process could not be identity-verified: {ex.Message}"));
            }
        }

        ILocalAgentProcessHandle process;
        try
        {
            process = _runtime.GetProcessById(identity.ProcessId);
        }
        catch (ArgumentException)
        {
            return ProcessLease.FromResult(Result(
                LocalAgentProcessOutcome.AlreadyExited,
                processId: identity.ProcessId,
                isStopped: true,
                detail: "The verified local-agent PID is no longer running."));
        }
        catch (InvalidOperationException)
        {
            return ProcessLease.FromResult(Result(
                LocalAgentProcessOutcome.AlreadyExited,
                processId: identity.ProcessId,
                isStopped: true,
                detail: "The verified local-agent PID is no longer available."));
        }
        catch (Win32Exception ex)
        {
            return ProcessLease.FromResult(Result(
                LocalAgentProcessOutcome.InspectionFailure,
                processId: identity.ProcessId,
                detail: $"The local-agent PID could not be opened for identity verification: {ex.Message}"));
        }
        catch (Exception ex)
        {
            return ProcessLease.FromResult(Result(
                LocalAgentProcessOutcome.InspectionFailure,
                processId: identity.ProcessId,
                detail: $"The local-agent PID could not be opened for identity verification: {ex.Message}"));
        }

        try
        {
            var observedProcessName = process.ProcessName;
            if (!string.IsNullOrWhiteSpace(identity.ExpectedExecutableName) &&
                !string.IsNullOrWhiteSpace(observedProcessName) &&
                !ProcessNamesMatch(observedProcessName, identity.ExpectedExecutableName))
            {
                process.Dispose();
                return ProcessLease.FromResult(Result(
                    LocalAgentProcessOutcome.VerificationRejected,
                    processId: identity.ProcessId,
                    detail:
                        $"The process name '{observedProcessName}' does not match discovery identity '{identity.ExpectedExecutableName}'.",
                    exactIdentityMismatchProved: true));
            }

            if (!string.IsNullOrWhiteSpace(identity.ExpectedExecutableName))
            {
                var observedStartedAtUtc = process.StartedAtUtc;
                if (observedStartedAtUtc != default &&
                    Math.Abs((observedStartedAtUtc - identity.StartedAtUtc).TotalSeconds) >
                    ExactStartTimeTolerance.TotalSeconds)
                {
                    process.Dispose();
                    return ProcessLease.FromResult(Result(
                        LocalAgentProcessOutcome.VerificationRejected,
                        processId: identity.ProcessId,
                        detail:
                            $"The process start time '{observedStartedAtUtc:O}' does not match discovery identity '{identity.StartedAtUtc:O}'.",
                        exactIdentityMismatchProved: true));
                }
            }

            if (!string.IsNullOrWhiteSpace(observedProcessName) &&
                !ExecutableIdentity.IsSupportedAgentProcessName(observedProcessName))
            {
                var unsupportedNameDetail =
                    $"unsupported executable name '{observedProcessName}'";
                process.Dispose();
                return ProcessLease.FromResult(Result(
                    LocalAgentProcessOutcome.VerificationRejected,
                    processId: identity.ProcessId,
                    isStopped: mode == VerificationMode.GracefulWait,
                    detail: reacquireTrackedProcess
                        ? $"The retained same-PID handle failed exact local-agent identity verification ({trackedIdentityFailure}); " +
                          $"the fresh process inspection failed ({unsupportedNameDetail})."
                        : $"The process failed exact local-agent identity verification ({unsupportedNameDetail})."));
            }

            if (process.HasExited)
            {
                process.Dispose();
                return ProcessLease.FromResult(Result(
                    LocalAgentProcessOutcome.AlreadyExited,
                    processId: identity.ProcessId,
                    isStopped: true,
                    detail: "The verified local-agent PID has already exited."));
            }

            var freshAssessment = AssessIdentity(process, identity);
            if (freshAssessment.State != IdentityVerificationState.Verified)
            {
                process.Dispose();
                return ProcessLease.FromResult(Result(
                    freshAssessment.State == IdentityVerificationState.Unresolved
                        ? LocalAgentProcessOutcome.InspectionFailure
                        : LocalAgentProcessOutcome.VerificationRejected,
                    processId: identity.ProcessId,
                    isStopped: freshAssessment.State == IdentityVerificationState.Rejected &&
                               mode == VerificationMode.GracefulWait,
                    detail: reacquireTrackedProcess
                        ? $"The retained same-PID handle failed exact local-agent identity verification ({trackedIdentityFailure}); " +
                          $"the fresh process inspection failed ({freshAssessment.Detail})."
                        : freshAssessment.State == IdentityVerificationState.Unresolved
                            ? $"The process identity inspection was incomplete ({freshAssessment.Detail})."
                            : $"The process failed exact local-agent identity verification ({freshAssessment.Detail})."));
            }

            return reacquireTrackedProcess
                ? RebindFreshVerifiedProcess(tracked!, process, identity.ProcessId)
                : new ProcessLease(process, DisposeProcess: true, Result: null);
        }
        catch (Exception ex)
        {
            process.Dispose();
            return ProcessLease.FromResult(Result(
                LocalAgentProcessOutcome.InspectionFailure,
                processId: identity.ProcessId,
                detail: $"The local-agent PID could not be identity-verified: {ex.Message}"));
        }
    }

    private IdentityVerificationAssessment AssessIdentity(
        ILocalAgentProcessHandle process,
        LocalAgentProcessIdentity identity)
    {
        var rejections = new List<string>();
        var unresolved = new List<string>();
        if (process.Id != identity.ProcessId)
        {
            rejections.Add($"PID mismatch: observed {process.Id}, expected {identity.ProcessId}");
        }

        if (string.IsNullOrWhiteSpace(process.ProcessName))
        {
            unresolved.Add("the executable name is unavailable");
        }
        else if (!ExecutableIdentity.IsSupportedAgentProcessName(process.ProcessName))
        {
            return new IdentityVerificationAssessment(
                IdentityVerificationState.Rejected,
                $"unsupported executable name '{process.ProcessName}'");
        }

        if (string.IsNullOrWhiteSpace(process.ExecutablePath))
        {
            unresolved.Add("the executable path is unavailable");
        }
        else if (!IsSupportedAgentExecutablePath(
                     process.ExecutablePath,
                     identity.SupportedExecutablePaths))
        {
            rejections.Add($"executable path '{process.ExecutablePath}' is outside the canonical current/former agent allowlist");
        }

        if (string.IsNullOrWhiteSpace(_runtime.CurrentUserSid))
        {
            unresolved.Add("the viewer account SID is unavailable");
        }
        else if (string.IsNullOrWhiteSpace(process.OwnerSid))
        {
            unresolved.Add("the process owner SID is unavailable");
        }
        else if (!string.Equals(
                     process.OwnerSid,
                     _runtime.CurrentUserSid,
                     StringComparison.OrdinalIgnoreCase))
        {
            rejections.Add("the process owner SID differs from the viewer account SID");
        }

        if (process.IsElevated == false)
        {
            rejections.Add("the process token is not elevated");
        }
        else if (process.IsElevated == null)
        {
            unresolved.Add("the process elevation state is unavailable");
        }

        var candidateUtc = process.StartedAtUtc;
        if (candidateUtc == default)
        {
            unresolved.Add("the process start time is unavailable");
        }
        else
        {
            var delta = candidateUtc - identity.StartedAtUtc;
            if (delta.Duration() > ExactStartTimeTolerance)
            {
                rejections.Add(
                    $"start-time mismatch: observed {candidateUtc:O}, authenticated health {identity.StartedAtUtc:O}, " +
                    $"delta {delta.Duration().TotalMilliseconds:N0} ms");
            }
        }

        if (rejections.Count > 0)
        {
            return new IdentityVerificationAssessment(
                IdentityVerificationState.Rejected,
                string.Join("; ", rejections.Concat(unresolved)));
        }

        return unresolved.Count > 0
            ? new IdentityVerificationAssessment(
                IdentityVerificationState.Unresolved,
                string.Join("; ", unresolved))
            : new IdentityVerificationAssessment(
                IdentityVerificationState.Verified,
                string.Empty);
    }

    private ProcessLease RebindFreshVerifiedProcess(
        ILocalAgentProcessHandle staleProcess,
        ILocalAgentProcessHandle freshProcess,
        int processId)
    {
        var disposed = false;
        var rebound = false;
        lock (_sync)
        {
            if (_disposed)
            {
                disposed = true;
            }
            else if (ReferenceEquals(_startedProcess, staleProcess))
            {
                _startedProcess = freshProcess;
                rebound = true;
            }
        }

        if (disposed)
        {
            DisposeProcessNoThrow(freshProcess);
            return ProcessLease.FromResult(Result(
                LocalAgentProcessOutcome.Disposed,
                processId: processId,
                detail: "The local-agent process lifecycle was disposed during fresh identity verification."));
        }

        if (rebound)
        {
            DisposeProcessNoThrow(staleProcess);
            return new ProcessLease(freshProcess, DisposeProcess: false, Result: null);
        }

        // Another lifecycle operation replaced or released the retained handle while
        // the query-only inspection ran. Keep the independently verified handle
        // transient so this caller can finish without overwriting newer state.
        return new ProcessLease(freshProcess, DisposeProcess: true, Result: null);
    }

    private bool IsVerifiedLaunchIdentity(
        ILocalAgentProcessHandle process,
        string requestedExecutablePath) =>
        ExecutableIdentity.IsSupportedAgentProcessName(process.ProcessName) &&
        IsSupportedAgentExecutablePath(process.ExecutablePath, [requestedExecutablePath]) &&
        !string.IsNullOrWhiteSpace(_runtime.CurrentUserSid) &&
        string.Equals(
            process.OwnerSid,
            _runtime.CurrentUserSid,
            StringComparison.OrdinalIgnoreCase) &&
        process.IsElevated == true;

    private static bool HasSupportedAgentExecutableName(string? executablePath) =>
        !string.IsNullOrWhiteSpace(executablePath) &&
        ExecutableIdentity.IsSupportedAgentProcessName(Path.GetFileName(executablePath));

    private static bool ProcessNamesMatch(string observed, string expected)
    {
        static string Normalize(string value)
        {
            var fileName = Path.GetFileName(value.Trim());
            return fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? fileName[..^4]
                : fileName;
        }

        return string.Equals(
            Normalize(observed),
            Normalize(expected),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Applies the single canonical executable-path allowlist policy used by
    /// launch, discovery-lease, health, reconnect, and shutdown verification.
    /// </summary>
    public static bool IsSupportedAgentExecutablePath(
        string? executablePath,
        IReadOnlyList<string>? supportedExecutablePaths)
    {
        if (!HasSupportedAgentExecutableName(executablePath) ||
            supportedExecutablePaths == null ||
            supportedExecutablePaths.Count == 0)
        {
            return false;
        }

        if (!TryGetCanonicalExecutablePath(executablePath!, out var candidate))
        {
            return false;
        }

        return supportedExecutablePaths.Any(path =>
        {
            if (!HasSupportedAgentExecutableName(path))
            {
                return false;
            }

            return TryGetCanonicalExecutablePath(path, out var supported) &&
                   string.Equals(candidate, supported, StringComparison.OrdinalIgnoreCase);
        });
    }

    private static bool TryGetCanonicalExecutablePath(string path, out string canonicalPath)
    {
        canonicalPath = string.Empty;
        try
        {
            canonicalPath = NormalizeExtendedPathPrefix(Path.GetFullPath(path));
        }
        catch
        {
            return false;
        }

        if (!OperatingSystem.IsWindows())
        {
            return true;
        }

        var universalNetworkPath = NativePathInspector.TryGetUniversalNetworkPath(canonicalPath);
        if (!string.IsNullOrWhiteSpace(universalNetworkPath))
        {
            try
            {
                canonicalPath = NormalizeExtendedPathPrefix(Path.GetFullPath(universalNetworkPath));
            }
            catch
            {
                // Keep the normalized drive spelling if the network provider
                // returned a path that Windows cannot normalize.
            }
        }

        try
        {
            using var handle = File.OpenHandle(
                canonicalPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var resolved = NativePathInspector.GetFinalPath(handle);
            if (!string.IsNullOrWhiteSpace(resolved))
            {
                canonicalPath = NormalizeExtendedPathPrefix(Path.GetFullPath(resolved));
            }
        }
        catch
        {
            // Preserve the existing exact lexical comparison when Windows cannot
            // open the executable path. Successful final-path resolution is used
            // only to collapse drive/UNC and reparse-point aliases to one path.
        }

        return true;
    }

    private static string NormalizeExtendedPathPrefix(string path)
    {
        const string extendedUncPrefix = @"\\?\UNC\";
        const string extendedPathPrefix = @"\\?\";
        if (path.StartsWith(extendedUncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[extendedUncPrefix.Length..];
        }

        return path.StartsWith(extendedPathPrefix, StringComparison.OrdinalIgnoreCase)
            ? path[extendedPathPrefix.Length..]
            : path;
    }

    private static class NativePathInspector
    {
        private const uint FileNameNormalized = 0;
        private const uint VolumeNameDos = 0;
        private const int UniversalNameInfoLevel = 0x00000001;
        private const int ErrorSuccess = 0;
        private const int ErrorMoreData = 234;

        public static string? TryGetUniversalNetworkPath(string path)
        {
            if (path.Length < 3 ||
                !char.IsLetter(path[0]) ||
                path[1] != Path.VolumeSeparatorChar ||
                (path[2] != Path.DirectorySeparatorChar && path[2] != Path.AltDirectorySeparatorChar))
            {
                return null;
            }

            var bufferSize = 0;
            var result = WNetGetUniversalName(
                path,
                UniversalNameInfoLevel,
                IntPtr.Zero,
                ref bufferSize);
            if (result != ErrorMoreData || bufferSize <= 0)
            {
                return null;
            }

            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                result = WNetGetUniversalName(
                    path,
                    UniversalNameInfoLevel,
                    buffer,
                    ref bufferSize);
                if (result != ErrorSuccess)
                {
                    return null;
                }

                var info = Marshal.PtrToStructure<UniversalNameInfo>(buffer);
                return info.UniversalName == IntPtr.Zero
                    ? null
                    : Marshal.PtrToStringUni(info.UniversalName);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static string GetFinalPath(SafeFileHandle handle)
        {
            var capacity = 512;
            while (capacity <= 32768)
            {
                var buffer = new StringBuilder(capacity);
                var length = GetFinalPathNameByHandle(
                    handle,
                    buffer,
                    (uint)buffer.Capacity,
                    FileNameNormalized | VolumeNameDos);
                if (length == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (length < buffer.Capacity)
                {
                    return buffer.ToString();
                }

                capacity = checked((int)length + 1);
            }

            throw new PathTooLongException("The resolved local-agent executable path exceeds the supported Windows path limit.");
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle fileHandle,
            StringBuilder filePath,
            uint filePathLength,
            uint flags);

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetGetUniversalName(
            string localPath,
            int infoLevel,
            IntPtr buffer,
            ref int bufferSize);

        [StructLayout(LayoutKind.Sequential)]
        private struct UniversalNameInfo
        {
            public IntPtr UniversalName;
        }
    }

    private void ReleaseTrackedProcessIfSame(ILocalAgentProcessHandle process)
    {
        lock (_sync)
        {
            if (!ReferenceEquals(_startedProcess, process))
            {
                return;
            }

            DisposeTrackedProcessNoThrow();
        }
    }

    private void DisposeTrackedProcessNoThrow()
    {
        var process = _startedProcess;
        _startedProcess = null;
        DisposeProcessNoThrow(process);
    }

    private static void DisposeProcessNoThrow(ILocalAgentProcessHandle? process)
    {
        try
        {
            process?.Dispose();
        }
        catch
        {
        }
    }

    private static int TryGetProcessId(ILocalAgentProcessHandle? process)
    {
        try
        {
            return process?.Id ?? 0;
        }
        catch
        {
            return 0;
        }
    }

    private static LocalAgentProcessResult Result(
        LocalAgentProcessOutcome outcome,
        int processId = 0,
        bool isRunning = false,
        bool isStopped = false,
        bool forced = false,
        string detail = "",
        bool exactIdentityMismatchProved = false) =>
        new(
            outcome,
            processId,
            isRunning,
            isStopped,
            forced,
            detail,
            exactIdentityMismatchProved);

    private static LocalAgentProcessResult MapLaunchFailure(Win32Exception exception)
    {
        var outcome = exception.NativeErrorCode switch
        {
            1223 => LocalAgentProcessOutcome.ElevationCanceled,
            2 or 3 => LocalAgentProcessOutcome.ExecutableNotFound,
            1326 or 1327 or 1328 or 1329 or 1330 or 1331 or 1909 =>
                LocalAgentProcessOutcome.CredentialsUnavailable,
            5 or 740 => LocalAgentProcessOutcome.ElevationDenied,
            _ => LocalAgentProcessOutcome.StartFailed
        };
        var detail = outcome switch
        {
            LocalAgentProcessOutcome.ElevationCanceled =>
                "The user declined the explicit UAC request. No local-agent process was started.",
            LocalAgentProcessOutcome.ExecutableNotFound =>
                "The supported local-agent executable was not found.",
            LocalAgentProcessOutcome.CredentialsUnavailable =>
                "Administrator credentials were unavailable or rejected by Windows.",
            LocalAgentProcessOutcome.ElevationDenied =>
                "Windows policy denied the explicit local-agent elevation request.",
            _ => $"Windows could not start the elevated local agent: {exception.Message}"
        };
        return Result(outcome, detail: detail);
    }

    private enum VerificationMode
    {
        Reuse,
        GracefulWait,
        ForcedStop
    }

    private enum IdentityVerificationState
    {
        Verified,
        Rejected,
        Unresolved
    }

    private sealed record IdentityVerificationAssessment(
        IdentityVerificationState State,
        string Detail);

    private sealed record ProcessLease(
        ILocalAgentProcessHandle? Process,
        bool DisposeProcess,
        LocalAgentProcessResult? Result)
    {
        public static ProcessLease FromResult(LocalAgentProcessResult result) =>
            new(null, DisposeProcess: false, result);
    }

    private sealed class SystemLocalAgentProcessRuntime : ILocalAgentProcessRuntime
    {
        public string CurrentUserSid { get; } = GetCurrentUserSid();

        public ILocalAgentProcessHandle? Start(LocalAgentProcessStartRequest request)
        {
            if (request.LaunchMode != LocalAgentLaunchMode.ExplicitUserConsent)
            {
                throw new InvalidOperationException(
                    "The system local-agent runtime supports only explicit user-consent elevation.");
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = request.ExecutablePath,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(request.ExecutablePath) ?? string.Empty,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            foreach (var argument in request.Arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            var process = Process.Start(startInfo);
            return process == null ? null : new SystemLocalAgentProcessHandle(process);
        }

        public ILocalAgentProcessHandle GetProcessById(int processId) =>
            new SystemLocalAgentProcessHandle(Process.GetProcessById(processId));

        private static string GetCurrentUserSid()
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User?.Value ?? string.Empty;
        }
    }

    private sealed class SystemLocalAgentProcessHandle : ILocalAgentProcessHandle
    {
        private readonly Process _process;
        private readonly string _processName;
        private readonly Lazy<NativeProcessIdentity> _identity;

        public SystemLocalAgentProcessHandle(Process process)
        {
            _process = process;
            _processName = process.ProcessName;
            _identity = new Lazy<NativeProcessIdentity>(
                () => NativeProcessInspector.Inspect(process.Id));
        }

        public int Id => _process.Id;

        public bool HasExited => _process.HasExited;

        public string ProcessName => _processName;

        public string ExecutablePath => _identity.Value.ExecutablePath;

        public DateTime StartedAtUtc => _identity.Value.StartedAtUtc;

        public string OwnerSid => _identity.Value.OwnerSid;

        public bool? IsElevated => _identity.Value.IsElevated;

        public bool IsRunningQueryOnly =>
            NativeProcessInspector.IsSameProcessRunning(_process.Id, _identity.Value.StartedAtUtc);

        public void Kill(bool entireProcessTree) => _process.Kill(entireProcessTree);

        public Task WaitForExitAsync(CancellationToken cancellationToken) =>
            _process.WaitForExitAsync(cancellationToken);

        public void Dispose() => _process.Dispose();
    }

    private sealed record NativeProcessIdentity(
        string ExecutablePath,
        DateTime StartedAtUtc,
        string OwnerSid,
        bool? IsElevated);

    private static class NativeProcessInspector
    {
        private const uint ProcessQueryLimitedInformation = 0x1000;
        private const uint TokenQuery = 0x0008;
        private const int TokenElevationClass = 20;

        public static NativeProcessIdentity Inspect(int processId)
        {
            var processHandle = OpenProcess(
                ProcessQueryLimitedInformation,
                inheritHandle: false,
                processId);
            if (processHandle == IntPtr.Zero)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"The local-agent PID {processId} could not be opened with query-only access.");
            }

            try
            {
                var executablePath = GetExecutablePath(processHandle);
                var startedAtUtc = GetStartedAtUtc(processHandle);
                var (ownerSid, isElevated) = GetTokenIdentityOrUnavailable(processHandle);
                return new NativeProcessIdentity(
                    executablePath,
                    startedAtUtc,
                    ownerSid,
                    isElevated);
            }
            finally
            {
                _ = CloseHandle(processHandle);
            }
        }

        public static bool IsSameProcessRunning(int processId, DateTime expectedStartedAtUtc)
        {
            var processHandle = OpenProcess(
                ProcessQueryLimitedInformation,
                inheritHandle: false,
                processId);
            if (processHandle == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                if (error is 87 or 1168)
                {
                    return false;
                }

                throw new Win32Exception(
                    error,
                    $"The local-agent PID {processId} could not be polled with query-only access.");
            }

            try
            {
                if (!GetProcessTimes(
                        processHandle,
                        out var creationTime,
                        out _,
                        out _,
                        out _))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error is 6 or 87 or 1168)
                    {
                        return false;
                    }

                    throw new Win32Exception(error, "The local-agent process start time could not be polled.");
                }

                var observedStartedAtUtc = DateTime.FromFileTimeUtc(creationTime.ToLong());
                if ((observedStartedAtUtc - expectedStartedAtUtc).Duration() > ExactStartTimeTolerance)
                {
                    return false;
                }

                if (!GetExitCodeProcess(processHandle, out var exitCode))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error is 6 or 87 or 1168)
                    {
                        return false;
                    }

                    throw new Win32Exception(error, "The local-agent process exit state could not be polled.");
                }

                return exitCode == 259;
            }
            finally
            {
                _ = CloseHandle(processHandle);
            }
        }

        private static string GetExecutablePath(IntPtr processHandle)
        {
            var capacity = 32768;
            var buffer = new StringBuilder(capacity);
            if (!QueryFullProcessImageName(
                    processHandle,
                    flags: 0,
                    buffer,
                    ref capacity))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The local-agent executable path could not be queried.");
            }

            return buffer.ToString();
        }

        private static DateTime GetStartedAtUtc(IntPtr processHandle)
        {
            if (!GetProcessTimes(
                    processHandle,
                    out var creationTime,
                    out _,
                    out _,
                    out _))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The local-agent process start time could not be queried.");
            }

            return DateTime.FromFileTimeUtc(creationTime.ToLong());
        }

        private static (string OwnerSid, bool? IsElevated) GetTokenIdentityOrUnavailable(
            IntPtr processHandle)
        {
            if (!OpenProcessToken(processHandle, TokenQuery, out var tokenHandle))
            {
                var error = Marshal.GetLastWin32Error();
                if (IsExpectedIdentityInspectionUnavailable(error))
                {
                    return (string.Empty, null);
                }

                throw new Win32Exception(
                    error,
                    "The local-agent process token could not be queried.");
            }

            try
            {
                var ownerSid = string.Empty;
                try
                {
                    using var identity = new WindowsIdentity(tokenHandle);
                    ownerSid = identity.User?.Value ?? string.Empty;
                }
                catch (Win32Exception ex) when (
                    IsExpectedIdentityInspectionUnavailable(ex.NativeErrorCode))
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
                catch (SecurityException)
                {
                }

                bool? isElevated;
                if (GetTokenInformation(
                        tokenHandle,
                        TokenElevationClass,
                        out var elevation,
                        Marshal.SizeOf<TokenElevation>(),
                        out _))
                {
                    isElevated = elevation.TokenIsElevated != 0;
                }
                else
                {
                    var error = Marshal.GetLastWin32Error();
                    if (!IsExpectedIdentityInspectionUnavailable(error))
                    {
                        throw new Win32Exception(
                            error,
                            "The local-agent elevation state could not be queried.");
                    }

                    isElevated = null;
                }

                return (ownerSid, isElevated);
            }
            finally
            {
                _ = CloseHandle(tokenHandle);
            }
        }

        private static bool IsExpectedIdentityInspectionUnavailable(int nativeError) =>
            nativeError is 5 or 6 or 87 or 1008 or 1168 or 1314;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint desiredAccess,
            bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(
            IntPtr processHandle,
            int flags,
            StringBuilder executablePath,
            ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr processHandle,
            out NativeFileTime creationTime,
            out NativeFileTime exitTime,
            out NativeFileTime kernelTime,
            out NativeFileTime userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(
            IntPtr processHandle,
            out uint exitCode);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle,
            uint desiredAccess,
            out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr tokenHandle,
            int tokenInformationClass,
            out TokenElevation tokenInformation,
            int tokenInformationLength,
            out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeFileTime
        {
            private uint _lowDateTime;
            private uint _highDateTime;

            public long ToLong() =>
                ((long)_highDateTime << 32) | _lowDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenElevation
        {
            public int TokenIsElevated;
        }
    }
}
