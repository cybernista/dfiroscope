using System.Globalization;
using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.AgentIpc;

public enum LocalAgentControlOutcome
{
    Started = 0,
    Reused = 1,
    Reconnected = 2,
    Stopped = 3,
    PairingReady = 4,
    PairingRotated = 5,
    PairingRevoked = 6,
    Absent = 7,
    Busy = 8,
    Canceled = 9,
    Superseded = 10,
    Rejected = 11,
    Unavailable = 12,
    TimedOut = 13,
    InternalFailure = 14
}

public enum LocalAgentControlStage
{
    None = 0,
    ValidateTarget = 1,
    Discover = 2,
    PreparePairing = 3,
    Launch = 4,
    Authenticate = 5,
    InspectPairing = 6,
    RotatePairing = 7,
    RevokePairing = 8,
    ValidateShutdown = 9,
    NormalShutdown = 10,
    ControlShutdown = 11,
    ReinspectProcess = 12,
    VerifiedProcessFallback = 13,
    LateExitObservation = 14,
    Completed = 15
}

public sealed record LocalAgentControlTarget(
    InvestigationSessionPaths SessionPaths,
    CaptureWorkspaceMode WorkspaceMode,
    long WorkspaceGeneration,
    IFeatureCatalog FeatureCatalog,
    string ViewerReleaseId,
    IReadOnlyList<string> SupportedExecutablePaths,
    string PrimaryAgentExecutablePath)
{
    public LocalAgentRecoveryRequest CreateRecoveryRequest() =>
        new(
            FeatureCatalog,
            ViewerReleaseId,
            WorkspaceGeneration,
            SupportedExecutablePaths);
}

public sealed record LocalAgentStartRequest(
    LocalAgentControlTarget Target,
    int LiveBufferMemoryMegabytes);

public sealed record LocalAgentReconnectRequest(
    LocalAgentRecoveryRequest RecoveryRequest,
    InvestigationSessionPaths? ExpectedSessionPaths = null);

public sealed record LocalAgentVerifiedShutdownTarget(
    int ProcessId,
    DateTime StartedAtUtc,
    string SessionId,
    string DatabasePath);

public sealed record LocalAgentStopRequest(
    LocalAgentControlTarget Target,
    bool AllowVerifiedProcessFallback,
    TimeSpan GracefulTimeout,
    string Reason,
    LocalAgentVerifiedShutdownTarget? VerifiedTarget = null);

public sealed record LocalAgentPairingRequest(
    LocalAgentControlTarget Target,
    bool Confirmed = false);

public sealed record LocalAgentControlResult(
    LocalAgentControlOutcome Outcome,
    LocalAgentControlStage Stage,
    string Diagnostic,
    LocalAgentRecoveryResult? Recovery = null,
    LocalAgentProcessResult? Process = null,
    AgentPairingStoreResult? Pairing = null,
    AgentIpcResponse? Response = null,
    bool Forced = false,
    LocalAgentVerifiedShutdownTarget? VerifiedShutdownTarget = null)
{
    public bool Succeeded => Outcome is
        LocalAgentControlOutcome.Started or
        LocalAgentControlOutcome.Reused or
        LocalAgentControlOutcome.Reconnected or
        LocalAgentControlOutcome.Stopped or
        LocalAgentControlOutcome.PairingReady or
        LocalAgentControlOutcome.PairingRotated or
        LocalAgentControlOutcome.PairingRevoked;

    public LocalAgentRecoveredBinding? Binding => Recovery?.Binding;
}

public interface ILocalAgentControlRuntime
{
    bool IsCurrent(LocalAgentControlTarget target);

    LocalAgentDiscoveryResult Discover();

    Task<LocalAgentRecoveryResult> RecoverAsync(
        LocalAgentRecoveryRequest request,
        CancellationToken cancellationToken);

    void BindSession(InvestigationSessionPaths sessionPaths);

    AgentPairingStoreResult InspectPairing(DateTime nowUtc);

    AgentPairingStoreResult PrepareNewPairing(DateTime nowUtc);

    bool IsSupportedAgentExecutablePath(
        string executablePath,
        IReadOnlyList<string> supportedExecutablePaths);

    LocalAgentProcessResult Start(LocalAgentProcessStartRequest request);

    LocalAgentProcessResult VerifyRunning(LocalAgentProcessIdentity identity);

    Task<AgentIpcResponse> SendNormalShutdownAsync(
        ShutdownAgentCommand command,
        CancellationToken cancellationToken);

    Task<AgentIpcResponse> SendControlShutdownAsync(
        ShutdownAgentCommand command,
        CancellationToken cancellationToken);

    Task<LocalAgentProcessResult> WaitForExitAsync(
        LocalAgentProcessIdentity identity,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    Task<LocalAgentProcessResult> ForceStopAsync(
        LocalAgentProcessIdentity identity,
        TimeSpan timeout);

    Task<AgentIpcResponse> RotatePairingAsync(CancellationToken cancellationToken);

    Task<AgentIpcResponse> RevokePairingAsync(CancellationToken cancellationToken);

    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public sealed class DelegateLocalAgentControlRuntime : ILocalAgentControlRuntime
{
    private readonly Func<LocalAgentControlTarget, bool> _isCurrent;
    private readonly Func<LocalAgentDiscoveryResult> _discover;
    private readonly Func<LocalAgentRecoveryRequest, CancellationToken, Task<LocalAgentRecoveryResult>> _recoverAsync;
    private readonly Action<InvestigationSessionPaths> _bindSession;
    private readonly Func<DateTime, AgentPairingStoreResult> _inspectPairing;
    private readonly Func<DateTime, AgentPairingStoreResult> _prepareNewPairing;
    private readonly Func<string, IReadOnlyList<string>, bool> _isSupportedAgentExecutablePath;
    private readonly Func<LocalAgentProcessStartRequest, LocalAgentProcessResult> _start;
    private readonly Func<LocalAgentProcessIdentity, LocalAgentProcessResult> _verifyRunning;
    private readonly Func<ShutdownAgentCommand, CancellationToken, Task<AgentIpcResponse>> _sendNormalShutdownAsync;
    private readonly Func<ShutdownAgentCommand, CancellationToken, Task<AgentIpcResponse>> _sendControlShutdownAsync;
    private readonly Func<LocalAgentProcessIdentity, TimeSpan, CancellationToken, Task<LocalAgentProcessResult>> _waitForExitAsync;
    private readonly Func<LocalAgentProcessIdentity, TimeSpan, Task<LocalAgentProcessResult>> _forceStopAsync;
    private readonly Func<CancellationToken, Task<AgentIpcResponse>> _rotatePairingAsync;
    private readonly Func<CancellationToken, Task<AgentIpcResponse>> _revokePairingAsync;
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;

    public DelegateLocalAgentControlRuntime(
        Func<LocalAgentControlTarget, bool> isCurrent,
        Func<LocalAgentDiscoveryResult> discover,
        Func<LocalAgentRecoveryRequest, CancellationToken, Task<LocalAgentRecoveryResult>> recoverAsync,
        Action<InvestigationSessionPaths> bindSession,
        Func<DateTime, AgentPairingStoreResult> inspectPairing,
        Func<DateTime, AgentPairingStoreResult> prepareNewPairing,
        Func<string, IReadOnlyList<string>, bool> isSupportedAgentExecutablePath,
        Func<LocalAgentProcessStartRequest, LocalAgentProcessResult> start,
        Func<LocalAgentProcessIdentity, LocalAgentProcessResult> verifyRunning,
        Func<ShutdownAgentCommand, CancellationToken, Task<AgentIpcResponse>> sendNormalShutdownAsync,
        Func<ShutdownAgentCommand, CancellationToken, Task<AgentIpcResponse>> sendControlShutdownAsync,
        Func<LocalAgentProcessIdentity, TimeSpan, CancellationToken, Task<LocalAgentProcessResult>> waitForExitAsync,
        Func<LocalAgentProcessIdentity, TimeSpan, Task<LocalAgentProcessResult>> forceStopAsync,
        Func<CancellationToken, Task<AgentIpcResponse>> rotatePairingAsync,
        Func<CancellationToken, Task<AgentIpcResponse>> revokePairingAsync,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null)
    {
        _isCurrent = isCurrent ?? throw new ArgumentNullException(nameof(isCurrent));
        _discover = discover ?? throw new ArgumentNullException(nameof(discover));
        _recoverAsync = recoverAsync ?? throw new ArgumentNullException(nameof(recoverAsync));
        _bindSession = bindSession ?? throw new ArgumentNullException(nameof(bindSession));
        _inspectPairing = inspectPairing ?? throw new ArgumentNullException(nameof(inspectPairing));
        _prepareNewPairing = prepareNewPairing ?? throw new ArgumentNullException(nameof(prepareNewPairing));
        _isSupportedAgentExecutablePath = isSupportedAgentExecutablePath ??
            throw new ArgumentNullException(nameof(isSupportedAgentExecutablePath));
        _start = start ?? throw new ArgumentNullException(nameof(start));
        _verifyRunning = verifyRunning ?? throw new ArgumentNullException(nameof(verifyRunning));
        _sendNormalShutdownAsync = sendNormalShutdownAsync ??
            throw new ArgumentNullException(nameof(sendNormalShutdownAsync));
        _sendControlShutdownAsync = sendControlShutdownAsync ??
            throw new ArgumentNullException(nameof(sendControlShutdownAsync));
        _waitForExitAsync = waitForExitAsync ?? throw new ArgumentNullException(nameof(waitForExitAsync));
        _forceStopAsync = forceStopAsync ?? throw new ArgumentNullException(nameof(forceStopAsync));
        _rotatePairingAsync = rotatePairingAsync ?? throw new ArgumentNullException(nameof(rotatePairingAsync));
        _revokePairingAsync = revokePairingAsync ?? throw new ArgumentNullException(nameof(revokePairingAsync));
        _delayAsync = delayAsync ?? Task.Delay;
    }

    public bool IsCurrent(LocalAgentControlTarget target) => _isCurrent(target);
    public LocalAgentDiscoveryResult Discover() => _discover();
    public Task<LocalAgentRecoveryResult> RecoverAsync(LocalAgentRecoveryRequest request, CancellationToken cancellationToken) =>
        _recoverAsync(request, cancellationToken);
    public void BindSession(InvestigationSessionPaths sessionPaths) => _bindSession(sessionPaths);
    public AgentPairingStoreResult InspectPairing(DateTime nowUtc) => _inspectPairing(nowUtc);
    public AgentPairingStoreResult PrepareNewPairing(DateTime nowUtc) => _prepareNewPairing(nowUtc);
    public bool IsSupportedAgentExecutablePath(
        string executablePath,
        IReadOnlyList<string> supportedExecutablePaths) =>
        _isSupportedAgentExecutablePath(executablePath, supportedExecutablePaths);
    public LocalAgentProcessResult Start(LocalAgentProcessStartRequest request) => _start(request);
    public LocalAgentProcessResult VerifyRunning(LocalAgentProcessIdentity identity) => _verifyRunning(identity);
    public Task<AgentIpcResponse> SendNormalShutdownAsync(ShutdownAgentCommand command, CancellationToken cancellationToken) =>
        _sendNormalShutdownAsync(command, cancellationToken);
    public Task<AgentIpcResponse> SendControlShutdownAsync(ShutdownAgentCommand command, CancellationToken cancellationToken) =>
        _sendControlShutdownAsync(command, cancellationToken);
    public Task<LocalAgentProcessResult> WaitForExitAsync(
        LocalAgentProcessIdentity identity,
        TimeSpan timeout,
        CancellationToken cancellationToken) =>
        _waitForExitAsync(identity, timeout, cancellationToken);
    public Task<LocalAgentProcessResult> ForceStopAsync(LocalAgentProcessIdentity identity, TimeSpan timeout) =>
        _forceStopAsync(identity, timeout);
    public Task<AgentIpcResponse> RotatePairingAsync(CancellationToken cancellationToken) =>
        _rotatePairingAsync(cancellationToken);
    public Task<AgentIpcResponse> RevokePairingAsync(CancellationToken cancellationToken) =>
        _revokePairingAsync(cancellationToken);
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        _delayAsync(delay, cancellationToken);
}

/// <summary>
/// Headless owner for explicit local-agent lifecycle and pairing-maintenance workflows.
/// Presentation adapters supply confirmation and project the immutable typed result.
/// Native process operations remain behind <see cref="ILocalAgentControlRuntime"/>.
/// </summary>
public sealed class LocalAgentControlCoordinator : IDisposable
{
    public static readonly TimeSpan DefaultStartupPollInterval = TimeSpan.FromMilliseconds(500);
    public static readonly TimeSpan DefaultGracefulShutdownTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan DefaultControlShutdownTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan DefaultForcedShutdownTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan DefaultLateExitGraceTimeout = TimeSpan.FromSeconds(15);
    public const int DefaultStartupAttempts = 61;
    public const int DefaultReconnectAttempts = 41;
    public const int DefaultShutdownAttempts = 3;
    public const int DefaultControlShutdownAttempts = 2;

    private readonly ILocalAgentControlRuntime _runtime;
    private readonly Func<DateTime> _utcNow;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly CancellationTokenSource _lifetimeCts = new();
    private bool _disposed;

    public LocalAgentControlCoordinator(
        ILocalAgentControlRuntime runtime,
        Func<DateTime>? utcNow = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
    }

    public Task<LocalAgentControlResult> StartAsync(
        LocalAgentStartRequest request,
        CancellationToken cancellationToken = default) =>
        RunSerializedAsync(token => StartCoreAsync(request, token), cancellationToken);

    public Task<LocalAgentControlResult> ReconnectAsync(
        LocalAgentReconnectRequest request,
        CancellationToken cancellationToken = default) =>
        RunSerializedAsync(token => ReconnectCoreAsync(request, token), cancellationToken);

    public Task<LocalAgentControlResult> StopAsync(
        LocalAgentStopRequest request,
        CancellationToken cancellationToken = default) =>
        RunSerializedAsync(token => StopCoreAsync(request, token), cancellationToken);

    public Task<LocalAgentControlResult> GetPairingStatusAsync(
        LocalAgentPairingRequest request,
        CancellationToken cancellationToken = default) =>
        RunSerializedAsync(token => PairingStatusCoreAsync(request, token), cancellationToken);

    public Task<LocalAgentControlResult> RotatePairingAsync(
        LocalAgentPairingRequest request,
        CancellationToken cancellationToken = default) =>
        RunSerializedAsync(token => RotatePairingCoreAsync(request, token), cancellationToken);

    public Task<LocalAgentControlResult> RevokePairingAsync(
        LocalAgentPairingRequest request,
        CancellationToken cancellationToken = default) =>
        RunSerializedAsync(token => RevokePairingCoreAsync(request, token), cancellationToken);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _lifetimeCts.Cancel();
        _lifetimeCts.Dispose();
        _operationGate.Dispose();
    }

    private async Task<LocalAgentControlResult> StartCoreAsync(
        LocalAgentStartRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var targetFailure = ValidateTarget(request.Target, requireExecutable: true);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (request.LiveBufferMemoryMegabytes is not (500 or 1024 or 2048))
        {
            return Reject(
                LocalAgentControlStage.ValidateTarget,
                "The live-buffer memory budget must be exactly 500, 1024, or 2048 MB.");
        }

        var launchTarget = LocalAgentLaunchTargetPolicy.Validate(
            request.Target.WorkspaceMode,
            request.Target.SessionPaths.SessionRoot,
            request.Target.SessionPaths.LiveDatabasePath);
        if (!launchTarget.IsValid)
        {
            return Reject(LocalAgentControlStage.ValidateTarget, launchTarget.Detail);
        }

        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.ValidateTarget);
        }

        var discovery = _runtime.Discover();
        if (discovery.BlocksAdd)
        {
            if (discovery.Outcome != LocalAgentDiscoveryOutcome.SingleCandidate)
            {
                return Unavailable(LocalAgentControlStage.Discover, discovery.Diagnostic);
            }

            LocalAgentRecoveryResult? recovery = null;
            for (var attempt = 0; attempt < DefaultReconnectAttempts; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_runtime.IsCurrent(request.Target))
                {
                    return Superseded(LocalAgentControlStage.Authenticate);
                }

                if (attempt > 0)
                {
                    await _runtime.DelayAsync(DefaultStartupPollInterval, cancellationToken)
                        .ConfigureAwait(false);
                }

                recovery = await _runtime.RecoverAsync(
                        request.Target.CreateRecoveryRequest(),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (recovery.Recovered || !ShouldRetryRecovery(recovery, allowAbsent: false))
                {
                    break;
                }
            }

            if (recovery == null)
            {
                return Unavailable(
                    LocalAgentControlStage.Authenticate,
                    "Existing local-agent recovery produced no result; no second process was started.");
            }

            if (!recovery.Recovered && ShouldRetryRecovery(recovery, allowAbsent: false))
            {
                recovery = WithRetryExhausted(
                    recovery,
                    DefaultReconnectAttempts,
                    "Existing local-agent recovery");
            }

            if (!recovery.Recovered)
            {
                return FromRecovery(recovery, LocalAgentControlStage.Authenticate);
            }

            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.Authenticate);
            }

            if (!MatchesSession(recovery.Binding!.SessionPaths, request.Target.SessionPaths))
            {
                return Reject(
                    LocalAgentControlStage.Authenticate,
                    "The verified running local agent belongs to a different explicit live session; no second process was started.",
                    recovery);
            }

            return Success(
                LocalAgentControlOutcome.Reused,
                "The compatible current/former local-agent process was reused and freshly authenticated without a second launch.",
                recovery: recovery,
                process: recovery.Binding.ProcessVerification,
                stage: LocalAgentControlStage.Authenticate);
        }

        cancellationToken.ThrowIfCancellationRequested();
        _runtime.BindSession(request.Target.SessionPaths);
        AgentPairingStoreResult prepared;
        try
        {
            prepared = _runtime.PrepareNewPairing(_utcNow());
        }
        catch
        {
            return new LocalAgentControlResult(
                LocalAgentControlOutcome.InternalFailure,
                LocalAgentControlStage.PreparePairing,
                "The current-user protected local-agent pairing generation could not be prepared.");
        }

        if (prepared.State != AgentPairingState.Ready || prepared.PairingGeneration <= 0)
        {
            return Reject(
                LocalAgentControlStage.PreparePairing,
                $"Pairing preparation returned {prepared.State} generation {prepared.PairingGeneration}; no process was started.",
                pairing: prepared);
        }

        var arguments = new[]
        {
            "--foreground",
            "--database",
            launchTarget.DatabasePath,
            "--prepared-pairing-generation",
            prepared.PairingGeneration.ToString(CultureInfo.InvariantCulture),
            "--live-buffer-memory-mb",
            request.LiveBufferMemoryMegabytes.ToString(CultureInfo.InvariantCulture)
        };
        var start = _runtime.Start(new LocalAgentProcessStartRequest(
            request.Target.PrimaryAgentExecutablePath,
            arguments));
        if (start.Outcome is not
            (LocalAgentProcessOutcome.Started or LocalAgentProcessOutcome.AlreadyRunning))
        {
            return new LocalAgentControlResult(
                MapProcessOutcome(start),
                LocalAgentControlStage.Launch,
                start.Detail,
                Process: start,
                Pairing: prepared);
        }

        LocalAgentRecoveryResult? lastRecovery = null;
        for (var attempt = 0; attempt < DefaultStartupAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.Authenticate);
            }

            if (attempt > 0)
            {
                await _runtime.DelayAsync(DefaultStartupPollInterval, cancellationToken)
                    .ConfigureAwait(false);
            }

            lastRecovery = await _runtime.RecoverAsync(
                    request.Target.CreateRecoveryRequest(),
                    cancellationToken)
                .ConfigureAwait(false);
            if (lastRecovery.Recovered)
            {
                if (!_runtime.IsCurrent(request.Target))
                {
                    return Superseded(LocalAgentControlStage.Authenticate);
                }

                if (!MatchesSession(lastRecovery.Binding!.SessionPaths, request.Target.SessionPaths) ||
                    lastRecovery.Binding.PairingGeneration != prepared.PairingGeneration)
                {
                    return Reject(
                        LocalAgentControlStage.Authenticate,
                        "The started process did not authenticate as the exact requested session and prepared pairing generation.",
                        lastRecovery,
                        start,
                        prepared);
                }

                return Success(
                    start.Outcome == LocalAgentProcessOutcome.AlreadyRunning
                        ? LocalAgentControlOutcome.Reused
                        : LocalAgentControlOutcome.Started,
                    "The primary local agent was started, exactly verified, and freshly authenticated without changing capture configuration or capture state.",
                    lastRecovery,
                    lastRecovery.Binding.ProcessVerification,
                    prepared,
                    stage: LocalAgentControlStage.Authenticate);
            }

            if (!ShouldRetryRecovery(lastRecovery, allowAbsent: true))
            {
                break;
            }
        }

        if (lastRecovery != null && ShouldRetryRecovery(lastRecovery, allowAbsent: true))
        {
            lastRecovery = WithRetryExhausted(
                lastRecovery,
                DefaultStartupAttempts,
                "Agent startup");
        }

        return lastRecovery == null
            ? Unavailable(LocalAgentControlStage.Authenticate, "The started local agent did not become discoverable.")
            : FromRecovery(lastRecovery, LocalAgentControlStage.Authenticate, start, prepared);
    }

    private async Task<LocalAgentControlResult> ReconnectCoreAsync(
        LocalAgentReconnectRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        LocalAgentRecoveryResult? recovery = null;
        for (var attempt = 0; attempt < DefaultReconnectAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (attempt > 0)
            {
                await _runtime.DelayAsync(DefaultStartupPollInterval, cancellationToken)
                    .ConfigureAwait(false);
            }

            recovery = await _runtime.RecoverAsync(request.RecoveryRequest, cancellationToken)
                .ConfigureAwait(false);
            if (recovery.Recovered || !ShouldRetryRecovery(recovery, allowAbsent: false))
            {
                break;
            }
        }

        if (recovery == null)
        {
            return Unavailable(
                LocalAgentControlStage.Authenticate,
                "The local-agent reconnect operation produced no recovery result.");
        }

        if (!recovery.Recovered && ShouldRetryRecovery(recovery, allowAbsent: false))
        {
            recovery = WithRetryExhausted(
                recovery,
                DefaultReconnectAttempts,
                "Local-agent reconnect");
        }

        if (!recovery.Recovered)
        {
            return FromRecovery(recovery, LocalAgentControlStage.Authenticate);
        }

        if (request.ExpectedSessionPaths != null &&
            !MatchesSession(recovery.Binding!.SessionPaths, request.ExpectedSessionPaths))
        {
            return Reject(
                LocalAgentControlStage.Authenticate,
                "The recovered local agent does not match the explicit session target; no process or pairing state was changed.",
                recovery);
        }

        return Success(
            LocalAgentControlOutcome.Reconnected,
            "The existing local agent was recovered and freshly authenticated without launching, rotating, configuring, or starting capture.",
            recovery,
            recovery.Binding!.ProcessVerification,
            recovery.Binding.ProtectedPairing,
            stage: LocalAgentControlStage.Authenticate);
    }

    private static bool ShouldRetryRecovery(
        LocalAgentRecoveryResult recovery,
        bool allowAbsent)
    {
        if (recovery.Outcome == LocalAgentRecoveryOutcome.WorkspacePending ||
            (allowAbsent && recovery.Outcome == LocalAgentRecoveryOutcome.Absent))
        {
            return true;
        }

        if (recovery.Outcome == LocalAgentRecoveryOutcome.CandidateRejected)
        {
            var conflicts = recovery.Discovery.Conflicts;
            return conflicts.Any(conflict =>
                       conflict.Kind == LocalAgentRecoveryConflictKind.ProcessInspectionUnresolved) &&
                   !conflicts.Any(conflict => conflict.Kind is
                       LocalAgentRecoveryConflictKind.ProcessIdentityRejected or
                       LocalAgentRecoveryConflictKind.IncompatibleLease);
        }

        return recovery.Outcome == LocalAgentRecoveryOutcome.AuthenticationRejected &&
               recovery.BindingValidation is
               {
                   Outcome: ViewerAgentCommandOutcome.HealthUnavailable,
                   CommandSubmissionAttempted: false
               };
    }

    private static LocalAgentRecoveryResult WithRetryExhausted(
        LocalAgentRecoveryResult recovery,
        int attempts,
        string operation) =>
        recovery with
        {
            Diagnostic =
                $"{operation} remained temporarily unavailable after {attempts} bounded attempts; no second process was launched and the current workspace was kept. {recovery.Diagnostic}"
        };

    private async Task<LocalAgentControlResult> StopCoreAsync(
        LocalAgentStopRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var shutdownStartedAtUtc = _utcNow();
        var targetFailure = ValidateTarget(request.Target, requireExecutable: false);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (request.GracefulTimeout < TimeSpan.FromSeconds(1) ||
            request.GracefulTimeout > TimeSpan.FromSeconds(120))
        {
            return Reject(
                LocalAgentControlStage.ValidateTarget,
                "The shutdown timeout must be between 1 and 120 seconds.");
        }

        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.ValidateShutdown);
        }

        LocalAgentRecoveryResult? recovery = null;
        AgentPairingStoreResult? pairing = null;
        LocalAgentVerifiedShutdownTarget shutdownTarget;
        if (request.VerifiedTarget != null)
        {
            shutdownTarget = request.VerifiedTarget;
            if (!MatchesVerifiedShutdownTarget(shutdownTarget, request.Target))
            {
                return Reject(
                    LocalAgentControlStage.ValidateShutdown,
                    "The previously authenticated shutdown target no longer matches the current live session; shutdown was not sent.");
            }

            _runtime.BindSession(request.Target.SessionPaths);
        }
        else
        {
            recovery = await _runtime.RecoverAsync(
                    request.Target.CreateRecoveryRequest(),
                    cancellationToken)
                .ConfigureAwait(false);
            if (!recovery.Recovered)
            {
                return FromRecovery(recovery, LocalAgentControlStage.ValidateShutdown);
            }

            var binding = recovery.Binding!;
            if (!MatchesSession(binding.SessionPaths, request.Target.SessionPaths))
            {
                return Reject(
                    LocalAgentControlStage.ValidateShutdown,
                    "The freshly authenticated agent belongs to a different session; shutdown was not sent.",
                    recovery);
            }

            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.ValidateShutdown);
            }

            _runtime.BindSession(binding.SessionPaths);
            pairing = binding.ProtectedPairing;
            shutdownTarget = new LocalAgentVerifiedShutdownTarget(
                binding.Health.ProcessId,
                binding.Health.StartedAtUtc,
                binding.SessionPaths.SessionId,
                binding.SessionPaths.LiveDatabasePath);
        }

        var identity = new LocalAgentProcessIdentity(
            shutdownTarget.ProcessId,
            shutdownTarget.StartedAtUtc,
            request.Target.SupportedExecutablePaths);
        var verified = _runtime.VerifyRunning(identity);
        if (verified.Outcome != LocalAgentProcessOutcome.VerifiedRunning)
        {
            return Reject(
                LocalAgentControlStage.ValidateShutdown,
                $"Shutdown was not sent because fresh exact process verification failed. {verified.Detail}",
                recovery,
                verified);
        }

        var shutdown = new ShutdownAgentCommand
        {
            Reason = string.IsNullOrWhiteSpace(request.Reason)
                ? "Explicit verified local-agent shutdown."
                : request.Reason,
            ExpectedDatabasePath = shutdownTarget.DatabasePath,
            TargetSessionId = shutdownTarget.SessionId,
            TargetDatabasePath = shutdownTarget.DatabasePath,
            TargetWorkspaceMode = request.Target.WorkspaceMode,
            RequestedWriteCategory = CaptureWriteCategory.Control
        };
        var attempts = new List<string>();
        for (var attempt = 1; attempt <= DefaultShutdownAttempts; attempt++)
        {
            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.NormalShutdown);
            }

            var response = await _runtime.SendNormalShutdownAsync(shutdown, cancellationToken)
                .ConfigureAwait(false);
            if (response.Success)
            {
                var wait = await _runtime.WaitForExitAsync(
                        identity,
                        request.GracefulTimeout,
                        cancellationToken)
                    .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (wait.IsConfirmedExactExit)
                {
                    if (!_runtime.IsCurrent(request.Target))
                    {
                        return Superseded(LocalAgentControlStage.NormalShutdown);
                    }

                    return Success(
                        LocalAgentControlOutcome.Stopped,
                        $"Local agent PID {identity.ProcessId} stopped gracefully after the normal authenticated shutdown request.",
                        recovery,
                        wait,
                        pairing,
                        response,
                        stage: LocalAgentControlStage.NormalShutdown);
                }

                attempts.Add(
                    "The normal shutdown request was accepted, but the process did not exit during the bounded drain wait. " +
                    $"Process observation: {wait.Outcome}; {Bound(wait.Detail)}");
                break;
            }

            attempts.Add($"Normal attempt {attempt}: {Bound(response.ErrorCode)} {Bound(response.ErrorMessage)}");
            var lateExit = await _runtime.WaitForExitAsync(
                    identity,
                    TimeSpan.FromSeconds(2),
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (lateExit.IsConfirmedExactExit)
            {
                if (!_runtime.IsCurrent(request.Target))
                {
                    return Superseded(LocalAgentControlStage.NormalShutdown);
                }

                return Success(
                    LocalAgentControlOutcome.Stopped,
                    $"Local agent PID {identity.ProcessId} exited after an interrupted normal shutdown response.",
                    recovery,
                    lateExit,
                    pairing,
                    response,
                    stage: LocalAgentControlStage.NormalShutdown);
            }

            if (string.Equals(response.ErrorCode, "SessionMismatch", StringComparison.Ordinal))
            {
                return Reject(
                    LocalAgentControlStage.NormalShutdown,
                    "The agent rejected the exact verified session database; no fallback was attempted.",
                    recovery,
                    lateExit,
                    pairing,
                    response);
            }
        }

        for (var attempt = 1; attempt <= DefaultControlShutdownAttempts; attempt++)
        {
            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.ControlShutdown);
            }

            var response = await _runtime.SendControlShutdownAsync(shutdown, cancellationToken)
                .ConfigureAwait(false);
            if (response.Success)
            {
                var wait = await _runtime.WaitForExitAsync(
                        identity,
                        Min(request.GracefulTimeout, DefaultControlShutdownTimeout),
                        cancellationToken)
                    .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (wait.IsConfirmedExactExit)
                {
                    if (!_runtime.IsCurrent(request.Target))
                    {
                        return Superseded(LocalAgentControlStage.ControlShutdown);
                    }

                    return Success(
                        LocalAgentControlOutcome.Stopped,
                        $"Local agent PID {identity.ProcessId} stopped through the matched-session shutdown-control pipe.",
                        recovery,
                        wait,
                        pairing,
                        response,
                        stage: LocalAgentControlStage.ControlShutdown);
                }

                attempts.Add(
                    "The shutdown-control request was accepted, but the process did not exit during the bounded wait. " +
                    $"Process observation: {wait.Outcome}; {Bound(wait.Detail)}");
                break;
            }

            attempts.Add($"Control attempt {attempt}: {Bound(response.ErrorCode)} {Bound(response.ErrorMessage)}");
            var lateExit = await _runtime.WaitForExitAsync(
                    identity,
                    TimeSpan.FromSeconds(2),
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (lateExit.IsConfirmedExactExit)
            {
                if (!_runtime.IsCurrent(request.Target))
                {
                    return Superseded(LocalAgentControlStage.ControlShutdown);
                }

                return Success(
                    LocalAgentControlOutcome.Stopped,
                    $"Local agent PID {identity.ProcessId} exited after an interrupted control-pipe response.",
                    recovery,
                    lateExit,
                    pairing,
                    response,
                    stage: LocalAgentControlStage.ControlShutdown);
            }

            if (string.Equals(response.ErrorCode, "SessionMismatch", StringComparison.Ordinal))
            {
                return Reject(
                    LocalAgentControlStage.ControlShutdown,
                    "The shutdown-control pipe rejected the exact verified session; no process fallback was attempted.",
                    recovery,
                    lateExit,
                    pairing,
                    response);
            }
        }

        if (!request.AllowVerifiedProcessFallback)
        {
            return new LocalAgentControlResult(
                LocalAgentControlOutcome.Rejected,
                LocalAgentControlStage.ReinspectProcess,
                $"Graceful shutdown did not complete and verified process fallback was not explicitly authorized. {string.Join(" ", attempts)}",
                recovery,
                verified,
                pairing);
        }

        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.ReinspectProcess);
        }

        var reinspected = _runtime.VerifyRunning(identity);
        if (reinspected.IsStopped)
        {
            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.ReinspectProcess);
            }

            return Success(
                LocalAgentControlOutcome.Stopped,
                $"Local agent PID {identity.ProcessId} exited before the authorized fallback.",
                recovery,
                reinspected,
                pairing,
                stage: LocalAgentControlStage.ReinspectProcess);
        }

        if (reinspected.Outcome != LocalAgentProcessOutcome.VerifiedRunning)
        {
            return Reject(
                LocalAgentControlStage.ReinspectProcess,
                $"The process identity changed before the authorized fallback. {reinspected.Detail}",
                recovery,
                reinspected,
                pairing);
        }

        var forced = await _runtime.ForceStopAsync(
                identity,
                Min(request.GracefulTimeout, DefaultForcedShutdownTimeout))
            .ConfigureAwait(false);
        if (forced.Outcome == LocalAgentProcessOutcome.ForcedStopCompleted)
        {
            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.VerifiedProcessFallback);
            }

            return Success(
                LocalAgentControlOutcome.Stopped,
                $"Local agent PID {identity.ProcessId} was terminated only after graceful stages failed and exact identity was freshly reverified.",
                recovery,
                forced,
                pairing,
                forced: true,
                stage: LocalAgentControlStage.VerifiedProcessFallback);
        }

        if (forced.IsStopped)
        {
            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.VerifiedProcessFallback);
            }

            return Success(
                LocalAgentControlOutcome.Stopped,
                $"Local agent PID {identity.ProcessId} exited while the authorized fallback was being applied.",
                recovery,
                forced,
                pairing,
                stage: LocalAgentControlStage.VerifiedProcessFallback);
        }

        var lateObservation = await _runtime.WaitForExitAsync(
                identity,
                DefaultLateExitGraceTimeout,
                cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (lateObservation.IsConfirmedExactExit)
        {
            if (!_runtime.IsCurrent(request.Target))
            {
                return Superseded(LocalAgentControlStage.LateExitObservation);
            }

            return Success(
                LocalAgentControlOutcome.Stopped,
                $"Local agent PID {identity.ProcessId}, started {identity.StartedAtUtc:O}, exited during the bounded late-exit grace period after the verified fallback wait timed out; observed shutdown elapsed {FormatElapsed(shutdownStartedAtUtc)}.",
                recovery,
                lateObservation,
                pairing,
                forced: true,
                stage: LocalAgentControlStage.LateExitObservation);
        }

        if (lateObservation.Outcome == LocalAgentProcessOutcome.VerificationRejected)
        {
            return Reject(
                LocalAgentControlStage.LateExitObservation,
                $"The exact process identity for PID {identity.ProcessId}, started {identity.StartedAtUtc:O}, changed during late-exit observation after {FormatElapsed(shutdownStartedAtUtc)}; the old shutdown request cannot complete the replacement process. {lateObservation.Detail}",
                recovery,
                lateObservation,
                pairing);
        }

        return new LocalAgentControlResult(
            forced.Outcome == LocalAgentProcessOutcome.ForcedStopTimedOut
                ? LocalAgentControlOutcome.TimedOut
                : LocalAgentControlOutcome.Rejected,
            LocalAgentControlStage.LateExitObservation,
            $"The exact verified local-agent PID {identity.ProcessId}, started {identity.StartedAtUtc:O}, did not stop during the initial, fallback, or bounded late-exit waits after {FormatElapsed(shutdownStartedAtUtc)}. {forced.Detail} {lateObservation.Detail} {string.Join(" ", attempts)}",
            recovery,
            lateObservation,
            pairing,
            VerifiedShutdownTarget: shutdownTarget);
    }

    private string FormatElapsed(DateTime startedAtUtc) =>
        $"{Math.Max(0, (_utcNow() - startedAtUtc).TotalSeconds).ToString("0.###", CultureInfo.InvariantCulture)}s";

    private Task<LocalAgentControlResult> PairingStatusCoreAsync(
        LocalAgentPairingRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var targetFailure = ValidateTarget(request.Target, requireExecutable: false);
        if (targetFailure != null)
        {
            return Task.FromResult(targetFailure);
        }

        if (!_runtime.IsCurrent(request.Target))
        {
            return Task.FromResult(Superseded(LocalAgentControlStage.InspectPairing));
        }

        _runtime.BindSession(request.Target.SessionPaths);
        var pairing = _runtime.InspectPairing(_utcNow());
        if (!_runtime.IsCurrent(request.Target))
        {
            return Task.FromResult(Superseded(LocalAgentControlStage.InspectPairing));
        }
        return Task.FromResult(Success(
            LocalAgentControlOutcome.PairingReady,
            "The explicit session pairing state was inspected without requesting health or changing pairing, process, configuration, capture, or evidence state.",
            pairing: pairing,
            stage: LocalAgentControlStage.InspectPairing));
    }

    private async Task<LocalAgentControlResult> RotatePairingCoreAsync(
        LocalAgentPairingRequest request,
        CancellationToken cancellationToken)
    {
        if (!request.Confirmed)
        {
            return Reject(
                LocalAgentControlStage.RotatePairing,
                "Pairing rotation requires explicit confirmation.");
        }

        var validated = await RecoverExactTargetAsync(request.Target, cancellationToken)
            .ConfigureAwait(false);
        if (!validated.Succeeded)
        {
            return validated;
        }

        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.RotatePairing);
        }

        _runtime.BindSession(validated.Binding!.SessionPaths);
        var response = await _runtime.RotatePairingAsync(cancellationToken).ConfigureAwait(false);
        if (!response.Success)
        {
            return Reject(
                LocalAgentControlStage.RotatePairing,
                $"The exact attached agent rejected pairing rotation: {Bound(response.ErrorCode)} {Bound(response.ErrorMessage)}",
                validated.Recovery,
                response: response);
        }

        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.RotatePairing);
        }

        var status = _runtime.InspectPairing(_utcNow());
        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.RotatePairing);
        }

        if (status.State is not (AgentPairingState.Ready or AgentPairingState.Connected) ||
            status.PairingGeneration <= validated.Binding.PairingGeneration)
        {
            return Reject(
                LocalAgentControlStage.RotatePairing,
                "The agent reported rotation, but the protected session did not expose a strictly newer usable generation.",
                validated.Recovery,
                pairing: status,
                response: response);
        }

        return Success(
            LocalAgentControlOutcome.PairingRotated,
            $"The exact attached local-agent pairing rotated to generation {status.PairingGeneration}; process, capture, configuration, and evidence state were unchanged.",
            validated.Recovery,
            validated.Process,
            status,
            response,
            stage: LocalAgentControlStage.RotatePairing);
    }

    private async Task<LocalAgentControlResult> RevokePairingCoreAsync(
        LocalAgentPairingRequest request,
        CancellationToken cancellationToken)
    {
        if (!request.Confirmed)
        {
            return Reject(
                LocalAgentControlStage.RevokePairing,
                "Pairing revocation requires explicit confirmation.");
        }

        var validated = await RecoverExactTargetAsync(request.Target, cancellationToken)
            .ConfigureAwait(false);
        if (!validated.Succeeded)
        {
            return validated;
        }

        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.RevokePairing);
        }

        _runtime.BindSession(validated.Binding!.SessionPaths);
        var response = await _runtime.RevokePairingAsync(cancellationToken).ConfigureAwait(false);
        if (!response.Success)
        {
            return Reject(
                LocalAgentControlStage.RevokePairing,
                $"The exact attached agent rejected pairing revocation: {Bound(response.ErrorCode)} {Bound(response.ErrorMessage)}",
                validated.Recovery,
                response: response);
        }

        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.RevokePairing);
        }

        var status = _runtime.InspectPairing(_utcNow());
        if (!_runtime.IsCurrent(request.Target))
        {
            return Superseded(LocalAgentControlStage.RevokePairing);
        }

        if (status.State != AgentPairingState.Revoked)
        {
            return Reject(
                LocalAgentControlStage.RevokePairing,
                "The agent reported revocation, but the protected session did not expose the revoked state.",
                validated.Recovery,
                pairing: status,
                response: response);
        }

        return Success(
            LocalAgentControlOutcome.PairingRevoked,
            "The exact attached local-agent pairing was revoked; the process kept running and no evidence, configuration, or session file was deleted.",
            validated.Recovery,
            validated.Process,
            status,
            response,
            stage: LocalAgentControlStage.RevokePairing);
    }

    private async Task<LocalAgentControlResult> RecoverExactTargetAsync(
        LocalAgentControlTarget target,
        CancellationToken cancellationToken)
    {
        var targetFailure = ValidateTarget(target, requireExecutable: false);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (!_runtime.IsCurrent(target))
        {
            return Superseded(LocalAgentControlStage.Authenticate);
        }

        var recovery = await _runtime.RecoverAsync(target.CreateRecoveryRequest(), cancellationToken)
            .ConfigureAwait(false);
        if (!recovery.Recovered)
        {
            return FromRecovery(recovery, LocalAgentControlStage.Authenticate);
        }

        if (!_runtime.IsCurrent(target))
        {
            return Superseded(LocalAgentControlStage.Authenticate);
        }

        if (!MatchesSession(recovery.Binding!.SessionPaths, target.SessionPaths))
        {
            return Reject(
                LocalAgentControlStage.Authenticate,
                "The authenticated local agent does not match the explicit session target.",
                recovery);
        }

        return Success(
            LocalAgentControlOutcome.Reconnected,
            "The explicit local-agent target was freshly authenticated.",
            recovery,
            recovery.Binding.ProcessVerification,
            recovery.Binding.ProtectedPairing,
            recovery.Binding.AuthenticatedHealthResponse,
            stage: LocalAgentControlStage.Authenticate);
    }

    private async Task<LocalAgentControlResult> RunSerializedAsync(
        Func<CancellationToken, Task<LocalAgentControlResult>> operation,
        CancellationToken cancellationToken)
    {
        if (_disposed)
        {
            return new LocalAgentControlResult(
                LocalAgentControlOutcome.Unavailable,
                LocalAgentControlStage.None,
                "The local-agent control coordinator is disposed.");
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return new LocalAgentControlResult(
                LocalAgentControlOutcome.Canceled,
                LocalAgentControlStage.None,
                "The local-agent control operation was canceled.");
        }

        bool entered;
        try
        {
            entered = await _operationGate.WaitAsync(0, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new LocalAgentControlResult(
                LocalAgentControlOutcome.Canceled,
                LocalAgentControlStage.None,
                "The local-agent control operation was canceled.");
        }

        if (!entered)
        {
            return new LocalAgentControlResult(
                LocalAgentControlOutcome.Busy,
                LocalAgentControlStage.None,
                "Another local-agent lifecycle or pairing operation is already in progress.");
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetimeCts.Token);
        try
        {
            return await operation(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            return new LocalAgentControlResult(
                LocalAgentControlOutcome.Canceled,
                LocalAgentControlStage.None,
                "The local-agent control operation was canceled.");
        }
        catch
        {
            return new LocalAgentControlResult(
                LocalAgentControlOutcome.InternalFailure,
                LocalAgentControlStage.None,
                "The local-agent control operation failed internally.");
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private LocalAgentControlResult? ValidateTarget(
        LocalAgentControlTarget target,
        bool requireExecutable)
    {
        if (target == null ||
            target.FeatureCatalog == null ||
            target.SessionPaths == null ||
            string.IsNullOrWhiteSpace(target.ViewerReleaseId) ||
            target.WorkspaceGeneration <= 0 ||
            target.SupportedExecutablePaths == null ||
            target.SupportedExecutablePaths.Count == 0)
        {
            return Reject(LocalAgentControlStage.ValidateTarget, "The local-agent control target is incomplete.");
        }

        if (!target.FeatureCatalog.IsPublished(FeatureIds.AgentsAndCapture))
        {
            return Reject(LocalAgentControlStage.ValidateTarget, "The Agents feature is not published.");
        }

        if (target.WorkspaceMode != CaptureWorkspaceMode.LiveCapture ||
            string.IsNullOrWhiteSpace(target.SessionPaths.SessionRoot) ||
            string.IsNullOrWhiteSpace(target.SessionPaths.SessionId) ||
            string.IsNullOrWhiteSpace(target.SessionPaths.LiveDatabasePath))
        {
            return Reject(LocalAgentControlStage.ValidateTarget, "An explicit active live session is required.");
        }

        if (requireExecutable &&
            (string.IsNullOrWhiteSpace(target.PrimaryAgentExecutablePath) ||
             !string.Equals(
                 Path.GetFileName(target.PrimaryAgentExecutablePath),
                 ExecutableIdentity.AgentExecutableFileName,
                 StringComparison.OrdinalIgnoreCase) ||
             !_runtime.IsSupportedAgentExecutablePath(
                 target.PrimaryAgentExecutablePath,
                 target.SupportedExecutablePaths)))
        {
            return Reject(
                LocalAgentControlStage.ValidateTarget,
                "A canonical primary DFIRoscope.Agent.exe path is required for a new launch.");
        }

        return null;
    }

    private static bool MatchesSession(
        InvestigationSessionPaths left,
        InvestigationSessionPaths right) =>
        string.Equals(left.SessionId, right.SessionId, StringComparison.Ordinal) &&
        PathsEqual(left.SessionRoot, right.SessionRoot) &&
        PathsEqual(left.LiveDatabasePath, right.LiveDatabasePath);

    private static bool MatchesVerifiedShutdownTarget(
        LocalAgentVerifiedShutdownTarget verified,
        LocalAgentControlTarget current) =>
        verified.ProcessId > 0 &&
        verified.StartedAtUtc != default &&
        string.Equals(verified.SessionId, current.SessionPaths.SessionId, StringComparison.Ordinal) &&
        PathsEqual(verified.DatabasePath, current.SessionPaths.LiveDatabasePath);

    private static bool PathsEqual(string left, string right)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(left),
                Path.GetFullPath(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static LocalAgentControlResult FromRecovery(
        LocalAgentRecoveryResult recovery,
        LocalAgentControlStage stage,
        LocalAgentProcessResult? process = null,
        AgentPairingStoreResult? pairing = null) =>
        new(
            recovery.Outcome switch
            {
                LocalAgentRecoveryOutcome.Absent => LocalAgentControlOutcome.Absent,
                LocalAgentRecoveryOutcome.Busy => LocalAgentControlOutcome.Busy,
                LocalAgentRecoveryOutcome.Canceled => LocalAgentControlOutcome.Canceled,
                LocalAgentRecoveryOutcome.Superseded => LocalAgentControlOutcome.Superseded,
                LocalAgentRecoveryOutcome.DiscoveryUnavailable or
                LocalAgentRecoveryOutcome.MultipleCandidates or
                LocalAgentRecoveryOutcome.AmbiguousCandidates or
                LocalAgentRecoveryOutcome.UnresolvedInspection => LocalAgentControlOutcome.Unavailable,
                LocalAgentRecoveryOutcome.InternalFailure => LocalAgentControlOutcome.InternalFailure,
                _ => LocalAgentControlOutcome.Rejected
            },
            stage,
            Bound(recovery.Diagnostic),
            recovery,
            process,
            pairing ?? recovery.ProtectedPairing,
            recovery.Binding?.AuthenticatedHealthResponse);

    private static LocalAgentControlOutcome MapProcessOutcome(LocalAgentProcessResult process) =>
        process.Outcome switch
        {
            LocalAgentProcessOutcome.ElevationCanceled or
            LocalAgentProcessOutcome.CredentialsUnavailable or
            LocalAgentProcessOutcome.ExecutableNotFound or
            LocalAgentProcessOutcome.ElevationDenied => LocalAgentControlOutcome.Unavailable,
            LocalAgentProcessOutcome.Disposed => LocalAgentControlOutcome.Unavailable,
            LocalAgentProcessOutcome.StartFailed or
            LocalAgentProcessOutcome.InspectionFailure => LocalAgentControlOutcome.InternalFailure,
            _ => LocalAgentControlOutcome.Rejected
        };

    private static LocalAgentControlResult Success(
        LocalAgentControlOutcome outcome,
        string diagnostic,
        LocalAgentRecoveryResult? recovery = null,
        LocalAgentProcessResult? process = null,
        AgentPairingStoreResult? pairing = null,
        AgentIpcResponse? response = null,
        bool forced = false,
        LocalAgentControlStage stage = LocalAgentControlStage.Completed) =>
        new(
            outcome,
            stage,
            Bound(diagnostic),
            recovery,
            process,
            pairing,
            response,
            forced);

    private static LocalAgentControlResult Reject(
        LocalAgentControlStage stage,
        string diagnostic,
        LocalAgentRecoveryResult? recovery = null,
        LocalAgentProcessResult? process = null,
        AgentPairingStoreResult? pairing = null,
        AgentIpcResponse? response = null) =>
        new(
            LocalAgentControlOutcome.Rejected,
            stage,
            Bound(diagnostic),
            recovery,
            process,
            pairing,
            response);

    private static LocalAgentControlResult Unavailable(
        LocalAgentControlStage stage,
        string diagnostic) =>
        new(LocalAgentControlOutcome.Unavailable, stage, Bound(diagnostic));

    private static LocalAgentControlResult Superseded(LocalAgentControlStage stage) =>
        new(
            LocalAgentControlOutcome.Superseded,
            stage,
            "The active session changed while local-agent control was in progress; the stale completion was not applied.");

    private static TimeSpan Min(TimeSpan left, TimeSpan right) => left <= right ? left : right;

    private static string Bound(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var oneLine = new string(value.Trim().Select(character => char.IsControl(character) ? ' ' : character).ToArray());
        return oneLine.Length <= 2048 ? oneLine : oneLine[..2048];
    }
}
