using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Features;

namespace ProcInsider.Cli;

internal sealed record ViewerCliAgentSessionOpenResult(
    IViewerCliAgentSession? Session,
    CliCommandResult? Failure)
{
    public bool Success => Session != null && Failure == null;
}

internal sealed record ViewerCliAgentControlResult(
    LocalAgentControlResult? Result,
    CliCommandResult? Failure)
{
    public bool Success => Result != null && Failure == null;
}

internal interface IViewerCliAgentSession : IDisposable
{
    AgentHealthSnapshot Health { get; }

    ViewerAgentCaptureActionTarget CaptureTarget { get; }

    Task<ViewerAgentCommandResult> ExecuteAsync(
        AgentCommand command,
        CancellationToken cancellationToken);

    Task<AgentIpcResponse> GetJobStatusAsync(
        Guid jobId,
        CancellationToken cancellationToken);
}

internal interface IViewerCliAgentService : IDisposable
{
    LocalAgentDiscoveryResult Discover();

    Task<ViewerCliAgentSessionOpenResult> OpenSessionAsync(
        string sessionTarget,
        CancellationToken cancellationToken);

    Task<ViewerCliAgentControlResult> ExecuteControlAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken);
}

internal sealed class ViewerCliAgentService : IViewerCliAgentService
{
    private const long OneShotWorkspaceGeneration = 1;

    private readonly IFeatureCatalog _featureCatalog;
    private readonly string _viewerReleaseId;
    private readonly Func<DateTime> _utcNow;
    private readonly LocalAgentProcessLifecycleService _processLifecycle;
    private bool _disposed;

    public ViewerCliAgentService(
        IFeatureCatalog featureCatalog,
        string viewerReleaseId,
        Func<DateTime>? utcNow = null,
        LocalAgentProcessLifecycleService? processLifecycle = null)
    {
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
        _viewerReleaseId = string.IsNullOrWhiteSpace(viewerReleaseId)
            ? throw new ArgumentException("A viewer release ID is required.", nameof(viewerReleaseId))
            : viewerReleaseId;
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
        _processLifecycle = processLifecycle ?? new LocalAgentProcessLifecycleService();
    }

    public LocalAgentDiscoveryResult Discover()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var coordinator = new LocalAgentRecoveryCoordinator(
            new DelegateLocalAgentRecoveryRuntime(
                () => AgentPairingStore.Discover(),
                identity => _processLifecycle.VerifyRunning(identity),
                (_, _, _, _, _) => throw new InvalidOperationException(
                    "Discovery must not inspect protected pairing state."),
                (_, _) => throw new InvalidOperationException(
                    "Discovery must not prepare a capture workspace."),
                (_, _) => throw new InvalidOperationException(
                    "Discovery must not request authenticated health.")),
            _utcNow);
        return coordinator.Discover();
    }

    public async Task<ViewerCliAgentSessionOpenResult> OpenSessionAsync(
        string sessionTarget,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (cancellationToken.IsCancellationRequested)
        {
            return Failed(CliExitCode.Canceled, "Canceled", "The command was canceled.");
        }

        if (!TryResolveManifestPath(sessionTarget, out var manifestPath))
        {
            return InvalidSession();
        }

        ViewerWorkspaceActivation activation;
        try
        {
            activation = await Task.Run(
                    () => new ViewerWorkspaceLifecycleRuntime()
                        .PrepareExistingLiveCapture(manifestPath),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Failed(CliExitCode.Canceled, "Canceled", "The command was canceled.");
        }
        catch (Exception ex)
        {
            return SessionPreparationFailure(ex);
        }

        var paths = activation.SessionPaths;
        AgentPairingStoreResult pairing;
        try
        {
            pairing = new AgentPairingStore(paths).Inspect(
                paths.SessionId,
                SessionPathService.NormalizeLiveDatabaseIdentity(paths.LiveDatabasePath),
                _viewerReleaseId,
                _utcNow());
        }
        catch
        {
            return PairingUnavailable();
        }

        if (pairing.State != AgentPairingState.Ready)
        {
            return PairingFailure(pairing.State);
        }

        if (pairing.Lease == null || pairing.PairingGeneration <= 0)
        {
            return PairingUnavailable();
        }

        var executablePaths = BuildCompatibleAgentExecutableCandidates();
        ViewerAgentCommandExecutionContext context;
        try
        {
            context = ViewerAgentCommandContextFactory.CreateVerifiedDeployedAgent(
                activation,
                pairing.Lease,
                _featureCatalog,
                _viewerReleaseId,
                executablePaths,
                AgentCommandKind.GetCaptureConfiguration,
                OneShotWorkspaceGeneration);
        }
        catch
        {
            return Failed(
                CliExitCode.Rejected,
                "SessionBindingRejected",
                "The explicit session and local-agent pairing do not identify the same compatible unsealed live workspace.");
        }

        var contextLease = new ViewerCliContextLease(
            context.WorkspaceGeneration,
            context.SessionPaths.SessionRoot);
        var client = new AgentNamedPipeClient(viewerReleaseId: _viewerReleaseId);
        var executor = new ViewerAgentCommandExecutor(
            new DelegateViewerAgentCommandRuntime(
                current => contextLease.IsCurrent(current),
                client.BindSession,
                (commandKind, token) => client.GetHealthExchangeAsync(commandKind, token),
                identity => _processLifecycle.VerifyRunning(identity),
                LocalAgentProcessLifecycleService.IsSupportedAgentExecutablePath,
                (command, endpoint, generation, token) =>
                    client.SubmitCommandExchangeAsync(command, endpoint, generation, token)),
            _utcNow);
        var validationCommand = CreateGetCaptureConfigurationCommand("cli-binding-validation");
        ViewerAgentCommandResult validation;
        try
        {
            validation = await executor.ValidateBindingAsync(
                    new ViewerAgentCommandExecutionRequest(validationCommand, context),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            contextLease.Dispose();
            client.UnbindSession();
            return Failed(CliExitCode.Canceled, "Canceled", "The command was canceled.");
        }
        catch
        {
            contextLease.Dispose();
            client.UnbindSession();
            return Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "Authenticated local-agent validation failed internally.");
        }

        if (!validation.Success ||
            !validation.PreflightVerified ||
            !validation.AuthenticatedHealthVerified ||
            validation.CommandSubmissionAttempted ||
            validation.VerifiedHealth == null)
        {
            contextLease.Dispose();
            client.UnbindSession();
            return new ViewerCliAgentSessionOpenResult(
                null,
                CliAgentFailureMapper.FromViewerResult(validation));
        }

        return new ViewerCliAgentSessionOpenResult(
            new ViewerCliAgentSession(
                validation.VerifiedHealth,
                new ViewerAgentCaptureActionTarget(
                    "local",
                    validation.VerifiedHealth.MachineName,
                    context.SessionPaths.SessionId,
                    context.SessionPaths.SessionRoot,
                    context.WorkspaceGeneration,
                    DumpsDirectory: context.SessionPaths.DumpsDirectory,
                    NetworkCapturesDirectory: context.SessionPaths.NetworkCapturesDirectory,
                    ZeekDirectory: context.SessionPaths.ZeekDirectory,
                    ProcessMonitorDirectory: context.SessionPaths.ProcessMonitorDirectory,
                    BenchmarkDirectory: context.SessionPaths.BenchmarkDirectory,
                    MemoryDirectory: context.SessionPaths.MemoryDirectory),
                context,
                executor,
                client,
                contextLease),
            null);
    }

    public async Task<ViewerCliAgentControlResult> ExecuteControlAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(invocation);
        if (invocation.Kind is not
            (CliCommandKind.AgentReconnect or
             CliCommandKind.AgentStart or
             CliCommandKind.AgentStop or
             CliCommandKind.AgentPairingStatus or
             CliCommandKind.AgentPairingRotate or
             CliCommandKind.AgentPairingRevoke))
        {
            return ControlFailure(
                CliExitCode.Failure,
                "HandlerMismatch",
                "The selected command is not a local-agent control action.");
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return ControlFailure(CliExitCode.Canceled, "Canceled", "The command was canceled.");
        }

        if (!TryResolveManifestPath(invocation.SessionTarget, out var manifestPath))
        {
            return ControlFailure(
                CliExitCode.Unavailable,
                "SessionUnavailable",
                "--session must identify an existing absolute session root or canonical session.json for a compatible unsealed live capture.");
        }

        ViewerWorkspaceActivation activation;
        try
        {
            activation = await Task.Run(
                    () => new ViewerWorkspaceLifecycleRuntime()
                        .PrepareExistingLiveCapture(manifestPath),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return ControlFailure(CliExitCode.Canceled, "Canceled", "The command was canceled.");
        }
        catch (Exception ex)
        {
            var failed = SessionPreparationFailure(ex).Failure!;
            return new ViewerCliAgentControlResult(null, failed);
        }

        var executablePaths = BuildCompatibleAgentExecutableCandidates();
        var primaryExecutablePath = executablePaths.FirstOrDefault(path =>
            string.Equals(
                Path.GetFileName(path),
                ExecutableIdentity.AgentExecutableFileName,
                StringComparison.OrdinalIgnoreCase) &&
            File.Exists(path)) ?? string.Empty;
        var target = new LocalAgentControlTarget(
            activation.SessionPaths,
            activation.Mode,
            OneShotWorkspaceGeneration,
            _featureCatalog,
            _viewerReleaseId,
            executablePaths,
            primaryExecutablePath);

        var normalClient = new AgentNamedPipeClient(viewerReleaseId: _viewerReleaseId);
        var recoveryClient = new AgentNamedPipeClient(viewerReleaseId: _viewerReleaseId);
        var controlClient = new AgentNamedPipeClient(
            AgentContracts.ShutdownControlPipeName,
            viewerReleaseId: _viewerReleaseId);
        var contextLease = new ViewerCliContextLease(
            OneShotWorkspaceGeneration,
            activation.SessionPaths.SessionRoot);
        var recoveryExecutor = new ViewerAgentCommandExecutor(
            new DelegateViewerAgentCommandRuntime(
                contextLease.IsCurrent,
                recoveryClient.BindSession,
                (commandKind, token) => recoveryClient.GetHealthExchangeAsync(commandKind, token),
                identity => _processLifecycle.VerifyRunning(identity),
                LocalAgentProcessLifecycleService.IsSupportedAgentExecutablePath,
                (command, endpoint, generation, token) =>
                    recoveryClient.SubmitCommandExchangeAsync(command, endpoint, generation, token)),
            _utcNow);
        using var recoveryCoordinator = new LocalAgentRecoveryCoordinator(
            new DelegateLocalAgentRecoveryRuntime(
                () => AgentPairingStore.Discover(),
                identity => _processLifecycle.VerifyRunning(identity),
                (discovery, sessionId, databaseIdentity, releaseId, nowUtc) =>
                    new AgentPairingStore(
                            discovery.DirectoryPath,
                            discovery.LeasePath,
                            discovery.SecretPath)
                        .Inspect(sessionId, databaseIdentity, releaseId, nowUtc),
                (captureManifestPath, token) => Task.Run(
                    () => new ViewerWorkspaceLifecycleRuntime()
                        .PrepareExistingLiveCapture(captureManifestPath),
                    token),
                (request, token) => recoveryExecutor.ValidateBindingAsync(request, token)),
            _utcNow);
        using var coordinator = new LocalAgentControlCoordinator(
            new DelegateLocalAgentControlRuntime(
                current =>
                    current.WorkspaceGeneration == OneShotWorkspaceGeneration &&
                    PathsEqual(
                        current.SessionPaths.SessionRoot,
                        activation.SessionPaths.SessionRoot),
                recoveryCoordinator.Discover,
                recoveryCoordinator.RecoverAsync,
                paths =>
                {
                    normalClient.BindSession(paths);
                    controlClient.BindSession(paths);
                },
                nowUtc => normalClient.InspectPairing(nowUtc),
                nowUtc => normalClient.PrepareNewPairing(nowUtc),
                LocalAgentProcessLifecycleService.IsSupportedAgentExecutablePath,
                request => _processLifecycle.Start(request),
                identity => _processLifecycle.VerifyRunning(identity),
                (command, token) => normalClient.SubmitCommandAsync(command, token),
                (command, token) => controlClient.SubmitCommandAsync(command, token),
                (identity, timeout, cancellationToken) =>
                    _processLifecycle.WaitForExitAsync(identity, timeout, cancellationToken),
                (identity, timeout) => _processLifecycle.ForceStopAsync(identity, timeout),
                token => normalClient.RotatePairingAsync(token),
                token => normalClient.RevokePairingAsync(token)),
            _utcNow);

        LocalAgentControlResult result = invocation.Kind switch
        {
            CliCommandKind.AgentReconnect => await coordinator.ReconnectAsync(
                new LocalAgentReconnectRequest(target.CreateRecoveryRequest(), activation.SessionPaths),
                cancellationToken).ConfigureAwait(false),
            CliCommandKind.AgentStart => await coordinator.StartAsync(
                new LocalAgentStartRequest(
                    target,
                    invocation.LiveBufferMemoryMegabytes ?? 500),
                cancellationToken).ConfigureAwait(false),
            CliCommandKind.AgentStop => await coordinator.StopAsync(
                new LocalAgentStopRequest(
                    target,
                    invocation.Confirmed,
                    TimeSpan.FromSeconds(invocation.TimeoutSeconds ?? 30),
                    "DFIRoscope CLI explicit agent stop."),
                cancellationToken).ConfigureAwait(false),
            CliCommandKind.AgentPairingStatus => await coordinator.GetPairingStatusAsync(
                new LocalAgentPairingRequest(target),
                cancellationToken).ConfigureAwait(false),
            CliCommandKind.AgentPairingRotate => await coordinator.RotatePairingAsync(
                new LocalAgentPairingRequest(target, invocation.Confirmed),
                cancellationToken).ConfigureAwait(false),
            CliCommandKind.AgentPairingRevoke => await coordinator.RevokePairingAsync(
                new LocalAgentPairingRequest(target, invocation.Confirmed),
                cancellationToken).ConfigureAwait(false),
            _ => throw new InvalidOperationException("Unsupported local-agent control action.")
        };
        contextLease.Dispose();
        recoveryClient.UnbindSession();
        normalClient.UnbindSession();
        controlClient.UnbindSession();
        return new ViewerCliAgentControlResult(result, null);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _processLifecycle.Dispose();
    }

    internal static GetCaptureConfigurationCommand CreateGetCaptureConfigurationCommand(
        string configurationVersion) =>
        new()
        {
            AgentId = "local",
            HostId = "local",
            ConfigurationVersion = configurationVersion
        };

    private static bool TryResolveManifestPath(string? sessionTarget, out string manifestPath)
    {
        manifestPath = string.Empty;
        if (string.IsNullOrWhiteSpace(sessionTarget) ||
            !Path.IsPathFullyQualified(sessionTarget))
        {
            return false;
        }

        try
        {
            var fullPath = Path.GetFullPath(sessionTarget);
            if (Directory.Exists(fullPath))
            {
                fullPath = Path.Combine(fullPath, SessionPathService.CapturePackageManifestFileName);
            }

            if (!File.Exists(fullPath) ||
                !string.Equals(
                    Path.GetFileName(fullPath),
                    SessionPathService.CapturePackageManifestFileName,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            manifestPath = fullPath;
            return true;
        }
        catch (Exception ex) when (ex is
            ArgumentException or
            NotSupportedException or
            PathTooLongException or
            IOException or
            UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static IReadOnlyList<string> BuildCompatibleAgentExecutableCandidates()
    {
        var configurationName = ResolveBuildConfigurationName();
        return ExecutableIdentity.BuildCompatibleAgentExecutableCandidates(
            AppContext.BaseDirectory,
            Environment.CurrentDirectory,
            configurationName);
    }

    private static string ResolveBuildConfigurationName()
    {
        try
        {
            var frameworkDirectory = Directory.GetParent(
                AppContext.BaseDirectory.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar));
            var candidate = frameworkDirectory?.Parent?.Name;
            if (string.Equals(candidate, "Debug", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(candidate, "Release", StringComparison.OrdinalIgnoreCase))
            {
                return candidate!;
            }
        }
        catch
        {
        }

#if DEBUG
        return "Debug";
#else
        return "Release";
#endif
    }

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

    private static ViewerCliAgentSessionOpenResult InvalidSession() =>
        Failed(
            CliExitCode.Unavailable,
            "SessionUnavailable",
            "--session must identify an existing absolute session root or canonical session.json for a compatible unsealed live capture.");

    private static ViewerCliAgentSessionOpenResult RejectedSession() =>
        Failed(
            CliExitCode.Rejected,
            "SessionRejected",
            "The explicit session failed compatible unsealed live-workspace validation.");

    internal static ViewerCliAgentSessionOpenResult SessionPreparationFailure(Exception exception) =>
        exception switch
        {
            InvalidDataException or ArgumentException or NotSupportedException => RejectedSession(),
            IOException or UnauthorizedAccessException => InvalidSession(),
            _ => Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The explicit session could not be validated because of an internal failure.")
        };

    internal static ViewerCliAgentSessionOpenResult PairingFailure(AgentPairingState state) =>
        state is
            AgentPairingState.Corrupt or
            AgentPairingState.WrongUser or
            AgentPairingState.WrongSession or
            AgentPairingState.WrongRelease or
            AgentPairingState.Revoked or
            AgentPairingState.ProcessMismatch
            ? Failed(
                CliExitCode.Rejected,
                "AuthenticationRejected",
                "The explicit session's local-agent authentication state was rejected.")
            : PairingUnavailable();

    private static ViewerCliAgentSessionOpenResult PairingUnavailable() =>
        Failed(
            CliExitCode.Unavailable,
            "PairingUnavailable",
            "The explicit session has no usable current-user local-agent pairing.");

    private static ViewerCliAgentSessionOpenResult Failed(
        CliExitCode exitCode,
        string code,
        string message) =>
        new(null, CliCommandResult.Failed(exitCode, code, message));

    private static ViewerCliAgentControlResult ControlFailure(
        CliExitCode exitCode,
        string code,
        string message) =>
        new(null, CliCommandResult.Failed(exitCode, code, message));

    private sealed class ViewerCliContextLease : IDisposable
    {
        private readonly long _generation;
        private readonly string _sessionRoot;
        private int _active = 1;

        public ViewerCliContextLease(long generation, string sessionRoot)
        {
            _generation = generation;
            _sessionRoot = Path.GetFullPath(sessionRoot);
        }

        public bool IsCurrent(ViewerAgentCommandExecutionContext context) =>
            Volatile.Read(ref _active) == 1 &&
            context.WorkspaceGeneration == _generation &&
            string.Equals(
                Path.GetFullPath(context.SessionPaths.SessionRoot),
                _sessionRoot,
                StringComparison.OrdinalIgnoreCase);

        public void Dispose() => Interlocked.Exchange(ref _active, 0);
    }

    private sealed class ViewerCliAgentSession : IViewerCliAgentSession
    {
        private readonly ViewerAgentCommandExecutionContext _context;
        private readonly ViewerAgentCommandExecutor _executor;
        private readonly AgentNamedPipeClient _client;
        private readonly ViewerCliContextLease _contextLease;
        private bool _disposed;

        public ViewerCliAgentSession(
            AgentHealthSnapshot health,
            ViewerAgentCaptureActionTarget captureTarget,
            ViewerAgentCommandExecutionContext context,
            ViewerAgentCommandExecutor executor,
            AgentNamedPipeClient client,
            ViewerCliContextLease contextLease)
        {
            Health = health;
            CaptureTarget = captureTarget;
            _context = context;
            _executor = executor;
            _client = client;
            _contextLease = contextLease;
        }

        public AgentHealthSnapshot Health { get; }

        public ViewerAgentCaptureActionTarget CaptureTarget { get; }

        public Task<ViewerAgentCommandResult> ExecuteAsync(
            AgentCommand command,
            CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentNullException.ThrowIfNull(command);
            var commandContext = _context with
            {
                WriteCategory = CaptureWritePolicy.GetCategory(command.Kind)
            };
            return _executor.ExecuteAsync(
                new ViewerAgentCommandExecutionRequest(command, commandContext),
                cancellationToken);
        }

        public Task<AgentIpcResponse> GetJobStatusAsync(
            Guid jobId,
            CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_contextLease.IsCurrent(_context))
            {
                return Task.FromResult(AgentIpcResponse.Failure(
                    Guid.NewGuid(),
                    "SessionSuperseded",
                    "The explicit session binding is no longer current."));
            }

            return _client.GetJobStatusAsync(jobId, cancellationToken);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _contextLease.Dispose();
            _client.UnbindSession();
        }
    }
}

internal static class CliAgentFailureMapper
{
    public static CliCommandResult FromViewerResult(ViewerAgentCommandResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.Success)
        {
            return CliCommandResult.Succeeded(result.Diagnostic);
        }

        var exitCode = result.Outcome switch
        {
            ViewerAgentCommandOutcome.Canceled => CliExitCode.Canceled,
            ViewerAgentCommandOutcome.HealthUnavailable => ContainsTimeout(result.ErrorCode)
                ? CliExitCode.Timeout
                : CliExitCode.Unavailable,
            ViewerAgentCommandOutcome.PairingRejected => CliExitCode.Rejected,
            ViewerAgentCommandOutcome.AgentRejected => CliExitCode.AgentRejected,
            ViewerAgentCommandOutcome.FeatureRejected or
            ViewerAgentCommandOutcome.OperationallyUnavailable or
            ViewerAgentCommandOutcome.AccessRejected or
            ViewerAgentCommandOutcome.WorkspaceRejected or
            ViewerAgentCommandOutcome.ContractRejected or
            ViewerAgentCommandOutcome.ReleaseRejected or
            ViewerAgentCommandOutcome.SessionRejected or
            ViewerAgentCommandOutcome.ProcessRejected or
            ViewerAgentCommandOutcome.InvalidContext or
            ViewerAgentCommandOutcome.Superseded => CliExitCode.Rejected,
            _ => ContainsTimeout(result.ErrorCode)
                ? CliExitCode.Timeout
                : CliExitCode.Failure
        };
        var (errorCode, message) = PublicFailure(result.Outcome, exitCode);
        return CliCommandResult.Failed(
            exitCode,
            errorCode,
            message,
            result.IsRetryable);
    }

    private static (string ErrorCode, string Message) PublicFailure(
        ViewerAgentCommandOutcome outcome,
        CliExitCode exitCode) => outcome switch
    {
        ViewerAgentCommandOutcome.Canceled =>
            ("Canceled", "The command was canceled."),
        ViewerAgentCommandOutcome.HealthUnavailable when exitCode == CliExitCode.Timeout =>
            ("AgentTimeout", "The authenticated local-agent operation timed out."),
        ViewerAgentCommandOutcome.HealthUnavailable =>
            ("AgentUnavailable", "Authenticated local-agent health is unavailable."),
        ViewerAgentCommandOutcome.PairingRejected =>
            ("AuthenticationRejected", "The local-agent authentication boundary rejected the request."),
        ViewerAgentCommandOutcome.AgentRejected =>
            ("AgentRejected", "The authenticated agent rejected the typed command."),
        ViewerAgentCommandOutcome.FeatureRejected =>
            ("FeatureRejected", "The command's required feature publication was rejected."),
        ViewerAgentCommandOutcome.OperationallyUnavailable =>
            ("CommandUnavailable", "The command is not operationally available."),
        ViewerAgentCommandOutcome.AccessRejected =>
            ("AccessRejected", "The trusted viewer access state rejected the command."),
        ViewerAgentCommandOutcome.WorkspaceRejected =>
            ("WorkspaceRejected", "The target workspace rejected the command."),
        ViewerAgentCommandOutcome.ContractRejected =>
            ("ContractRejected", "The viewer-agent contract validation rejected the command."),
        ViewerAgentCommandOutcome.ReleaseRejected =>
            ("ReleaseRejected", "The viewer-agent release validation rejected the command."),
        ViewerAgentCommandOutcome.SessionRejected =>
            ("SessionRejected", "The exact session binding rejected the command."),
        ViewerAgentCommandOutcome.ProcessRejected =>
            ("ProcessRejected", "The exact local-agent process identity was rejected."),
        ViewerAgentCommandOutcome.InvalidContext =>
            ("InvalidContext", "The trusted command context was invalid."),
        ViewerAgentCommandOutcome.Superseded =>
            ("Superseded", "The command context was superseded before completion."),
        _ =>
            ("InternalFailure", "The local-agent operation failed internally.")
    };

    private static bool ContainsTimeout(string? code) =>
        !string.IsNullOrWhiteSpace(code) &&
        code.Contains("timeout", StringComparison.OrdinalIgnoreCase);
}
