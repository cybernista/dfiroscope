using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.Features;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;

namespace ProcInsider.Agent;

internal enum AgentInfrastructureRuntimeState
{
    Stopped = 0,
    Connecting = 1,
    AuthenticatingAndNegotiating = 2,
    Active = 3,
    BackingOff = 4,
    Draining = 5,
    ConfigurationIncompatible = 6,
    SecurityIncompatible = 7,
    ProtocolIncompatible = 8,
    RouteIncompatible = 9,
    TerminalFailed = 10
}

internal sealed record AgentInfrastructureRuntimeSnapshot(
    AgentInfrastructureRuntimeState State,
    int ConnectionAttempts,
    Guid ConnectionGeneration,
    Guid SessionId,
    long ServerSessionGeneration,
    string CaseId,
    string CaptureId,
    string ErrorCode,
    long HealthRevision,
    AgentInfrastructureEvidenceConnectivitySnapshot Evidence);

internal sealed class AgentInfrastructureRouteLease
{
    private readonly object _gate = new();
    private AgentAuthorizationScope? _scope;

    public AgentAuthorizationScope? Scope
    {
        get
        {
            lock (_gate)
            {
                return _scope is null ? null : _scope with { };
            }
        }
    }

    public bool TryBind(AgentAuthorizationScope scope, string localSessionId, out string errorCode)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (string.IsNullOrWhiteSpace(scope.CaseId) || string.IsNullOrWhiteSpace(scope.CaptureId) ||
            string.IsNullOrWhiteSpace(scope.DatabaseIdentity) ||
            !string.Equals(scope.SessionId, localSessionId, StringComparison.Ordinal) ||
            scope.WorkspaceMode != CaptureWorkspaceMode.LiveCapture || scope.CaptureSealed)
        {
            errorCode = "InfrastructureAssignedRouteInvalid";
            return false;
        }

        lock (_gate)
        {
            if (_scope != null && !Equals(_scope, scope))
            {
                errorCode = "InfrastructureAssignedRouteChanged";
                return false;
            }
            _scope = scope with { };
        }
        errorCode = string.Empty;
        return true;
    }

    public bool IsExactTarget(InfrastructureCommandTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        lock (_gate)
        {
            return _scope != null && Equals(_scope, target.Scope);
        }
    }
}

/// <summary>
/// Supervises the publication-gated outbound Agent runtime. Construction is passive;
/// callers must first enable the transactional outbox and then explicitly call Start.
/// </summary>
internal sealed class AgentInfrastructureRuntime : IAsyncDisposable
{
    private static readonly TimeSpan DefaultIdleUploadDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan DefaultBusyUploadDelay = TimeSpan.FromMilliseconds(100);
    private readonly object _gate = new();
    private readonly Contracts.InfrastructureAgentConfiguration _configuration;
    private readonly string _localSessionId;
    private readonly AgentInfrastructureSessionClient _sessions;
    private readonly AgentInfrastructureCommandDispatcher _commands;
    private readonly AgentInfrastructureEvidenceSpool _spool;
    private readonly AgentCommittedEvidenceBatchPublisher _publisher;
    private readonly AgentInfrastructureEvidenceConnectivity _connectivity;
    private readonly AgentInfrastructureRouteLease _route;
    private readonly Func<AgentControlSnapshot> _getControlSnapshot;
    private readonly Func<CancellationToken, Task> _drainAcceptedWork;
    private readonly Func<double> _nextJitterFraction;
    private readonly TimeSpan _idleUploadDelay;
    private readonly TimeSpan _busyUploadDelay;
    private readonly CancellationTokenSource _stop = new();
    private Task? _worker;
    private Task? _stopTask;
    private AgentInfrastructureRuntimeState _state;
    private int _connectionAttempts;
    private Guid _connectionGeneration;
    private Guid _sessionId;
    private long _serverSessionGeneration;
    private string _errorCode = string.Empty;
    private long _healthRevision;
    private string _eligibleAgentId = string.Empty;
    private Guid _eligibleConnectionGeneration;
    private bool _remoteCommandsEligible;
    private bool _disposed;

    public AgentInfrastructureRuntime(
        Contracts.InfrastructureAgentConfiguration configuration,
        string localSessionId,
        AgentInfrastructureSessionClient sessions,
        AgentInfrastructureCommandDispatcher commands,
        AgentInfrastructureEvidenceSpool spool,
        AgentCommittedEvidenceBatchPublisher publisher,
        AgentInfrastructureEvidenceConnectivity connectivity,
        AgentInfrastructureRouteLease route,
        Func<AgentControlSnapshot> getControlSnapshot,
        Func<CancellationToken, Task>? drainAcceptedWork = null,
        Func<double>? nextJitterFraction = null,
        TimeSpan? idleUploadDelay = null,
        TimeSpan? busyUploadDelay = null)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _localSessionId = string.IsNullOrWhiteSpace(localSessionId)
            ? throw new ArgumentException("The exact local evidence session is required.", nameof(localSessionId))
            : localSessionId;
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _commands = commands ?? throw new ArgumentNullException(nameof(commands));
        _spool = spool ?? throw new ArgumentNullException(nameof(spool));
        _publisher = publisher ?? throw new ArgumentNullException(nameof(publisher));
        _connectivity = connectivity ?? throw new ArgumentNullException(nameof(connectivity));
        _route = route ?? throw new ArgumentNullException(nameof(route));
        _getControlSnapshot = getControlSnapshot ?? throw new ArgumentNullException(nameof(getControlSnapshot));
        _drainAcceptedWork = drainAcceptedWork ?? (_ => Task.CompletedTask);
        _nextJitterFraction = nextJitterFraction ?? Random.Shared.NextDouble;
        _idleUploadDelay = ValidateDelay(idleUploadDelay ?? DefaultIdleUploadDelay, nameof(idleUploadDelay));
        _busyUploadDelay = ValidateDelay(busyUploadDelay ?? DefaultBusyUploadDelay, nameof(busyUploadDelay));
    }

    public event Action<AgentInfrastructureRuntimeSnapshot>? StateChanged;

    public AgentInfrastructureRuntimeSnapshot Snapshot
    {
        get
        {
            lock (_gate)
            {
                return SnapshotUnderLock();
            }
        }
    }

    public bool IsAuthenticationCurrent(string agentId, Guid connectionGeneration)
    {
        lock (_gate)
        {
            return _remoteCommandsEligible && _state == AgentInfrastructureRuntimeState.Active &&
                   string.Equals(_eligibleAgentId, agentId, StringComparison.Ordinal) &&
                   _eligibleConnectionGeneration == connectionGeneration;
        }
    }

    public void Start()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_worker != null)
            {
                throw new InvalidOperationException("The Infrastructure Agent runtime is already active.");
            }
            if (_stop.IsCancellationRequested)
            {
                throw new InvalidOperationException("A stopped Infrastructure Agent runtime cannot be restarted.");
            }
            if (!_publisher.IsStarted)
            {
                throw new InvalidOperationException(
                    "The transactional evidence outbox must be enabled before the Infrastructure runtime starts.");
            }
            _worker = Task.Run(() => SuperviseAsync(_stop.Token));
        }
    }

    public Task Completion
    {
        get
        {
            lock (_gate)
            {
                return _worker ?? Task.CompletedTask;
            }
        }
    }

    public Task StopAsync()
    {
        lock (_gate)
        {
            if (_stopTask != null)
            {
                return _stopTask;
            }
            RevokeRemoteCommandsUnderLock();
            _stop.Cancel();
            _stopTask = ObserveStopAsync(_worker);
            return _stopTask;
        }
    }

    private async Task SuperviseAsync(CancellationToken cancellationToken)
    {
        try
        {
            await AgentInfrastructureEvidenceUploader.ConvergeAcknowledgedCleanupAsync(
                    _spool,
                    _publisher.Outbox,
                    _connectivity,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await DrainAcceptedWorkWithoutSessionAsync().ConfigureAwait(false);
            SetState(AgentInfrastructureRuntimeState.Stopped, string.Empty);
            return;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException)
        {
            SetTerminal(AgentInfrastructureRuntimeState.TerminalFailed,
                "InfrastructureAcknowledgementRecoveryFailed");
            return;
        }

        var acceptedWorkDrainAttempted = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            SetState(AgentInfrastructureRuntimeState.Connecting, string.Empty);
            Interlocked.Increment(ref _connectionAttempts);
            var opened = await _sessions.OpenAsync(
                    _configuration,
                    cancellationToken,
                    phase => SetState(
                        phase == AgentInfrastructureSessionOpenPhase.Connecting
                            ? AgentInfrastructureRuntimeState.Connecting
                            : AgentInfrastructureRuntimeState.AuthenticatingAndNegotiating,
                        string.Empty))
                .ConfigureAwait(false);
            if (!opened.Succeeded || opened.Connection == null)
            {
                if (cancellationToken.IsCancellationRequested ||
                    opened.FailureClass == AgentInfrastructureSessionOpenFailureClass.Canceled)
                {
                    break;
                }
                if (!opened.Retryable)
                {
                    SetTerminal(MapTerminalState(opened.FailureClass), opened.ErrorCode);
                    return;
                }
                await BackoffAsync(opened.ErrorCode, cancellationToken).ConfigureAwait(false);
                continue;
            }

            await using var connection = opened.Connection;
            if (!_route.TryBind(connection.Authenticated.Scope, _localSessionId, out var routeError))
            {
                _connectivity.RecordDisconnected(DateTime.UtcNow, _nextJitterFraction(), routeError);
                SetTerminal(AgentInfrastructureRuntimeState.RouteIncompatible, routeError);
                return;
            }
            if (!TryActivateSession(connection, out var generationError))
            {
                _connectivity.RecordDisconnected(DateTime.UtcNow, _nextJitterFraction(), generationError);
                SetTerminal(AgentInfrastructureRuntimeState.SecurityIncompatible, generationError);
                return;
            }

            _connectivity.RecordConnected();
            SetState(AgentInfrastructureRuntimeState.Active, string.Empty, preserveEligibility: true);

            using var sessionStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var control = RunControlLoopAsync(connection, sessionStop.Token);
            var heartbeat = RunHeartbeatLoopAsync(connection, sessionStop.Token);
            var uploads = RunUploadLoopAsync(connection, sessionStop.Token);
            var completed = await Task.WhenAny(control, heartbeat, uploads).ConfigureAwait(false);
            RevokeRemoteCommands();
            sessionStop.Cancel();
            var failure = InspectSessionFailure(completed);
            await ObserveSessionTasksAsync(control, heartbeat, uploads).ConfigureAwait(false);

            if (cancellationToken.IsCancellationRequested)
            {
                await DrainAsync(connection).ConfigureAwait(false);
                acceptedWorkDrainAttempted = true;
                break;
            }
            if (!failure.Retryable)
            {
                SetTerminal(AgentInfrastructureRuntimeState.ProtocolIncompatible, failure.ErrorCode);
                return;
            }
            await BackoffAsync(failure.ErrorCode, cancellationToken).ConfigureAwait(false);
        }
        if (cancellationToken.IsCancellationRequested && !acceptedWorkDrainAttempted)
        {
            await DrainAcceptedWorkWithoutSessionAsync().ConfigureAwait(false);
        }
        SetState(AgentInfrastructureRuntimeState.Stopped, string.Empty);
    }

    private async Task RunControlLoopAsync(
        AgentInfrastructureSessionConnection connection,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested &&
               connection.State == InfrastructureSessionLifecycleState.Active)
        {
            var decision = await connection.ReadAndDispatchControlAsync(_commands, cancellationToken)
                .ConfigureAwait(false);
            if (!decision.Allowed)
            {
                throw SessionFailure(decision.Failure, decision.ErrorCode);
            }
        }
    }

    private async Task RunHeartbeatLoopAsync(
        AgentInfrastructureSessionConnection connection,
        CancellationToken cancellationToken)
    {
        var interval = connection.Negotiation.Limits!.KeepAliveInterval;
        while (!cancellationToken.IsCancellationRequested &&
               connection.State == InfrastructureSessionLifecycleState.Active)
        {
            var observedAtUtc = DateTime.UtcNow;
            var control = _getControlSnapshot();
            if (!control.IsAuthoritative || control.Generation <= 0 ||
                control.ActiveWork.Count > 1_000_000)
            {
                throw new AgentInfrastructureSessionRuntimeException(
                    "AgentControlSnapshotInvalid", retryable: false);
            }
            var spool = _spool.GetHealth(observedAtUtc);
            var outbox = _publisher.Outbox;
            var health = await connection.SendHealthAsync(new InfrastructureSessionHealthPayload
            {
                HealthRevision = Interlocked.Increment(ref _healthRevision),
                ObservedAtUtc = observedAtUtc,
                AvailabilityCode = ResolveAvailabilityCode(spool.State),
                ControlGeneration = control.Generation,
                CaptureState = control.CaptureState,
                ActiveWorkCount = control.ActiveWork.Count,
                PendingOutboxEntries = CountOutbox(outbox, InfrastructureEvidenceOutboxState.Pending),
                SpooledOutboxEntries = CountOutbox(outbox, InfrastructureEvidenceOutboxState.Spooled),
                CleanupPendingOutboxEntries = CountOutbox(
                    outbox,
                    InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending),
                PendingSpoolPackages = spool.PendingPackages,
                PendingSpoolBytes = spool.PendingBytes
            }, cancellationToken).ConfigureAwait(false);
            if (!health.Allowed)
            {
                throw SessionFailure(health.Failure, health.ErrorCode);
            }
            var keepAlive = await connection.SendKeepAliveAsync(cancellationToken).ConfigureAwait(false);
            if (!keepAlive.Allowed)
            {
                throw SessionFailure(keepAlive.Failure, keepAlive.ErrorCode);
            }
            await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task RunUploadLoopAsync(
        AgentInfrastructureSessionConnection connection,
        CancellationToken cancellationToken)
    {
        var uploader = CreateUploader(connection);
        while (!cancellationToken.IsCancellationRequested &&
               connection.State == InfrastructureSessionLifecycleState.Active)
        {
            var result = await uploader.UploadNextAsync(cancellationToken).ConfigureAwait(false);
            if (!result.Completed && result.Failure is InfrastructureEvidenceFailure.SessionStale or
                    InfrastructureEvidenceFailure.Canceled)
            {
                throw new AgentInfrastructureSessionRuntimeException(result.ErrorCode, retryable: true);
            }
            if (!result.Completed && result.ErrorCode == "EvidenceUploadTransportFailed")
            {
                throw new AgentInfrastructureSessionRuntimeException(result.ErrorCode, retryable: true);
            }
            await Task.Delay(
                    result.ErrorCode == "EvidenceSpoolEmpty" ? _idleUploadDelay : _busyUploadDelay,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private AgentInfrastructureEvidenceUploader CreateUploader(
        AgentInfrastructureSessionConnection connection) =>
        new(
            _spool,
            _publisher.Outbox,
            new AgentInfrastructureEvidenceStreamTransport(connection),
            _connectivity);

    private bool TryActivateSession(
        AgentInfrastructureSessionConnection connection,
        out string errorCode)
    {
        var authenticated = connection.Authenticated;
        var binding = connection.Negotiation.Binding!;
        lock (_gate)
        {
            if (_connectionGeneration != Guid.Empty &&
                (_connectionGeneration == authenticated.ConnectionGeneration ||
                 _sessionId == binding.SessionId ||
                 binding.ServerSessionGeneration <= _serverSessionGeneration))
            {
                errorCode = "InfrastructureSessionGenerationNotNewer";
                return false;
            }
            _connectionGeneration = authenticated.ConnectionGeneration;
            _sessionId = binding.SessionId;
            _serverSessionGeneration = binding.ServerSessionGeneration;
            _eligibleAgentId = authenticated.AgentId;
            _eligibleConnectionGeneration = authenticated.ConnectionGeneration;
            _remoteCommandsEligible = true;
        }
        errorCode = string.Empty;
        return true;
    }

    private async Task BackoffAsync(string errorCode, CancellationToken cancellationToken)
    {
        RevokeRemoteCommands();
        var delay = _connectivity.RecordDisconnected(
            DateTime.UtcNow,
            _nextJitterFraction(),
            BoundCode(errorCode, "InfrastructureSessionClosed"));
        SetState(AgentInfrastructureRuntimeState.BackingOff, errorCode);
        try
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private async Task DrainAsync(AgentInfrastructureSessionConnection connection)
    {
        RevokeRemoteCommands();
        SetState(AgentInfrastructureRuntimeState.Draining, string.Empty);
        using var drain = new CancellationTokenSource(connection.Negotiation.Limits!.DrainTimeout);
        await DrainAcceptedWorkAsync(drain).ConfigureAwait(false);

        var uploader = CreateUploader(connection);
        while (!drain.IsCancellationRequested &&
               connection.State == InfrastructureSessionLifecycleState.Active)
        {
            AgentInfrastructureEvidenceUploadResult result;
            try
            {
                result = await uploader.UploadNextAsync(drain.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (drain.IsCancellationRequested)
            {
                break;
            }
            if (!result.Completed || result.ErrorCode == "EvidenceSpoolEmpty")
            {
                break;
            }
        }
        if (!drain.IsCancellationRequested &&
            connection.State == InfrastructureSessionLifecycleState.Active)
        {
            await connection.BeginDrainAsync(InfrastructureSessionDrainReason.AgentShutdown, drain.Token)
                .ConfigureAwait(false);
        }
    }

    private async Task DrainAcceptedWorkWithoutSessionAsync()
    {
        RevokeRemoteCommands();
        SetState(AgentInfrastructureRuntimeState.Draining, string.Empty);
        using var drain = new CancellationTokenSource(new InfrastructureSessionLimits().DrainTimeout);
        await DrainAcceptedWorkAsync(drain).ConfigureAwait(false);
    }

    private async Task DrainAcceptedWorkAsync(CancellationTokenSource drain)
    {
        try
        {
            await _drainAcceptedWork(drain.Token).WaitAsync(drain.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (drain.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            SetState(AgentInfrastructureRuntimeState.Draining, "AgentAcceptedWorkDrainFailed");
        }
    }

    private static AgentInfrastructureSessionRuntimeException SessionFailure(
        InfrastructureSessionFailure failure,
        string errorCode) =>
        new(BoundCode(errorCode, "InfrastructureSessionClosed"), IsTransient(failure));

    private static bool IsTransient(InfrastructureSessionFailure failure) => failure is
        InfrastructureSessionFailure.SessionLimitReached or
        InfrastructureSessionFailure.SessionDuplicate or
        InfrastructureSessionFailure.SessionStale or
        InfrastructureSessionFailure.SessionClosed or
        InfrastructureSessionFailure.RequestLimitReached or
        InfrastructureSessionFailure.QueueSaturated or
        InfrastructureSessionFailure.MemoryBudgetExceeded or
        InfrastructureSessionFailure.KeepAliveTimedOut or
        InfrastructureSessionFailure.Canceled or
        InfrastructureSessionFailure.RateLimitReached or
        InfrastructureSessionFailure.EvidenceQuotaBlocked;

    private static AgentInfrastructureSessionFailure InspectSessionFailure(Task completed)
    {
        if (completed.IsFaulted)
        {
            var error = completed.Exception?.Flatten().InnerExceptions
                .OfType<AgentInfrastructureSessionRuntimeException>()
                .FirstOrDefault();
            if (error != null)
            {
                return new(error.Retryable, error.ErrorCode);
            }
            return new(false, "InfrastructureSessionWorkerFailed");
        }
        return new(true, completed.IsCanceled
            ? "InfrastructureSessionCanceled"
            : "InfrastructureSessionClosed");
    }

    private static async Task ObserveSessionTasksAsync(params Task[] tasks)
    {
        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidDataException or
                                   AgentInfrastructureSessionRuntimeException)
        {
        }
    }

    private static AgentInfrastructureRuntimeState MapTerminalState(
        AgentInfrastructureSessionOpenFailureClass failureClass) => failureClass switch
        {
            AgentInfrastructureSessionOpenFailureClass.Configuration =>
                AgentInfrastructureRuntimeState.ConfigurationIncompatible,
            AgentInfrastructureSessionOpenFailureClass.Security =>
                AgentInfrastructureRuntimeState.SecurityIncompatible,
            AgentInfrastructureSessionOpenFailureClass.Protocol =>
                AgentInfrastructureRuntimeState.ProtocolIncompatible,
            _ => AgentInfrastructureRuntimeState.TerminalFailed
        };

    private static string ResolveAvailabilityCode(InfrastructureEvidenceSpoolState spoolState) => spoolState switch
    {
        InfrastructureEvidenceSpoolState.Healthy => "AgentHealthy",
        InfrastructureEvidenceSpoolState.Backpressured => "AgentBackpressured",
        InfrastructureEvidenceSpoolState.QuotaBlocked => "AgentSpoolQuotaBlocked",
        InfrastructureEvidenceSpoolState.Corrupt => "AgentSpoolCorrupt",
        InfrastructureEvidenceSpoolState.Draining => "AgentDraining",
        _ => "AgentOffline"
    };

    private static int CountOutbox(
        AgentInfrastructureEvidenceOutbox outbox,
        InfrastructureEvidenceOutboxState state) =>
        outbox.List(state, InfrastructureEvidenceOutboxPolicy.MaxPageSize).Count;

    private void SetTerminal(AgentInfrastructureRuntimeState state, string errorCode)
    {
        RevokeRemoteCommands();
        SetState(state, errorCode);
    }

    private void RevokeRemoteCommands()
    {
        lock (_gate)
        {
            RevokeRemoteCommandsUnderLock();
        }
    }

    private void RevokeRemoteCommandsUnderLock()
    {
        _remoteCommandsEligible = false;
        _eligibleAgentId = string.Empty;
        _eligibleConnectionGeneration = Guid.Empty;
    }

    private void SetState(
        AgentInfrastructureRuntimeState state,
        string? errorCode,
        bool preserveEligibility = false)
    {
        AgentInfrastructureRuntimeSnapshot snapshot;
        lock (_gate)
        {
            _state = state;
            _errorCode = BoundCode(errorCode, string.Empty);
            if (!preserveEligibility && state != AgentInfrastructureRuntimeState.Active)
            {
                RevokeRemoteCommandsUnderLock();
            }
            snapshot = SnapshotUnderLock();
        }
        var handlers = StateChanged;
        if (handlers == null)
        {
            return;
        }
        foreach (Action<AgentInfrastructureRuntimeSnapshot> handler in handlers.GetInvocationList())
        {
            try
            {
                handler(snapshot);
            }
            catch (Exception)
            {
                // Diagnostics observers cannot become runtime authority or stop supervision.
            }
        }
    }

    private AgentInfrastructureRuntimeSnapshot SnapshotUnderLock()
    {
        var route = _route.Scope;
        return new(
            _state,
            _connectionAttempts,
            _connectionGeneration,
            _sessionId,
            _serverSessionGeneration,
            route?.CaseId ?? string.Empty,
            route?.CaptureId ?? string.Empty,
            _errorCode,
            Interlocked.Read(ref _healthRevision),
            _connectivity.Snapshot);
    }

    private static string BoundCode(string? value, string fallback)
    {
        var selected = string.IsNullOrWhiteSpace(value) ? fallback : value;
        return selected.Length <= 128 ? selected : selected[..128];
    }

    private static TimeSpan ValidateDelay(TimeSpan value, string parameterName) =>
        value > TimeSpan.Zero && value <= TimeSpan.FromMinutes(1)
            ? value
            : throw new ArgumentOutOfRangeException(parameterName);

    private static async Task ObserveStopAsync(Task? worker)
    {
        if (worker == null)
        {
            return;
        }
        try
        {
            await worker.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
        }
        await StopAsync().ConfigureAwait(false);
        await _publisher.DisposeAsync().ConfigureAwait(false);
        _stop.Dispose();
    }

    private sealed record AgentInfrastructureSessionFailure(bool Retryable, string ErrorCode);

    private sealed class AgentInfrastructureSessionRuntimeException : Exception
    {
        public AgentInfrastructureSessionRuntimeException(string errorCode, bool retryable)
            : base(errorCode)
        {
            ErrorCode = BoundCode(errorCode, "InfrastructureSessionWorkerFailed");
            Retryable = retryable;
        }

        public string ErrorCode { get; }

        public bool Retryable { get; }
    }
}

internal static class AgentInfrastructureRuntimeFactory
{
    public static bool TryCreate(
        InfrastructureModeAccessService access,
        Func<AgentInfrastructureRuntime> factory,
        out AgentInfrastructureRuntime? runtime,
        out InfrastructureAccessDecision decision)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(factory);
        return access.TryCreate(
            InfrastructureEntryPointKind.IpcOrNetworkClientCreation,
            factory,
            out runtime,
            out decision,
            InfrastructureFeatureArea.AgentManagement);
    }
}
