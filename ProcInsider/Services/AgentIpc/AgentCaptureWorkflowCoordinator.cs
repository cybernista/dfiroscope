using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public enum AgentCaptureWorkflowPhase
{
    Detached,
    Disconnected,
    Connecting,
    Connected,
    Polling,
    CommandPending,
    Failed,
    Disposed
}

public enum AgentCaptureWorkflowOutcome
{
    None,
    Succeeded,
    Failed,
    Canceled,
    Superseded,
    Skipped,
    Disposed
}

public sealed record AgentCaptureHealthAssessment(
    bool IsExpectedSession,
    bool IsReleaseCompatible,
    string Error = "",
    bool IsProcessIdentityVerified = true)
{
    public bool Accepted =>
        IsExpectedSession &&
        IsReleaseCompatible &&
        IsProcessIdentityVerified;
}

public sealed record AgentCaptureWorkflowState(
    long WorkspaceGeneration,
    long OperationGeneration,
    long PollGeneration,
    AgentCaptureWorkflowPhase Phase,
    AgentCaptureWorkflowOutcome LastOutcome,
    bool IsReachable,
    bool IsViewerAttached,
    bool IsPollRunning,
    bool IsReleaseCompatible,
    string ConnectedAgentId,
    string MonitoredAgentId,
    int HealthFailureCount,
    DateTime NextPollUtc,
    AgentCaptureControlViewState Control,
    IReadOnlyDictionary<JobKind, Guid> CaptureJobIds,
    string LastError)
{
    public string WorkspaceTrackedAgentId =>
        !string.IsNullOrWhiteSpace(ConnectedAgentId)
            ? ConnectedAgentId
            : MonitoredAgentId;

    public bool HasWorkspaceTrackedAgent =>
        !string.IsNullOrWhiteSpace(WorkspaceTrackedAgentId);

    public int AuthenticatedConnectedAgentCount =>
        IsReachable &&
        IsViewerAttached &&
        !string.IsNullOrWhiteSpace(ConnectedAgentId)
            ? 1
            : 0;

    public static AgentCaptureWorkflowState Initial(long workspaceGeneration) => new(
        workspaceGeneration,
        0,
        0,
        AgentCaptureWorkflowPhase.Disconnected,
        AgentCaptureWorkflowOutcome.None,
        false,
        false,
        false,
        false,
        string.Empty,
        string.Empty,
        0,
        DateTime.MinValue,
        AgentCaptureControlViewState.Unknown(),
        new Dictionary<JobKind, Guid>(),
        string.Empty);
}

public sealed record AgentCaptureWorkflowResult(
    AgentCaptureWorkflowOutcome Outcome,
    AgentCaptureWorkflowState State,
    AgentIpcResponse? Response = null,
    AgentCaptureHealthAssessment? Assessment = null,
    IReadOnlyList<AgentIpcResponse>? JobResponses = null)
{
    public bool Succeeded => Outcome == AgentCaptureWorkflowOutcome.Succeeded;
}

public sealed record AgentCaptureCommandRequest(
    JobKind JobKind,
    AgentCapturePendingAction PendingAction,
    AgentCommand Command,
    string Action,
    bool StartAgentIfNeeded = true,
    bool RequireViewerConnection = true);

public sealed class AgentCaptureWorkflowStateChangedEventArgs(
    AgentCaptureWorkflowState state) : EventArgs
{
    public AgentCaptureWorkflowState State { get; } = state;
}

public interface IAgentCaptureWorkflowRuntime
{
    Task<AgentIpcResponse> GetConnectionHealthAsync(CancellationToken cancellationToken);

    Task<AgentIpcResponse> GetStatusHealthAsync(CancellationToken cancellationToken);

    Task<AgentIpcResponse> GetJobStatusAsync(Guid jobId, CancellationToken cancellationToken);

    Task<AgentIpcResponse?> SubmitCommandAsync(
        AgentCommand command,
        string action,
        bool startAgentIfNeeded,
        bool requireViewerConnection,
        CancellationToken cancellationToken);

    AgentCaptureHealthAssessment AssessHealth(AgentHealthSnapshot? health);
}

public sealed class DelegateAgentCaptureWorkflowRuntime : IAgentCaptureWorkflowRuntime
{
    private readonly Func<CancellationToken, Task<AgentIpcResponse>> _getConnectionHealth;
    private readonly Func<CancellationToken, Task<AgentIpcResponse>> _getStatusHealth;
    private readonly Func<Guid, CancellationToken, Task<AgentIpcResponse>> _getJobStatus;
    private readonly Func<AgentCommand, string, bool, bool, CancellationToken, Task<AgentIpcResponse?>> _submitCommand;
    private readonly Func<AgentHealthSnapshot?, AgentCaptureHealthAssessment> _assessHealth;

    public DelegateAgentCaptureWorkflowRuntime(
        Func<CancellationToken, Task<AgentIpcResponse>> getConnectionHealth,
        Func<CancellationToken, Task<AgentIpcResponse>> getStatusHealth,
        Func<Guid, CancellationToken, Task<AgentIpcResponse>> getJobStatus,
        Func<AgentCommand, string, bool, bool, CancellationToken, Task<AgentIpcResponse?>> submitCommand,
        Func<AgentHealthSnapshot?, AgentCaptureHealthAssessment> assessHealth)
    {
        _getConnectionHealth = getConnectionHealth ?? throw new ArgumentNullException(nameof(getConnectionHealth));
        _getStatusHealth = getStatusHealth ?? throw new ArgumentNullException(nameof(getStatusHealth));
        _getJobStatus = getJobStatus ?? throw new ArgumentNullException(nameof(getJobStatus));
        _submitCommand = submitCommand ?? throw new ArgumentNullException(nameof(submitCommand));
        _assessHealth = assessHealth ?? throw new ArgumentNullException(nameof(assessHealth));
    }

    public Task<AgentIpcResponse> GetConnectionHealthAsync(CancellationToken cancellationToken) =>
        _getConnectionHealth(cancellationToken);

    public Task<AgentIpcResponse> GetStatusHealthAsync(CancellationToken cancellationToken) =>
        _getStatusHealth(cancellationToken);

    public Task<AgentIpcResponse> GetJobStatusAsync(Guid jobId, CancellationToken cancellationToken) =>
        _getJobStatus(jobId, cancellationToken);

    public Task<AgentIpcResponse?> SubmitCommandAsync(
        AgentCommand command,
        string action,
        bool startAgentIfNeeded,
        bool requireViewerConnection,
        CancellationToken cancellationToken) =>
        _submitCommand(command, action, startAgentIfNeeded, requireViewerConnection, cancellationToken);

    public AgentCaptureHealthAssessment AssessHealth(AgentHealthSnapshot? health) =>
        _assessHealth(health);
}

/// <summary>
/// Headless owner for viewer attachment, reconnect/poll generations, the authoritative
/// capture-control projection, and live/network/Process Monitor capture job sequencing.
/// MainViewModel supplies policy-checked IPC callbacks and projects immutable state into WPF.
/// </summary>
public sealed class AgentCaptureWorkflowCoordinator : IDisposable
{
    private static readonly JobKind[] CaptureJobKinds =
    [
        JobKind.LiveCapture,
        JobKind.NetworkCapture,
        JobKind.ProcessMonitorCapture
    ];

    private static readonly TimeSpan DefaultReconnectInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan DefaultDisconnectedInterval = TimeSpan.FromSeconds(15);
    private const int DefaultFastReconnectAttempts = 5;

    private readonly object _gate = new();
    private readonly IAgentCaptureWorkflowRuntime _runtime;
    private readonly AgentCaptureControlProjectionService _controlProjection;
    private readonly TimeSpan _reconnectInterval;
    private readonly TimeSpan _disconnectedInterval;
    private readonly int _fastReconnectAttempts;
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly Dictionary<JobKind, Guid> _captureJobIds = new();
    private CancellationTokenSource? _operationCts;
    private CancellationTokenSource? _pollCts;
    private AgentCaptureWorkflowState _state;
    private bool _disposed;

    public AgentCaptureWorkflowCoordinator(
        long initialWorkspaceGeneration,
        IAgentCaptureWorkflowRuntime runtime,
        AgentCaptureControlProjectionService? controlProjection = null,
        TimeSpan? reconnectInterval = null,
        TimeSpan? disconnectedInterval = null,
        int fastReconnectAttempts = DefaultFastReconnectAttempts)
    {
        if (initialWorkspaceGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(initialWorkspaceGeneration));
        }

        if (fastReconnectAttempts < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(fastReconnectAttempts));
        }

        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _controlProjection = controlProjection ?? new AgentCaptureControlProjectionService();
        _reconnectInterval = reconnectInterval ?? DefaultReconnectInterval;
        _disconnectedInterval = disconnectedInterval ?? DefaultDisconnectedInterval;
        _fastReconnectAttempts = fastReconnectAttempts;
        _state = AgentCaptureWorkflowState.Initial(initialWorkspaceGeneration) with
        {
            Control = _controlProjection.Current
        };
    }

    public event EventHandler<AgentCaptureWorkflowStateChangedEventArgs>? StateChanged;

    public AgentCaptureWorkflowState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public AgentCaptureControlViewState Control => State.Control;

    public bool HasTrackedCaptureJobs
    {
        get
        {
            lock (_gate)
            {
                return _captureJobIds.Count > 0;
            }
        }
    }

    public Guid? GetTrackedJobId(JobKind jobKind)
    {
        EnsureCaptureJobKind(jobKind);
        lock (_gate)
        {
            return _captureJobIds.TryGetValue(jobKind, out var jobId) ? jobId : null;
        }
    }

    public async Task<AgentCaptureWorkflowResult> ConnectAsync(
        string agentId,
        CancellationToken cancellationToken = default)
    {
        var operation = BeginOperation(AgentCaptureWorkflowPhase.Connecting, cancellationToken);
        if (operation == null)
        {
            return DisposedResult();
        }

        try
        {
            var response = await _runtime.GetConnectionHealthAsync(operation.Token);
            operation.Token.ThrowIfCancellationRequested();
            var assessment = _runtime.AssessHealth(response.Health);
            return CompleteConnection(operation, agentId, response, assessment);
        }
        catch (OperationCanceledException)
        {
            return CompleteCanceled(operation);
        }
        catch (Exception ex)
        {
            return CompleteFailure(operation, ex.Message);
        }
        finally
        {
            EndOperation(operation);
        }
    }

    public AgentCaptureWorkflowResult AttachVerified(
        string agentId,
        AgentIpcResponse authenticatedHealthResponse)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentNullException.ThrowIfNull(authenticatedHealthResponse);

        var operation = BeginOperation(AgentCaptureWorkflowPhase.Connecting, CancellationToken.None);
        if (operation == null)
        {
            return DisposedResult();
        }

        try
        {
            var assessment = _runtime.AssessHealth(authenticatedHealthResponse.Health);
            return CompleteConnection(operation, agentId, authenticatedHealthResponse, assessment);
        }
        finally
        {
            EndOperation(operation);
        }
    }

    public void Disconnect(string detail)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            CancelOperationLocked();
            CancelPollLocked();
            var control = _controlProjection.MarkUnavailable(detail, DateTime.UtcNow);
            state = _state with
            {
                OperationGeneration = checked(_state.OperationGeneration + 1),
                Phase = AgentCaptureWorkflowPhase.Disconnected,
                LastOutcome = AgentCaptureWorkflowOutcome.Succeeded,
                IsReachable = false,
                IsViewerAttached = false,
                IsReleaseCompatible = false,
                ConnectedAgentId = string.Empty,
                MonitoredAgentId = string.Empty,
                HealthFailureCount = 0,
                NextPollUtc = DateTime.MinValue,
                Control = control,
                LastError = string.Empty
            };
            _state = SnapshotLocked(state);
        }

        Publish(state);
    }

    /// <summary>
    /// Detaches viewer-selected operations while retaining authenticated health monitoring
    /// and the fresh control projection required by configured capture commands.
    /// </summary>
    public void DetachViewer(string detail)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            CancelOperationLocked();
            state = SnapshotLocked(_state with
            {
                OperationGeneration = checked(_state.OperationGeneration + 1),
                Phase = AgentCaptureWorkflowPhase.Disconnected,
                LastOutcome = AgentCaptureWorkflowOutcome.Succeeded,
                IsViewerAttached = false,
                ConnectedAgentId = string.Empty,
                LastError = string.Empty
            });
            _state = state;
        }

        Publish(state);
    }

    /// <summary>
    /// Keeps the verified deployed local agent under authoritative control polling even
    /// when the viewer is not attached for selected-process or host-management commands.
    /// </summary>
    public void MonitorDeployedAgent(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_state.IsReachable ||
                _state.Control.SnapshotStatus != AgentControlSnapshotStatus.Current)
            {
                return;
            }

            state = SnapshotLocked(_state with
            {
                MonitoredAgentId = agentId,
                LastError = string.Empty
            });
            _state = state;
        }

        Publish(state);
    }

    public AgentCaptureWorkflowState BindWorkspace(long workspaceGeneration, string detail)
    {
        if (workspaceGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(workspaceGeneration));
        }

        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            CancelOperationLocked();
            CancelPollLocked();
            _captureJobIds.Clear();
            var control = _controlProjection.Reset(detail);
            state = AgentCaptureWorkflowState.Initial(workspaceGeneration) with
            {
                OperationGeneration = checked(_state.OperationGeneration + 1),
                PollGeneration = checked(_state.PollGeneration + 1),
                Phase = AgentCaptureWorkflowPhase.Detached,
                LastOutcome = AgentCaptureWorkflowOutcome.Succeeded,
                Control = control
            };
            _state = SnapshotLocked(state);
        }

        Publish(state);
        return state;
    }

    public async Task<AgentCaptureWorkflowResult> ExecuteCaptureCommandAsync(
        AgentCaptureCommandRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        EnsureCaptureJobKind(request.JobKind);
        ArgumentNullException.ThrowIfNull(request.Command);

        var operation = BeginOperation(AgentCaptureWorkflowPhase.CommandPending, cancellationToken);
        if (operation == null)
        {
            return DisposedResult();
        }

        try
        {
            var response = await _runtime.SubmitCommandAsync(
                request.Command,
                request.Action,
                request.StartAgentIfNeeded,
                request.RequireViewerConnection,
                operation.Token);
            if (IsCommandOutcomeUnknown(response))
            {
                return CompleteCommand(operation, request, response);
            }

            operation.Token.ThrowIfCancellationRequested();
            return CompleteCommand(operation, request, response);
        }
        catch (OperationCanceledException)
        {
            return CompleteCanceled(operation);
        }
        catch (Exception ex)
        {
            return CompleteFailure(operation, ex.Message);
        }
        finally
        {
            EndOperation(operation);
        }
    }

    public async Task<AgentCaptureWorkflowResult> PollAsync(
        bool hasAdditionalTrackedWork,
        DateTime nowUtc,
        CancellationToken cancellationToken = default)
    {
        PollOperation? poll;
        lock (_gate)
        {
            if (_disposed)
            {
                return DisposedResultLocked();
            }

            if (_pollCts != null ||
                (string.IsNullOrWhiteSpace(_state.MonitoredAgentId) &&
                 _captureJobIds.Count == 0 &&
                 !hasAdditionalTrackedWork) ||
                (!_state.IsReachable && nowUtc < _state.NextPollUtc))
            {
                return new AgentCaptureWorkflowResult(
                    AgentCaptureWorkflowOutcome.Skipped,
                    _state);
            }

            _pollCts = CancellationTokenSource.CreateLinkedTokenSource(
                _lifetimeCts.Token,
                cancellationToken);
            var pollGeneration = checked(_state.PollGeneration + 1);
            poll = new PollOperation(
                _state.WorkspaceGeneration,
                pollGeneration,
                _pollCts,
                _pollCts.Token);
            _state = SnapshotLocked(_state with
            {
                PollGeneration = pollGeneration,
                Phase = AgentCaptureWorkflowPhase.Polling,
                LastOutcome = AgentCaptureWorkflowOutcome.None,
                IsPollRunning = true,
                LastError = string.Empty
            });
        }

        Publish(State);
        try
        {
            var health = await _runtime.GetStatusHealthAsync(poll.Token);
            poll.Token.ThrowIfCancellationRequested();
            var assessment = _runtime.AssessHealth(health.Health);
            if (!ApplyPolledHealth(poll, health, assessment, nowUtc))
            {
                return SupersededResult();
            }

            var jobs = new List<AgentIpcResponse>();
            if (health.Success && assessment.Accepted)
            {
                foreach (var jobId in CaptureJobSnapshot())
                {
                    var response = await _runtime.GetJobStatusAsync(jobId, poll.Token);
                    poll.Token.ThrowIfCancellationRequested();
                    if (!ApplyPolledJob(poll, response))
                    {
                        return SupersededResult();
                    }

                    jobs.Add(response);
                    if (!response.Success && IsUnavailableResponse(response))
                    {
                        break;
                    }
                }
            }

            AgentCaptureWorkflowState completed;
            lock (_gate)
            {
                if (!IsCurrentPollLocked(poll))
                {
                    return SupersededResultLocked();
                }

                var pollSucceeded = health.Success && assessment.Accepted;
                completed = SnapshotLocked(_state with
                {
                    Phase = _state.IsViewerAttached
                        ? AgentCaptureWorkflowPhase.Connected
                        : AgentCaptureWorkflowPhase.Disconnected,
                    LastOutcome = pollSucceeded
                        ? AgentCaptureWorkflowOutcome.Succeeded
                        : AgentCaptureWorkflowOutcome.Failed,
                    LastError = pollSucceeded
                        ? string.Empty
                        : health.Success
                            ? FirstNonEmpty(assessment.Error, FormatFailure(health))
                            : FormatFailure(health)
                });
                _state = completed;
            }

            Publish(completed);
            return new AgentCaptureWorkflowResult(
                completed.LastOutcome,
                completed,
                health,
                assessment,
                jobs);
        }
        catch (OperationCanceledException)
        {
            return CompleteCanceledPoll(poll);
        }
        catch (Exception ex)
        {
            return CompleteFailedPoll(poll, ex.Message);
        }
        finally
        {
            EndPoll(poll);
        }
    }

    public AgentCaptureControlViewState ObserveResponse(
        AgentIpcResponse response,
        DateTime? nowUtc = null)
    {
        ArgumentNullException.ThrowIfNull(response);
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return _state.Control;
            }

            state = ApplyResponseLocked(response, nowUtc ?? DateTime.UtcNow);
            _state = SnapshotLocked(state);
        }

        Publish(state);
        return state.Control;
    }

    public AgentCaptureControlViewState BeginPendingJob(
        JobKind jobKind,
        AgentCapturePendingAction action,
        DateTime? nowUtc = null)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var control = _controlProjection.BeginPendingJob(jobKind, action, nowUtc ?? DateTime.UtcNow);
            state = SnapshotLocked(_state with { Control = control });
            _state = state;
        }

        Publish(state);
        return state.Control;
    }

    public AgentCaptureControlViewState BeginPendingCapture(
        AgentCapturePendingAction action,
        string captureId = "",
        DateTime? nowUtc = null)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var control = _controlProjection.BeginPendingCapture(
                action,
                nowUtc ?? DateTime.UtcNow,
                captureId);
            state = SnapshotLocked(_state with { Control = control });
            _state = state;
        }

        Publish(state);
        return state.Control;
    }

    public void TrackCaptureJob(JobKind jobKind, Guid? jobId)
    {
        EnsureCaptureJobKind(jobKind);
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            if (jobId.HasValue && jobId.Value != Guid.Empty)
            {
                _captureJobIds[jobKind] = jobId.Value;
            }
            else
            {
                _captureJobIds.Remove(jobKind);
            }

            state = SnapshotLocked(_state);
            _state = state;
        }

        Publish(state);
    }

    public AgentCaptureControlViewState Reset(string detail)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return _state.Control;
            }

            _captureJobIds.Clear();
            var control = _controlProjection.Reset(detail);
            state = SnapshotLocked(_state with
            {
                Phase = AgentCaptureWorkflowPhase.Disconnected,
                LastOutcome = AgentCaptureWorkflowOutcome.Succeeded,
                IsReachable = false,
                IsViewerAttached = false,
                IsReleaseCompatible = false,
                ConnectedAgentId = string.Empty,
                MonitoredAgentId = string.Empty,
                HealthFailureCount = 0,
                NextPollUtc = DateTime.MinValue,
                Control = control,
                LastError = string.Empty
            });
            _state = state;
        }

        Publish(state);
        return state.Control;
    }

    public void Dispose()
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            CancelOperationLocked();
            CancelPollLocked();
            _lifetimeCts.Cancel();
            _captureJobIds.Clear();
            state = SnapshotLocked(_state with
            {
                OperationGeneration = checked(_state.OperationGeneration + 1),
                PollGeneration = checked(_state.PollGeneration + 1),
                Phase = AgentCaptureWorkflowPhase.Disposed,
                LastOutcome = AgentCaptureWorkflowOutcome.Disposed,
                IsReachable = false,
                IsViewerAttached = false,
                IsPollRunning = false,
                ConnectedAgentId = string.Empty,
                MonitoredAgentId = string.Empty
            });
            _state = state;
        }

        Publish(state);
        _lifetimeCts.Dispose();
    }

    private AgentCaptureWorkflowResult CompleteConnection(
        Operation operation,
        string agentId,
        AgentIpcResponse response,
        AgentCaptureHealthAssessment assessment)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (!IsCurrentOperationLocked(operation))
            {
                return SupersededResultLocked(response, assessment);
            }

            state = ApplyResponseLocked(response, DateTime.UtcNow);
            var succeeded = response.Success && assessment.Accepted;
            state = SnapshotLocked(state with
            {
                Phase = succeeded ? AgentCaptureWorkflowPhase.Connected : AgentCaptureWorkflowPhase.Failed,
                LastOutcome = succeeded ? AgentCaptureWorkflowOutcome.Succeeded : AgentCaptureWorkflowOutcome.Failed,
                IsReachable = succeeded,
                IsViewerAttached = succeeded,
                ConnectedAgentId = succeeded ? agentId ?? string.Empty : string.Empty,
                MonitoredAgentId = succeeded ? agentId ?? string.Empty : string.Empty,
                LastError = succeeded
                    ? string.Empty
                    : response.Success
                        ? FirstNonEmpty(assessment.Error, FormatFailure(response))
                        : FormatFailure(response)
            });
            _state = state;
        }

        Publish(state);
        return new AgentCaptureWorkflowResult(state.LastOutcome, state, response, assessment);
    }

    private AgentCaptureWorkflowResult CompleteCommand(
        Operation operation,
        AgentCaptureCommandRequest request,
        AgentIpcResponse? response)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (!IsCurrentOperationLocked(operation))
            {
                if (IsCommandOutcomeUnknown(response))
                {
                    return new AgentCaptureWorkflowResult(
                        AgentCaptureWorkflowOutcome.Failed,
                        _state,
                        response);
                }

                return SupersededResultLocked(response);
            }

            if (response == null)
            {
                state = SnapshotLocked(_state with
                {
                    Phase = AgentCaptureWorkflowPhase.Failed,
                    LastOutcome = AgentCaptureWorkflowOutcome.Failed,
                    LastError = $"The agent did not return a response for {request.Action}."
                });
            }
            else
            {
                state = ApplyResponseLocked(response, DateTime.UtcNow);
                if (response.Success)
                {
                    if (response.AcceptedJobId.HasValue && response.AcceptedJobId.Value != Guid.Empty)
                    {
                        _captureJobIds[request.JobKind] = response.AcceptedJobId.Value;
                    }

                    var control = _controlProjection.BeginPendingJob(
                        request.JobKind,
                        request.PendingAction,
                        DateTime.UtcNow);
                    state = state with { Control = control };
                }

                state = SnapshotLocked(state with
                {
                    Phase = response.Success
                        ? state.IsViewerAttached
                            ? AgentCaptureWorkflowPhase.Connected
                            : AgentCaptureWorkflowPhase.Disconnected
                        : AgentCaptureWorkflowPhase.Failed,
                    LastOutcome = response.Success
                        ? AgentCaptureWorkflowOutcome.Succeeded
                        : AgentCaptureWorkflowOutcome.Failed,
                    LastError = response.Success ? string.Empty : FormatFailure(response)
                });
            }

            _state = state;
        }

        Publish(state);
        return new AgentCaptureWorkflowResult(state.LastOutcome, state, response);
    }

    private bool ApplyPolledHealth(
        PollOperation poll,
        AgentIpcResponse response,
        AgentCaptureHealthAssessment assessment,
        DateTime nowUtc)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (!IsCurrentPollLocked(poll))
            {
                return false;
            }

            state = ApplyResponseLocked(response, nowUtc);
            if (response.Success && !assessment.Accepted)
            {
                state = state with
                {
                    IsViewerAttached = false,
                    ConnectedAgentId = string.Empty,
                    MonitoredAgentId = string.Empty
                };
            }

            _state = SnapshotLocked(state with
            {
                Phase = AgentCaptureWorkflowPhase.Polling,
                IsPollRunning = true
            });
            state = _state;
        }

        Publish(state);
        return true;
    }

    private bool ApplyPolledJob(PollOperation poll, AgentIpcResponse response)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (!IsCurrentPollLocked(poll))
            {
                return false;
            }

            state = ApplyResponseLocked(response, DateTime.UtcNow);
            _state = SnapshotLocked(state with
            {
                Phase = AgentCaptureWorkflowPhase.Polling,
                IsPollRunning = true
            });
            state = _state;
        }

        Publish(state);
        return true;
    }

    private AgentCaptureWorkflowState ApplyResponseLocked(
        AgentIpcResponse response,
        DateTime nowUtc)
    {
        var state = _state;
        if (response.Health != null)
        {
            var assessment = _runtime.AssessHealth(response.Health);
            var control = _controlProjection.ApplyHealth(
                response.Health,
                assessment.IsExpectedSession,
                nowUtc);
            if (assessment.IsExpectedSession && !assessment.Accepted)
            {
                control = _controlProjection.MarkUnavailable(assessment.Error, nowUtc);
            }

            state = state with
            {
                IsReachable = response.Success && assessment.Accepted,
                IsViewerAttached = assessment.Accepted && state.IsViewerAttached,
                IsReleaseCompatible = assessment.IsReleaseCompatible,
                ConnectedAgentId = assessment.Accepted
                    ? state.ConnectedAgentId
                    : string.Empty,
                MonitoredAgentId = assessment.Accepted
                    ? state.MonitoredAgentId
                    : string.Empty,
                HealthFailureCount = response.Success ? 0 : state.HealthFailureCount,
                NextPollUtc = response.Success ? DateTime.MinValue : state.NextPollUtc,
                Control = control,
                LastError = assessment.Accepted ? string.Empty : assessment.Error
            };
            ReconcileCaptureJobsFromControlLocked(control);
        }
        else if (!response.Success && IsUnavailableResponse(response))
        {
            var failureCount = checked(state.HealthFailureCount + 1);
            var interval = failureCount <= _fastReconnectAttempts
                ? _reconnectInterval
                : _disconnectedInterval;
            state = state with
            {
                IsReachable = false,
                HealthFailureCount = failureCount,
                NextPollUtc = nowUtc.Add(interval),
                Control = _controlProjection.MarkUnavailable(FormatFailure(response), nowUtc),
                LastError = FormatFailure(response)
            };
        }
        else if (!response.Success)
        {
            var failure = FormatFailure(response);
            var pairingFailure = IsPairingFailureResponse(response);
            var processIdentityFailure = string.Equals(
                response.ErrorCode,
                ViewerAgentCommandErrorCodes.ProcessIdentityMismatch,
                StringComparison.Ordinal);
            var hardDetach = pairingFailure || processIdentityFailure;
            if (processIdentityFailure)
            {
                _captureJobIds.Clear();
            }

            state = state with
            {
                Phase = processIdentityFailure
                    ? AgentCaptureWorkflowPhase.Failed
                    : state.Phase,
                LastOutcome = processIdentityFailure
                    ? AgentCaptureWorkflowOutcome.Failed
                    : state.LastOutcome,
                IsReachable = false,
                IsViewerAttached = hardDetach ? false : state.IsViewerAttached,
                ConnectedAgentId = hardDetach ? string.Empty : state.ConnectedAgentId,
                MonitoredAgentId = hardDetach ? string.Empty : state.MonitoredAgentId,
                HealthFailureCount = processIdentityFailure ? 0 : state.HealthFailureCount,
                NextPollUtc = processIdentityFailure ? DateTime.MinValue : state.NextPollUtc,
                Control = _controlProjection.MarkUnavailable(failure, nowUtc),
                LastError = failure
            };
        }
        else if (response.Success)
        {
            state = state with
            {
                IsReachable = true,
                HealthFailureCount = 0,
                NextPollUtc = DateTime.MinValue
            };
        }

        if (response.Job != null && IsCaptureJobKind(response.Job.JobKind))
        {
            var job = response.Job;
            if (job.State is JobState.Queued or JobState.Running or JobState.Paused)
            {
                _captureJobIds[job.JobKind] = job.JobId;
            }
            else if (job.State is JobState.Completed or JobState.Cancelled or JobState.Failed)
            {
                var sourceState = _controlProjection.Current.GetJobSource(job.JobKind).State;
                var retainNetworkDrain = job.JobKind == JobKind.NetworkCapture &&
                                         job.State != JobState.Failed &&
                                         sourceState is AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining;
                if (!retainNetworkDrain)
                {
                    _captureJobIds.Remove(job.JobKind);
                }
            }
        }

        return SnapshotLocked(state);
    }

    private void ReconcileCaptureJobsFromControlLocked(AgentCaptureControlViewState control)
    {
        foreach (var jobKind in CaptureJobKinds)
        {
            var source = control.GetJobSource(jobKind);
            var authoritativeJobId = source.JobIds.FirstOrDefault(jobId => jobId != Guid.Empty);
            if (authoritativeJobId != Guid.Empty)
            {
                _captureJobIds[jobKind] = authoritativeJobId;
            }
            else if (source.State is AgentCaptureRunState.Off or AgentCaptureRunState.Failed)
            {
                _captureJobIds.Remove(jobKind);
            }
        }
    }

    private Operation? BeginOperation(
        AgentCaptureWorkflowPhase phase,
        CancellationToken cancellationToken)
    {
        AgentCaptureWorkflowState state;
        Operation operation;
        lock (_gate)
        {
            if (_disposed)
            {
                return null;
            }

            CancelOperationLocked();
            _operationCts = CancellationTokenSource.CreateLinkedTokenSource(
                _lifetimeCts.Token,
                cancellationToken);
            var generation = checked(_state.OperationGeneration + 1);
            operation = new Operation(
                _state.WorkspaceGeneration,
                generation,
                _operationCts,
                _operationCts.Token);
            state = SnapshotLocked(_state with
            {
                OperationGeneration = generation,
                Phase = phase,
                LastOutcome = AgentCaptureWorkflowOutcome.None,
                LastError = string.Empty
            });
            _state = state;
        }

        Publish(state);
        return operation;
    }

    private AgentCaptureWorkflowResult CompleteCanceled(Operation operation)
    {
        AgentCaptureWorkflowState state;
        AgentCaptureWorkflowOutcome outcome;
        lock (_gate)
        {
            if (_disposed)
            {
                return DisposedResultLocked();
            }

            var current = IsCurrentOperationLocked(operation);
            outcome = current
                ? AgentCaptureWorkflowOutcome.Canceled
                : AgentCaptureWorkflowOutcome.Superseded;
            if (!current)
            {
                return new AgentCaptureWorkflowResult(outcome, _state);
            }

            state = SnapshotLocked(_state with
            {
                Phase = _state.IsViewerAttached
                    ? AgentCaptureWorkflowPhase.Connected
                    : AgentCaptureWorkflowPhase.Disconnected,
                LastOutcome = outcome
            });
            _state = state;
        }

        Publish(state);
        return new AgentCaptureWorkflowResult(outcome, state);
    }

    private AgentCaptureWorkflowResult CompleteFailure(Operation operation, string error)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (!IsCurrentOperationLocked(operation))
            {
                return SupersededResultLocked();
            }

            state = SnapshotLocked(_state with
            {
                Phase = AgentCaptureWorkflowPhase.Failed,
                LastOutcome = AgentCaptureWorkflowOutcome.Failed,
                LastError = error
            });
            _state = state;
        }

        Publish(state);
        return new AgentCaptureWorkflowResult(AgentCaptureWorkflowOutcome.Failed, state);
    }

    private AgentCaptureWorkflowResult CompleteCanceledPoll(PollOperation poll)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return DisposedResultLocked();
            }

            return new AgentCaptureWorkflowResult(
                IsCurrentPollLocked(poll)
                    ? AgentCaptureWorkflowOutcome.Canceled
                    : AgentCaptureWorkflowOutcome.Superseded,
                _state);
        }
    }

    private AgentCaptureWorkflowResult CompleteFailedPoll(PollOperation poll, string error)
    {
        AgentCaptureWorkflowState state;
        lock (_gate)
        {
            if (!IsCurrentPollLocked(poll))
            {
                return SupersededResultLocked();
            }

            state = SnapshotLocked(_state with
            {
                Phase = AgentCaptureWorkflowPhase.Failed,
                LastOutcome = AgentCaptureWorkflowOutcome.Failed,
                LastError = error
            });
            _state = state;
        }

        Publish(state);
        return new AgentCaptureWorkflowResult(AgentCaptureWorkflowOutcome.Failed, state);
    }

    private void EndOperation(Operation operation)
    {
        lock (_gate)
        {
            if (ReferenceEquals(_operationCts, operation.Source))
            {
                _operationCts = null;
            }
        }

        operation.Source.Dispose();
    }

    private void EndPoll(PollOperation poll)
    {
        AgentCaptureWorkflowState? state = null;
        lock (_gate)
        {
            if (ReferenceEquals(_pollCts, poll.Source))
            {
                _pollCts = null;
                if (!_disposed && _state.IsPollRunning)
                {
                    state = SnapshotLocked(_state with
                    {
                        IsPollRunning = false,
                        Phase = _state.IsViewerAttached
                            ? AgentCaptureWorkflowPhase.Connected
                            : AgentCaptureWorkflowPhase.Disconnected
                    });
                    _state = state;
                }
            }
        }

        poll.Source.Dispose();
        if (state != null)
        {
            Publish(state);
        }
    }

    private void CancelOperationLocked()
    {
        _operationCts?.Cancel();
        _operationCts = null;
    }

    private void CancelPollLocked()
    {
        _pollCts?.Cancel();
        _pollCts = null;
    }

    private bool IsCurrentOperationLocked(Operation operation) =>
        !_disposed &&
        operation.WorkspaceGeneration == _state.WorkspaceGeneration &&
        operation.Generation == _state.OperationGeneration &&
        ReferenceEquals(_operationCts, operation.Source);

    private bool IsCurrentPollLocked(PollOperation poll) =>
        !_disposed &&
        poll.WorkspaceGeneration == _state.WorkspaceGeneration &&
        poll.Generation == _state.PollGeneration &&
        ReferenceEquals(_pollCts, poll.Source);

    private Guid[] CaptureJobSnapshot()
    {
        lock (_gate)
        {
            return _captureJobIds.Values.Distinct().ToArray();
        }
    }

    private AgentCaptureWorkflowState SnapshotLocked(AgentCaptureWorkflowState state) =>
        state with
        {
            CaptureJobIds = new Dictionary<JobKind, Guid>(_captureJobIds),
            Control = _controlProjection.Current
        };

    private void Publish(AgentCaptureWorkflowState state) =>
        StateChanged?.Invoke(this, new AgentCaptureWorkflowStateChangedEventArgs(state));

    private AgentCaptureWorkflowResult SupersededResult(
        AgentIpcResponse? response = null,
        AgentCaptureHealthAssessment? assessment = null)
    {
        lock (_gate)
        {
            return SupersededResultLocked(response, assessment);
        }
    }

    private AgentCaptureWorkflowResult SupersededResultLocked(
        AgentIpcResponse? response = null,
        AgentCaptureHealthAssessment? assessment = null) =>
        new(AgentCaptureWorkflowOutcome.Superseded, _state, response, assessment);

    private AgentCaptureWorkflowResult DisposedResult()
    {
        lock (_gate)
        {
            return DisposedResultLocked();
        }
    }

    private AgentCaptureWorkflowResult DisposedResultLocked() =>
        new(AgentCaptureWorkflowOutcome.Disposed, _state);

    private static bool IsCaptureJobKind(JobKind jobKind) =>
        CaptureJobKinds.Contains(jobKind);

    private static bool IsCommandOutcomeUnknown(AgentIpcResponse? response) =>
        string.Equals(
            response?.ErrorCode,
            ViewerAgentCommandErrorCodes.CommandOutcomeUnknown,
            StringComparison.Ordinal);

    private static void EnsureCaptureJobKind(JobKind jobKind)
    {
        if (!IsCaptureJobKind(jobKind))
        {
            throw new ArgumentOutOfRangeException(
                nameof(jobKind),
                jobKind,
                "Only live, network, and Process Monitor capture jobs are owned by this coordinator.");
        }
    }

    private static bool IsUnavailableResponse(AgentIpcResponse response) =>
        !response.Success && response.ErrorCode is
            "Timeout" or
            "PipeIoError" or
            "PipeAccessDenied" or
            "InvalidResponse" or
            "InvalidJson" or
            "EmptyResponse";

    private static bool IsPairingFailureResponse(AgentIpcResponse response) =>
        !response.Success &&
        (response.ErrorCode.StartsWith("Pairing", StringComparison.Ordinal) ||
         response.ErrorCode.StartsWith("PairedAgent", StringComparison.Ordinal) ||
         response.ErrorCode is "UnauthorizedCaller" or "UnauthorizedClient");

    private static string FormatFailure(AgentIpcResponse response) =>
        FirstNonEmpty(response.ErrorMessage, response.ErrorCode, "Agent IPC request failed.");

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private sealed record Operation(
        long WorkspaceGeneration,
        long Generation,
        CancellationTokenSource Source,
        CancellationToken Token);

    private sealed record PollOperation(
        long WorkspaceGeneration,
        long Generation,
        CancellationTokenSource Source,
        CancellationToken Token);
}
