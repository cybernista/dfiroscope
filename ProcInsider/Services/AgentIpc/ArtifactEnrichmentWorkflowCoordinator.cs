using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public enum ArtifactEnrichmentWorkflowPhase
{
    Idle,
    Queueing,
    Polling,
    Cancelling,
    Failed,
    Disposed
}

public enum ArtifactEnrichmentWorkflowOutcome
{
    None,
    Succeeded,
    Failed,
    Canceled,
    Superseded,
    Skipped,
    Duplicate,
    Disposed
}

public enum ArtifactEnrichmentQueueScope
{
    Independent,
    Global,
    SelectedProcess,
    SelectedProcessPe,
    ConfiguredCapture,
    ExplicitAll,
    ExplicitProcessEntities,
    ExplicitProcessKeys
}

public sealed record ArtifactEnrichmentSelectionContext(
    string ProcessEntityId,
    string ProcessKey,
    string ProcessName,
    int ProcessId,
    ProcessStatus ProcessStatus,
    ArtifactCaptureStatus ModuleCaptureStatus,
    DateTime? ModuleLastCapturedUtc,
    ArtifactCaptureStatus HandleCaptureStatus,
    DateTime? HandleLastCapturedUtc);

public sealed record ArtifactEnrichmentQueueRequest(
    ArtifactEnrichmentQueueScope Scope,
    bool CaptureModules,
    bool CaptureHandles,
    bool CapturePe,
    PeStringExtractionMode PeStringExtractionMode,
    string Action,
    ArtifactEnrichmentSelectionContext? Selection = null,
    bool Force = false,
    bool StartAgentIfNeeded = true,
    bool RequireViewerConnection = false,
    IReadOnlyList<string>? ProcessEntityIds = null,
    IReadOnlyList<string>? ProcessKeys = null);

public sealed record ArtifactEnrichmentTrackedJob(
    Guid JobId,
    JobKind JobKind,
    ArtifactEnrichmentQueueScope Scope,
    bool CaptureModules,
    bool CaptureHandles,
    bool CapturePe,
    ArtifactEnrichmentSelectionContext? Selection);

public sealed record ArtifactEnrichmentCompletion(
    ArtifactEnrichmentTrackedJob Job,
    JobState TerminalState);

public sealed record ArtifactEnrichmentWorkflowState(
    long WorkspaceGeneration,
    long OperationGeneration,
    long PollGeneration,
    ArtifactEnrichmentWorkflowPhase Phase,
    ArtifactEnrichmentWorkflowOutcome LastOutcome,
    bool IsPollRunning,
    IReadOnlyDictionary<Guid, ArtifactEnrichmentTrackedJob> TrackedJobs,
    IReadOnlyList<string> QueuedModuleProcessKeys,
    IReadOnlyList<string> QueuedHandleProcessKeys,
    string LastError)
{
    public static ArtifactEnrichmentWorkflowState Initial(long workspaceGeneration) => new(
        workspaceGeneration,
        0,
        0,
        ArtifactEnrichmentWorkflowPhase.Idle,
        ArtifactEnrichmentWorkflowOutcome.None,
        false,
        new Dictionary<Guid, ArtifactEnrichmentTrackedJob>(),
        Array.Empty<string>(),
        Array.Empty<string>(),
        string.Empty);
}

public sealed record ArtifactEnrichmentWorkflowResult(
    ArtifactEnrichmentWorkflowOutcome Outcome,
    ArtifactEnrichmentWorkflowState State,
    ArtifactEnrichmentQueueRequest? Request = null,
    AgentIpcResponse? Response = null,
    IReadOnlyList<Guid>? CancelledJobIds = null,
    IReadOnlyList<JobKind>? AffectedWorkloads = null,
    string Detail = "")
{
    public bool Succeeded => Outcome == ArtifactEnrichmentWorkflowOutcome.Succeeded;
}

public sealed record ArtifactEnrichmentPollResult(
    ArtifactEnrichmentWorkflowOutcome Outcome,
    ArtifactEnrichmentWorkflowState State,
    IReadOnlyList<AgentIpcResponse> Responses,
    IReadOnlyList<ArtifactEnrichmentCompletion> Completions,
    bool CanContinue)
{
    public bool Succeeded => Outcome == ArtifactEnrichmentWorkflowOutcome.Succeeded;
}

public sealed class ArtifactEnrichmentWorkflowStateChangedEventArgs(
    ArtifactEnrichmentWorkflowState state) : EventArgs
{
    public ArtifactEnrichmentWorkflowState State { get; } = state;
}

public interface IArtifactEnrichmentWorkflowRuntime
{
    Task<AgentIpcResponse?> SubmitCommandAsync(
        AgentCommand command,
        string action,
        bool startAgentIfNeeded,
        bool requireViewerConnection,
        CancellationToken cancellationToken);

    Task<AgentIpcResponse> GetJobStatusAsync(Guid jobId, CancellationToken cancellationToken);

    AgentCaptureControlViewState GetControlProjection();

    void BeginPendingJob(JobKind jobKind, AgentCapturePendingAction action);
}

public sealed class DelegateArtifactEnrichmentWorkflowRuntime : IArtifactEnrichmentWorkflowRuntime
{
    private readonly Func<AgentCommand, string, bool, bool, CancellationToken, Task<AgentIpcResponse?>> _submit;
    private readonly Func<Guid, CancellationToken, Task<AgentIpcResponse>> _getJobStatus;
    private readonly Func<AgentCaptureControlViewState> _getControlProjection;
    private readonly Action<JobKind, AgentCapturePendingAction> _beginPendingJob;

    public DelegateArtifactEnrichmentWorkflowRuntime(
        Func<AgentCommand, string, bool, bool, CancellationToken, Task<AgentIpcResponse?>> submit,
        Func<Guid, CancellationToken, Task<AgentIpcResponse>> getJobStatus,
        Func<AgentCaptureControlViewState> getControlProjection,
        Action<JobKind, AgentCapturePendingAction> beginPendingJob)
    {
        _submit = submit ?? throw new ArgumentNullException(nameof(submit));
        _getJobStatus = getJobStatus ?? throw new ArgumentNullException(nameof(getJobStatus));
        _getControlProjection = getControlProjection ?? throw new ArgumentNullException(nameof(getControlProjection));
        _beginPendingJob = beginPendingJob ?? throw new ArgumentNullException(nameof(beginPendingJob));
    }

    public Task<AgentIpcResponse?> SubmitCommandAsync(
        AgentCommand command,
        string action,
        bool startAgentIfNeeded,
        bool requireViewerConnection,
        CancellationToken cancellationToken) =>
        _submit(command, action, startAgentIfNeeded, requireViewerConnection, cancellationToken);

    public Task<AgentIpcResponse> GetJobStatusAsync(Guid jobId, CancellationToken cancellationToken) =>
        _getJobStatus(jobId, cancellationToken);

    public AgentCaptureControlViewState GetControlProjection() => _getControlProjection();

    public void BeginPendingJob(JobKind jobKind, AgentCapturePendingAction action) =>
        _beginPendingJob(jobKind, action);
}

/// <summary>
/// Headless owner for viewer artifact-enrichment queueing, selected-process freshness and
/// deduplication, exact job polling/cancellation, and workspace-bound lifecycle state.
/// MainViewModel retains publication/write policy and WPF-only result projection.
/// </summary>
public sealed class ArtifactEnrichmentWorkflowCoordinator : IDisposable
{
    public static readonly TimeSpan DefaultSelectedArtifactFreshnessWindow = TimeSpan.FromMinutes(5);

    private static readonly JobKind[] EnrichmentWorkloadKinds =
    [
        JobKind.ModuleEnrichment,
        JobKind.HandleEnrichment,
        JobKind.PeAnalysis
    ];

    private readonly object _gate = new();
    private readonly IArtifactEnrichmentWorkflowRuntime _runtime;
    private readonly TimeSpan _selectedArtifactFreshnessWindow;
    private readonly Func<DateTime> _utcNow;
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly Dictionary<Guid, ArtifactEnrichmentTrackedJob> _trackedJobs = new();
    private readonly HashSet<string> _queuedModuleProcessKeys = new(StringComparer.Ordinal);
    private readonly HashSet<string> _queuedHandleProcessKeys = new(StringComparer.Ordinal);
    private CancellationTokenSource? _operationCts;
    private CancellationTokenSource? _pollCts;
    private ArtifactEnrichmentWorkflowState _state;
    private bool _pollRunning;
    private bool _disposed;

    public ArtifactEnrichmentWorkflowCoordinator(
        long initialWorkspaceGeneration,
        IArtifactEnrichmentWorkflowRuntime runtime,
        TimeSpan? selectedArtifactFreshnessWindow = null,
        Func<DateTime>? utcNow = null)
    {
        if (initialWorkspaceGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(initialWorkspaceGeneration));
        }

        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _selectedArtifactFreshnessWindow = selectedArtifactFreshnessWindow ??
                                           DefaultSelectedArtifactFreshnessWindow;
        if (_selectedArtifactFreshnessWindow < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(selectedArtifactFreshnessWindow));
        }

        _utcNow = utcNow ?? (() => DateTime.UtcNow);
        _state = ArtifactEnrichmentWorkflowState.Initial(initialWorkspaceGeneration);
    }

    public event EventHandler<ArtifactEnrichmentWorkflowStateChangedEventArgs>? StateChanged;

    public ArtifactEnrichmentWorkflowState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public bool HasTrackedJobs
    {
        get
        {
            lock (_gate)
            {
                return _trackedJobs.Count > 0;
            }
        }
    }

    public IReadOnlyList<string> DescribeTrackedJobs()
    {
        lock (_gate)
        {
            return _trackedJobs.Values
                .OrderBy(job => job.JobKind)
                .ThenBy(job => job.JobId)
                .Select(job => job.Selection == null
                    ? $"{DescribeJob(job.JobKind)} ({job.JobId})"
                    : $"selected artifact enrichment ({job.JobId}, {job.Selection.ProcessName})")
                .ToArray();
        }
    }

    public async Task<ArtifactEnrichmentWorkflowResult> QueueAsync(
        ArtifactEnrichmentQueueRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);

        var operation = BeginOperation(ArtifactEnrichmentWorkflowPhase.Queueing, cancellationToken);
        if (operation == null)
        {
            return DisposedResult(request);
        }

        try
        {
            var preliminary = EvaluateSelectedRequest(request);
            if (preliminary != null)
            {
                return CompleteOperation(operation, preliminary.Value.Outcome, request, null, preliminary.Value.Detail);
            }

            var explicitEntityIds = request.Scope == ArtifactEnrichmentQueueScope.ExplicitProcessEntities
                ? NormalizeExplicitEntityIds(request.ProcessEntityIds)
                : null;
            var explicitProcessKeys = request.Scope == ArtifactEnrichmentQueueScope.ExplicitProcessKeys
                ? NormalizeExplicitProcessKeys(request.ProcessKeys)
                : null;
            var selectedEntityId = string.IsNullOrWhiteSpace(request.Selection?.ProcessEntityId)
                ? null
                : request.Selection.ProcessEntityId;
            var command = new QueueEnrichmentCommand
            {
                AllProcesses = request.Scope is
                    ArtifactEnrichmentQueueScope.Independent or
                    ArtifactEnrichmentQueueScope.Global or
                    ArtifactEnrichmentQueueScope.ExplicitAll,
                ProcessEntityIds = explicitEntityIds ??
                    (selectedEntityId == null ? null : [selectedEntityId]),
                ProcessKeys = explicitProcessKeys ??
                    (request.Selection == null || selectedEntityId != null
                        ? null
                        : [request.Selection.ProcessKey]),
                CaptureModules = request.CaptureModules,
                CaptureHandles = request.CaptureHandles,
                CapturePe = request.CapturePe,
                PeStringExtractionMode = request.PeStringExtractionMode
            };
            var response = await _runtime.SubmitCommandAsync(
                command,
                request.Action,
                request.StartAgentIfNeeded,
                request.RequireViewerConnection,
                operation.Token);
            if (IsCommandOutcomeUnknown(response))
            {
                return CompleteOperation(
                    operation,
                    ArtifactEnrichmentWorkflowOutcome.Failed,
                    request,
                    response,
                    FirstNonEmpty(response?.ErrorMessage, response?.ErrorCode, "agent command outcome unknown"));
            }

            operation.Token.ThrowIfCancellationRequested();

            if (!IsCurrent(operation))
            {
                return SupersededResult(request);
            }

            if (response?.Success != true)
            {
                return CompleteOperation(
                    operation,
                    ArtifactEnrichmentWorkflowOutcome.Failed,
                    request,
                    response,
                    FirstNonEmpty(response?.ErrorMessage, response?.ErrorCode, "agent command failed"));
            }

            var jobKind = AgentEnrichmentPlanning.GetJobKind(
                request.CaptureModules,
                request.CaptureHandles,
                request.CapturePe);
            TrackAcceptedRequest(request, response.AcceptedJobId, jobKind);
            BeginPendingStart(request);
            return CompleteOperation(
                operation,
                ArtifactEnrichmentWorkflowOutcome.Succeeded,
                request,
                response,
                "Enrichment command accepted.");
        }
        catch (OperationCanceledException)
        {
            return CancellationResult(operation, request);
        }
        catch (Exception ex)
        {
            return CompleteOperation(
                operation,
                ArtifactEnrichmentWorkflowOutcome.Failed,
                request,
                null,
                ex.Message);
        }
    }

    public async Task<ArtifactEnrichmentWorkflowResult> CancelAsync(
        IReadOnlyList<JobKind> requestedWorkloads,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestedWorkloads);
        if (requestedWorkloads.Count == 0 || requestedWorkloads.Any(kind => !EnrichmentWorkloadKinds.Contains(kind)))
        {
            throw new ArgumentException("At least one supported enrichment workload is required.", nameof(requestedWorkloads));
        }

        var operation = BeginOperation(ArtifactEnrichmentWorkflowPhase.Cancelling, cancellationToken);
        if (operation == null)
        {
            return DisposedResult();
        }

        try
        {
            var projection = _runtime.GetControlProjection();
            var plan = AgentEnrichmentControlPlanning.PlanCancellation(
                projection,
                requestedWorkloads.ToArray());
            if (plan.JobIds.Count == 0)
            {
                return CompleteOperation(
                    operation,
                    ArtifactEnrichmentWorkflowOutcome.Skipped,
                    null,
                    null,
                    "No authoritative agent workload job is active; no viewer fallback was run.",
                    [],
                    plan.AffectedWorkloads);
            }

            var cancelledJobIds = new List<Guid>();
            string failure = string.Empty;
            foreach (var jobId in plan.JobIds)
            {
                var response = await _runtime.SubmitCommandAsync(
                    new CancelJobCommand { JobId = jobId },
                    $"cancel enrichment job {jobId}",
                    startAgentIfNeeded: false,
                    requireViewerConnection: false,
                    operation.Token);
                if (IsCommandOutcomeUnknown(response))
                {
                    if (IsCurrent(operation))
                    {
                        BeginPendingCancellationForKnownPrefix(
                            projection,
                            plan.AffectedWorkloads,
                            cancelledJobIds);
                    }

                    return CompleteOperation(
                        operation,
                        ArtifactEnrichmentWorkflowOutcome.Failed,
                        null,
                        response,
                        FirstNonEmpty(
                            response?.ErrorMessage,
                            response?.ErrorCode,
                            "enrichment cancellation outcome unknown"),
                        cancelledJobIds,
                        plan.AffectedWorkloads);
                }

                operation.Token.ThrowIfCancellationRequested();
                if (!IsCurrent(operation))
                {
                    return SupersededResult();
                }

                if (response?.Success == true)
                {
                    cancelledJobIds.Add(jobId);
                }
                else
                {
                    failure = FirstNonEmpty(response?.ErrorMessage, response?.ErrorCode, "agent command failed");
                    break;
                }
            }

            BeginPendingCancellationForKnownPrefix(
                projection,
                plan.AffectedWorkloads,
                cancelledJobIds);

            var outcome = string.IsNullOrEmpty(failure)
                ? ArtifactEnrichmentWorkflowOutcome.Succeeded
                : ArtifactEnrichmentWorkflowOutcome.Failed;
            var detail = string.IsNullOrEmpty(failure)
                ? $"Requested cancellation for {cancelledJobIds.Count:N0} exact agent enrichment job(s)."
                : $"Cancelled {cancelledJobIds.Count:N0} enrichment job(s); cancellation then failed: {failure}";
            return CompleteOperation(
                operation,
                outcome,
                null,
                null,
                detail,
                cancelledJobIds,
                plan.AffectedWorkloads);
        }
        catch (OperationCanceledException)
        {
            return CancellationResult(operation);
        }
        catch (Exception ex)
        {
            return CompleteOperation(
                operation,
                ArtifactEnrichmentWorkflowOutcome.Failed,
                null,
                null,
                ex.Message);
        }
    }

    public async Task<ArtifactEnrichmentPollResult> PollAsync(CancellationToken cancellationToken = default)
    {
        PollLease? lease;
        lock (_gate)
        {
            if (_disposed)
            {
                return new ArtifactEnrichmentPollResult(
                    ArtifactEnrichmentWorkflowOutcome.Disposed,
                    _state,
                    [],
                    [],
                    false);
            }

            if (_pollRunning)
            {
                return new ArtifactEnrichmentPollResult(
                    ArtifactEnrichmentWorkflowOutcome.Skipped,
                    _state,
                    [],
                    [],
                    true);
            }

            if (_trackedJobs.Count == 0)
            {
                return new ArtifactEnrichmentPollResult(
                    ArtifactEnrichmentWorkflowOutcome.Skipped,
                    _state,
                    [],
                    [],
                    true);
            }

            _pollRunning = true;
            _pollCts?.Dispose();
            _pollCts = CancellationTokenSource.CreateLinkedTokenSource(
                _lifetimeCts.Token,
                cancellationToken);
            var generation = _state.PollGeneration + 1;
            lease = new PollLease(
                _state.WorkspaceGeneration,
                generation,
                _pollCts,
                _trackedJobs.Values.ToArray());
            PublishStateLocked(_state with
            {
                PollGeneration = generation,
                Phase = ArtifactEnrichmentWorkflowPhase.Polling,
                LastOutcome = ArtifactEnrichmentWorkflowOutcome.None,
                IsPollRunning = true,
                LastError = string.Empty
            });
        }

        var responses = new List<AgentIpcResponse>();
        var completions = new List<ArtifactEnrichmentCompletion>();
        try
        {
            foreach (var job in lease.Jobs)
            {
                var response = await _runtime.GetJobStatusAsync(job.JobId, lease.Token);
                lease.Token.ThrowIfCancellationRequested();
                responses.Add(response);
                if (!IsCurrent(lease))
                {
                    return CompletePoll(
                        lease,
                        ArtifactEnrichmentWorkflowOutcome.Superseded,
                        responses,
                        completions,
                        false,
                        string.Empty);
                }

                if (!response.Success)
                {
                    return CompletePoll(
                        lease,
                        ArtifactEnrichmentWorkflowOutcome.Failed,
                        responses,
                        completions,
                        false,
                        FirstNonEmpty(response.ErrorMessage, response.ErrorCode, "agent job poll failed"));
                }

                if (response.Job?.State is JobState.Completed or JobState.Cancelled or JobState.Failed)
                {
                    lock (_gate)
                    {
                        if (IsCurrentLocked(lease) &&
                            _trackedJobs.Remove(job.JobId, out var removed))
                        {
                            ClearSelectedQueuedLocked(removed);
                            completions.Add(new ArtifactEnrichmentCompletion(removed, response.Job.State));
                        }
                    }
                }
            }

            return CompletePoll(
                lease,
                ArtifactEnrichmentWorkflowOutcome.Succeeded,
                responses,
                completions,
                true,
                string.Empty);
        }
        catch (OperationCanceledException)
        {
            var outcome = IsCurrent(lease)
                ? ArtifactEnrichmentWorkflowOutcome.Canceled
                : ArtifactEnrichmentWorkflowOutcome.Superseded;
            return CompletePoll(lease, outcome, responses, completions, false, string.Empty);
        }
        catch (Exception ex)
        {
            return CompletePoll(
                lease,
                ArtifactEnrichmentWorkflowOutcome.Failed,
                responses,
                completions,
                false,
                ex.Message);
        }
    }

    public void TrackJob(
        Guid jobId,
        JobKind jobKind,
        ArtifactEnrichmentQueueScope scope = ArtifactEnrichmentQueueScope.ConfiguredCapture)
    {
        if (jobId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty job id is required.", nameof(jobId));
        }

        EnsureEnrichmentJobKind(jobKind);
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _trackedJobs[jobId] = new ArtifactEnrichmentTrackedJob(
                jobId,
                jobKind,
                scope,
                jobKind == JobKind.ModuleEnrichment,
                jobKind == JobKind.HandleEnrichment,
                jobKind == JobKind.PeAnalysis,
                null);
            PublishSnapshotLocked();
        }
    }

    public void BindWorkspace(long workspaceGeneration, string detail = "Workspace rebound.")
    {
        if (workspaceGeneration < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(workspaceGeneration));
        }

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            var targetState = ArtifactEnrichmentWorkflowState.Initial(workspaceGeneration) with
            {
                OperationGeneration = _state.OperationGeneration + 1,
                PollGeneration = _state.PollGeneration + 1,
                LastOutcome = ArtifactEnrichmentWorkflowOutcome.Superseded,
                LastError = detail
            };
            ClearTrackingLocked();
            _state = targetState;
            CancelActiveWorkLocked();
            PublishStateLocked(targetState);
        }
    }

    public void Reset(string detail = "Artifact enrichment reset.")
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            var targetState = ArtifactEnrichmentWorkflowState.Initial(_state.WorkspaceGeneration) with
            {
                OperationGeneration = _state.OperationGeneration + 1,
                PollGeneration = _state.PollGeneration + 1,
                LastOutcome = ArtifactEnrichmentWorkflowOutcome.Canceled,
                LastError = detail
            };
            ClearTrackingLocked();
            _state = targetState;
            CancelActiveWorkLocked();
            PublishStateLocked(targetState);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            var targetState = _state with
            {
                OperationGeneration = _state.OperationGeneration + 1,
                PollGeneration = _state.PollGeneration + 1,
                Phase = ArtifactEnrichmentWorkflowPhase.Disposed,
                LastOutcome = ArtifactEnrichmentWorkflowOutcome.Disposed,
                IsPollRunning = false,
                TrackedJobs = new Dictionary<Guid, ArtifactEnrichmentTrackedJob>(),
                QueuedModuleProcessKeys = Array.Empty<string>(),
                QueuedHandleProcessKeys = Array.Empty<string>(),
                LastError = string.Empty
            };
            _disposed = true;
            ClearTrackingLocked();
            _state = targetState;
            CancelActiveWorkLocked();
            _lifetimeCts.Cancel();
            PublishStateLocked(targetState);
        }

        _operationCts?.Dispose();
        _pollCts?.Dispose();
        _lifetimeCts.Dispose();
    }

    private OperationLease? BeginOperation(
        ArtifactEnrichmentWorkflowPhase phase,
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return null;
            }

            _operationCts?.Cancel();
            _operationCts?.Dispose();
            _operationCts = CancellationTokenSource.CreateLinkedTokenSource(
                _lifetimeCts.Token,
                cancellationToken);
            var generation = _state.OperationGeneration + 1;
            PublishStateLocked(_state with
            {
                OperationGeneration = generation,
                Phase = phase,
                LastOutcome = ArtifactEnrichmentWorkflowOutcome.None,
                LastError = string.Empty
            });
            return new OperationLease(
                _state.WorkspaceGeneration,
                generation,
                _operationCts);
        }
    }

    private (ArtifactEnrichmentWorkflowOutcome Outcome, string Detail)? EvaluateSelectedRequest(
        ArtifactEnrichmentQueueRequest request)
    {
        var selection = request.Selection;
        if (selection == null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(selection.ProcessKey))
        {
            return (ArtifactEnrichmentWorkflowOutcome.Skipped,
                "Selected process has no stable process key; artifact enrichment was not queued.");
        }

        if (selection.ProcessStatus is ProcessStatus.Exited or ProcessStatus.NotFound)
        {
            return (ArtifactEnrichmentWorkflowOutcome.Skipped,
                "The selected process is no longer available for live enrichment.");
        }

        if (!request.Force && !NeedsSelectedEnrichment(request, selection))
        {
            return (ArtifactEnrichmentWorkflowOutcome.Skipped,
                "The selected artifact evidence is still fresh.");
        }

        lock (_gate)
        {
            var duplicate = (request.CaptureModules && _queuedModuleProcessKeys.Contains(selection.ProcessKey)) ||
                            (request.CaptureHandles && _queuedHandleProcessKeys.Contains(selection.ProcessKey));
            return duplicate
                ? (ArtifactEnrichmentWorkflowOutcome.Duplicate,
                    "Matching selected-process enrichment is already queued.")
                : null;
        }
    }

    private bool NeedsSelectedEnrichment(
        ArtifactEnrichmentQueueRequest request,
        ArtifactEnrichmentSelectionContext selection)
    {
        if (request.CapturePe)
        {
            return true;
        }

        if (request.CaptureModules &&
            NeedsArtifactEnrichment(selection.ModuleCaptureStatus, selection.ModuleLastCapturedUtc))
        {
            return true;
        }

        return request.CaptureHandles &&
               NeedsArtifactEnrichment(selection.HandleCaptureStatus, selection.HandleLastCapturedUtc);
    }

    private bool NeedsArtifactEnrichment(ArtifactCaptureStatus status, DateTime? lastCaptured)
    {
        return status switch
        {
            ArtifactCaptureStatus.Pending => true,
            ArtifactCaptureStatus.Capturing => false,
            ArtifactCaptureStatus.Captured => !IsArtifactCaptureFresh(lastCaptured),
            ArtifactCaptureStatus.Failed => false,
            ArtifactCaptureStatus.NotFound => false,
            ArtifactCaptureStatus.NotAvailable => false,
            _ => true
        };
    }

    private bool IsArtifactCaptureFresh(DateTime? lastCaptured)
    {
        if (!lastCaptured.HasValue)
        {
            return false;
        }

        var capturedUtc = lastCaptured.Value.Kind == DateTimeKind.Utc
            ? lastCaptured.Value
            : lastCaptured.Value.ToUniversalTime();
        return _utcNow() - capturedUtc <= _selectedArtifactFreshnessWindow;
    }

    private void TrackAcceptedRequest(
        ArtifactEnrichmentQueueRequest request,
        Guid? jobId,
        JobKind jobKind)
    {
        if (!jobId.HasValue || jobId.Value == Guid.Empty)
        {
            return;
        }

        lock (_gate)
        {
            var job = new ArtifactEnrichmentTrackedJob(
                jobId.Value,
                jobKind,
                request.Scope,
                request.CaptureModules,
                request.CaptureHandles,
                request.CapturePe,
                request.Selection);
            _trackedJobs[job.JobId] = job;
            if (request.Selection != null)
            {
                if (request.CaptureModules)
                {
                    _queuedModuleProcessKeys.Add(request.Selection.ProcessKey);
                }

                if (request.CaptureHandles)
                {
                    _queuedHandleProcessKeys.Add(request.Selection.ProcessKey);
                }
            }

            PublishSnapshotLocked();
        }
    }

    private void BeginPendingStart(ArtifactEnrichmentQueueRequest request)
    {
        if (request.CaptureModules)
        {
            _runtime.BeginPendingJob(JobKind.ModuleEnrichment, AgentCapturePendingAction.Start);
        }

        if (request.CaptureHandles)
        {
            _runtime.BeginPendingJob(JobKind.HandleEnrichment, AgentCapturePendingAction.Start);
        }

        if (request.CapturePe)
        {
            _runtime.BeginPendingJob(JobKind.PeAnalysis, AgentCapturePendingAction.Start);
        }
    }

    private ArtifactEnrichmentWorkflowResult CompleteOperation(
        OperationLease operation,
        ArtifactEnrichmentWorkflowOutcome outcome,
        ArtifactEnrichmentQueueRequest? request,
        AgentIpcResponse? response,
        string detail,
        IReadOnlyList<Guid>? cancelledJobIds = null,
        IReadOnlyList<JobKind>? affectedWorkloads = null)
    {
        ArtifactEnrichmentWorkflowState state;
        lock (_gate)
        {
            if (!IsCurrentLocked(operation))
            {
                if (IsCommandOutcomeUnknown(response))
                {
                    return new ArtifactEnrichmentWorkflowResult(
                        ArtifactEnrichmentWorkflowOutcome.Failed,
                        _state,
                        request,
                        response,
                        cancelledJobIds,
                        affectedWorkloads,
                        detail);
                }

                return SupersededResultLocked(request);
            }

            state = SnapshotStateLocked(_state with
            {
                Phase = outcome == ArtifactEnrichmentWorkflowOutcome.Failed
                    ? ArtifactEnrichmentWorkflowPhase.Failed
                    : ArtifactEnrichmentWorkflowPhase.Idle,
                LastOutcome = outcome,
                LastError = outcome == ArtifactEnrichmentWorkflowOutcome.Failed ? detail : string.Empty
            });
            PublishStateLocked(state);
        }

        return new ArtifactEnrichmentWorkflowResult(
            outcome,
            state,
            request,
            response,
            cancelledJobIds,
            affectedWorkloads,
            detail);
    }

    private ArtifactEnrichmentPollResult CompletePoll(
        PollLease lease,
        ArtifactEnrichmentWorkflowOutcome outcome,
        IReadOnlyList<AgentIpcResponse> responses,
        IReadOnlyList<ArtifactEnrichmentCompletion> completions,
        bool canContinue,
        string error)
    {
        ArtifactEnrichmentWorkflowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return new ArtifactEnrichmentPollResult(
                    ArtifactEnrichmentWorkflowOutcome.Disposed,
                    _state,
                    responses,
                    completions,
                    false);
            }

            if (!IsCurrentLocked(lease))
            {
                outcome = ArtifactEnrichmentWorkflowOutcome.Superseded;
                canContinue = false;
            }

            _pollRunning = false;
            state = SnapshotStateLocked(_state with
            {
                Phase = outcome == ArtifactEnrichmentWorkflowOutcome.Failed
                    ? ArtifactEnrichmentWorkflowPhase.Failed
                    : ArtifactEnrichmentWorkflowPhase.Idle,
                LastOutcome = outcome,
                IsPollRunning = false,
                LastError = error
            });
            PublishStateLocked(state);
        }

        return new ArtifactEnrichmentPollResult(outcome, state, responses, completions, canContinue);
    }

    private ArtifactEnrichmentWorkflowResult CancellationResult(
        OperationLease operation,
        ArtifactEnrichmentQueueRequest? request = null)
    {
        lock (_gate)
        {
            if (!IsCurrentLocked(operation))
            {
                return SupersededResultLocked(request);
            }
        }

        return CompleteOperation(
            operation,
            ArtifactEnrichmentWorkflowOutcome.Canceled,
            request,
            null,
            "Artifact enrichment operation was canceled.");
    }

    private ArtifactEnrichmentWorkflowResult SupersededResult(
        ArtifactEnrichmentQueueRequest? request = null)
    {
        lock (_gate)
        {
            return SupersededResultLocked(request);
        }
    }

    private ArtifactEnrichmentWorkflowResult SupersededResultLocked(
        ArtifactEnrichmentQueueRequest? request)
    {
        if (_disposed)
        {
            return new ArtifactEnrichmentWorkflowResult(
                ArtifactEnrichmentWorkflowOutcome.Disposed,
                _state,
                request,
                Detail: "Artifact enrichment coordinator is disposed.");
        }

        return new ArtifactEnrichmentWorkflowResult(
            ArtifactEnrichmentWorkflowOutcome.Superseded,
            SnapshotStateLocked(_state),
            request,
            Detail: "Artifact enrichment operation was superseded by newer workspace or workflow state.");
    }

    private static bool IsCommandOutcomeUnknown(AgentIpcResponse? response) =>
        string.Equals(
            response?.ErrorCode,
            ViewerAgentCommandErrorCodes.CommandOutcomeUnknown,
            StringComparison.Ordinal);

    private void BeginPendingCancellationForKnownPrefix(
        AgentCaptureControlViewState projection,
        IReadOnlyList<JobKind> affectedWorkloads,
        IReadOnlyList<Guid> cancelledJobIds)
    {
        foreach (var kind in affectedWorkloads)
        {
            if (projection.GetJobSource(kind).JobIds.Any(cancelledJobIds.Contains))
            {
                _runtime.BeginPendingJob(kind, AgentCapturePendingAction.Stop);
            }
        }
    }

    private ArtifactEnrichmentWorkflowResult DisposedResult(
        ArtifactEnrichmentQueueRequest? request = null)
    {
        return new ArtifactEnrichmentWorkflowResult(
            ArtifactEnrichmentWorkflowOutcome.Disposed,
            State,
            request,
            Detail: "Artifact enrichment coordinator is disposed.");
    }

    private void ClearSelectedQueuedLocked(ArtifactEnrichmentTrackedJob job)
    {
        if (job.Selection == null)
        {
            return;
        }

        if (job.CaptureModules)
        {
            _queuedModuleProcessKeys.Remove(job.Selection.ProcessKey);
        }

        if (job.CaptureHandles)
        {
            _queuedHandleProcessKeys.Remove(job.Selection.ProcessKey);
        }
    }

    private void ClearTrackingLocked()
    {
        _trackedJobs.Clear();
        _queuedModuleProcessKeys.Clear();
        _queuedHandleProcessKeys.Clear();
        _pollRunning = false;
    }

    private void CancelActiveWorkLocked()
    {
        _operationCts?.Cancel();
        _pollCts?.Cancel();
    }

    private bool IsCurrent(OperationLease operation)
    {
        lock (_gate)
        {
            return IsCurrentLocked(operation);
        }
    }

    private bool IsCurrentLocked(OperationLease operation) =>
        !_disposed &&
        operation.WorkspaceGeneration == _state.WorkspaceGeneration &&
        operation.Generation == _state.OperationGeneration &&
        ReferenceEquals(operation.Source, _operationCts);

    private bool IsCurrent(PollLease lease)
    {
        lock (_gate)
        {
            return IsCurrentLocked(lease);
        }
    }

    private bool IsCurrentLocked(PollLease lease) =>
        !_disposed &&
        lease.WorkspaceGeneration == _state.WorkspaceGeneration &&
        lease.Generation == _state.PollGeneration &&
        ReferenceEquals(lease.Source, _pollCts);

    private void PublishSnapshotLocked() => PublishStateLocked(SnapshotStateLocked(_state));

    private ArtifactEnrichmentWorkflowState SnapshotStateLocked(ArtifactEnrichmentWorkflowState state) =>
        state with
        {
            TrackedJobs = new Dictionary<Guid, ArtifactEnrichmentTrackedJob>(_trackedJobs),
            QueuedModuleProcessKeys = _queuedModuleProcessKeys.OrderBy(value => value, StringComparer.Ordinal).ToArray(),
            QueuedHandleProcessKeys = _queuedHandleProcessKeys.OrderBy(value => value, StringComparer.Ordinal).ToArray()
        };

    private void PublishStateLocked(ArtifactEnrichmentWorkflowState state)
    {
        _state = state;
        StateChanged?.Invoke(this, new ArtifactEnrichmentWorkflowStateChangedEventArgs(state));
    }

    private static void ValidateRequest(ArtifactEnrichmentQueueRequest request)
    {
        if (!request.CaptureModules && !request.CaptureHandles && !request.CapturePe)
        {
            throw new ArgumentException("At least one enrichment workload must be requested.", nameof(request));
        }

        if (!Enum.IsDefined(request.PeStringExtractionMode) ||
            !request.CapturePe && request.PeStringExtractionMode != PeStringExtractionMode.Deferred)
        {
            throw new ArgumentException(
                "PE string extraction mode must be a known value and is valid only with PE enrichment.",
                nameof(request));
        }

        if (string.IsNullOrWhiteSpace(request.Action))
        {
            throw new ArgumentException("A non-empty action description is required.", nameof(request));
        }

        if (request.Scope is ArtifactEnrichmentQueueScope.SelectedProcess or
            ArtifactEnrichmentQueueScope.SelectedProcessPe && request.Selection == null)
        {
            throw new ArgumentException("Selected-process enrichment requires selection context.", nameof(request));
        }

        if (request.Scope is not
                (ArtifactEnrichmentQueueScope.SelectedProcess or ArtifactEnrichmentQueueScope.SelectedProcessPe) &&
            request.Selection != null)
        {
            throw new ArgumentException(
                "Selection context is valid only for selected-process enrichment.",
                nameof(request));
        }

        var hasEntityIds = request.ProcessEntityIds is { Count: > 0 };
        var hasProcessKeys = request.ProcessKeys is { Count: > 0 };
        switch (request.Scope)
        {
            case ArtifactEnrichmentQueueScope.ExplicitAll:
                if (hasEntityIds || hasProcessKeys)
                {
                    throw new ArgumentException(
                        "Explicit all-process enrichment cannot also name process targets.",
                        nameof(request));
                }

                break;
            case ArtifactEnrichmentQueueScope.ExplicitProcessEntities:
                if (!ViewerAgentEvidenceActionService.TryNormalizeProcessEntityIds(
                        request.ProcessEntityIds,
                        out _,
                        out var entityError) ||
                    hasProcessKeys)
                {
                    throw new ArgumentException(
                        string.IsNullOrWhiteSpace(entityError)
                            ? "Explicit process-entity enrichment requires only process entity IDs."
                            : entityError,
                        nameof(request));
                }

                break;
            case ArtifactEnrichmentQueueScope.ExplicitProcessKeys:
                if (!ViewerAgentEvidenceActionService.TryNormalizeProcessKeys(
                        request.ProcessKeys,
                        out _,
                        out var keyError) ||
                    hasEntityIds)
                {
                    throw new ArgumentException(
                        string.IsNullOrWhiteSpace(keyError)
                            ? "Explicit process-key enrichment requires only exact process keys."
                            : keyError,
                        nameof(request));
                }

                break;
            default:
                if (hasEntityIds || hasProcessKeys)
                {
                    throw new ArgumentException(
                        "Explicit target arrays require an explicit enrichment scope.",
                        nameof(request));
                }

                break;
        }
    }

    private static string[] NormalizeExplicitEntityIds(IReadOnlyList<string>? values)
    {
        if (!ViewerAgentEvidenceActionService.TryNormalizeProcessEntityIds(values, out var normalized, out var error))
        {
            throw new ArgumentException(error, nameof(values));
        }

        return normalized;
    }

    private static string[] NormalizeExplicitProcessKeys(IReadOnlyList<string>? values)
    {
        if (!ViewerAgentEvidenceActionService.TryNormalizeProcessKeys(values, out var normalized, out var error))
        {
            throw new ArgumentException(error, nameof(values));
        }

        return normalized;
    }

    private static void EnsureEnrichmentJobKind(JobKind jobKind)
    {
        if (!EnrichmentWorkloadKinds.Contains(jobKind))
        {
            throw new ArgumentOutOfRangeException(nameof(jobKind), jobKind, "Unsupported enrichment job kind.");
        }
    }

    private static string DescribeJob(JobKind jobKind) => jobKind switch
    {
        JobKind.ModuleEnrichment => "artifact enrichment",
        JobKind.HandleEnrichment => "artifact enrichment",
        JobKind.PeAnalysis => "PE analysis",
        _ => "enrichment"
    };

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private sealed record OperationLease(
        long WorkspaceGeneration,
        long Generation,
        CancellationTokenSource Source)
    {
        public CancellationToken Token => Source.Token;
    }

    private sealed record PollLease(
        long WorkspaceGeneration,
        long Generation,
        CancellationTokenSource Source,
        IReadOnlyList<ArtifactEnrichmentTrackedJob> Jobs)
    {
        public CancellationToken Token => Source.Token;
    }
}
