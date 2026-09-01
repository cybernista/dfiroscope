using System.Diagnostics;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services;

public enum ViewerSnapshotFollowMode
{
    Manual,
    Follow
}

public enum ViewerSnapshotFollowPhase
{
    ManualPinned,
    FollowingClean,
    FollowingDirtyWaiting,
    Preparing,
    Publishing,
    Backoff,
    Unavailable,
    Disposed
}

public enum ViewerSnapshotFollowTrigger
{
    Initial,
    Manual,
    Automatic
}

public enum ViewerSnapshotFollowOutcome
{
    Succeeded,
    Failed,
    Canceled,
    Superseded,
    Skipped,
    Unavailable,
    Disposed
}

public enum ViewerSnapshotRefreshRuntimePhase
{
    PreparingCandidate,
    PreparingPresentation,
    ActivatingDatabase,
    PublishingPresentation,
    StartingAnalysis
}

public sealed record ViewerSnapshotFollowWorkspace(
    long Generation,
    string SessionId,
    CaptureWorkspaceMode Mode,
    bool IsCompatible,
    bool IsSwitching = false,
    bool IsShuttingDown = false)
{
    public static ViewerSnapshotFollowWorkspace None { get; } = new(
        0,
        string.Empty,
        CaptureWorkspaceMode.None,
        IsCompatible: false);

    public static ViewerSnapshotFollowWorkspace FromLifecycleState(
        ViewerWorkspaceLifecycleState state,
        CaptureCompatibilityAssessment? fallbackAssessment = null,
        bool isShuttingDown = false)
    {
        ArgumentNullException.ThrowIfNull(state);
        var mode = state.Identity.Mode;
        var assessment = state.ActiveWorkspace?.PackageInfo?.CompatibilityAssessment ??
                         fallbackAssessment;
        return new ViewerSnapshotFollowWorkspace(
            state.Generation,
            state.Identity.SessionId,
            mode,
            IsCompatible: mode == CaptureWorkspaceMode.LiveCapture ||
                assessment?.Allows(CaptureOpenCapability.ReadEvidence) == true,
            IsSwitching: state.Phase == ViewerWorkspaceLifecyclePhase.Switching ||
                mode == CaptureWorkspaceMode.Switching,
            IsShuttingDown: isShuttingDown);
    }

    public bool CanRefresh =>
        Generation >= 0 &&
        !string.IsNullOrWhiteSpace(SessionId) &&
        Mode == CaptureWorkspaceMode.LiveCapture &&
        IsCompatible &&
        !IsSwitching &&
        !IsShuttingDown;
}

public sealed record ViewerSnapshotRefreshRuntimeProgress(
    ViewerSnapshotRefreshRuntimePhase Phase,
    string Message);

public sealed record ViewerSnapshotRefreshRuntimeRequest(
    ViewerSnapshotFollowTrigger Trigger,
    long WorkspaceGeneration,
    string SessionId,
    DatabaseChangedNotification? TargetCursor);

public sealed record ViewerSnapshotRefreshRuntimeResult(
    ViewerSnapshotFollowOutcome Outcome,
    long WorkspaceGeneration,
    DatabaseChangedNotification? PublishedCursor,
    bool CandidatePrepared,
    bool DatabaseActivated,
    bool ViewPublished,
    SnapshotAnalysisPreparationState AnalysisState,
    DateTime? SnapshotUtc,
    double BackgroundElapsedMilliseconds,
    double PublicationElapsedMilliseconds,
    string Error = "")
{
    public bool Succeeded =>
        Outcome == ViewerSnapshotFollowOutcome.Succeeded &&
        CandidatePrepared &&
        DatabaseActivated &&
        ViewPublished;

    public static ViewerSnapshotRefreshRuntimeResult Failed(
        ViewerSnapshotRefreshRuntimeRequest request,
        string error) => new(
            ViewerSnapshotFollowOutcome.Failed,
            request.WorkspaceGeneration,
            request.TargetCursor,
            CandidatePrepared: false,
            DatabaseActivated: false,
            ViewPublished: false,
            SnapshotAnalysisPreparationState.NotStarted,
            SnapshotUtc: null,
            BackgroundElapsedMilliseconds: 0,
            PublicationElapsedMilliseconds: 0,
            error);
}

public sealed record ViewerSnapshotFollowDiagnostics(
    long RequestCount,
    long AutomaticRequestCount,
    long ManualRequestCount,
    long SuccessCount,
    long FailureCount,
    long CoalescedCursorCount,
    int ActiveExecutionCount,
    int MaximumObservedConcurrency,
    ViewerSnapshotFollowTrigger? LastTrigger,
    ViewerSnapshotFollowOutcome? LastOutcome,
    double LastElapsedMilliseconds,
    double LastBackgroundElapsedMilliseconds,
    double LastPublicationElapsedMilliseconds,
    DateTime? LastRetryUtc,
    string LastError);

public sealed record ViewerSnapshotFollowState(
    long StateGeneration,
    ViewerSnapshotFollowMode Mode,
    ViewerSnapshotFollowPhase Phase,
    ViewerSnapshotFollowWorkspace Workspace,
    TimeSpan FollowInterval,
    DatabaseChangedNotification? ObservedCursor,
    DatabaseChangedNotification? AcknowledgedCursor,
    bool IsCursorSourceAvailable,
    bool IsDirty,
    bool IsAnalysisPreparing,
    long PendingCommittedWorkItemCount,
    long PendingCommittedRowCount,
    int ConsecutiveAutomaticFailures,
    DateTime? NextEligibleUtc,
    DateTime? LastPublishedSnapshotUtc,
    bool IsInitialRefreshComplete,
    ViewerSnapshotFollowTrigger? ActiveTrigger,
    ViewerSnapshotFollowDiagnostics Diagnostics,
    string StatusText)
{
    public static ViewerSnapshotFollowState Initial { get; } = new(
        0,
        ViewerSnapshotFollowMode.Manual,
        ViewerSnapshotFollowPhase.ManualPinned,
        ViewerSnapshotFollowWorkspace.None,
        ViewerSnapshotFollowCoordinator.MinimumFollowInterval,
        null,
        null,
        IsCursorSourceAvailable: false,
        IsDirty: false,
        IsAnalysisPreparing: false,
        PendingCommittedWorkItemCount: 0,
        PendingCommittedRowCount: 0,
        ConsecutiveAutomaticFailures: 0,
        NextEligibleUtc: null,
        LastPublishedSnapshotUtc: null,
        IsInitialRefreshComplete: false,
        ActiveTrigger: null,
        new ViewerSnapshotFollowDiagnostics(
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            null,
            null,
            0,
            0,
            0,
            null,
            string.Empty),
        "Manual snapshot mode is pinned.");
}

public sealed class ViewerSnapshotFollowStateChangedEventArgs(
    ViewerSnapshotFollowState state) : EventArgs
{
    public ViewerSnapshotFollowState State { get; } = state;
}

public sealed record ViewerSnapshotFollowResult(
    ViewerSnapshotFollowOutcome Outcome,
    ViewerSnapshotFollowTrigger Trigger,
    long WorkspaceGeneration,
    DatabaseChangedNotification? TargetCursor,
    DatabaseChangedNotification? AcknowledgedCursor,
    ViewerSnapshotRefreshRuntimeResult? RuntimeResult,
    string Error = "")
{
    public bool Succeeded => Outcome == ViewerSnapshotFollowOutcome.Succeeded;
}

public interface IViewerSnapshotFollowRuntime
{
    Task<ViewerSnapshotRefreshRuntimeResult> RefreshAsync(
        ViewerSnapshotRefreshRuntimeRequest request,
        IProgress<ViewerSnapshotRefreshRuntimeProgress>? progress,
        CancellationToken cancellationToken);
}

public sealed class DelegateViewerSnapshotFollowRuntime(
    Func<ViewerSnapshotRefreshRuntimeRequest,
        IProgress<ViewerSnapshotRefreshRuntimeProgress>?,
        CancellationToken,
        Task<ViewerSnapshotRefreshRuntimeResult>> refreshAsync) : IViewerSnapshotFollowRuntime
{
    private readonly Func<ViewerSnapshotRefreshRuntimeRequest,
        IProgress<ViewerSnapshotRefreshRuntimeProgress>?,
        CancellationToken,
        Task<ViewerSnapshotRefreshRuntimeResult>> _refreshAsync =
            refreshAsync ?? throw new ArgumentNullException(nameof(refreshAsync));

    public Task<ViewerSnapshotRefreshRuntimeResult> RefreshAsync(
        ViewerSnapshotRefreshRuntimeRequest request,
        IProgress<ViewerSnapshotRefreshRuntimeProgress>? progress,
        CancellationToken cancellationToken) =>
        _refreshAsync(request, progress, cancellationToken);
}

public interface IViewerSnapshotFollowClock
{
    DateTime UtcNow { get; }

    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public sealed class SystemViewerSnapshotFollowClock : IViewerSnapshotFollowClock
{
    public DateTime UtcNow => DateTime.UtcNow;

    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        delay <= TimeSpan.Zero
            ? Task.CompletedTask
            : Task.Delay(delay, cancellationToken);
}

/// <summary>
/// WPF-free state owner for Manual-versus-Follow snapshot scheduling. It coalesces
/// durable writer cursors, enforces one active refresh and the one-minute floor,
/// defers automatic work while analysis is preparing, and acknowledges evidence only
/// after the runtime reports a completely published presentation.
/// </summary>
public sealed class ViewerSnapshotFollowCoordinator : IDisposable
{
    public static readonly TimeSpan MinimumFollowInterval = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan MaximumAutomaticBackoff = TimeSpan.FromMinutes(15);

    private const long MaximumPendingMetadataCount = 1_000_000_000;

    private readonly object _gate = new();
    private readonly IViewerSnapshotFollowRuntime _runtime;
    private readonly IViewerSnapshotFollowClock _clock;
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private ViewerSnapshotFollowState _state = ViewerSnapshotFollowState.Initial;
    private CancellationTokenSource _workspaceCts = new();
    private CancellationTokenSource? _scheduleCts;
    private long _workspaceVersion;
    private long _operationGeneration;
    private bool _disposed;

    public ViewerSnapshotFollowCoordinator(
        IViewerSnapshotFollowRuntime runtime,
        IViewerSnapshotFollowClock? clock = null,
        TimeSpan? followInterval = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _clock = clock ?? new SystemViewerSnapshotFollowClock();
        _state = _state with
        {
            FollowInterval = ClampFollowInterval(followInterval ?? MinimumFollowInterval)
        };
    }

    public event EventHandler<ViewerSnapshotFollowStateChangedEventArgs>? StateChanged;

    public ViewerSnapshotFollowState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public void BindWorkspace(ViewerSnapshotFollowWorkspace workspace)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        CancellationTokenSource? priorWorkspace = null;
        CancellationTokenSource? priorSchedule = null;
        ViewerSnapshotFollowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            var changed = workspace.Generation != _state.Workspace.Generation ||
                          workspace.Mode != _state.Workspace.Mode ||
                          !string.Equals(
                              workspace.SessionId,
                              _state.Workspace.SessionId,
                              StringComparison.Ordinal);
            if (changed)
            {
                _workspaceVersion++;
                _operationGeneration++;
                priorWorkspace = _workspaceCts;
                _workspaceCts = new CancellationTokenSource();
                priorSchedule = TakeScheduleLocked();
                state = NextStateLocked(_state with
                {
                    Mode = ViewerSnapshotFollowMode.Manual,
                    Phase = workspace.CanRefresh
                        ? ViewerSnapshotFollowPhase.ManualPinned
                        : ViewerSnapshotFollowPhase.Unavailable,
                    Workspace = workspace,
                    ObservedCursor = null,
                    AcknowledgedCursor = null,
                    IsCursorSourceAvailable = false,
                    IsDirty = false,
                    PendingCommittedWorkItemCount = 0,
                    PendingCommittedRowCount = 0,
                    ConsecutiveAutomaticFailures = 0,
                    NextEligibleUtc = null,
                    LastPublishedSnapshotUtc = null,
                    IsInitialRefreshComplete = false,
                    ActiveTrigger = null,
                    Diagnostics = _state.Diagnostics with { ActiveExecutionCount = 0 },
                    StatusText = workspace.CanRefresh
                        ? "Workspace changed; Manual snapshot mode is pinned."
                        : "Snapshot refresh is unavailable for the current workspace."
                });
            }
            else
            {
                state = NextStateLocked(_state with
                {
                    Workspace = workspace,
                    Phase = ResolveIdlePhaseLocked(_state with { Workspace = workspace }),
                    StatusText = workspace.CanRefresh
                        ? _state.StatusText
                        : "Snapshot refresh is unavailable for the current workspace."
                });
                if (!workspace.CanRefresh)
                {
                    priorSchedule = TakeScheduleLocked();
                }
            }
        }

        CancelOnly(priorSchedule);
        CancelAndDispose(priorWorkspace);
        RaiseStateChanged(state);
        ScheduleAutomaticIfNeeded();
    }

    public void SetFollowEnabled(bool enabled)
    {
        CancellationTokenSource? priorSchedule = null;
        ViewerSnapshotFollowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            priorSchedule = TakeScheduleLocked();
            if (!enabled)
            {
                state = NextStateLocked(_state with
                {
                    Mode = ViewerSnapshotFollowMode.Manual,
                    Phase = ViewerSnapshotFollowPhase.ManualPinned,
                    NextEligibleUtc = null,
                    StatusText = "Manual snapshot mode is pinned."
                });
            }
            else
            {
                var nextEligible = _state.IsDirty
                    ? MaxUtc(
                        _state.NextEligibleUtc,
                        _clock.UtcNow + _state.FollowInterval)
                    : null;
                var proposed = _state with
                {
                    Mode = ViewerSnapshotFollowMode.Follow,
                    NextEligibleUtc = nextEligible
                };
                state = NextStateLocked(proposed with
                {
                    Phase = ResolveIdlePhaseLocked(proposed),
                    StatusText = ResolveStatusTextLocked(proposed)
                });
            }
        }

        CancelOnly(priorSchedule);
        RaiseStateChanged(state);
        ScheduleAutomaticIfNeeded();
    }

    public TimeSpan SetFollowInterval(TimeSpan interval)
    {
        CancellationTokenSource? priorSchedule;
        ViewerSnapshotFollowState state;
        var clamped = ClampFollowInterval(interval);
        lock (_gate)
        {
            if (_disposed)
            {
                return clamped;
            }

            priorSchedule = TakeScheduleLocked();
            DateTime? nextEligible = _state.IsDirty && _state.Mode == ViewerSnapshotFollowMode.Follow
                ? _clock.UtcNow + clamped
                : null;
            state = NextStateLocked(_state with
            {
                FollowInterval = clamped,
                NextEligibleUtc = nextEligible,
                StatusText = _state.Mode == ViewerSnapshotFollowMode.Follow
                    ? $"Follow interval is {clamped.TotalSeconds:N0} seconds."
                    : _state.StatusText
            });
        }

        CancelOnly(priorSchedule);
        RaiseStateChanged(state);
        ScheduleAutomaticIfNeeded();
        return clamped;
    }

    public void SetCursorSourceAvailable(bool available)
    {
        CancellationTokenSource? priorSchedule = null;
        ViewerSnapshotFollowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            if (!available)
            {
                priorSchedule = TakeScheduleLocked();
            }

            var proposed = _state with { IsCursorSourceAvailable = available };
            state = NextStateLocked(proposed with
            {
                Phase = ResolveIdlePhaseLocked(proposed),
                StatusText = ResolveStatusTextLocked(proposed)
            });
        }

        CancelOnly(priorSchedule);
        RaiseStateChanged(state);
        ScheduleAutomaticIfNeeded();
    }

    public void SetAnalysisPreparationState(bool isPreparing)
    {
        CancellationTokenSource? priorSchedule = null;
        ViewerSnapshotFollowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            if (isPreparing)
            {
                priorSchedule = TakeScheduleLocked();
            }

            var proposed = _state with { IsAnalysisPreparing = isPreparing };
            state = NextStateLocked(proposed with
            {
                Phase = ResolveIdlePhaseLocked(proposed),
                StatusText = isPreparing && proposed.Mode == ViewerSnapshotFollowMode.Follow && proposed.IsDirty
                    ? "New evidence is pending until snapshot analysis reaches a safe terminal boundary."
                    : ResolveStatusTextLocked(proposed)
            });
        }

        CancelOnly(priorSchedule);
        RaiseStateChanged(state);
        ScheduleAutomaticIfNeeded();
    }

    public void ObserveCursor(DatabaseChangedNotification? cursor)
    {
        if (!DatabaseChangeCursor.IsAvailable(cursor))
        {
            SetCursorSourceAvailable(false);
            return;
        }

        ViewerSnapshotFollowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            var relation = DatabaseChangeCursor.Compare(cursor, _state.ObservedCursor);
            if (relation is DatabaseChangeCursorRelation.Older or DatabaseChangeCursorRelation.Same)
            {
                if (!_state.IsCursorSourceAvailable)
                {
                    var available = _state with { IsCursorSourceAvailable = true };
                    state = NextStateLocked(available with
                    {
                        Phase = ResolveIdlePhaseLocked(available),
                        StatusText = ResolveStatusTextLocked(available)
                    });
                }
                else
                {
                    return;
                }
            }
            else
            {
                var dirty = IsNewerThanAcknowledged(cursor, _state.AcknowledgedCursor);
                var pending = CalculatePendingMetadata(cursor, _state.AcknowledgedCursor);
                var diagnostics = _state.Diagnostics with
                {
                    CoalescedCursorCount = _state.ObservedCursor == null
                        ? _state.Diagnostics.CoalescedCursorCount
                        : _state.Diagnostics.CoalescedCursorCount + 1
                };
                DateTime? nextEligible = dirty && _state.Mode == ViewerSnapshotFollowMode.Follow
                    ? _state.NextEligibleUtc ?? _clock.UtcNow + _state.FollowInterval
                    : _state.NextEligibleUtc;
                var proposed = _state with
                {
                    ObservedCursor = cursor,
                    IsCursorSourceAvailable = true,
                    IsDirty = dirty,
                    PendingCommittedWorkItemCount = pending.WorkItems,
                    PendingCommittedRowCount = pending.Rows,
                    NextEligibleUtc = nextEligible,
                    Diagnostics = diagnostics
                };
                state = NextStateLocked(proposed with
                {
                    Phase = ResolveIdlePhaseLocked(proposed),
                    StatusText = ResolveStatusTextLocked(proposed)
                });
            }
        }

        RaiseStateChanged(state);
        ScheduleAutomaticIfNeeded();
    }

    public Task<ViewerSnapshotFollowResult> RefreshManualAsync(
        CancellationToken cancellationToken = default) =>
        RunRefreshAsync(ViewerSnapshotFollowTrigger.Manual, waitForActive: true, cancellationToken);

    public Task<ViewerSnapshotFollowResult> RefreshInitialAsync(
        CancellationToken cancellationToken = default) =>
        RunRefreshAsync(ViewerSnapshotFollowTrigger.Initial, waitForActive: false, cancellationToken);

    public void Dispose()
    {
        CancellationTokenSource? schedule;
        CancellationTokenSource workspace;
        ViewerSnapshotFollowState state;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _workspaceVersion++;
            schedule = TakeScheduleLocked();
            workspace = _workspaceCts;
            state = NextStateLocked(_state with
            {
                Phase = ViewerSnapshotFollowPhase.Disposed,
                ActiveTrigger = null,
                NextEligibleUtc = null,
                StatusText = "Snapshot follow coordination is disposed."
            });
        }

        _lifetimeCts.Cancel();
        CancelOnly(schedule);
        CancelAndDispose(workspace);
        _lifetimeCts.Dispose();
        RaiseStateChanged(state);
    }

    private async Task<ViewerSnapshotFollowResult> RunRefreshAsync(
        ViewerSnapshotFollowTrigger trigger,
        bool waitForActive,
        CancellationToken cancellationToken)
    {
        CancellationToken workspaceToken;
        long workspaceVersion;
        lock (_gate)
        {
            if (_disposed)
            {
                return CreateTerminalResult(
                    ViewerSnapshotFollowOutcome.Disposed,
                    trigger,
                    "Snapshot follow coordination is disposed.");
            }

            workspaceToken = _workspaceCts.Token;
            workspaceVersion = _workspaceVersion;
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            workspaceToken,
            _lifetimeCts.Token);
        var gateEntered = false;
        try
        {
            if (waitForActive)
            {
                await _operationGate.WaitAsync(linkedCts.Token).ConfigureAwait(false);
                gateEntered = true;
            }
            else
            {
                gateEntered = await _operationGate.WaitAsync(0, linkedCts.Token).ConfigureAwait(false);
                if (!gateEntered)
                {
                    return CreateTerminalResult(
                        ViewerSnapshotFollowOutcome.Skipped,
                        trigger,
                        "Another snapshot refresh already owns the single-flight operation.");
                }
            }

            ViewerSnapshotRefreshRuntimeRequest request;
            long operationGeneration;
            CancellationTokenSource? priorSchedule;
            ViewerSnapshotFollowState preparingState;
            lock (_gate)
            {
                if (_disposed)
                {
                    return CreateTerminalResult(
                        ViewerSnapshotFollowOutcome.Disposed,
                        trigger,
                        "Snapshot follow coordination is disposed.");
                }

                if (workspaceVersion != _workspaceVersion)
                {
                    return CreateTerminalResult(
                        ViewerSnapshotFollowOutcome.Superseded,
                        trigger,
                        "The workspace changed before snapshot refresh could start.");
                }

                if (!_state.Workspace.CanRefresh)
                {
                    return CreateTerminalResult(
                        ViewerSnapshotFollowOutcome.Unavailable,
                        trigger,
                        "Snapshot refresh is unavailable for the current workspace.");
                }

                if (trigger == ViewerSnapshotFollowTrigger.Automatic && !CanRunAutomaticLocked())
                {
                    return CreateTerminalResult(
                        ViewerSnapshotFollowOutcome.Skipped,
                        trigger,
                        "Automatic snapshot refresh is not currently eligible.");
                }

                if (trigger == ViewerSnapshotFollowTrigger.Initial &&
                    _state.IsInitialRefreshComplete)
                {
                    return CreateTerminalResult(
                        ViewerSnapshotFollowOutcome.Skipped,
                        trigger,
                        "The initial process-inventory snapshot has already been published.");
                }

                priorSchedule = TakeScheduleLocked();
                operationGeneration = ++_operationGeneration;
                request = new ViewerSnapshotRefreshRuntimeRequest(
                    trigger,
                    _state.Workspace.Generation,
                    _state.Workspace.SessionId,
                    _state.ObservedCursor);
                var diagnostics = _state.Diagnostics with
                {
                    RequestCount = _state.Diagnostics.RequestCount + 1,
                    AutomaticRequestCount = _state.Diagnostics.AutomaticRequestCount +
                        (trigger == ViewerSnapshotFollowTrigger.Automatic ? 1 : 0),
                    ManualRequestCount = _state.Diagnostics.ManualRequestCount +
                        (trigger == ViewerSnapshotFollowTrigger.Manual ? 1 : 0),
                    ActiveExecutionCount = 1,
                    MaximumObservedConcurrency = Math.Max(
                        _state.Diagnostics.MaximumObservedConcurrency,
                        1),
                    LastTrigger = trigger,
                    LastError = string.Empty
                };
                preparingState = NextStateLocked(_state with
                {
                    Phase = ViewerSnapshotFollowPhase.Preparing,
                    ActiveTrigger = trigger,
                    NextEligibleUtc = null,
                    Diagnostics = diagnostics,
                    StatusText = trigger == ViewerSnapshotFollowTrigger.Automatic
                        ? "Preparing a coherent snapshot update in the background."
                        : trigger == ViewerSnapshotFollowTrigger.Initial
                            ? "Publishing the first complete process inventory."
                            : "Preparing a manual coherent snapshot update."
                });
            }

            CancelOnly(priorSchedule);
            RaiseStateChanged(preparingState);

            var stopwatch = Stopwatch.StartNew();
            ViewerSnapshotRefreshRuntimeResult runtimeResult;
            try
            {
                var progress = new InlineProgress<ViewerSnapshotRefreshRuntimeProgress>(update =>
                    ApplyRuntimeProgress(operationGeneration, workspaceVersion, update));
                runtimeResult = await _runtime
                    .RefreshAsync(request, progress, linkedCts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
            {
                stopwatch.Stop();
                var superseded = workspaceVersion != GetWorkspaceVersion();
                return CompleteCanceledOperation(
                    trigger,
                    request,
                    operationGeneration,
                    superseded,
                    stopwatch.Elapsed);
            }
            catch (Exception ex)
            {
                runtimeResult = ViewerSnapshotRefreshRuntimeResult.Failed(request, ex.Message);
            }

            stopwatch.Stop();
            return CompleteOperation(
                trigger,
                request,
                runtimeResult,
                operationGeneration,
                workspaceVersion,
                stopwatch.Elapsed);
        }
        catch (OperationCanceledException)
        {
            var superseded = workspaceVersion != GetWorkspaceVersion();
            return CreateTerminalResult(
                superseded
                    ? ViewerSnapshotFollowOutcome.Superseded
                    : _disposed
                        ? ViewerSnapshotFollowOutcome.Disposed
                        : ViewerSnapshotFollowOutcome.Canceled,
                trigger,
                superseded
                    ? "The workspace changed before snapshot refresh could start."
                    : "Snapshot refresh was canceled.");
        }
        finally
        {
            if (gateEntered)
            {
                _operationGate.Release();
            }

            ScheduleAutomaticIfNeeded();
        }
    }

    private ViewerSnapshotFollowResult CompleteOperation(
        ViewerSnapshotFollowTrigger trigger,
        ViewerSnapshotRefreshRuntimeRequest request,
        ViewerSnapshotRefreshRuntimeResult runtimeResult,
        long operationGeneration,
        long workspaceVersion,
        TimeSpan elapsed)
    {
        ViewerSnapshotFollowState state;
        ViewerSnapshotFollowOutcome outcome;
        string error;
        lock (_gate)
        {
            if (_disposed)
            {
                return CreateTerminalResult(
                    ViewerSnapshotFollowOutcome.Disposed,
                    trigger,
                    "Snapshot follow coordination is disposed.");
            }

            if (workspaceVersion != _workspaceVersion ||
                operationGeneration != _operationGeneration ||
                runtimeResult.WorkspaceGeneration != _state.Workspace.Generation)
            {
                return CreateTerminalResult(
                    ViewerSnapshotFollowOutcome.Superseded,
                    trigger,
                    "The snapshot result belongs to an obsolete workspace generation.");
            }

            var publishedCursorMatches = DoesPublishedCursorMatchTarget(
                runtimeResult.PublishedCursor,
                request.TargetCursor);
            var fullySucceeded = runtimeResult.Succeeded && publishedCursorMatches;
            var diagnostics = _state.Diagnostics with
            {
                ActiveExecutionCount = 0,
                LastOutcome = fullySucceeded
                    ? ViewerSnapshotFollowOutcome.Succeeded
                    : runtimeResult.Succeeded
                        ? ViewerSnapshotFollowOutcome.Failed
                        : runtimeResult.Outcome,
                LastElapsedMilliseconds = elapsed.TotalMilliseconds,
                LastBackgroundElapsedMilliseconds = runtimeResult.BackgroundElapsedMilliseconds,
                LastPublicationElapsedMilliseconds = runtimeResult.PublicationElapsedMilliseconds,
                LastError = fullySucceeded
                    ? string.Empty
                    : publishedCursorMatches
                        ? runtimeResult.Error
                        : "Snapshot publication did not confirm the exact requested durable cursor."
            };

            if (fullySucceeded)
            {
                var acknowledged = request.TargetCursor;
                var dirty = IsNewerThanAcknowledged(_state.ObservedCursor, acknowledged);
                var pending = CalculatePendingMetadata(_state.ObservedCursor, acknowledged);
                DateTime? nextEligible = dirty && _state.Mode == ViewerSnapshotFollowMode.Follow
                    ? _clock.UtcNow + _state.FollowInterval
                    : null;
                var proposed = _state with
                {
                    AcknowledgedCursor = acknowledged,
                    IsDirty = dirty,
                    PendingCommittedWorkItemCount = pending.WorkItems,
                    PendingCommittedRowCount = pending.Rows,
                    ConsecutiveAutomaticFailures = 0,
                    NextEligibleUtc = nextEligible,
                    LastPublishedSnapshotUtc = runtimeResult.SnapshotUtc,
                    IsInitialRefreshComplete =
                        _state.IsInitialRefreshComplete ||
                        trigger == ViewerSnapshotFollowTrigger.Initial,
                    ActiveTrigger = null,
                    Diagnostics = diagnostics with
                    {
                        SuccessCount = diagnostics.SuccessCount + 1,
                        LastRetryUtc = null
                    }
                };
                state = NextStateLocked(proposed with
                {
                    Phase = ResolveIdlePhaseLocked(proposed),
                    StatusText = dirty
                        ? "Snapshot published; newer committed evidence remains pending."
                        : "Snapshot publication is current with the latest acknowledged cursor."
                });
                outcome = ViewerSnapshotFollowOutcome.Succeeded;
                error = string.Empty;
            }
            else
            {
                var failures = trigger == ViewerSnapshotFollowTrigger.Automatic
                    ? _state.ConsecutiveAutomaticFailures + 1
                    : _state.ConsecutiveAutomaticFailures;
                DateTime? retryUtc = _state.Mode == ViewerSnapshotFollowMode.Follow && _state.IsDirty
                    ? _clock.UtcNow + (trigger == ViewerSnapshotFollowTrigger.Automatic
                        ? CalculateBackoff(_state.FollowInterval, failures)
                        : _state.FollowInterval)
                    : null;
                var proposed = _state with
                {
                    ConsecutiveAutomaticFailures = failures,
                    NextEligibleUtc = retryUtc,
                    ActiveTrigger = null,
                    Diagnostics = diagnostics with
                    {
                        FailureCount = diagnostics.FailureCount + 1,
                        LastRetryUtc = retryUtc
                    }
                };
                state = NextStateLocked(proposed with
                {
                    Phase = _state.Mode == ViewerSnapshotFollowMode.Follow && _state.IsDirty
                        ? ViewerSnapshotFollowPhase.Backoff
                        : ResolveIdlePhaseLocked(proposed),
                    StatusText = retryUtc.HasValue
                        ? $"Snapshot publication failed; the previous view remains active and retry is scheduled for {retryUtc.Value:O}."
                        : "Snapshot publication failed; the previous view remains active."
                });
                outcome = runtimeResult.Outcome == ViewerSnapshotFollowOutcome.Succeeded
                    ? ViewerSnapshotFollowOutcome.Failed
                    : runtimeResult.Outcome;
                error = publishedCursorMatches
                    ? string.IsNullOrWhiteSpace(runtimeResult.Error)
                        ? "Snapshot publication did not complete."
                        : runtimeResult.Error
                    : "Snapshot publication did not confirm the exact requested durable cursor.";
            }
        }

        RaiseStateChanged(state);
        return new ViewerSnapshotFollowResult(
            outcome,
            trigger,
            request.WorkspaceGeneration,
            request.TargetCursor,
            state.AcknowledgedCursor,
            runtimeResult,
            error);
    }

    private ViewerSnapshotFollowResult CompleteCanceledOperation(
        ViewerSnapshotFollowTrigger trigger,
        ViewerSnapshotRefreshRuntimeRequest request,
        long operationGeneration,
        bool superseded,
        TimeSpan elapsed)
    {
        ViewerSnapshotFollowState? state = null;
        lock (_gate)
        {
            if (!_disposed && operationGeneration == _operationGeneration)
            {
                var diagnostics = _state.Diagnostics with
                {
                    ActiveExecutionCount = 0,
                    LastOutcome = superseded
                        ? ViewerSnapshotFollowOutcome.Superseded
                        : ViewerSnapshotFollowOutcome.Canceled,
                    LastElapsedMilliseconds = elapsed.TotalMilliseconds,
                    LastError = superseded
                        ? "The workspace changed during snapshot refresh."
                        : "Snapshot refresh was canceled."
                };
                var proposed = _state with
                {
                    ActiveTrigger = null,
                    Diagnostics = diagnostics
                };
                state = NextStateLocked(proposed with
                {
                    Phase = ResolveIdlePhaseLocked(proposed),
                    StatusText = diagnostics.LastError
                });
            }
        }

        if (state != null)
        {
            RaiseStateChanged(state);
        }

        return new ViewerSnapshotFollowResult(
            superseded
                ? ViewerSnapshotFollowOutcome.Superseded
                : ViewerSnapshotFollowOutcome.Canceled,
            trigger,
            request.WorkspaceGeneration,
            request.TargetCursor,
            state?.AcknowledgedCursor,
            null,
            superseded
                ? "The workspace changed during snapshot refresh."
                : "Snapshot refresh was canceled.");
    }

    private void ApplyRuntimeProgress(
        long operationGeneration,
        long workspaceVersion,
        ViewerSnapshotRefreshRuntimeProgress progress)
    {
        ViewerSnapshotFollowState state;
        lock (_gate)
        {
            if (_disposed ||
                operationGeneration != _operationGeneration ||
                workspaceVersion != _workspaceVersion)
            {
                return;
            }

            state = NextStateLocked(_state with
            {
                Phase = progress.Phase == ViewerSnapshotRefreshRuntimePhase.PublishingPresentation
                    ? ViewerSnapshotFollowPhase.Publishing
                    : ViewerSnapshotFollowPhase.Preparing,
                StatusText = progress.Message
            });
        }

        RaiseStateChanged(state);
    }

    private void ScheduleAutomaticIfNeeded()
    {
        CancellationTokenSource? priorSchedule = null;
        CancellationTokenSource? schedule = null;
        DateTime dueUtc = default;
        long workspaceVersion = 0;
        ViewerSnapshotFollowState? state = null;
        lock (_gate)
        {
            if (_disposed || !CanRunAutomaticLocked() || _state.Diagnostics.ActiveExecutionCount > 0)
            {
                return;
            }

            priorSchedule = TakeScheduleLocked();
            dueUtc = _state.NextEligibleUtc ?? _clock.UtcNow + _state.FollowInterval;
            schedule = CancellationTokenSource.CreateLinkedTokenSource(
                _workspaceCts.Token,
                _lifetimeCts.Token);
            _scheduleCts = schedule;
            workspaceVersion = _workspaceVersion;
            var proposed = _state with { NextEligibleUtc = dueUtc };
            state = NextStateLocked(proposed with
            {
                Phase = _state.ConsecutiveAutomaticFailures > 0
                    ? ViewerSnapshotFollowPhase.Backoff
                    : ViewerSnapshotFollowPhase.FollowingDirtyWaiting,
                StatusText = _state.ConsecutiveAutomaticFailures > 0
                    ? $"Automatic snapshot retry is scheduled for {dueUtc:O}."
                    : $"New evidence is coalesced for the next eligible snapshot at {dueUtc:O}."
            });
        }

        CancelOnly(priorSchedule);
        if (state != null)
        {
            RaiseStateChanged(state);
        }

        _ = RunScheduledRefreshAsync(schedule!, workspaceVersion, dueUtc);
    }

    private async Task RunScheduledRefreshAsync(
        CancellationTokenSource schedule,
        long workspaceVersion,
        DateTime dueUtc)
    {
        try
        {
            var delay = dueUtc - _clock.UtcNow;
            await _clock.DelayAsync(delay, schedule.Token).ConfigureAwait(false);
            schedule.Token.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed ||
                    workspaceVersion != _workspaceVersion ||
                    !ReferenceEquals(_scheduleCts, schedule))
                {
                    return;
                }

                _scheduleCts = null;
            }

            await RunRefreshAsync(
                ViewerSnapshotFollowTrigger.Automatic,
                waitForActive: false,
                schedule.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Rescheduling, workspace supersession, Manual mode, and disposal cancel waits.
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_scheduleCts, schedule))
                {
                    _scheduleCts = null;
                }
            }

            schedule.Dispose();
        }
    }

    private bool CanRunAutomaticLocked() =>
        !_disposed &&
        _state.Mode == ViewerSnapshotFollowMode.Follow &&
        _state.Workspace.CanRefresh &&
        _state.IsCursorSourceAvailable &&
        _state.IsDirty &&
        !_state.IsAnalysisPreparing;

    private ViewerSnapshotFollowPhase ResolveIdlePhaseLocked(ViewerSnapshotFollowState state)
    {
        if (!state.Workspace.CanRefresh)
        {
            return ViewerSnapshotFollowPhase.Unavailable;
        }

        if (state.Mode == ViewerSnapshotFollowMode.Manual)
        {
            return ViewerSnapshotFollowPhase.ManualPinned;
        }

        if (!state.IsCursorSourceAvailable)
        {
            return ViewerSnapshotFollowPhase.Unavailable;
        }

        return state.IsDirty
            ? state.ConsecutiveAutomaticFailures > 0
                ? ViewerSnapshotFollowPhase.Backoff
                : ViewerSnapshotFollowPhase.FollowingDirtyWaiting
            : ViewerSnapshotFollowPhase.FollowingClean;
    }

    private string ResolveStatusTextLocked(ViewerSnapshotFollowState state)
    {
        if (!state.Workspace.CanRefresh)
        {
            return "Snapshot refresh is unavailable for the current workspace.";
        }

        if (state.Mode == ViewerSnapshotFollowMode.Manual)
        {
            return state.IsDirty
                ? "New committed evidence is available; Manual mode keeps the current snapshot pinned."
                : "Manual snapshot mode is pinned.";
        }

        if (!state.IsCursorSourceAvailable)
        {
            return "Follow is unavailable until a verified current agent supplies a durable change cursor.";
        }

        if (state.IsAnalysisPreparing && state.IsDirty)
        {
            return "New evidence is pending until snapshot analysis reaches a safe terminal boundary.";
        }

        return state.IsDirty
            ? "New committed evidence is waiting for the next eligible snapshot."
            : "Follow is current with the latest acknowledged cursor.";
    }

    private ViewerSnapshotFollowState NextStateLocked(ViewerSnapshotFollowState state)
    {
        _state = state with { StateGeneration = _state.StateGeneration + 1 };
        return _state;
    }

    private CancellationTokenSource? TakeScheduleLocked()
    {
        var schedule = _scheduleCts;
        _scheduleCts = null;
        return schedule;
    }

    private long GetWorkspaceVersion()
    {
        lock (_gate)
        {
            return _workspaceVersion;
        }
    }

    private ViewerSnapshotFollowResult CreateTerminalResult(
        ViewerSnapshotFollowOutcome outcome,
        ViewerSnapshotFollowTrigger trigger,
        string error)
    {
        var state = State;
        return new ViewerSnapshotFollowResult(
            outcome,
            trigger,
            state.Workspace.Generation,
            state.ObservedCursor,
            state.AcknowledgedCursor,
            null,
            error);
    }

    private void RaiseStateChanged(ViewerSnapshotFollowState state)
    {
        StateChanged?.Invoke(this, new ViewerSnapshotFollowStateChangedEventArgs(state));
    }

    private static void CancelAndDispose(CancellationTokenSource? source)
    {
        if (source == null)
        {
            return;
        }

        try
        {
            source.Cancel();
        }
        finally
        {
            source.Dispose();
        }
    }

    private static void CancelOnly(CancellationTokenSource? source)
    {
        source?.Cancel();
    }

    private static bool IsNewerThanAcknowledged(
        DatabaseChangedNotification? observed,
        DatabaseChangedNotification? acknowledged) =>
        DatabaseChangeCursor.Compare(observed, acknowledged) is
            DatabaseChangeCursorRelation.Newer or
            DatabaseChangeCursorRelation.WriterInstanceChanged;

    private static bool DoesPublishedCursorMatchTarget(
        DatabaseChangedNotification? published,
        DatabaseChangedNotification? target)
    {
        var targetAvailable = DatabaseChangeCursor.IsAvailable(target);
        var publishedAvailable = DatabaseChangeCursor.IsAvailable(published);
        if (!targetAvailable || !publishedAvailable)
        {
            return targetAvailable == publishedAvailable;
        }

        return DatabaseChangeCursor.Compare(published, target) == DatabaseChangeCursorRelation.Same;
    }

    private static (long WorkItems, long Rows) CalculatePendingMetadata(
        DatabaseChangedNotification? observed,
        DatabaseChangedNotification? acknowledged)
    {
        if (!DatabaseChangeCursor.IsAvailable(observed))
        {
            return (0, 0);
        }

        var sameWriter = DatabaseChangeCursor.IsAvailable(acknowledged) &&
                         observed!.WriterInstanceId == acknowledged!.WriterInstanceId;
        var workItems = sameWriter
            ? Math.Max(0, observed!.CommittedWorkItemCount - acknowledged!.CommittedWorkItemCount)
            : Math.Max(0, observed!.CommittedWorkItemCount);
        var rows = sameWriter
            ? Math.Max(0, observed.CommittedRowCount - acknowledged!.CommittedRowCount)
            : Math.Max(0, observed.CommittedRowCount);
        return (
            Math.Min(workItems, MaximumPendingMetadataCount),
            Math.Min(rows, MaximumPendingMetadataCount));
    }

    private static TimeSpan ClampFollowInterval(TimeSpan interval)
    {
        if (interval <= TimeSpan.Zero)
        {
            return MinimumFollowInterval;
        }

        return interval < MinimumFollowInterval
            ? MinimumFollowInterval
            : interval;
    }

    private static TimeSpan CalculateBackoff(TimeSpan interval, int failureCount)
    {
        var exponent = Math.Clamp(failureCount - 1, 0, 8);
        var multiplier = 1L << exponent;
        var ticks = interval.Ticks > MaximumAutomaticBackoff.Ticks / multiplier
            ? MaximumAutomaticBackoff.Ticks
            : interval.Ticks * multiplier;
        return TimeSpan.FromTicks(Math.Clamp(
            ticks,
            interval.Ticks,
            MaximumAutomaticBackoff.Ticks));
    }

    private static DateTime? MaxUtc(DateTime? left, DateTime right) =>
        !left.HasValue || left.Value < right ? right : left;

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        private readonly Action<T> _report = report ?? throw new ArgumentNullException(nameof(report));

        public void Report(T value) => _report(value);
    }
}
