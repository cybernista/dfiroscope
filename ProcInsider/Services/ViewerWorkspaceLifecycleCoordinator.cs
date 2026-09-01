using System.IO;
using ProcInsider.Models;

namespace ProcInsider.Services;

public enum ViewerWorkspaceLifecycleOutcome
{
    Succeeded,
    Failed,
    Canceled,
    Busy,
    Disposed
}

public enum ViewerWorkspaceLifecyclePhase
{
    Idle,
    ValidatingTarget,
    Switching,
    StoppingCurrent,
    DetachingCurrent,
    MaterializingTarget,
    Active,
    Failed,
    Disposed
}

public sealed record ViewerWorkspaceActivation(
    CaptureWorkspaceMode Mode,
    InvestigationSessionPaths SessionPaths,
    CapturePackageInfo? PackageInfo)
{
    public CaptureWorkspaceIdentity Identity { get; } = new(
        Mode,
        SessionPaths.SessionId,
        SessionPaths.SessionRoot);

    public bool IsDirectArchivedDatabase => Mode == CaptureWorkspaceMode.ArchivedCapture;
}

public sealed record ViewerWorkspaceLifecycleState(
    long Generation,
    ViewerWorkspaceLifecyclePhase Phase,
    CaptureWorkspaceIdentity Identity,
    ViewerWorkspaceActivation? ActiveWorkspace,
    string LastError)
{
    public static ViewerWorkspaceLifecycleState Initial { get; } = new(
        0,
        ViewerWorkspaceLifecyclePhase.Idle,
        CaptureWorkspaceIdentity.None,
        null,
        string.Empty);
}

public sealed class ViewerWorkspaceLifecycleStateChangedEventArgs(
    ViewerWorkspaceLifecycleState state) : EventArgs
{
    public ViewerWorkspaceLifecycleState State { get; } = state;
}

public sealed record ViewerWorkspaceLifecycleProgress(
    long Generation,
    ViewerWorkspaceLifecyclePhase Phase,
    int CurrentStep,
    int TotalSteps,
    string Message,
    bool IsIndeterminate = false);

/// <summary>
/// Identifies the narrow interval in which an exact current live-capture manifest is valid,
/// the Agent-owned SQLite file exists, and the Agent has not committed its evidence-format
/// metadata yet. Callers may retry this condition without changing the current workspace.
/// </summary>
public sealed class ViewerWorkspaceStartupPendingException : IOException
{
    public ViewerWorkspaceStartupPendingException(
        string message,
        string databasePath,
        CaptureCompatibilityAssessment compatibilityAssessment)
        : base(message)
    {
        DatabasePath = databasePath ?? string.Empty;
        CompatibilityAssessment = compatibilityAssessment ??
            throw new ArgumentNullException(nameof(compatibilityAssessment));
    }

    public string DatabasePath { get; }

    public CaptureCompatibilityAssessment CompatibilityAssessment { get; }
}

public sealed record ViewerWorkspaceLifecycleResult(
    ViewerWorkspaceLifecycleOutcome Outcome,
    long Generation,
    CaptureWorkspaceIdentity CurrentIdentity,
    ViewerWorkspaceActivation? ActiveWorkspace,
    bool PreviousWorkspaceReleased,
    string Error = "")
{
    public bool Succeeded => Outcome == ViewerWorkspaceLifecycleOutcome.Succeeded;
}

public sealed record ViewerWorkspaceTransitionCallbacks(
    Func<CancellationToken, Task> StopAndVerifyCurrentAsync,
    Func<CancellationToken, Task> DetachAndReleaseCurrentAsync,
    Func<ViewerWorkspaceActivation, CancellationToken, Task> MaterializeTargetAsync);

public interface IViewerWorkspaceLifecycleRuntime
{
    ViewerWorkspaceActivation PrepareArchivedCapture(string captureManifestPath);

    ViewerWorkspaceActivation PrepareExistingLiveCapture(string captureManifestPath);

    ViewerWorkspaceActivation CreateFreshLiveCapture();
}

public sealed class ViewerWorkspaceLifecycleRuntime : IViewerWorkspaceLifecycleRuntime
{
    public ViewerWorkspaceActivation PrepareExistingLiveCapture(string captureManifestPath)
    {
        var packageInfo = SessionPathService.InspectCapturePackage(
            captureManifestPath,
            CaptureOpenContext.ViewerLiveSnapshot,
            SqliteStagingStore.AssessExistingDatabase);
        if (IsAgentDatabaseInitializationPending(packageInfo))
        {
            throw new ViewerWorkspaceStartupPendingException(
                "The exact paired live workspace is waiting for the Agent to finish initializing evidence metadata.",
                packageInfo.LiveDatabasePath,
                packageInfo.CompatibilityAssessment);
        }

        var sessionPaths = SessionPathService.OpenExistingCapturePackage(
            captureManifestPath,
            CaptureOpenContext.ViewerLiveSnapshot,
            SqliteStagingStore.AssessExistingDatabase);
        if (!string.Equals(packageInfo.SessionId, sessionPaths.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The selected live capture manifest identity did not match its resolved session paths.");
        }

        return new ViewerWorkspaceActivation(
            CaptureWorkspaceMode.LiveCapture,
            sessionPaths,
            packageInfo);
    }

    private static bool IsAgentDatabaseInitializationPending(CapturePackageInfo packageInfo)
    {
        var assessment = packageInfo.CompatibilityAssessment;
        return packageInfo.HasLiveDatabase &&
               packageInfo.SchemaVersion == CaptureCompatibilityPolicy.CurrentManifestSchemaVersion &&
               packageInfo.EvidenceFormatVersion == CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion &&
               assessment.State == CaptureCompatibilityState.MissingVersionMetadata &&
               assessment.ManifestSchemaVersion == CaptureCompatibilityPolicy.CurrentManifestSchemaVersion &&
               assessment.EvidenceFormatVersion == null &&
               assessment.Context == CaptureOpenContext.ViewerLiveSnapshot &&
               assessment.ArtifactKind == CaptureArtifactKind.ViewerSnapshotCopy;
    }

    public ViewerWorkspaceActivation PrepareArchivedCapture(string captureManifestPath)
    {
        var packageInfo = SessionPathService.InspectCapturePackage(
            captureManifestPath,
            CaptureOpenContext.ViewerArchivedReadOnly,
            SqliteStagingStore.AssessExistingDatabase);
        var sessionPaths = SessionPathService.OpenExistingCapturePackage(
            captureManifestPath,
            CaptureOpenContext.ViewerArchivedReadOnly,
            SqliteStagingStore.AssessExistingDatabase);
        if (!string.Equals(packageInfo.SessionId, sessionPaths.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The selected capture manifest identity did not match its resolved session paths.");
        }

        return new ViewerWorkspaceActivation(
            CaptureWorkspaceMode.ArchivedCapture,
            sessionPaths,
            packageInfo);
    }

    public ViewerWorkspaceActivation CreateFreshLiveCapture()
    {
        var sessionPaths = SessionPathService.CreateDefaultSession();
        var packageInfo = SessionPathService.InspectCapturePackage(
            sessionPaths.SessionRoot,
            CaptureOpenContext.InspectionOnly,
            SqliteStagingStore.AssessExistingDatabase);
        if (!string.Equals(packageInfo.SessionId, sessionPaths.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The new live capture manifest identity did not match its requested session.");
        }

        return new ViewerWorkspaceActivation(
            CaptureWorkspaceMode.LiveCapture,
            sessionPaths,
            packageInfo);
    }
}

/// <summary>
/// Headless owner for manifest-first archived activation and fresh-live workspace/session
/// transitions. The WPF composition root supplies only feature-specific stop, detach, and
/// materialization callbacks; target preparation, transition state, identity, serialization,
/// generation, cancellation, and cleanup stay here.
/// </summary>
public sealed class ViewerWorkspaceLifecycleCoordinator : IDisposable
{
    private const int TransitionStepCount = 4;

    private readonly CaptureWorkspaceCoordinator _workspaceCoordinator;
    private readonly IViewerWorkspaceLifecycleRuntime _runtime;
    private readonly SemaphoreSlim _transitionGate = new(1, 1);
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly object _stateLock = new();
    private ViewerWorkspaceLifecycleState _state = ViewerWorkspaceLifecycleState.Initial;
    private ViewerWorkspaceActivation? _activeWorkspace;
    private bool _disposed;

    public ViewerWorkspaceLifecycleCoordinator(
        InvestigationSessionPaths initialSessionPaths,
        CapturePackageInfo? initialPackageInfo,
        IViewerWorkspaceLifecycleRuntime? runtime = null)
        : this(
            initialSessionPaths,
            initialPackageInfo,
            runtime,
            new CaptureWorkspaceCoordinator())
    {
    }

    internal ViewerWorkspaceLifecycleCoordinator(
        InvestigationSessionPaths initialSessionPaths,
        CapturePackageInfo? initialPackageInfo,
        IViewerWorkspaceLifecycleRuntime? runtime,
        CaptureWorkspaceCoordinator workspaceCoordinator)
    {
        ArgumentNullException.ThrowIfNull(initialSessionPaths);
        ArgumentNullException.ThrowIfNull(workspaceCoordinator);
        _runtime = runtime ?? new ViewerWorkspaceLifecycleRuntime();
        _workspaceCoordinator = workspaceCoordinator;
        _activeWorkspace = new ViewerWorkspaceActivation(
            CaptureWorkspaceMode.LiveCapture,
            initialSessionPaths,
            initialPackageInfo);
        _workspaceCoordinator.StateChanged += OnWorkspaceStateChanged;
        _workspaceCoordinator.Initialize(_activeWorkspace.Identity);
    }

    public event EventHandler<ViewerWorkspaceLifecycleStateChangedEventArgs>? StateChanged;

    public ViewerWorkspaceLifecycleState State
    {
        get
        {
            lock (_stateLock)
            {
                return _state;
            }
        }
    }

    public CaptureWorkspaceIdentity Current => _workspaceCoordinator.Current;

    public CaptureWorkspaceMode Mode => _workspaceCoordinator.Mode;

    public long Generation => _workspaceCoordinator.Generation;

    public ViewerWorkspaceActivation? ActiveWorkspace
    {
        get
        {
            lock (_stateLock)
            {
                return _activeWorkspace;
            }
        }
    }

    public Task<ViewerWorkspaceLifecycleResult> OpenArchivedCaptureAsync(
        string captureManifestPath,
        ViewerWorkspaceTransitionCallbacks callbacks,
        IProgress<ViewerWorkspaceLifecycleProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(captureManifestPath))
        {
            throw new ArgumentException("A capture manifest path is required.", nameof(captureManifestPath));
        }

        return RunTransitionAsync(
            () => _runtime.PrepareArchivedCapture(captureManifestPath),
            CaptureOpenCapability.ReadEvidence,
            callbacks,
            progress,
            cancellationToken);
    }

    public Task<ViewerWorkspaceLifecycleResult> OpenExistingLiveCaptureAsync(
        string captureManifestPath,
        ViewerWorkspaceTransitionCallbacks callbacks,
        IProgress<ViewerWorkspaceLifecycleProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(captureManifestPath))
        {
            throw new ArgumentException("A capture manifest path is required.", nameof(captureManifestPath));
        }

        return RunTransitionAsync(
            () => _runtime.PrepareExistingLiveCapture(captureManifestPath),
            CaptureOpenCapability.ReadEvidence,
            callbacks,
            progress,
            cancellationToken);
    }

    public async Task<ViewerWorkspaceActivation> PrepareExistingLiveCaptureAsync(
        string captureManifestPath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(captureManifestPath))
        {
            throw new ArgumentException("A capture manifest path is required.", nameof(captureManifestPath));
        }

        ObjectDisposedException.ThrowIf(IsDisposed(), this);
        var activation = await Task.Run(
            () => _runtime.PrepareExistingLiveCapture(captureManifestPath),
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        if (activation.Mode != CaptureWorkspaceMode.LiveCapture ||
            activation.PackageInfo?.CompatibilityAssessment is not { } compatibility ||
            !compatibility.Allows(CaptureOpenCapability.ReadEvidence))
        {
            throw new InvalidDataException(
                "The prospective local-agent workspace is not a compatible live capture package.");
        }

        return activation;
    }

    public Task<ViewerWorkspaceLifecycleResult> ActivatePreparedLiveCaptureAsync(
        ViewerWorkspaceActivation activation,
        ViewerWorkspaceTransitionCallbacks callbacks,
        IProgress<ViewerWorkspaceLifecycleProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activation);
        if (activation.Mode != CaptureWorkspaceMode.LiveCapture ||
            activation.PackageInfo?.CompatibilityAssessment is not { } compatibility ||
            !compatibility.Allows(CaptureOpenCapability.ReadEvidence))
        {
            throw new ArgumentException(
                "A prepared compatible live capture activation is required.",
                nameof(activation));
        }

        return RunTransitionAsync(
            () => activation,
            CaptureOpenCapability.ReadEvidence,
            callbacks,
            progress,
            cancellationToken);
    }

    public Task<ViewerWorkspaceLifecycleResult> CreateFreshLiveCaptureAsync(
        ViewerWorkspaceTransitionCallbacks callbacks,
        IProgress<ViewerWorkspaceLifecycleProgress>? progress = null,
        CancellationToken cancellationToken = default)
        => RunTransitionAsync(
            _runtime.CreateFreshLiveCapture,
            CaptureOpenCapability.InspectMetadata,
            callbacks,
            progress,
            cancellationToken);

    public void Dispose()
    {
        lock (_stateLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        _lifetimeCts.Cancel();
        PublishState(State with
        {
            Generation = Generation,
            Phase = ViewerWorkspaceLifecyclePhase.Disposed
        }, allowWhenDisposed: true);
    }

    private async Task<ViewerWorkspaceLifecycleResult> RunTransitionAsync(
        Func<ViewerWorkspaceActivation> prepareTarget,
        CaptureOpenCapability requiredCapability,
        ViewerWorkspaceTransitionCallbacks callbacks,
        IProgress<ViewerWorkspaceLifecycleProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(prepareTarget);
        ArgumentNullException.ThrowIfNull(callbacks);
        ArgumentNullException.ThrowIfNull(callbacks.StopAndVerifyCurrentAsync);
        ArgumentNullException.ThrowIfNull(callbacks.DetachAndReleaseCurrentAsync);
        ArgumentNullException.ThrowIfNull(callbacks.MaterializeTargetAsync);

        if (IsDisposed())
        {
            return CreateResult(
                ViewerWorkspaceLifecycleOutcome.Disposed,
                "The viewer workspace lifecycle coordinator is disposed.");
        }

        bool gateEntered;
        try
        {
            gateEntered = await _transitionGate.WaitAsync(0, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return CreateResult(
                ViewerWorkspaceLifecycleOutcome.Canceled,
                "The capture workspace transition was canceled before it started.");
        }

        if (!gateEntered)
        {
            return CreateResult(
                ViewerWorkspaceLifecycleOutcome.Busy,
                "Another capture workspace transition is already in progress.");
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetimeCts.Token);
        try
        {
            Report(
                ViewerWorkspaceLifecyclePhase.ValidatingTarget,
                1,
                "Validating the target capture workspace before releasing the current workspace...",
                progress,
                isIndeterminate: true);
            var activation = await Task.Run(prepareTarget, linkedCts.Token);
            linkedCts.Token.ThrowIfCancellationRequested();

            await _workspaceCoordinator.SwitchCompatibleAsync(
                activation.Identity,
                _ => Task.FromResult(
                    activation.PackageInfo?.CompatibilityAssessment
                    ?? throw new InvalidOperationException("The target capture compatibility metadata is unavailable.")),
                requiredCapability,
                async token =>
                {
                    Report(
                        ViewerWorkspaceLifecyclePhase.StoppingCurrent,
                        2,
                        "Stopping and verifying the current capture workspace...",
                        progress,
                        isIndeterminate: true);
                    await callbacks.StopAndVerifyCurrentAsync(token);
                },
                async token =>
                {
                    Report(
                        ViewerWorkspaceLifecyclePhase.DetachingCurrent,
                        3,
                        "Detaching and releasing the current capture workspace...",
                        progress,
                        isIndeterminate: true);
                    await callbacks.DetachAndReleaseCurrentAsync(token);
                },
                async token =>
                {
                    Report(
                        ViewerWorkspaceLifecyclePhase.MaterializingTarget,
                        4,
                        activation.IsDirectArchivedDatabase
                            ? "Binding the archived capture database read-only..."
                            : "Binding the fresh live capture session...",
                        progress,
                        isIndeterminate: true);
                    await callbacks.MaterializeTargetAsync(activation, token);
                    lock (_stateLock)
                    {
                        _activeWorkspace = activation;
                    }
                },
                linkedCts.Token);

            Report(
                ViewerWorkspaceLifecyclePhase.Active,
                TransitionStepCount,
                activation.IsDirectArchivedDatabase
                    ? "Archived capture workspace activated."
                    : "Fresh live capture workspace activated.",
                progress);
            return CreateResult(ViewerWorkspaceLifecycleOutcome.Succeeded, string.Empty);
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
            var disposed = IsDisposed();
            var message = disposed
                ? "The viewer workspace lifecycle coordinator was disposed."
                : "The capture workspace transition was canceled.";
            PublishFailure(message, disposed ? ViewerWorkspaceLifecyclePhase.Disposed : ViewerWorkspaceLifecyclePhase.Failed);
            return CreateResult(
                disposed ? ViewerWorkspaceLifecycleOutcome.Disposed : ViewerWorkspaceLifecycleOutcome.Canceled,
                message);
        }
        catch (Exception ex)
        {
            PublishFailure(ex.Message, ViewerWorkspaceLifecyclePhase.Failed);
            return CreateResult(ViewerWorkspaceLifecycleOutcome.Failed, ex.Message);
        }
        finally
        {
            _transitionGate.Release();
        }
    }

    private void OnWorkspaceStateChanged(object? sender, EventArgs e)
    {
        var identity = _workspaceCoordinator.Current;
        ViewerWorkspaceActivation? activeWorkspace;
        lock (_stateLock)
        {
            if (identity.Mode == CaptureWorkspaceMode.None)
            {
                _activeWorkspace = null;
            }

            activeWorkspace = _activeWorkspace;
        }

        var phase = identity.Mode switch
        {
            CaptureWorkspaceMode.Switching => ViewerWorkspaceLifecyclePhase.Switching,
            CaptureWorkspaceMode.None => ViewerWorkspaceLifecyclePhase.Idle,
            _ => ViewerWorkspaceLifecyclePhase.Active
        };
        PublishState(State with
        {
            Generation = _workspaceCoordinator.Generation,
            Phase = phase,
            Identity = identity,
            ActiveWorkspace = activeWorkspace,
            LastError = string.Empty
        });
    }

    private void Report(
        ViewerWorkspaceLifecyclePhase phase,
        int currentStep,
        string message,
        IProgress<ViewerWorkspaceLifecycleProgress>? progress,
        bool isIndeterminate = false)
    {
        PublishState(State with
        {
            Generation = Generation,
            Phase = phase,
            Identity = Current,
            ActiveWorkspace = ActiveWorkspace,
            LastError = string.Empty
        });
        progress?.Report(new ViewerWorkspaceLifecycleProgress(
            Generation,
            phase,
            currentStep,
            TransitionStepCount,
            message,
            isIndeterminate));
    }

    private void PublishFailure(string error, ViewerWorkspaceLifecyclePhase phase)
    {
        PublishState(State with
        {
            Generation = Generation,
            Phase = phase,
            Identity = Current,
            ActiveWorkspace = ActiveWorkspace,
            LastError = error
        }, allowWhenDisposed: phase == ViewerWorkspaceLifecyclePhase.Disposed);
    }

    private ViewerWorkspaceLifecycleResult CreateResult(
        ViewerWorkspaceLifecycleOutcome outcome,
        string error)
    {
        var current = Current;
        return new ViewerWorkspaceLifecycleResult(
            outcome,
            Generation,
            current,
            ActiveWorkspace,
            current.Mode == CaptureWorkspaceMode.None,
            error);
    }

    private void PublishState(
        ViewerWorkspaceLifecycleState state,
        bool allowWhenDisposed = false)
    {
        EventHandler<ViewerWorkspaceLifecycleStateChangedEventArgs>? handler;
        lock (_stateLock)
        {
            if (_disposed && !allowWhenDisposed)
            {
                return;
            }

            _state = state;
            handler = StateChanged;
        }

        handler?.Invoke(this, new ViewerWorkspaceLifecycleStateChangedEventArgs(state));
    }

    private bool IsDisposed()
    {
        lock (_stateLock)
        {
            return _disposed;
        }
    }
}
