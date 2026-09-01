using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;

namespace ProcInsider.Services;

public enum LiveSnapshotRefreshOutcome
{
    Succeeded,
    Failed,
    Canceled,
    Superseded,
    Disposed
}

public enum LiveSnapshotRefreshPhase
{
    Idle,
    CreatingSnapshot,
    OpeningCandidate,
    PreparingPresentation,
    ActivatingSnapshot,
    PublishingPresentation,
    SnapshotActive,
    Failed,
    Disposed
}

public enum SnapshotAnalysisPreparationState
{
    NotStarted,
    Preparing,
    Ready,
    Canceled,
    Failed
}

public sealed record LiveSnapshotRefreshRequest(
    string LiveDatabasePath,
    string SnapshotDatabasePath,
    string AnnotationDatabasePath,
    string EvidenceSessionId,
    CaptureManifestCompatibilityMetadata? Manifest = null,
    bool IncludeProcessRisk = true);

public sealed record LiveSnapshotRefreshProgress(
    long Generation,
    LiveSnapshotRefreshPhase Phase,
    int CurrentStep,
    int TotalSteps,
    string Message,
    bool IsIndeterminate = false);

public sealed record LiveSnapshotRefreshCoordinatorState(
    long Generation,
    LiveSnapshotRefreshPhase Phase,
    string ActiveDatabasePath,
    DateTime? ActiveSnapshotUtc,
    SnapshotAnalysisPreparationState AnalysisState,
    string AnalysisDatabasePath,
    bool IsDirectArchivedDatabase,
    int AnalysisCompletedGroups,
    int AnalysisTotalGroups,
    double AnalysisElapsedMilliseconds,
    long AnalysisAllocatedBytes,
    string AnalysisText,
    string LastError)
{
    public static LiveSnapshotRefreshCoordinatorState Initial { get; } = new(
        0,
        LiveSnapshotRefreshPhase.Idle,
        string.Empty,
        null,
        SnapshotAnalysisPreparationState.NotStarted,
        string.Empty,
        false,
        0,
        0,
        0,
        0,
        string.Empty,
        string.Empty);
}

public sealed class LiveSnapshotRefreshCoordinatorStateChangedEventArgs(
    LiveSnapshotRefreshCoordinatorState state) : EventArgs
{
    public LiveSnapshotRefreshCoordinatorState State { get; } = state;
}

public sealed record LiveSnapshotRefreshResult(
    LiveSnapshotRefreshOutcome Outcome,
    long Generation,
    LiveSnapshotDatabaseBinding? Binding,
    SqliteSnapshotResult? Snapshot,
    string Error = "")
{
    public bool Succeeded => Outcome == LiveSnapshotRefreshOutcome.Succeeded;
}

public sealed record LiveSnapshotSourceRetryPolicy(
    int MaximumAttempts,
    TimeSpan Delay)
{
    public static LiveSnapshotSourceRetryPolicy Default { get; } = new(
        MaximumAttempts: 21,
        Delay: TimeSpan.FromMilliseconds(500));

    public LiveSnapshotSourceRetryPolicy Validate()
    {
        if (MaximumAttempts is < 1 or > 121)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumAttempts),
                "Live snapshot source attempts must be between 1 and 121.");
        }

        if (Delay < TimeSpan.Zero || Delay > TimeSpan.FromSeconds(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(Delay),
                "Live snapshot source retry delay must be between zero and five seconds.");
        }

        return this;
    }
}

public sealed record LiveSnapshotCandidateContext(
    long Generation,
    LiveSnapshotRefreshRequest Request,
    SqliteSnapshotResult Snapshot,
    LiveSnapshotDatabaseBinding Binding);

public sealed record LiveSnapshotActivationContext(
    long Generation,
    LiveSnapshotRefreshRequest Request,
    SqliteSnapshotResult Snapshot,
    LiveSnapshotDatabaseBinding Binding);

/// <summary>
/// Owns the maintenance connection and read/query services for one activated live snapshot.
/// The query services themselves open bounded connections per operation; the maintenance owner
/// is suspended only while a staged replacement is promoted or rolled back.
/// </summary>
public sealed class LiveSnapshotDatabaseBinding : IDisposable
{
    private readonly Func<IDisposable?>? _ownerFactory;
    private readonly Action<IDisposable?>? _beforeOwnerSuspend;
    private IDisposable? _owner;
    private bool _disposed;

    public LiveSnapshotDatabaseBinding(
        string databasePath,
        SqliteSnapshotResult snapshot,
        SqliteStagingQueryService? queryService = null,
        ProcessListingService? listingService = null,
        IDisposable? owner = null,
        Func<IDisposable?>? ownerFactory = null,
        Action<IDisposable?>? beforeOwnerSuspend = null)
    {
        DatabasePath = Path.GetFullPath(databasePath);
        Snapshot = snapshot;
        QueryService = queryService;
        ListingService = listingService;
        _owner = owner;
        _ownerFactory = ownerFactory;
        _beforeOwnerSuspend = beforeOwnerSuspend;
    }

    public string DatabasePath { get; }

    public SqliteSnapshotResult Snapshot { get; }

    public SqliteStagingQueryService? QueryService { get; }

    public ProcessListingService? ListingService { get; }

    internal void SuspendOwner()
    {
        ThrowIfDisposed();
        if (_owner == null)
        {
            return;
        }

        _beforeOwnerSuspend?.Invoke(_owner);
        _owner.Dispose();
        _owner = null;
    }

    internal void ResumeOwner()
    {
        ThrowIfDisposed();
        _owner ??= _ownerFactory?.Invoke();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _owner?.Dispose();
        _owner = null;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

public interface ILiveSnapshotPromotion : IDisposable
{
    void Commit();

    void Rollback();
}

public interface ILiveSnapshotRefreshRuntime
{
    Task<SqliteSnapshotResult> CreateCandidateAsync(
        LiveSnapshotRefreshRequest request,
        string candidatePath,
        CancellationToken cancellationToken);

    LiveSnapshotDatabaseBinding OpenBinding(
        LiveSnapshotRefreshRequest request,
        SqliteSnapshotResult snapshot);

    ILiveSnapshotPromotion PromoteCandidate(string candidatePath, string activeSnapshotPath);

    Task PrepareAnalysisAsync(
        string databasePath,
        string evidenceSessionId,
        bool isDirectArchivedDatabase,
        IProgress<SqliteAnalysisIndexBuildProgress> progress,
        CancellationToken cancellationToken);

    void DeleteCandidate(string candidatePath);
}

public sealed class SqliteLiveSnapshotRefreshRuntime : ILiveSnapshotRefreshRuntime
{
    private readonly SqliteSnapshotService _snapshotService;

    public SqliteLiveSnapshotRefreshRuntime(SqliteSnapshotService? snapshotService = null)
    {
        _snapshotService = snapshotService ?? new SqliteSnapshotService();
    }

    public Task<SqliteSnapshotResult> CreateCandidateAsync(
        LiveSnapshotRefreshRequest request,
        string candidatePath,
        CancellationToken cancellationToken)
        => _snapshotService.CreateSnapshotAsync(
            request.LiveDatabasePath,
            candidatePath,
            request.EvidenceSessionId,
            request.Manifest,
            cancellationToken);

    public LiveSnapshotDatabaseBinding OpenBinding(
        LiveSnapshotRefreshRequest request,
        SqliteSnapshotResult snapshot)
    {
        SqliteStagingStore OpenStore()
        {
            var store = SqliteAnalysisIndexMaintenanceStoreFactory.Create(
                snapshot.SnapshotPath,
                request.EvidenceSessionId);
            try
            {
                store.OpenExistingForViewerSnapshot();
                return store;
            }
            catch
            {
                store.Dispose();
                throw;
            }
        }

        var owner = OpenStore();
        try
        {
            var queryService = new SqliteStagingQueryService(
                snapshot.SnapshotPath,
                request.AnnotationDatabasePath,
                openContext: CaptureOpenContext.ViewerLiveSnapshot,
                manifest: request.Manifest,
                expectedEvidenceSessionId: request.EvidenceSessionId);
            var listingService = new ProcessListingService(
                queryService,
                request.IncludeProcessRisk);
            return new LiveSnapshotDatabaseBinding(
                snapshot.SnapshotPath,
                snapshot,
                queryService,
                listingService,
                owner,
                OpenStore,
                existingOwner =>
                {
                    if (existingOwner is not SqliteStagingStore store)
                    {
                        return;
                    }

                    try
                    {
                        store.CheckpointViewerSnapshotWalForReplacement(request.LiveDatabasePath);
                    }
                    catch
                    {
                        // Promotion still has a file-level rollback. A checkpoint diagnostic is best-effort.
                    }
                });
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    public ILiveSnapshotPromotion PromoteCandidate(string candidatePath, string activeSnapshotPath)
        => new FileSnapshotPromotion(candidatePath, activeSnapshotPath);

    public Task PrepareAnalysisAsync(
        string databasePath,
        string evidenceSessionId,
        bool isDirectArchivedDatabase,
        IProgress<SqliteAnalysisIndexBuildProgress> progress,
        CancellationToken cancellationToken)
        => Task.Run(() =>
        {
            using var store = SqliteAnalysisIndexMaintenanceStoreFactory.Create(
                databasePath,
                evidenceSessionId);
            if (isDirectArchivedDatabase)
            {
                store.OpenExistingForArchivedAnalysisMaintenance();
            }
            else
            {
                store.OpenExistingForViewerSnapshot();
            }

            store.EnsureAnalysisIndexes(progress, cancellationToken);
        }, cancellationToken);

    public void DeleteCandidate(string candidatePath)
    {
        DeleteIfExists(candidatePath);
        DeleteIfExists($"{candidatePath}-wal");
        DeleteIfExists($"{candidatePath}-shm");
    }

    private sealed class FileSnapshotPromotion : ILiveSnapshotPromotion
    {
        private readonly string _activeSnapshotPath;
        private readonly string _backupPath;
        private readonly bool _hadActiveSnapshot;
        private bool _completed;

        public FileSnapshotPromotion(string candidatePath, string activeSnapshotPath)
        {
            candidatePath = Path.GetFullPath(candidatePath);
            _activeSnapshotPath = Path.GetFullPath(activeSnapshotPath);
            if (!File.Exists(candidatePath))
            {
                throw new FileNotFoundException("The staged viewer snapshot candidate does not exist.", candidatePath);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(_activeSnapshotPath) ?? AppContext.BaseDirectory);
            _backupPath = $"{_activeSnapshotPath}.{Guid.NewGuid():N}.rollback";
            _hadActiveSnapshot = File.Exists(_activeSnapshotPath);
            DeleteSidecars(_activeSnapshotPath);
            if (_hadActiveSnapshot)
            {
                File.Replace(candidatePath, _activeSnapshotPath, _backupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(candidatePath, _activeSnapshotPath);
            }
        }

        public void Commit()
        {
            if (_completed)
            {
                return;
            }

            _completed = true;
            try
            {
                DeleteIfExists(_backupPath);
            }
            catch
            {
                // A stale rollback copy is safer than failing an already-open activated snapshot.
            }
        }

        public void Rollback()
        {
            if (_completed)
            {
                return;
            }

            _completed = true;
            DeleteSidecars(_activeSnapshotPath);
            if (_hadActiveSnapshot && File.Exists(_backupPath))
            {
                var discardedPath = $"{_activeSnapshotPath}.{Guid.NewGuid():N}.discarded";
                if (File.Exists(_activeSnapshotPath))
                {
                    File.Replace(_backupPath, _activeSnapshotPath, discardedPath, ignoreMetadataErrors: true);
                    DeleteIfExists(discardedPath);
                }
                else
                {
                    File.Move(_backupPath, _activeSnapshotPath);
                }
            }
            else
            {
                DeleteIfExists(_activeSnapshotPath);
            }

            DeleteIfExists(_backupPath);
            DeleteSidecars(_activeSnapshotPath);
        }

        public void Dispose()
        {
            Rollback();
        }
    }

    private static void DeleteSidecars(string databasePath)
    {
        DeleteIfExists($"{databasePath}-wal");
        DeleteIfExists($"{databasePath}-shm");
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}

/// <summary>
/// Headless owner for live snapshot refresh, activation, analysis preparation, supersession,
/// rollback, and cleanup. MainViewModel projects its immutable state into WPF properties.
/// </summary>
public sealed class LiveSnapshotRefreshCoordinator : IDisposable, IAsyncDisposable
{
    private const int RefreshStepCount = 6;

    private readonly ILiveSnapshotRefreshRuntime _runtime;
    private readonly LiveSnapshotSourceRetryPolicy _sourceRetryPolicy;
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly object _stateLock = new();
    private CancellationTokenSource? _refreshCts;
    private CancellationTokenSource? _analysisCts;
    private Task? _analysisTask;
    private long _refreshGeneration;
    private long _analysisGeneration;
    private LiveSnapshotDatabaseBinding? _activeBinding;
    private LiveSnapshotRefreshCoordinatorState _state = LiveSnapshotRefreshCoordinatorState.Initial;
    private bool _disposed;

    public LiveSnapshotRefreshCoordinator(
        ILiveSnapshotRefreshRuntime? runtime = null,
        LiveSnapshotSourceRetryPolicy? sourceRetryPolicy = null,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null)
    {
        _runtime = runtime ?? new SqliteLiveSnapshotRefreshRuntime();
        _sourceRetryPolicy = (sourceRetryPolicy ?? LiveSnapshotSourceRetryPolicy.Default).Validate();
        _delayAsync = delayAsync ?? Task.Delay;
    }

    public event EventHandler<LiveSnapshotRefreshCoordinatorStateChangedEventArgs>? StateChanged;

    public LiveSnapshotRefreshCoordinatorState State
    {
        get
        {
            lock (_stateLock)
            {
                return _state;
            }
        }
    }

    public LiveSnapshotDatabaseBinding? ActiveBinding
    {
        get
        {
            lock (_stateLock)
            {
                return _activeBinding;
            }
        }
    }

    public DateTime? ActiveSnapshotUtc => State.ActiveSnapshotUtc;

    public async Task<LiveSnapshotRefreshResult> RefreshAsync(
        LiveSnapshotRefreshRequest request,
        IProgress<LiveSnapshotRefreshProgress>? progress = null,
        Func<CancellationToken, Task>? beforeActivation = null,
        Func<LiveSnapshotCandidateContext, CancellationToken, Task>? preparePresentation = null,
        Func<LiveSnapshotActivationContext, CancellationToken, Task>? publishPresentation = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (IsDisposed())
        {
            return new LiveSnapshotRefreshResult(
                LiveSnapshotRefreshOutcome.Disposed,
                Volatile.Read(ref _refreshGeneration),
                ActiveBinding,
                ActiveBinding?.Snapshot,
                "The live snapshot refresh coordinator is disposed.");
        }

        var generation = Interlocked.Increment(ref _refreshGeneration);
        var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var previousCts = Interlocked.Exchange(ref _refreshCts, linkedCts);
        previousCts?.Cancel();
        var gateEntered = false;
        var candidatePath = BuildCandidatePath(request.SnapshotDatabasePath, generation);

        try
        {
            await _refreshGate.WaitAsync(linkedCts.Token);
            gateEntered = true;
            linkedCts.Token.ThrowIfCancellationRequested();
            EnsureCurrentGeneration(generation, linkedCts.Token);

            ReportRefresh(
                generation,
                LiveSnapshotRefreshPhase.CreatingSnapshot,
                1,
                "Creating a WAL-safe viewer snapshot candidate...",
                progress);
            var candidate = await CreateCandidateWithRetryAsync(
                generation,
                request,
                candidatePath,
                progress,
                linkedCts.Token);
            EnsureCurrentGeneration(generation, linkedCts.Token);

            ReportRefresh(
                generation,
                LiveSnapshotRefreshPhase.OpeningCandidate,
                2,
                "Validating the viewer snapshot candidate...",
                progress,
                isIndeterminate: true);
            using (var validationBinding = _runtime.OpenBinding(request, candidate))
            {
                // Opening the complete binding proves both maintenance and read/query paths before promotion.
                if (preparePresentation != null)
                {
                    ReportRefresh(
                        generation,
                        LiveSnapshotRefreshPhase.PreparingPresentation,
                        3,
                        "Preparing the coherent viewer presentation from the validated candidate...",
                        progress,
                        isIndeterminate: true);
                    await preparePresentation(
                        new LiveSnapshotCandidateContext(
                            generation,
                            request,
                            candidate,
                            validationBinding),
                        linkedCts.Token);
                    EnsureCurrentGeneration(generation, linkedCts.Token);
                }

                validationBinding.SuspendOwner();
            }

            EnsureCurrentGeneration(generation, linkedCts.Token);
            await CancelAnalysisPreparationCoreAsync(
                "Snapshot analysis preparation was superseded by a newer refresh.");
            if (beforeActivation != null)
            {
                await beforeActivation(linkedCts.Token);
            }

            ReportRefresh(
                generation,
                LiveSnapshotRefreshPhase.ActivatingSnapshot,
                4,
                "Activating the validated viewer snapshot...",
                progress);
            var previousBinding = ActiveBinding;
            LiveSnapshotDatabaseBinding? replacementBinding = null;
            ILiveSnapshotPromotion? promotion = null;
            try
            {
                previousBinding?.SuspendOwner();
                try
                {
                    promotion = _runtime.PromoteCandidate(
                        candidate.SnapshotPath,
                        request.SnapshotDatabasePath);
                }
                catch
                {
                    previousBinding?.ResumeOwner();
                    throw;
                }

                var activatedSnapshot = candidate with
                {
                    SnapshotPath = Path.GetFullPath(request.SnapshotDatabasePath)
                };
                replacementBinding = _runtime.OpenBinding(request, activatedSnapshot);
                EnsureCurrentGeneration(generation, linkedCts.Token);

                lock (_stateLock)
                {
                    ThrowIfDisposed();
                    _activeBinding = replacementBinding;
                }

                if (publishPresentation != null)
                {
                    ReportRefresh(
                        generation,
                        LiveSnapshotRefreshPhase.PublishingPresentation,
                        5,
                        "Publishing the prepared viewer presentation...",
                        progress);
                    await publishPresentation(
                        new LiveSnapshotActivationContext(
                            generation,
                            request,
                            activatedSnapshot,
                            replacementBinding),
                        linkedCts.Token);
                    EnsureCurrentGeneration(generation, linkedCts.Token);
                }

                promotion.Commit();
                previousBinding?.Dispose();
                promotion.Dispose();
                promotion = null;
                replacementBinding = null;

                PublishState(State with
                {
                    Generation = generation,
                    Phase = LiveSnapshotRefreshPhase.SnapshotActive,
                    ActiveDatabasePath = activatedSnapshot.SnapshotPath,
                    ActiveSnapshotUtc = activatedSnapshot.SnapshotUtc,
                    LastError = string.Empty
                });
                ReportRefresh(
                    generation,
                    LiveSnapshotRefreshPhase.SnapshotActive,
                    6,
                    "Viewer snapshot activated; analysis preparation is starting in the background.",
                    progress);

                StartAnalysisPreparation(
                    activatedSnapshot.SnapshotPath,
                    request.EvidenceSessionId,
                    isDirectArchivedDatabase: false,
                    generation);
                return new LiveSnapshotRefreshResult(
                    LiveSnapshotRefreshOutcome.Succeeded,
                    generation,
                    ActiveBinding,
                    activatedSnapshot);
            }
            catch
            {
                replacementBinding?.Dispose();
                promotion?.Rollback();
                promotion?.Dispose();
                previousBinding?.ResumeOwner();
                lock (_stateLock)
                {
                    _activeBinding = previousBinding;
                }

                throw;
            }
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
            var superseded = generation != Volatile.Read(ref _refreshGeneration);
            return new LiveSnapshotRefreshResult(
                superseded ? LiveSnapshotRefreshOutcome.Superseded : LiveSnapshotRefreshOutcome.Canceled,
                generation,
                ActiveBinding,
                ActiveBinding?.Snapshot,
                superseded
                    ? "The live snapshot refresh was superseded by a newer refresh or workspace transition."
                    : "The live snapshot refresh was canceled.");
        }
        catch (Exception ex)
        {
            var current = State;
            PublishState(current with
            {
                Generation = generation,
                Phase = LiveSnapshotRefreshPhase.Failed,
                LastError = ex.Message
            });
            return new LiveSnapshotRefreshResult(
                LiveSnapshotRefreshOutcome.Failed,
                generation,
                ActiveBinding,
                ActiveBinding?.Snapshot,
                ex.Message);
        }
        finally
        {
            try
            {
                _runtime.DeleteCandidate(candidatePath);
            }
            catch
            {
                // Candidate cleanup is bounded and best-effort; active state is already decided.
            }

            if (gateEntered)
            {
                _refreshGate.Release();
            }

            Interlocked.CompareExchange(ref _refreshCts, null, linkedCts);
            linkedCts.Dispose();
        }
    }

    public async Task StartAnalysisPreparationAsync(
        string databasePath,
        string evidenceSessionId,
        bool isDirectArchivedDatabase)
    {
        ThrowIfDisposed();
        await CancelAnalysisPreparationCoreAsync(
            "Analysis preparation was superseded by a newer workspace request.");
        StartAnalysisPreparation(
            Path.GetFullPath(databasePath),
            evidenceSessionId,
            isDirectArchivedDatabase,
            Volatile.Read(ref _refreshGeneration));
    }

    public Task CancelAnalysisPreparationAsync()
        => CancelAnalysisPreparationCoreAsync("Analysis preparation was canceled.");

    private async Task CancelAnalysisPreparationCoreAsync(string cancellationText)
    {
        CancellationTokenSource? cts;
        Task? task;
        long cancellationGeneration;
        lock (_stateLock)
        {
            cts = _analysisCts;
            task = _analysisTask;
            cancellationGeneration = ++_analysisGeneration;
            cts?.Cancel();
        }

        if (task != null)
        {
            try
            {
                await task;
            }
            catch (OperationCanceledException)
            {
                // Supersession and workspace release intentionally cancel preparation.
            }
        }

        var publishCanceled = false;
        lock (_stateLock)
        {
            if (ReferenceEquals(_analysisCts, cts))
            {
                _analysisCts = null;
                _analysisTask = null;
                publishCanceled = cts != null;
            }
            else if (cts != null &&
                     _analysisCts == null &&
                     _analysisGeneration == cancellationGeneration)
            {
                publishCanceled = true;
            }
        }

        cts?.Dispose();
        if (publishCanceled && !IsDisposed())
        {
            var state = State;
            var diagnostics = FormatAnalysisDiagnostics(
                state.AnalysisElapsedMilliseconds,
                state.AnalysisAllocatedBytes);
            PublishState(state with
            {
                AnalysisState = SnapshotAnalysisPreparationState.Canceled,
                AnalysisText = $"{cancellationText}{diagnostics}",
                LastError = string.Empty
            });
        }
    }

    public async Task ReleaseActiveBindingAsync()
    {
        if (IsDisposed())
        {
            return;
        }

        Interlocked.Increment(ref _refreshGeneration);
        Interlocked.Exchange(ref _refreshCts, null)?.Cancel();
        await _refreshGate.WaitAsync();
        try
        {
            await CancelAnalysisPreparationCoreAsync(
                "Analysis preparation was canceled because the workspace was released.");
            LiveSnapshotDatabaseBinding? binding;
            lock (_stateLock)
            {
                binding = _activeBinding;
                _activeBinding = null;
            }

            binding?.Dispose();
            PublishState(LiveSnapshotRefreshCoordinatorState.Initial with
            {
                Generation = Volatile.Read(ref _refreshGeneration)
            });
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (IsDisposed())
        {
            return;
        }

        await ReleaseActiveBindingAsync();
        Dispose();
    }

    public void Dispose()
    {
        lock (_stateLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _refreshGeneration++;
            _analysisGeneration++;
            _refreshCts?.Cancel();
            _analysisCts?.Cancel();
            _activeBinding?.Dispose();
            _activeBinding = null;
            _state = _state with
            {
                Generation = _refreshGeneration,
                Phase = LiveSnapshotRefreshPhase.Disposed,
                ActiveDatabasePath = string.Empty,
                ActiveSnapshotUtc = null,
                AnalysisState = SnapshotAnalysisPreparationState.NotStarted,
                AnalysisDatabasePath = string.Empty,
                AnalysisCompletedGroups = 0,
                AnalysisTotalGroups = 0,
                AnalysisElapsedMilliseconds = 0,
                AnalysisAllocatedBytes = 0,
                AnalysisText = string.Empty
            };
        }
    }

    private void StartAnalysisPreparation(
        string databasePath,
        string evidenceSessionId,
        bool isDirectArchivedDatabase,
        long refreshGeneration)
    {
        var cts = new CancellationTokenSource();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        long analysisGeneration;
        lock (_stateLock)
        {
            ThrowIfDisposed();
            analysisGeneration = ++_analysisGeneration;
            _analysisCts = cts;
            _analysisTask = completion.Task;
        }

        var databaseDescription = isDirectArchivedDatabase ? "archived database" : "snapshot";
        PublishState(State with
        {
            Generation = refreshGeneration,
            AnalysisState = SnapshotAnalysisPreparationState.Preparing,
            AnalysisDatabasePath = databasePath,
            IsDirectArchivedDatabase = isDirectArchivedDatabase,
            AnalysisCompletedGroups = 0,
            AnalysisTotalGroups = 0,
            AnalysisElapsedMilliseconds = 0,
            AnalysisAllocatedBytes = 0,
            AnalysisText = $"Preparing {databaseDescription} analysis indexes in the background...",
            LastError = string.Empty
        });

        var progress = new InlineProgress<SqliteAnalysisIndexBuildProgress>(update =>
        {
            if (!IsCurrentAnalysis(analysisGeneration, cts))
            {
                return;
            }

            PublishState(State with
            {
                AnalysisCompletedGroups = update.CompletedGroups,
                AnalysisTotalGroups = update.TotalGroups,
                AnalysisElapsedMilliseconds = update.TotalElapsedMilliseconds,
                AnalysisAllocatedBytes = update.TotalAllocatedBytes,
                AnalysisText = FormatAnalysisProgress(databaseDescription, update)
            });
        });

        var preparation = PrepareAnalysisCoreAsync(
            databasePath,
            evidenceSessionId,
            isDirectArchivedDatabase,
            databaseDescription,
            refreshGeneration,
            analysisGeneration,
            cts,
            progress);
        _ = CompleteAnalysisPreparationAsync(preparation, completion);
    }

    private static async Task CompleteAnalysisPreparationAsync(
        Task preparation,
        TaskCompletionSource completion)
    {
        try
        {
            await preparation;
            completion.TrySetResult();
        }
        catch (Exception ex)
        {
            completion.TrySetException(ex);
        }
    }

    private async Task PrepareAnalysisCoreAsync(
        string databasePath,
        string evidenceSessionId,
        bool isDirectArchivedDatabase,
        string databaseDescription,
        long refreshGeneration,
        long analysisGeneration,
        CancellationTokenSource cts,
        IProgress<SqliteAnalysisIndexBuildProgress> progress)
    {
        try
        {
            await _runtime.PrepareAnalysisAsync(
                databasePath,
                evidenceSessionId,
                isDirectArchivedDatabase,
                progress,
                cts.Token);
            if (IsCurrentAnalysis(analysisGeneration, cts))
            {
                PublishState(State with
                {
                    Generation = refreshGeneration,
                    AnalysisState = SnapshotAnalysisPreparationState.Ready,
                    AnalysisText = $"{(isDirectArchivedDatabase ? "Archived database" : "Snapshot")} analysis indexes are ready." +
                                   FormatAnalysisDiagnostics(
                                       State.AnalysisElapsedMilliseconds,
                                       State.AnalysisAllocatedBytes),
                    LastError = string.Empty
                });
            }
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            // The analysis generation was superseded or the workspace was released.
        }
        catch (Exception ex)
        {
            if (IsCurrentAnalysis(analysisGeneration, cts))
            {
                PublishState(State with
                {
                    Generation = refreshGeneration,
                    AnalysisState = SnapshotAnalysisPreparationState.Failed,
                    AnalysisText = $"{(char.ToUpperInvariant(databaseDescription[0]))}{databaseDescription[1..]} analysis index preparation failed: {ex.Message}" +
                                   FormatAnalysisDiagnostics(
                                       State.AnalysisElapsedMilliseconds,
                                       State.AnalysisAllocatedBytes),
                    LastError = ex.Message
                });
            }
        }
        finally
        {
            lock (_stateLock)
            {
                if (ReferenceEquals(_analysisCts, cts))
                {
                    _analysisCts = null;
                    _analysisTask = null;
                }
            }

            cts.Dispose();
        }
    }

    private void ReportRefresh(
        long generation,
        LiveSnapshotRefreshPhase phase,
        int currentStep,
        string message,
        IProgress<LiveSnapshotRefreshProgress>? progress,
        bool isIndeterminate = false)
    {
        PublishState(State with
        {
            Generation = generation,
            Phase = phase,
            LastError = string.Empty
        });
        progress?.Report(new LiveSnapshotRefreshProgress(
            generation,
            phase,
            currentStep,
            RefreshStepCount,
            message,
            isIndeterminate));
    }

    private async Task<SqliteSnapshotResult> CreateCandidateWithRetryAsync(
        long generation,
        LiveSnapshotRefreshRequest request,
        string candidatePath,
        IProgress<LiveSnapshotRefreshProgress>? progress,
        CancellationToken cancellationToken)
    {
        LiveSnapshotSourcePendingException? lastPending = null;
        for (var attempt = 1; attempt <= _sourceRetryPolicy.MaximumAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureCurrentGeneration(generation, cancellationToken);
            try
            {
                return await _runtime.CreateCandidateAsync(
                    request,
                    candidatePath,
                    cancellationToken);
            }
            catch (LiveSnapshotSourcePendingException ex)
            {
                lastPending = ex;
                if (attempt >= _sourceRetryPolicy.MaximumAttempts)
                {
                    break;
                }

                ReportRefresh(
                    generation,
                    LiveSnapshotRefreshPhase.CreatingSnapshot,
                    1,
                    $"Live evidence is still becoming readable; retry {attempt + 1} of {_sourceRetryPolicy.MaximumAttempts}. {ex.Message}",
                    progress,
                    isIndeterminate: true);
                await _delayAsync(_sourceRetryPolicy.Delay, cancellationToken);
            }
        }

        throw new IOException(
            $"The live evidence database did not become readable after {_sourceRetryPolicy.MaximumAttempts} attempts. " +
            (lastPending?.Message ?? "No readiness diagnostic was available."),
            lastPending);
    }

    private void PublishState(LiveSnapshotRefreshCoordinatorState state)
    {
        EventHandler<LiveSnapshotRefreshCoordinatorStateChangedEventArgs>? handler;
        lock (_stateLock)
        {
            if (_disposed && state.Phase != LiveSnapshotRefreshPhase.Disposed)
            {
                return;
            }

            _state = state;
            handler = StateChanged;
        }

        handler?.Invoke(this, new LiveSnapshotRefreshCoordinatorStateChangedEventArgs(state));
    }

    private bool IsCurrentAnalysis(long generation, CancellationTokenSource cts)
    {
        lock (_stateLock)
        {
            return !_disposed &&
                   generation == _analysisGeneration &&
                   ReferenceEquals(_analysisCts, cts) &&
                   !cts.IsCancellationRequested;
        }
    }

    private bool IsDisposed()
    {
        lock (_stateLock)
        {
            return _disposed;
        }
    }

    private void EnsureCurrentGeneration(long generation, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (generation != Volatile.Read(ref _refreshGeneration))
        {
            throw new OperationCanceledException("The refresh was superseded.", cancellationToken);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private static string BuildCandidatePath(string activeSnapshotPath, long generation)
    {
        var fullPath = Path.GetFullPath(activeSnapshotPath);
        var directory = Path.GetDirectoryName(fullPath) ?? AppContext.BaseDirectory;
        var nonce = Guid.NewGuid().ToString("N")[..12];
        return Path.Combine(
            directory,
            $"r-{generation:X8}-{nonce}.candidate");
    }

    private static string FormatAnalysisProgress(
        string databaseDescription,
        SqliteAnalysisIndexBuildProgress update)
    {
        var stageName = update.IsSearchIndex
            ? $"{databaseDescription} full-text search index"
            : $"{update.GroupName} indexes";
        if (update.StageState == SqliteAnalysisIndexBuildStageState.Started)
        {
            return $"Building {stageName} in the background " +
                   $"({update.CompletedGroups:N0} of {update.TotalGroups:N0} stages complete)...";
        }

        return $"Built {stageName} in {update.StageElapsedMilliseconds:N0} ms " +
               $"({update.StageAllocatedBytes:N0} bytes allocated; " +
               $"{update.CompletedGroups:N0} of {update.TotalGroups:N0} stages complete).";
    }

    private static string FormatAnalysisDiagnostics(double elapsedMilliseconds, long allocatedBytes)
    {
        if (elapsedMilliseconds <= 0 && allocatedBytes <= 0)
        {
            return string.Empty;
        }

        return $" Elapsed {elapsedMilliseconds:N0} ms; allocated {allocatedBytes:N0} bytes.";
    }

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value)
        {
            report(value);
        }
    }
}
