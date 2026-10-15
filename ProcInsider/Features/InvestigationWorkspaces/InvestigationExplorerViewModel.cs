using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services.Ai;
using ProcInsider.Services;
using ProcInsider.Services.Presentation;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

public sealed record InvestigationExplorerEntry(Investigation Investigation, string Availability, string Model = "No model used");

public sealed class InvestigationExplorerViewModel : ViewModelBase, IDisposable
{
    private readonly WorkspaceManager _manager;
    private CancellationTokenSource _refresh = new();
    private bool _disposed;
    private readonly System.Windows.Threading.Dispatcher _dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
    private AnnotationDatabaseService? _subscribedStore;
    private sealed class NotificationRefreshState
    {
        internal int Queued;
        internal long Version;
    }
    private volatile NotificationRefreshState _notifications = new();
    internal event Action? EntriesChanged;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private string _status = "Open a capture to see its investigations.";
    public ObservableCollection<InvestigationExplorerEntry> Investigations { get; } = [];
    private int? _count = 0;
    public int? Count { get => _count; private set => SetProperty(ref _count, value); }
    private int _visibleLimit = 200;
    public IAsyncRelayCommand LoadMoreCommand { get; }
    public IAsyncRelayCommand<Investigation> OpenNewCommand { get; }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand<Investigation> OpenCommand { get; }

    internal InvestigationExplorerViewModel(WorkspaceManager manager)
    {
        _manager = manager;
        LoadMoreCommand = new AsyncRelayCommand(async () => { _visibleLimit += 200; await RefreshAsync(); });
        OpenNewCommand = new AsyncRelayCommand<Investigation>(item => item is null || !_manager.AiAvailable ? Task.CompletedTask :
            _manager.Navigation.NavigateAiInvestigationAsync(item.Id, mode: WorkspaceNavigationMode.OpenNew));
        RefreshCommand = new AsyncRelayCommand(RefreshAsync, AsyncRelayCommandOptions.AllowConcurrentExecutions);
        OpenCommand = new AsyncRelayCommand<Investigation>(item => item is null ? Task.CompletedTask :
            _manager.AiAvailable ? _manager.Navigation.NavigateAiInvestigationAsync(item.Id) :
            _manager.Navigation.NavigateInvestigationAsync(item.Id));
    }

    internal void CaptureChanged()
    {
        if (_subscribedStore != null) _subscribedStore.AiAnnotationsChanged -= AnnotationsChanged;
        _subscribedStore = _disposed ? null : _manager.CaptureBinding?.Annotations;
        // Retired callbacks retain their own state and cannot clear this capture's queued flag.
        _notifications = new NotificationRefreshState();
        if (_subscribedStore != null) _subscribedStore.AiAnnotationsChanged += AnnotationsChanged;
        _refresh.Cancel();
        Investigations.Clear();
        Count = 0;
        _visibleLimit = 200;
        EntriesChanged?.Invoke();
        Status = _manager.CaptureBinding is null ? "Open a capture to see its investigations." :
            "Refresh to see saved investigations for this capture.";
        if (_manager.CaptureBinding is not null)
            _ = RefreshCommand.ExecuteAsync(null);
    }

    internal static bool IsCompatible(Investigation investigation, AiConversation? conversation,
        ViewerCaptureBinding binding) => AnnotationDatabaseService.IsExplorerInvestigationCompatible(
            investigation.Id, investigation.ConversationId, investigation.Target, conversation, binding.Paths.SessionId);

    private void AnnotationsChanged(AnnotationDatabaseService store)
    {
        if (_disposed || !ReferenceEquals(store, _subscribedStore)) return;
        var state = _notifications;
        Interlocked.Increment(ref state.Version);
        QueueAnnotationRefresh(store, state);
    }
    private void QueueAnnotationRefresh(AnnotationDatabaseService store, NotificationRefreshState state)
    {
        if (_disposed || !ReferenceEquals(store, _subscribedStore) || !ReferenceEquals(state, _notifications) ||
            Interlocked.CompareExchange(ref state.Queued, 1, 0) != 0) return;
        _dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, new Action(async () =>
        {
            var processedVersion = Volatile.Read(ref state.Version);
            bool Current() => !_disposed && ReferenceEquals(state, _notifications) &&
                !_manager.ReadsSuspended && ReferenceEquals(store, _subscribedStore) &&
                ReferenceEquals(store, _manager.CaptureBinding?.Annotations);
            try
            {
                do
                {
                    if (!Current()) return;
                    processedVersion = Volatile.Read(ref state.Version);
                    await RefreshQueuedAsync(store);
                }
                while (Current() && processedVersion != Volatile.Read(ref state.Version));
            }
            finally
            {
                Interlocked.Exchange(ref state.Queued, 0);
                // Close the race between observing the last version and clearing the flag.
                if (Current() && processedVersion != Volatile.Read(ref state.Version))
                    QueueAnnotationRefresh(store, state);
            }
        }));
    }
    internal Task RefreshAsync() => RefreshQueuedAsync(null);

    private async Task RefreshQueuedAsync(AnnotationDatabaseService? expectedStore)
    {
        await _refreshGate.WaitAsync();
        try
        {
            if (_disposed || expectedStore != null && (!ReferenceEquals(expectedStore, _subscribedStore) ||
                !ReferenceEquals(expectedStore, _manager.CaptureBinding?.Annotations))) return;
            await RefreshCoreAsync();
        }
        finally { _refreshGate.Release(); }
    }

    private async Task RefreshCoreAsync()
    {
        _refresh.Cancel();
        _refresh.Dispose();
        _refresh = new CancellationTokenSource();
        var token = _refresh.Token;
        var binding = _manager.CaptureBinding;
        if (_disposed || _manager.ReadsSuspended || binding is null)
        {
            Investigations.Clear();
            EntriesChanged?.Invoke();
            Count = binding is null ? 0 : null;
            Status = "The active capture is unavailable.";
            return;
        }
        Status = "Loading investigations...";
        try
        {
            var inventory = await binding.Annotations.ReadAiExplorerInventoryAsync(binding.Paths.SessionId, 0, _visibleLimit, token);
            var entries = new List<InvestigationExplorerEntry>();
            foreach (var (item, conversation) in inventory.Investigations)
            {
                var resolution = await Task.Run(() => new AiEvidenceReferenceResolver(binding.Query)
                    .ResolveProcess(item.Target!, binding.Paths.SessionId), token);
                var messages = await binding.Annotations.LoadConversationMessagesAsync(item.ConversationId, cancellationToken: token);
                var model = AiConversationBrief.From(conversation!, messages).Model;
                entries.Add(new(item, resolution.IsResolved ? "Original available." :
                    $"Original unavailable: {resolution.Message} Saved investigation remains readable.", model));
            }
            if (token.IsCancellationRequested || _disposed || _manager.ReadsSuspended ||
                !ReferenceEquals(binding, _manager.CaptureBinding)) return;
            Count = inventory.InvestigationCount;
            Investigations.Clear();
            foreach (var entry in entries) Investigations.Add(entry);
            EntriesChanged?.Invoke();
            Status = $"Showing {entries.Count} of {Count} saved investigation(s), including unavailable originals.";
        }
        catch (OperationCanceledException) { }
        catch (Exception error)
        {
            if (!token.IsCancellationRequested && ReferenceEquals(binding, _manager.CaptureBinding))
            {
                Count = null;
                Status = "Investigations unavailable: " + error.Message;
            }
        }
    }

    public void Dispose()
    {
        _disposed = true;
        _notifications = new NotificationRefreshState();
        if (_subscribedStore != null) _subscribedStore.AiAnnotationsChanged -= AnnotationsChanged;
        _subscribedStore = null;
        _refresh.Cancel();
        _refresh.Dispose();
    }
}
