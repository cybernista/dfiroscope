using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Presentation;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

public sealed record ConversationExplorerEntry(AiConversation Conversation, string Availability, string Model = "No model used");

// This is navigation over annotations, not an evidence scope in the Explorer tree.
public sealed class ConversationExplorerViewModel : ViewModelBase, IDisposable
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
    private string _status = "Open a capture to see its chats.";
    public ObservableCollection<ConversationExplorerEntry> Conversations { get; } = [];
    private int? _count = 0;
    public int? Count { get => _count; private set => SetProperty(ref _count, value); }
    private int _visibleLimit = 200;
    public IAsyncRelayCommand LoadMoreCommand { get; }
    public IAsyncRelayCommand<AiConversation> OpenNewCommand { get; }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand<AiConversation> OpenCommand { get; }

    internal ConversationExplorerViewModel(WorkspaceManager manager)
    {
        _manager = manager;
        LoadMoreCommand = new AsyncRelayCommand(async () => { _visibleLimit += 200; await RefreshAsync(); });
        OpenNewCommand = new AsyncRelayCommand<AiConversation>(item => item is null || !_manager.AiAvailable ? Task.CompletedTask :
            _manager.Navigation.NavigateAiConversationAsync(item.Id, mode: WorkspaceNavigationMode.OpenNew));
        RefreshCommand = new AsyncRelayCommand(RefreshAsync, AsyncRelayCommandOptions.AllowConcurrentExecutions);
        OpenCommand = new AsyncRelayCommand<AiConversation>(OpenAsync);
    }

    internal void CaptureChanged()
    {
        if (_subscribedStore != null) _subscribedStore.AiAnnotationsChanged -= AnnotationsChanged;
        _subscribedStore = _disposed ? null : _manager.CaptureBinding?.Annotations;
        // Retired callbacks retain their own state and cannot clear this capture's queued flag.
        _notifications = new NotificationRefreshState();
        if (_subscribedStore != null) _subscribedStore.AiAnnotationsChanged += AnnotationsChanged;
        _refresh.Cancel();
        Conversations.Clear();
        Count = 0;
        _visibleLimit = 200;
        EntriesChanged?.Invoke();
        Status = _manager.CaptureBinding == null ? "Open a capture to see its chats." :
            "Refresh to see saved conversations for this capture.";
        if (_manager.CaptureBinding != null)
            _ = RefreshCommand.ExecuteAsync(null);
    }

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
        if (_disposed || _manager.ReadsSuspended || binding == null)
        {
            Conversations.Clear();
            EntriesChanged?.Invoke();
            Count = binding is null ? 0 : null;
            Status = "The active capture is unavailable.";
            return;
        }
        Status = "Loading chats...";
        try
        {
            var inventory = await binding.Annotations.ReadAiExplorerInventoryAsync(binding.Paths.SessionId, _visibleLimit, 0, token);
            var stored = inventory.Conversations;
            var compatible = await Task.Run(async () =>
            {
                var resolver = new AiEvidenceReferenceResolver(binding.Query);
                var result = new List<ConversationExplorerEntry>();
                foreach (var conversation in stored.Take(_visibleLimit))
                {
                    token.ThrowIfCancellationRequested();
                    if (!IsCompatible(conversation, binding)) continue;
                    var messages = await binding.Annotations.LoadConversationMessagesAsync(conversation.Id, cancellationToken: token);
                    var model = AiConversationBrief.From(conversation, messages).Model;
                    if (conversation.Scope.ContextType == AiConversationContextType.General)
                    {
                        result.Add(new(conversation, conversation.IsHistorical ? "Historical chat; original host context was not recorded. Read-only." :
                            "General discussion; select the same host context to reopen.", model));
                        continue;
                    }
                    var reference = conversation.Scope.ObjectReference!;
                    if (reference.Evidence.Kind == EvidenceReferenceKind.ProcessEntity)
                    {
                        var resolution = resolver.ResolveProcess(reference, binding.Paths.SessionId);
                        result.Add(new(conversation, resolution.IsResolved ? "Original available." : $"Original unavailable: {resolution.Message}", model));
                    }
                    else
                    {
                        try
                        {
                            var resolved = binding.Query is null ? null : await EvidenceObjectAgentTools.ResolveAsync(binding.Query,
                                _manager.Navigation.Access, reference, binding.Paths.SessionId, token);
                            result.Add(new(conversation, resolved is null ? "Exact original unavailable." : "Original available.", model));
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception) { result.Add(new(conversation, "Exact original unavailable in the current projection.", model)); }
                    }
                }
                return result;
            }, token);
            if (token.IsCancellationRequested || !ReferenceEquals(binding, _manager.CaptureBinding) ||
                _disposed || _manager.ReadsSuspended) return;
            Count = inventory.ChatCount;
            Conversations.Clear();
            foreach (var conversation in compatible)
                Conversations.Add(conversation);
            EntriesChanged?.Invoke();
            Status = $"Showing {Conversations.Count} of {Count} saved chat(s), including unavailable originals.";
        }
        catch (OperationCanceledException) { }
        catch (Exception error)
        {
            if (!token.IsCancellationRequested && ReferenceEquals(binding, _manager.CaptureBinding))
            {
                Count = null;
                Status = "Chats unavailable: " + error.Message;
            }
        }
    }

    internal static bool IsCompatible(AiConversation conversation, ViewerCaptureBinding binding) =>
        AnnotationDatabaseService.IsExplorerChatCompatible(conversation, binding.Paths.SessionId);
    private async Task OpenAsync(AiConversation? conversation)
    {
        if (conversation == null) return;
        if (_manager.AiAvailable) await _manager.Navigation.NavigateAiConversationAsync(conversation.Id);
        else await _manager.Navigation.NavigateConversationAsync(conversation.Id);
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
