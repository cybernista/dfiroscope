using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Features.InvestigationWorkspaces;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Services;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Presentation;

namespace ProcInsider.ViewModels;

/// <summary>Saved AI navigation owned by one Processes presentation and its selected exact process.</summary>
public sealed class ProcessSavedAiNavigationViewModel : ViewModelBase, IDisposable
{
    private readonly ProcessPresentationViewModel _presentation;
    private readonly Dispatcher _dispatcher = Dispatcher.CurrentDispatcher;
    private ViewerCaptureBinding? _binding;
    private AiEvidenceReference? _process;
    private CancellationTokenSource _refresh = new();
    private CancellationTokenSource _navigation = new();
    private long _revision;
    private int _limit = 200;
    private bool _disposed;
    private bool _updating;
    private object? _selectedItem;
    private bool _hasMore;
    private string _status = "Select a process to see its saved chats and investigations.";

    public ObservableCollection<object> Items { get; } = [];
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public object? SelectedItem { get => _selectedItem; set => SetProperty(ref _selectedItem, value); }
    public bool IsUpdating => _updating;
    public bool HasMore { get => _hasMore; private set => SetProperty(ref _hasMore, value); }
    public IAsyncRelayCommand<object> OpenCommand { get; }
    public IAsyncRelayCommand LoadMoreCommand { get; }

    internal ProcessSavedAiNavigationViewModel(ProcessPresentationViewModel presentation)
    {
        _presentation = presentation;
        OpenCommand = new AsyncRelayCommand<object>(OpenAsync);
        LoadMoreCommand = new AsyncRelayCommand(async () => { _limit += 200; await RefreshAsync(); });
    }

    internal void Bind(ViewerCaptureBinding? binding)
    {
        if (_disposed) return;
        _navigation.Cancel();
        _navigation.Dispose();
        _navigation = new();
        if (_binding is not null) _binding.Annotations.AiAnnotationsChanged -= AnnotationsChanged;
        _binding = binding;
        if (_binding is not null) _binding.Annotations.AiAnnotationsChanged += AnnotationsChanged;
        _limit = 200;
        ClearItems();
        Refresh();
    }

    internal void SelectProcess(ProcessInfo? process)
    {
        if (_disposed) return;
        _navigation.Cancel();
        _navigation.Dispose();
        _navigation = new();
        _process = process is { ProcessEntityId: { Length: > 0 } }
            ? ProcessEvidenceAgentTools.CreateObjectContext(process).Reference : null;
        _limit = 200;
        ClearItems();
        Refresh();
    }

    private void ClearItems()
    {
        _updating = true;
        Items.Clear();
        SelectedItem = null;
        HasMore = false;
        _updating = false;
    }

    private void AnnotationsChanged(AnnotationDatabaseService store)
    {
        if (_disposed || !ReferenceEquals(store, _binding?.Annotations)) return;
        _dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
        {
            if (!_disposed && ReferenceEquals(store, _binding?.Annotations)) Refresh();
        }));
    }

    internal void Refresh() => _ = RefreshAsync();

    private async Task RefreshAsync()
    {
        if (_disposed) return;
        _refresh.Cancel();
        _refresh.Dispose();
        _refresh = new CancellationTokenSource();
        var token = _refresh.Token;
        var revision = Interlocked.Increment(ref _revision);
        var binding = _binding;
        var process = _process;
        if (binding is null || process is null)
        {
            ClearItems();
            Status = binding is null ? "Open a capture to see saved process AI work." :
                "Select a process with a durable identity to see saved AI work.";
            return;
        }
        Status = "Loading saved chats and investigations...";
        try
        {
            var origin = AiConversationCreationOrigin.ForProcess(process);
            var conversations = new List<AiConversation>();
            var lastPageCount = 0;
            for (var offset = 0; offset < _limit; offset += 200)
            {
                var page = await binding.Annotations.ListProcessOriginConversationsAsync(origin, 200, offset, token);
                lastPageCount = page.Count;
                conversations.AddRange(page);
                if (page.Count < 200) break;
            }
            var rows = new List<object>();
            var availability = new AiEvidenceReferenceResolver(binding.Query)
                .ResolveProcess(process, binding.Paths.SessionId);
            var label = availability.IsResolved ? "Original available." :
                $"Original unavailable: {availability.Message}";
            foreach (var conversation in conversations)
            {
                token.ThrowIfCancellationRequested();
                var messages = await binding.Annotations.LoadConversationMessagesAsync(
                    conversation.Id, cancellationToken: token);
                var model = AiConversationBrief.From(conversation, messages).Model;
                if (conversation.Scope.ContextType == AiConversationContextType.Investigation)
                {
                    var investigation = await binding.Annotations.LoadInvestigationAsync(
                        conversation.Scope.ContextId, token);
                    if (investigation is not null)
                        rows.Add(new InvestigationExplorerEntry(investigation, label, model));
                }
                else rows.Add(new ConversationExplorerEntry(conversation, label, model));
            }
            if (_disposed || token.IsCancellationRequested || revision != Volatile.Read(ref _revision) ||
                !ReferenceEquals(binding, _binding) || !ReferenceEquals(process, _process)) return;
            _updating = true;
            var selectedId = SelectedItem switch
            {
                ConversationExplorerEntry chat => chat.Conversation.Id,
                InvestigationExplorerEntry investigation => investigation.Investigation.Id,
                _ => null
            };
            Items.Clear();
            foreach (var row in rows) Items.Add(row);
            HasMore = conversations.Count == _limit && lastPageCount == 200;
            SelectedItem = rows.FirstOrDefault(row => row switch
            {
                ConversationExplorerEntry chat => chat.Conversation.Id == selectedId,
                InvestigationExplorerEntry investigation => investigation.Investigation.Id == selectedId,
                _ => false
            });
            _updating = false;
            Status = HasMore ? $"Showing {rows.Count} saved items. Load more to continue." :
                $"Showing {rows.Count} Processes-origin saved chat(s) and investigation(s) for this process.";
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (revision == Volatile.Read(ref _revision) && ReferenceEquals(binding, _binding))
                Status = "Saved process AI work unavailable: " + error.Message;
        }
    }

    private async Task OpenAsync(object? item)
    {
        if (_disposed || item is null || _binding is null || _process is null) return;
        try
        {
            var binding = _binding;
            var process = _process;
            var token = _navigation.Token;
            var expectedOrigin = AiConversationCreationOrigin.ForProcess(process);
            var savedConversation = item switch
            {
                ConversationExplorerEntry chat => chat.Conversation,
                InvestigationExplorerEntry investigation => await binding.Annotations.LoadConversationAsync(
                    investigation.Investigation.ConversationId, token),
                _ => null
            };
            if (token.IsCancellationRequested || savedConversation?.CreationOrigin != expectedOrigin ||
                !ReferenceEquals(binding, _binding) || !ReferenceEquals(process, _process)) return;
            var opened = item switch
            {
                ConversationExplorerEntry chat => await _presentation.LoadConversationAsync(chat.Conversation.Id, token),
                InvestigationExplorerEntry investigation => await _presentation.LoadInvestigationAsync(investigation.Investigation.Id, token),
                _ => false
            };
            if (token.IsCancellationRequested || !ReferenceEquals(binding, _binding) ||
                !ReferenceEquals(process, _process)) return;
            if (!opened) Status = "The exact saved item or its original is unavailable in this process workspace.";
        }
        catch (OperationCanceledException) { }
        catch (Exception error)
        {
            if (!_disposed) Status = "Saved item could not be opened: " + error.Message;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_binding is not null) _binding.Annotations.AiAnnotationsChanged -= AnnotationsChanged;
        _binding = null;
        _refresh.Cancel();
        _refresh.Dispose();
        _navigation.Cancel();
        _navigation.Dispose();
        Items.Clear();
    }
}
