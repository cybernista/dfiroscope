using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.Ai;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class AiWorkspaceViewModel : WorkspaceInstanceViewModel
{
    private readonly WorkspaceManager _manager;
    private readonly Lazy<ProcessConversationViewModel> _object;
    private readonly Lazy<AiChatViewModel> _general;
    private readonly Lazy<InvestigationDataViewModel>? _investigation;
    private object? _conversation;
    private bool _technicalDetailsVisible = true;
    internal AiGeneralSubmissionContext? SubmissionContext { get; set; }
    internal ProcInsider.Models.EvidenceIdentity? SelectedEvidenceScope { get; set; }
    internal long SelectedEvidenceScopeGeneration { get; set; }
    internal string GeneralContextId { get; set; } = "chat-" + Guid.NewGuid().ToString("N");
    public AiChatViewModel General => _general.Value;
    public System.Collections.ObjectModel.ObservableCollection<object> SavedAiItems => _manager.ExplorerSections.SavedAiItems;
    public IAsyncRelayCommand<object> OpenSavedAiCommand => _manager.ExplorerSections.OpenSavedAiCommand;
    public IAsyncRelayCommand<object> OpenSavedAiNewCommand => _manager.ExplorerSections.OpenSavedAiNewCommand;
    internal bool IsUpdatingSavedItems => _manager.ExplorerSections.IsUpdatingAiInventory;
    public ConversationExplorerViewModel? Chats => _manager.ExplorerSections.Conversations;
    public InvestigationExplorerViewModel? Investigations => _manager.ExplorerSections.Investigations;
    public ProcessConversationViewModel ObjectConversation => _object.Value;
    public InvestigationDataViewModel? InvestigationConversation => _investigation?.Value;
    public object? Conversation { get => _conversation; private set => SetProperty(ref _conversation, value); }
    public bool TechnicalDetailsVisible { get => _technicalDetailsVisible; set => SetProperty(ref _technicalDetailsVisible, value); }
    public IRelayCommand ToggleTechnicalDetailsCommand { get; }
    public IRelayCommand NewChatCommand { get; }
    public IAsyncRelayCommand RefreshCommand { get; }

    internal AiWorkspaceViewModel(WorkspaceTypeMetadata type, int ordinal, WorkspaceManager manager,
        Func<WorkspaceInstanceViewModel, ProcessConversationViewModel> createObject,
        Func<WorkspaceInstanceViewModel, InvestigationDataViewModel>? createInvestigation,
        Func<WorkspaceManager, AiChatViewModel> createAssistant) : base(type, ordinal)
    {
        _manager = manager;
        _general = new(() =>
        {
            var presenter = createAssistant(manager);
            presenter.WorkspaceActive = () => !IsDisposed && !manager.ReadsSuspended &&
                ReferenceEquals(manager.ActiveInstance, this) && manager.CaptureBinding is { } binding &&
                Context is { } context && context.CaptureGeneration == binding.CaptureGeneration && context.SessionId == binding.Paths.SessionId;
            presenter.SetGeneralContextId(GeneralContextId);
            presenter.RefreshContext();
            return presenter;
        });
        _object = new(() => createObject(this));
        if (createInvestigation != null) _investigation = new(() => createInvestigation(this));
        NavigationDescription = "Chats";
        ToggleTechnicalDetailsCommand = new RelayCommand(() => TechnicalDetailsVisible = !TechnicalDetailsVisible);
        NewChatCommand = new RelayCommand(() =>
        {
            if (IsDisposed || !ReferenceEquals(manager.ActiveInstance, this) || manager.ReadsSuspended ||
                manager.CaptureBinding is not { } binding || Context is not { } context ||
                context.CaptureGeneration != binding.CaptureGeneration || context.SessionId != binding.Paths.SessionId) return;
            manager.Navigation.Cancel();
            GeneralContextId = "chat-" + Guid.NewGuid().ToString("N");
            General.SetGeneralContextId(GeneralContextId);
            General.PromptText = "";
            General.RefreshContext();
            ShowGeneral();
        });
        RefreshCommand = new AsyncRelayCommand(async () =>
        {
            if (Chats != null) await Chats.RefreshAsync();
            if (Investigations != null) await Investigations.RefreshAsync();
        });
    }

    internal void ShowGeneral() { General.SetGeneralContextId(GeneralContextId); Conversation = General; NavigationDescription = "Chats"; }
    internal void ShowObject() { Conversation = ObjectConversation; NavigationDescription = "Chats"; }
    internal void ShowInvestigation() { Conversation = InvestigationConversation; NavigationDescription = "Investigation"; }
    internal void Cancel()
    {
        if (_general.IsValueCreated) _general.Value.Cancel();
        if (_object.IsValueCreated) _object.Value.Cancel();
        if (_investigation?.IsValueCreated == true) _investigation.Value.Cancel();
    }
    internal void RefreshGeneralContext() { if (_general.IsValueCreated) _general.Value.RefreshContext(); }
    internal void CaptureChanged()
    {
        Cancel();
        SubmissionContext = null;
        SelectedEvidenceScope = null;
        if (_object.IsValueCreated) _object.Value.Detach();
        if (_investigation?.IsValueCreated == true) _investigation.Value.Detach();
        RefreshGeneralContext();
        Conversation = _general.IsValueCreated ? _general.Value : null;
        NavigationDescription = "Chats";
    }
    public override void Dispose()
    {
        if (IsDisposed) return;
        IsDisposed = true;
        if (_general.IsValueCreated) _general.Value.Dispose();
        if (_object.IsValueCreated) _object.Value.Dispose();
        if (_investigation?.IsValueCreated == true) _investigation.Value.Dispose();
    }
}
