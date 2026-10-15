using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

public enum AiExplorerRoute { Chats, Investigations }

// Green selection scopes the saved annotation branches only; it never selects evidence.
public sealed class AiExplorerNode : ViewModelBase
{
    private readonly string _label;
    private int? _count = 0;
    private bool _included;
    private bool _isExpanded;
    public bool IsExpanded { get => _isExpanded; set => SetProperty(ref _isExpanded, value); }
    public bool CanToggleGreen => Route != null;
    public AiExplorerRoute? Route { get; }
    public ObservableCollection<object> Children { get; } = [];
    public int? Count { get => _count; internal set { if (SetProperty(ref _count, value)) OnPropertyChanged(nameof(Title)); } }
    public string Title => Count is { } count ? $"{_label} ({count})" : $"{_label} (unavailable)";
    public bool IsGreenIncludedDirectly
    {
        get => _included;
        internal set { if (SetProperty(ref _included, value)) { OnPropertyChanged(nameof(ScopeGlyph)); OnPropertyChanged(nameof(ScopeStateDescription)); } }
    }
    public bool HasGreenIncludedDescendant => Children.OfType<AiExplorerNode>().Any(node => node.IsGreenIncludedDirectly);
    internal void RefreshDescendantScope() => OnPropertyChanged(nameof(HasGreenIncludedDescendant));
    private string _status = "Saved annotations for the active capture.";
    public string Status { get => _status; internal set => SetProperty(ref _status, value); }
    public string ScopeGlyph => IsGreenIncludedDirectly ? "G" : string.Empty;
    public string ScopeStateDescription => IsGreenIncludedDirectly ? "Included in the saved annotation list scope." : "Excluded from the saved annotation list scope.";
    internal AiExplorerNode(string label, AiExplorerRoute? route) { _label = label; Route = route; }
}
public sealed record AiExplorerMore(string Title, IAsyncRelayCommand Command);

internal sealed class ExplorerSectionViewModel : ViewModelBase, IDisposable
{
    private FeatureTabDescriptor _descriptor;
    private bool _isSelected;
    public FeatureTabKey Key => _descriptor.Key;
    public string Header => _descriptor.Header;
    public bool IsSelected
    {
        get => _isSelected;
        set { if (SetProperty(ref _isSelected, value)) OnPropertyChanged(nameof(Content)); }
    }
    private string _availability = string.Empty;
    public string Availability { get => _availability; private set => SetProperty(ref _availability, value); }
    public object? Content
    {
        get
        {
            if (!IsSelected) return null;
            var content = _descriptor.Content;
            Availability = _descriptor.HasActivationFailed ? $"Unavailable: {_descriptor.ActivationError}" : string.Empty;
            return content;
        }
    }
    internal ExplorerSectionViewModel(FeatureTabDescriptor descriptor)
    {
        _descriptor = descriptor;
        descriptor.PropertyChanged += DescriptorChanged;
    }
    private void DescriptorChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e) => OnPropertyChanged(nameof(Header));
    internal void Bind(FeatureTabDescriptor descriptor)
    {
        if (ReferenceEquals(_descriptor, descriptor)) return;
        _descriptor.PropertyChanged -= DescriptorChanged;
        _descriptor = descriptor;
        _descriptor.PropertyChanged += DescriptorChanged;
        OnPropertyChanged(nameof(Header));
        OnPropertyChanged(nameof(Content));
    }
    public void Dispose() => _descriptor.PropertyChanged -= DescriptorChanged;
}

internal sealed class ExplorerSectionsViewModel : ViewModelBase, IDisposable
{
    private readonly WorkspaceManager _manager;
    private readonly IReadOnlyList<FeatureTabDescriptor> _sharedTabs;
    private readonly IReadOnlyList<FeatureTabDescriptor> _navigationTabs;
    private ProcessPresentationViewModel? _subscribed;
    private readonly ConversationExplorerViewModel? _conversations;
    private readonly InvestigationExplorerViewModel? _investigations;
    public AiExplorerNode? AiRoot { get; }
    public ObservableCollection<object> SavedAiItems { get; } = [];
    public IAsyncRelayCommand<AiExplorerNode> NavigateAiCommand { get; }
    public IRelayCommand<AiExplorerNode> ToggleAiGreenCommand { get; }
    public IAsyncRelayCommand<object> OpenSavedAiCommand { get; }
    public IAsyncRelayCommand<object> OpenSavedAiNewCommand { get; }
    internal bool IsUpdatingAiInventory { get; private set; }
    private readonly AiExplorerNode? _chatsNode;
    private readonly AiExplorerNode? _investigationsNode;
    private WorkspaceContext? _savedAiContext;
    private bool _hasNavigatedAi;
    private AiExplorerRoute? _navigatedAiRoute;
    private WorkspaceInstanceViewModel? _assistantWorkspace;
    public AiChatViewModel? Assistant { get; }
    public IAsyncRelayCommand OpenAiCommand => _manager.OpenAiCommand;
    public ExplorerViewModel Explorer { get; }
    public ObservableCollection<object> Roots { get; } = [];
    public ObservableCollection<ExplorerSectionViewModel> Sections { get; } = [];
    private ExplorerSectionViewModel? _selectedSection;
    public ExplorerSectionViewModel? SelectedSection
    {
        get => _selectedSection;
        set
        {
            if (ReferenceEquals(value, _selectedSection)) return;
            if (_selectedSection != null) _selectedSection.IsSelected = false;
            if (SetProperty(ref _selectedSection, value) && value != null)
            {
                value.IsSelected = true;
                if (value.Key == ExplorerTabKeys.Ai && _conversations != null)
                {
                    _ = _conversations.RefreshCommand.ExecuteAsync(null);
                    _ = _investigations?.RefreshCommand.ExecuteAsync(null);
                }
            }
        }
    }
    public IAsyncRelayCommand<ExplorerNodeViewModel> ToggleGreenCommand { get; }
    public IAsyncRelayCommand<ExplorerNodeViewModel> OpenNewCommand { get; }
    public WorkspaceNavigationService Navigation => _manager.Navigation;
    public EventsExplorerViewModel? Events => _manager.EventsExplorer;
    public NetworkExplorerViewModel? Network => _manager.NetworkExplorer;
    public PersistenceExplorerViewModel? Persistence => _manager.PersistenceExplorer;
    public ArtifactsExplorerViewModel? Artifacts => _manager.ArtifactsExplorer;
    public bool EventsAvailable => _manager.EventsAvailable;
    public ProcessPresentationViewModel? ActivePresentation => _manager.ActivePresentation;
    public ConversationExplorerViewModel? Conversations => _conversations;
    public InvestigationExplorerViewModel? Investigations => _investigations;
    public ProcInsider.Services.Presentation.ViewerSharedActions SharedActions => _manager.SharedActions;
    internal ExplorerSectionsViewModel(WorkspaceManager manager, FeatureAccessService access,
        Func<ExplorerScope, Task<IReadOnlyList<ExplorerNodeViewModel>>>? loadChildren,
        IReadOnlyList<FeatureTabDescriptor>? sharedTabs,
        Func<WorkspaceManager, AiChatViewModel>? createAssistant = null)
    {
        _manager = manager;
        NavigateAiCommand = new AsyncRelayCommand<AiExplorerNode>(NavigateAiAsync, node => node != null && manager.AiAvailable && !manager.ReadsSuspended);
        ToggleAiGreenCommand = new RelayCommand<AiExplorerNode>(ToggleAiGreen, node => node?.CanToggleGreen == true && !manager.ReadsSuspended);
        OpenSavedAiCommand = new AsyncRelayCommand<object>(item => OpenSavedAiAsync(item, false));
        OpenSavedAiNewCommand = new AsyncRelayCommand<object>(item => OpenSavedAiAsync(item, true));
        _sharedTabs = sharedTabs?.Where(d => access.IsPublished(d.FeatureId)).ToArray() ?? [];
        Explorer = new ExplorerViewModel(_ => { }, async scope =>
        {
            var capture = Navigation.Capture;
            if (manager.ReadsSuspended || loadChildren == null) return [];
            var children = await loadChildren(scope);
            return manager.ReadsSuspended || capture != Navigation.Capture ? [] : children;
        }, access);
        ToggleGreenCommand = new AsyncRelayCommand<ExplorerNodeViewModel>(
            node => node == null ? Task.CompletedTask : NavigateAsync(node, green: true), node => node?.CanSelectScope == true);
        OpenNewCommand = new AsyncRelayCommand<ExplorerNodeViewModel>(
            node => node == null ? Task.CompletedTask : NavigateAsync(node, openNew: true), node => node?.CanSelectScope == true);
        var navigationTabs = new List<FeatureTabDescriptor>
        {
            new(ExplorerTabKeys.Explore, "Explore", FeatureIds.InvestigationWorkspaces, 0, () => Explorer)
        };
        if (access.IsPublished(FeatureIds.AiAssistance))
        {
            AiRoot = new("AI", null);
            _chatsNode = new("Chats", AiExplorerRoute.Chats);
            _investigationsNode = new("Investigations", AiExplorerRoute.Investigations);
            AiRoot.Children.Add(_chatsNode);
            AiRoot.Children.Add(_investigationsNode);
            _conversations = new ConversationExplorerViewModel(manager);
            _investigations = new InvestigationExplorerViewModel(manager);
            _conversations.PropertyChanged += AiInventoryChanged;
            _investigations.PropertyChanged += AiInventoryChanged;
            _conversations.EntriesChanged += ProjectAiRows;
            _investigations.EntriesChanged += ProjectAiRows;
            Assistant = createAssistant?.Invoke(manager);
            navigationTabs.Add(new(ExplorerTabKeys.Ai, "AI providers", FeatureIds.AiAssistance, 200,
                () => new ProcInsider.Views.Features.Ai.ExplorerAiView { DataContext = Assistant?.SettingsViewModel }));
        }
        _navigationTabs = navigationTabs;
        Explorer.RootNodes.CollectionChanged += RootsChanged;
        RootsChanged(null, null!);
        manager.ActiveContextChanged += Rebind;
        Rebind();
    }
    private async Task NavigateAiAsync(AiExplorerNode? node)
    {
        if (node is null || !_manager.AiAvailable || _manager.ReadsSuspended) return;
        ProjectAiRows(); // Synchronize a changed capture before applying this navigation choice.
        _hasNavigatedAi = true;
        _navigatedAiRoute = node.Route;
        ProjectAiRows();
        // Category navigation never replaces an already open transcript's exact context.
        await Navigation.OpenAiWorkspaceAsync();
    }
    private void ToggleAiGreen(AiExplorerNode? node)
    {
        if (node?.CanToggleGreen != true || _manager.ReadsSuspended) return;
        if (node.Route == AiExplorerRoute.Chats) SetAiScope(!node.IsGreenIncludedDirectly, _investigationsNode!.IsGreenIncludedDirectly);
        else SetAiScope(_chatsNode!.IsGreenIncludedDirectly, !node.IsGreenIncludedDirectly);
    }
    private void SetAiScope(bool chats, bool investigations)
    {
        if (AiRoot is null) return;
        _chatsNode!.IsGreenIncludedDirectly = chats;
        _investigationsNode!.IsGreenIncludedDirectly = investigations;
        AiRoot.IsGreenIncludedDirectly = false;
        AiRoot.RefreshDescendantScope();
        ProjectAiRows();
    }
    private Task OpenSavedAiAsync(object? item, bool openNew) => item switch
    {
        ConversationExplorerEntry chat => (openNew ? _conversations!.OpenNewCommand : _conversations!.OpenCommand).ExecuteAsync(chat.Conversation),
        InvestigationExplorerEntry investigation => (openNew ? _investigations!.OpenNewCommand : _investigations!.OpenCommand).ExecuteAsync(investigation.Investigation),
        AiExplorerMore more => more.Command.ExecuteAsync(null),
        _ => Task.CompletedTask
    };
    private void AiInventoryChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e) => ProjectAiInventory();
    private void ProjectAiInventory()
    {
        if (AiRoot is null) return;
        _chatsNode!.Count = _conversations!.Count;
        _chatsNode.Status = _conversations.Status;
        _investigationsNode!.Status = _investigations!.Status;
        AiRoot.Status = _conversations.Status + " " + _investigations.Status;
        _investigationsNode!.Count = _investigations!.Count;
        AiRoot.Count = _chatsNode.Count is { } chats && _investigationsNode.Count is { } investigations ? chats + investigations : null;
    }
    private void ProjectAiRows()
    {
        if (AiRoot is null) return;
        WorkspaceContext? context = _manager.CaptureBinding is { } binding
            ? new(binding.Paths.SessionId, binding.CaptureGeneration) : null;
        if (context != _savedAiContext)
        {
            _savedAiContext = context;
            ResetAiSelection();
        }
        IsUpdatingAiInventory = true;
        try
        {
            SavedAiItems.Clear();
            var anyGreen = _chatsNode!.IsGreenIncludedDirectly || _investigationsNode!.IsGreenIncludedDirectly;
            if (_chatsNode.IsGreenIncludedDirectly || (!anyGreen && _hasNavigatedAi && (_navigatedAiRoute is null or AiExplorerRoute.Chats)))
            {
                foreach (var entry in _conversations!.Conversations) SavedAiItems.Add(entry);
                if (_conversations.Count > _conversations.Conversations.Count) SavedAiItems.Add(new AiExplorerMore("Load more chats...", _conversations.LoadMoreCommand));
            }
            if (_investigationsNode!.IsGreenIncludedDirectly || (!anyGreen && _hasNavigatedAi && (_navigatedAiRoute is null or AiExplorerRoute.Investigations)))
            {
                foreach (var entry in _investigations!.Investigations) SavedAiItems.Add(entry);
                if (_investigations.Count > _investigations.Investigations.Count) SavedAiItems.Add(new AiExplorerMore("Load more investigations...", _investigations.LoadMoreCommand));
            }
        }
        finally { IsUpdatingAiInventory = false; }
    }
    private void RootsChanged(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
    {
        var eventActivityRoots = Explorer.RootNodes.Where(node =>
            node.Scope.Kind == ExplorerScopeKind.SystemActivityRoot).ToArray();
        Events?.BindActivityRoots(eventActivityRoots);
        var networkRoots=Explorer.RootNodes.Where(node=>node.Scope.Kind==ExplorerScopeKind.NetworkRoot).ToArray();
        Network?.BindLegacy(networkRoots);
        var explorerRoots = Explorer.RootNodes.Where(node =>
            node.Scope.Kind != ExplorerScopeKind.UsersRoot &&
            node.Scope.Kind != ExplorerScopeKind.FilesystemRoot &&
            (!EventsAvailable || !eventActivityRoots.Contains(node)) && (Network==null || !networkRoots.Contains(node)));
        var desired = explorerRoots.Cast<object>().Concat(EventsAvailable && Events != null ? new object[] { Events } : []).Concat(Network!=null?new object[]{Network}:[]).Concat(Persistence != null ? new object[] { Persistence } : []).Concat(Artifacts != null ? new object[] { Artifacts } : []).Concat(AiRoot != null ? new object[] { AiRoot } : []).ToArray();
        foreach (var removed in Roots.Where(r => !desired.Contains(r)).ToArray()) Roots.Remove(removed);
        for (var i = 0; i < desired.Length; i++)
        {
            var index = Roots.IndexOf(desired[i]);
            if (index < 0) Roots.Insert(i, desired[i]); else if (index != i) Roots.Move(index, i);
        }
    }
    internal void Rebind()
    {
        if (_assistantWorkspace != null) _assistantWorkspace.PropertyChanged -= AssistantContextChanged;
        _assistantWorkspace = _manager.ActiveInstance;
        if (_assistantWorkspace != null) _assistantWorkspace.PropertyChanged += AssistantContextChanged;
        Assistant?.RefreshContext();
        (_manager.ActiveInstance as AiWorkspaceViewModel)?.RefreshGeneralContext();
        if (_subscribed != null) _subscribed.PropertyChanged -= PresentationChanged;
        _subscribed = ActivePresentation;
        if (_subscribed != null) _subscribed.PropertyChanged += PresentationChanged;
        var descriptors = _navigationTabs.Concat(_sharedTabs).Concat(ActivePresentation?.ExplorerTabs.Where(d =>
            !_navigationTabs.Any(s => s.Key == d.Key) && !_sharedTabs.Any(s => s.Key == d.Key)) ?? [])
            .ToArray();
        foreach (var removed in Sections.Where(s => !descriptors.Any(d => d.Key == s.Key)).ToArray()) { removed.Dispose(); Sections.Remove(removed); }
        foreach (var descriptor in descriptors)
        {
            var section = Sections.FirstOrDefault(s => s.Key == descriptor.Key);
            if (section == null) Sections.Add(new(descriptor)); else section.Bind(descriptor);
        }
        if (SelectedSection == null || !Sections.Contains(SelectedSection)) SelectedSection = Sections.FirstOrDefault();
        OnPropertyChanged(nameof(ActivePresentation));
        ProjectSelectors();
    }
    private void PresentationChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ProcessPresentationViewModel.SelectedProcess) or nameof(ProcessPresentationViewModel.ScopedSelectionStatus)) Assistant?.RefreshContext();
        if (e.PropertyName == nameof(ProcessPresentationViewModel.ScopedSelectionStatus)) ProjectSelectors();
        if (e.PropertyName == nameof(ProcessPresentationViewModel.SelectedExplorerTab) && ActivePresentation?.SelectedExplorerTab is { } tab)
            Expand(tab.Key);
    }
    internal bool Expand(FeatureTabKey key)
    {
        var section = Sections.FirstOrDefault(s => s.Key == key);
        if (section == null) return false;
        SelectedSection = section;
        // The shared Assistant is selected by stable key; WPF creates its view when rendered.
        if (key == ExplorerTabKeys.Ai) return true;
        return section.Content != null;
    }
    internal void ApplyMetadata(ExplorerCountRefreshPayload payload)
    {
        Explorer.RefreshCounts(payload.Counts);
        Explorer.RefreshEvidenceRoots(payload.EvidenceRoots);
        foreach (var descriptor in _sharedTabs)
        {
            if (descriptor.Key == ExplorerTabKeys.Search) descriptor.UpdateCount(payload.Counts.SearchResultCount);
            if (descriptor.Key == ExplorerTabKeys.Sigma) descriptor.UpdateCount(payload.Counts.SigmaFindingCount);
        }
        ProjectSelectors();
    }
    internal void Reset()
    {
        Assistant?.RefreshContext();
        (_manager.ActiveInstance as AiWorkspaceViewModel)?.RefreshGeneralContext();
        _conversations?.CaptureChanged();
        _investigations?.CaptureChanged();
        ApplyMetadata(new(new(), []));
        Explorer.ResetSelection();
        ResetAiSelection();
        ProjectAiRows();
    }
    private void ResetAiSelection()
    {
        if (AiRoot is null) return;
        _hasNavigatedAi = false;
        _navigatedAiRoute = null;
        AiRoot.IsGreenIncludedDirectly = false;
        AiRoot.IsExpanded = false;
        foreach (var node in AiRoot.Children.OfType<AiExplorerNode>())
        {
            node.IsGreenIncludedDirectly = false;
            node.IsExpanded = false;
        }
        AiRoot.RefreshDescendantScope();
    }
    internal void ProjectSelectors()
    {
        Explorer.ApplyScopeSelectionState(ActivePresentation?._includedScopes.Keys ?? Enumerable.Empty<string>(),
            ActivePresentation?._excludedScopes.Keys ?? Enumerable.Empty<string>());
        var selected = ActivePresentation?.ExplorerViewModel.SelectedScopes.Select(s => s.StableId).ToHashSet() ?? [];
        void Apply(IEnumerable<ExplorerNodeViewModel> nodes)
        {
            foreach (var node in nodes) { node.IsScopeSelected = selected.Contains(node.Scope.StableId); Apply(node.Children); }
        }
        Apply(Explorer.RootNodes);
    }
    internal Task<WorkspaceNavigationResult> NavigateAsync(ExplorerNodeViewModel node, bool openNew = false, bool green = false,
        ExplorerSelectionGesture gesture = ExplorerSelectionGesture.Replace) =>
        Navigation.NavigateAsync(new(WorkspaceTypeId.Processes, Navigation.Capture, node.Scope,
            Mode: openNew ? WorkspaceNavigationMode.OpenNew : WorkspaceNavigationMode.Reuse, Gesture: gesture), green);
    internal ExplorerNodeViewModel CopyScopeTo(ProcessPresentationViewModel presentation, ExplorerScope scope)
    {
        static ExplorerNodeViewModel Copy(ExplorerNodeViewModel source)
        {
            var copy = new ExplorerNodeViewModel(source.Scope, source.Count);
            if (source.HasLazyChildren && !source.ChildrenLoaded) copy.MarkChildrenLazy();
            else foreach (var child in source.Children) copy.Children.Add(Copy(child));
            return copy;
        }
        static void Synchronize(ExplorerNodeViewModel source, ExplorerNodeViewModel local)
        {
            local.UpdateCount(source.Count);
            if (!source.ChildrenLoaded || source.IsLoadingChildren) return;
            if (!local.ChildrenLoaded) local.ReplaceChildren(source.Children.Select(Copy));
            else foreach (var child in source.Children.Where(n => !n.IsPlaceholder))
            {
                var existing = local.Children.FirstOrDefault(n => n.Scope.StableId == child.Scope.StableId);
                if (existing == null) local.Children.Add(Copy(child));
                else Synchronize(child, existing);
            }
        }
        static IEnumerable<ExplorerNodeViewModel> Walk(IEnumerable<ExplorerNodeViewModel> nodes) =>
            nodes.SelectMany(n => new[] { n }.Concat(Walk(n.Children)));
        // Preserve the local Explorer's indexed roots, Ctrl selection and Shift anchor identities.
        foreach (var root in Explorer.RootNodes)
        {
            var local = presentation.ExplorerViewModel.RootNodes.FirstOrDefault(n => n.Scope.StableId == root.Scope.StableId);
            if (local != null) Synchronize(root, local);
        }
        presentation.ExplorerViewModel.ApplyScopeSelectionState(presentation._includedScopes.Keys, presentation._excludedScopes.Keys);
        return Walk(presentation.ExplorerViewModel.RootNodes).FirstOrDefault(n => n.Scope.StableId == scope.StableId)
            ?? new ExplorerNodeViewModel(scope);
    }
    public void Dispose()
    {
        Assistant?.Dispose();
        if (_assistantWorkspace != null) _assistantWorkspace.PropertyChanged -= AssistantContextChanged;
        if (_conversations != null)
        {
            _conversations.PropertyChanged -= AiInventoryChanged;
            _conversations.EntriesChanged -= ProjectAiRows;
        }
        if (_investigations != null)
        {
            _investigations.PropertyChanged -= AiInventoryChanged;
            _investigations.EntriesChanged -= ProjectAiRows;
        }
        _conversations?.Dispose();
        _investigations?.Dispose();
        Explorer.RootNodes.CollectionChanged -= RootsChanged;
        _manager.ActiveContextChanged -= Rebind;
        if (_subscribed != null) _subscribed.PropertyChanged -= PresentationChanged;
        foreach (var section in Sections) section.Dispose();
    }

    private void AssistantContextChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is "SelectedEvent" or "SelectedRow" or "SelectedEndpoint" or "SelectedScope" or "Filter" or "Scope")
        {
            Assistant?.RefreshContext();
            (_manager.ActiveInstance as AiWorkspaceViewModel)?.RefreshGeneralContext();
        }
    }
}
