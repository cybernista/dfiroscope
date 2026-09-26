using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

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
            if (SetProperty(ref _selectedSection, value) && value != null) value.IsSelected = true;
        }
    }
    public IAsyncRelayCommand<ExplorerNodeViewModel> ToggleGreenCommand { get; }
    public IAsyncRelayCommand<ExplorerNodeViewModel> OpenNewCommand { get; }
    public WorkspaceNavigationService Navigation => _manager.Navigation;
    public EventsExplorerViewModel? Events => _manager.EventsExplorer;
    public bool EventsAvailable => _manager.EventsAvailable;
    public ProcessPresentationViewModel? ActivePresentation => _manager.ActivePresentation;
    public ProcInsider.Services.Presentation.ViewerSharedActions SharedActions => _manager.SharedActions;
    internal ExplorerSectionsViewModel(WorkspaceManager manager, FeatureAccessService access,
        Func<ExplorerScope, Task<IReadOnlyList<ExplorerNodeViewModel>>>? loadChildren,
        IReadOnlyList<FeatureTabDescriptor>? sharedTabs)
    {
        _manager = manager;
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
        _navigationTabs = navigationTabs;
        Explorer.RootNodes.CollectionChanged += RootsChanged;
        RootsChanged(null, null!);
        manager.ActiveContextChanged += Rebind;
        Rebind();
    }
    private void RootsChanged(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
    {
        var eventActivityRoots = Explorer.RootNodes.Where(node =>
            node.Scope.Kind == ExplorerScopeKind.SystemActivityRoot).ToArray();
        Events?.BindActivityRoots(eventActivityRoots);
        var explorerRoots = Explorer.RootNodes.Where(node =>
            node.Scope.Kind != ExplorerScopeKind.UsersRoot &&
            (!EventsAvailable || !eventActivityRoots.Contains(node)));
        var desired = explorerRoots.Cast<object>().Concat(EventsAvailable && Events != null ? new object[] { Events } : []).ToArray();
        foreach (var removed in Roots.Where(r => !desired.Contains(r)).ToArray()) Roots.Remove(removed);
        for (var i = 0; i < desired.Length; i++)
        {
            var index = Roots.IndexOf(desired[i]);
            if (index < 0) Roots.Insert(i, desired[i]); else if (index != i) Roots.Move(index, i);
        }
    }
    internal void Rebind()
    {
        if (_subscribed != null) _subscribed.PropertyChanged -= PresentationChanged;
        _subscribed = ActivePresentation;
        if (_subscribed != null) _subscribed.PropertyChanged += PresentationChanged;
        var descriptors = _navigationTabs.Concat(_sharedTabs).Concat(ActivePresentation?.ExplorerTabs.Where(d =>
            d.Key != ExplorerTabKeys.Explore && !_sharedTabs.Any(s => s.Key == d.Key)) ?? [])
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
        if (e.PropertyName == nameof(ProcessPresentationViewModel.ScopedSelectionStatus)) ProjectSelectors();
        if (e.PropertyName == nameof(ProcessPresentationViewModel.SelectedExplorerTab) && ActivePresentation?.SelectedExplorerTab is { } tab)
            Expand(tab.Key);
    }
    internal bool Expand(FeatureTabKey key)
    {
        var section = Sections.FirstOrDefault(s => s.Key == key);
        if (section == null) return false;
        SelectedSection = section;
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
        ApplyMetadata(new(new(), []));
        Explorer.ResetSelection();
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
        Explorer.RootNodes.CollectionChanged -= RootsChanged;
        _manager.ActiveContextChanged -= Rebind;
        if (_subscribed != null) _subscribed.PropertyChanged -= PresentationChanged;
        foreach (var section in Sections) section.Dispose();
    }
}
