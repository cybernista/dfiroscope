using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class ArtifactsExplorerNode(string title, ForensicArtifactResultGreenSelector? selector = null,
    IReadOnlyList<ForensicArtifactResultColumnFilter>? filters = null) : ViewModelBase
{
    private long? _count;
    private bool _green, _descendant;
    public string Title { get; } = title;
    public ForensicArtifactResultGreenSelector? Selector { get; } = selector;
    public IReadOnlyList<ForensicArtifactResultColumnFilter> Filters { get; } = filters ?? [];
    public ObservableCollection<ArtifactsExplorerNode> Children { get; } = [];
    public bool IsExpanded { get; set; }
    public bool CanToggleGreen => Selector != null;
    public bool IsGreenIncludedDirectly => _green;
    public bool HasGreenIncludedDescendant => _descendant;
    public string Display => $"{Title} ({_count ?? 0:N0})";
    public string ScopeGlyph => _green ? "G" : "";
    public string ScopeStateDescription => "Green selection filters retained evidence only; it never starts collection or changes stored results.";
    internal void Count(long? count) { _count = count; OnPropertyChanged(nameof(Display)); }
    internal void Project(IReadOnlyList<ForensicArtifactResultGreenSelector> selectors)
    {
        _green = Selector is { } selector && selectors.Contains(selector);
        _descendant = Children.Any(child => child._green || child._descendant);
        OnPropertyChanged(nameof(ScopeGlyph));
        OnPropertyChanged(nameof(IsGreenIncludedDirectly));
        OnPropertyChanged(nameof(HasGreenIncludedDescendant));
    }
}

/// <summary>Explorer projection for generic results. It reads the assessed snapshot and never invokes collection.</summary>
internal sealed class ArtifactsExplorerViewModel : ViewModelBase, IDisposable
{
    private readonly WorkspaceManager _manager;
    private readonly ArtifactsWorkspaceReadSession _session;
    private CancellationTokenSource _request = new();
    private Task _work = Task.CompletedTask;
    private bool _disposed, _suspended;
    private long _countRevision = -1, _loadingRevision = -1;
    private ArtifactsWorkspaceViewModel? _active;
    public ArtifactsExplorerNode Root { get; } = new("Artifacts");
    public ObservableCollection<ArtifactsExplorerNode> Children => Root.Children;
    public string Display => Root.Display;
    public bool IsExpanded { get; set; }
    public string Status { get; private set; } = "No assessed Artifacts read binding.";
    public IAsyncRelayCommand<ArtifactsExplorerNode> SelectCommand { get; }
    public IAsyncRelayCommand<ArtifactsExplorerNode> OpenNewCommand { get; }
    public IAsyncRelayCommand<ArtifactsExplorerNode> ToggleGreenCommand { get; }
    internal ArtifactsExplorerViewModel(WorkspaceManager manager, ArtifactsWorkspaceReadSession session)
    {
        _manager = manager; _session = session;
        var prefetchFilter = new ForensicArtifactResultColumnFilter(ForensicArtifactResultColumn.ArtifactType,
            new ColumnFilterCriteria { AllValues = false, Values = ["Prefetch"] });
        var executionFilter = new ForensicArtifactResultColumnFilter(ForensicArtifactResultColumn.Category,
            new ColumnFilterCriteria { AllValues = false, Values = ["Execution"] });
        var prefetch = new ArtifactsExplorerNode("Prefetch", new(ForensicArtifactResultScopeFacet.ArtifactType, "Prefetch"), [prefetchFilter]);
        prefetch.Children.Add(new ArtifactsExplorerNode("Execution", new(ForensicArtifactResultScopeFacet.Category, "Execution"), [prefetchFilter, executionFilter]));
        Root.Children.Add(prefetch);
        SelectCommand = new AsyncRelayCommand<ArtifactsExplorerNode>(node => NavigateAsync(node, false, false));
        OpenNewCommand = new AsyncRelayCommand<ArtifactsExplorerNode>(node => NavigateAsync(node, true, false));
        ToggleGreenCommand = new AsyncRelayCommand<ArtifactsExplorerNode>(node => NavigateAsync(node, false, true));
        manager.ActiveContextChanged += Invalidate;
    }
    private async Task NavigateAsync(ArtifactsExplorerNode? node, bool openNew, bool green)
    {
        if (node == null || _disposed || _suspended || _manager.ReadsSuspended) return;
        var result = await _manager.Navigation.NavigateAsync(new(WorkspaceTypeId.Artifacts, _manager.Navigation.Capture,
            Mode: openNew ? WorkspaceNavigationMode.OpenNew : WorkspaceNavigationMode.Reuse,
            ArtifactFilters: green ? null : node.Filters,
            ArtifactSelectors: green ? null : node.Filters.Count == 0 && node.Selector is { } scope ? [scope] : [], ArtifactTitle: node.Title));
        if (green && node.Selector is { } selector && result.Outcome == ViewerNavigationOutcome.Succeeded && _manager.ActiveInstance is ArtifactsWorkspaceViewModel workspace)
        {
            workspace.ToggleGreen(selector); ProjectSelectors();
        }
    }
    internal void Invalidate()
    {
        if (_disposed || _suspended || _session.Suspended || _manager.ReadsSuspended) return;
        var active = _manager.ActiveInstance as ArtifactsWorkspaceViewModel;
        if (!ReferenceEquals(active, _active))
        {
            if (_active != null) _active.QueryChanged -= Invalidate;
            _active = active;
            if (_active != null) _active.QueryChanged += Invalidate;
        }
        ProjectSelectors();
        if (_countRevision == _session.Revision || _loadingRevision == _session.Revision) return;
        _work = LoadAsync();
    }
    private async Task LoadAsync()
    {
        _request.Cancel(); _request.Dispose(); _request = new(); var token = _request.Token; var revision = _session.Revision; _loadingRevision = revision;
        foreach (var node in Nodes()) node.Count(null);
        try
        {
            var activeQuery = new ForensicArtifactResultQuery();
            var page = await _session.QueryAsync(activeQuery, token);
            var prefetchNode = Children.First(node => node.Selector?.Facet == ForensicArtifactResultScopeFacet.ArtifactType);
            var executionNode = prefetchNode.Children.Single();
            var prefetchQuery = new ForensicArtifactResultQuery(Filters: prefetchNode.Filters);
            var executionQuery = new ForensicArtifactResultQuery(Filters: executionNode.Filters);
            var prefetch = await _session.QueryAsync(prefetchQuery, token);
            var execution = await _session.QueryAsync(executionQuery, token);
            if (token.IsCancellationRequested || _disposed || _suspended || _session.Suspended || _manager.ReadsSuspended || revision != _session.Revision) return;
            Root.Count(page.Availability == ForensicArtifactResultAvailability.Available ? page.RootCount : null);
            prefetchNode.Count(prefetch.Availability == ForensicArtifactResultAvailability.Available ? prefetch.ViewCount : null);
            executionNode.Count(execution.Availability == ForensicArtifactResultAvailability.Available ? execution.ViewCount : null);
            _countRevision = revision;
            Status = page.Availability == ForensicArtifactResultAvailability.Available ? $"{page.RootCount:N0} retained results." : page.Diagnostic;

        }
        catch (OperationCanceledException) { }
        catch (Exception error) { if (!token.IsCancellationRequested && !_disposed && !_suspended && !_session.Suspended && !_manager.ReadsSuspended && revision == _session.Revision) { _countRevision = revision; Status = "Artifacts counts unavailable: " + error.Message; } }
        finally { if (_loadingRevision == revision) _loadingRevision = -1; if (!token.IsCancellationRequested && revision == _session.Revision) { ProjectSelectors(); OnPropertyChanged(nameof(Display)); OnPropertyChanged(nameof(Status)); } }
    }
    private IEnumerable<ArtifactsExplorerNode> Nodes() => new[] { Root }.Concat(Root.Children.SelectMany(child => new[] { child }.Concat(child.Children)));
    internal void ProjectSelectors()
    {
        var selectors = (_manager.ActiveInstance as ArtifactsWorkspaceViewModel)?.GreenSelectors ?? [];
        foreach (var node in Nodes().Reverse()) node.Project(selectors);
    }
    internal async Task QuiesceAsync(CancellationToken token) { _suspended = true; _loadingRevision = -1; _request.Cancel(); await _work.WaitAsync(token); }
    internal void Resume() { _suspended = false; Invalidate(); }
    public void Dispose() { if (_disposed) return; _disposed = true; _request.Cancel(); _manager.ActiveContextChanged -= Invalidate; if (_active != null) _active.QueryChanged -= Invalidate; }
}
