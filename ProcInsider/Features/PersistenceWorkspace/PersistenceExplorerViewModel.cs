using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Features.PersistenceWorkspace;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.ViewModels;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class PersistenceExplorerNode(string title, PersistenceView? view = null, string? category = null, string? periodId = null, EvidenceIdentity? scope = null) : ViewModelBase
{
    private long? _count;
    private bool _green, _descendant, _excluded;
    private string _title = title;
    public string Title => _title;
    public PersistenceView? View { get; } = view;
    public string? Category { get; } = category;
    public string? PeriodId { get; } = periodId;
    public EvidenceIdentity? Scope { get; } = scope;
    public ObservableCollection<PersistenceExplorerNode> Children { get; } = [];
    public bool IsExpanded { get; set; }
    public string Display => $"{Title} ({_count ?? 0:N0})";
    public bool IsGreenIncludedDirectly => _green;
    public bool HasGreenIncludedDescendant => _descendant;
    public bool IsScopeExcluded => _excluded;
    public string ScopeGlyph => _green ? "G" : _excluded ? "−" : "";
    public string ScopeStateDescription => "Green includes, Exclude subtracts. Green criteria and column filters use AND within each independent period/view. This filters recorded evidence; it never controls collectors.";
    internal PersistenceSelector Selector => new(View, Category, PeriodId: PeriodId, Scope: Scope);
    internal void Count(long? count) { _count = count; OnPropertyChanged(nameof(Display)); }
    internal void UpdateTitle(string value) { if (SetProperty(ref _title, value, nameof(Title))) OnPropertyChanged(nameof(Display)); }
    internal void Project(IReadOnlyList<PersistenceSelector> selectors)
    {
        bool Covers(PersistenceSelector selector) => selector.Scope == Scope && selector.PeriodId == PeriodId && (selector.View == null || selector.View == View) && (selector.Category == null || selector.Category == Category);
        _excluded = selectors.Any(s => s.Excluded && Covers(s));
        _green = !_excluded && selectors.Any(s => !s.Excluded && Covers(s));
        _descendant = Children.Any(child => selectors.Any(s => !s.Excluded && s.Scope == child.Scope && s.PeriodId == child.PeriodId && s.View == child.View && s.Category == child.Category)) || Children.Any(child => child.HasGreenIncludedDescendant);
        foreach (var name in new[] { nameof(IsGreenIncludedDirectly), nameof(HasGreenIncludedDescendant), nameof(IsScopeExcluded), nameof(ScopeGlyph) }) OnPropertyChanged(name);
    }
}

internal sealed class PersistenceExplorerViewModel : ViewModelBase, IDisposable
{
    private readonly WorkspaceManager _manager;
    private readonly PersistenceWorkspaceReadSession _session;
    private PersistenceWorkspaceViewModel? _subscribed;
    private CancellationTokenSource _request = new();
    private Task _work = Task.CompletedTask;
    private bool _disposed, _suspended;
    private long _countRevision = -1, _loadingRevision = -1;
    public PersistenceExplorerNode Root { get; } = new("Persistence");
    public ObservableCollection<PersistenceExplorerNode> Children => Root.Children;
    public string Display => Root.Display;
    public string Status { get; private set; } = "No assessed Persistence read binding.";
    public bool IsExpanded { get; set; }
    public IAsyncRelayCommand<PersistenceExplorerNode> SelectCommand { get; }
    public IAsyncRelayCommand<PersistenceExplorerNode> OpenNewCommand { get; }
    public IAsyncRelayCommand<PersistenceExplorerNode> ToggleGreenCommand { get; }
    public IAsyncRelayCommand<PersistenceExplorerNode> ExcludeCommand { get; }
    internal PersistenceExplorerViewModel(WorkspaceManager manager, PersistenceWorkspaceReadSession session)
    {
        _manager = manager; _session = session;
        SelectCommand = new AsyncRelayCommand<PersistenceExplorerNode>(node => NavigateAsync(node, false, false));
        OpenNewCommand = new AsyncRelayCommand<PersistenceExplorerNode>(node => NavigateAsync(node, true, false));
        ToggleGreenCommand = new AsyncRelayCommand<PersistenceExplorerNode>(node => NavigateAsync(node, false, true));
        ExcludeCommand = new AsyncRelayCommand<PersistenceExplorerNode>(node => NavigateAsync(node, false, true, true));
        manager.ActiveContextChanged += Rebind;
    }
    private async Task NavigateAsync(PersistenceExplorerNode? node, bool openNew, bool toggle, bool excluded = false)
    {
        if (node == null || _disposed || _suspended || _manager.ReadsSuspended) return;
        await _manager.Navigation.NavigateAsync(new(WorkspaceTypeId.Persistence, _manager.Navigation.Capture,
            Mode: openNew ? WorkspaceNavigationMode.OpenNew : WorkspaceNavigationMode.Reuse,
            PersistenceView: node.View ?? PersistenceView.Current, PersistenceCategory: node.Category,
            PersistenceSelector: toggle ? node.Selector with { Excluded = excluded } : null,
            PersistencePeriodId: node.PeriodId, PersistenceScope: node.Scope));
    }
    private void Rebind()
    {
        if (_subscribed != null) _subscribed.Refreshed -= Reload;
        _subscribed = _manager.ActiveInstance as PersistenceWorkspaceViewModel;
        if (_subscribed != null) _subscribed.Refreshed += Reload;
        Reload();
    }
    private void Reload()
    {
        if (_disposed || _suspended || _session.Suspended || _manager.ReadsSuspended) return;
        ProjectSelectors();
        if (_countRevision == _session.Revision || _loadingRevision == _session.Revision) return;
        _work = LoadAsync();
    }
    private void ProjectSelectors()
    {
        foreach (var node in Nodes().Reverse()) node.Project(_subscribed?.Selectors ?? []);
    }
    private async Task LoadAsync()
    {
        _request.Cancel(); _request.Dispose(); _request = new(); var token = _request.Token;
        var revision = _session.Revision; _loadingRevision = revision;
        foreach (var node in Nodes()) node.Count(null);
        OnPropertyChanged(nameof(Display));
        var rootCountKnown = false;
        try
        {
            var scopes = (await _session.ScopesAsync(token)).ToArray();
            var periods = new List<(EvidenceIdentity Scope, PersistencePeriod Period)>();
            foreach (var scope in scopes)
                periods.AddRange((await _session.AllPeriodsAsync(scope, token)).Select(period => (scope, period)));
            if (!Current()) return;
            foreach (var scope in scopes) _subscribed?.ObservePeriods(scope, periods.Where(item => item.Scope == scope).Select(item => item.Period).ToArray(), revision);
            var desired = periods.OrderByDescending(item => item.Period.StartedUtc ?? item.Period.LastObservedUtc)
                .ThenBy(item => PersistenceComparisonPolicy.ScopeKey(item.Scope), StringComparer.Ordinal)
                .ThenBy(item => item.Period.PeriodId, StringComparer.Ordinal).ToArray();
            var nodes = new List<PersistenceExplorerNode>();
            var titles = new Dictionary<PersistenceExplorerNode, string>();
            var countsByNode = new Dictionary<PersistenceExplorerNode, Dictionary<string, long>>();
            long rootTotal = 0;
            foreach (var item in desired)
            {
                var periodNode = Children.FirstOrDefault(node => node.Scope == item.Scope && node.PeriodId == item.Period.PeriodId)
                    ?? CreatePeriod(item.Scope, item.Period, scopes.Length > 1);
                nodes.Add(periodNode);
                titles[periodNode] = PeriodTitle(item.Scope, item.Period, scopes.Length > 1);
                var current = periodNode.Children.Single(node => node.View == PersistenceView.Current);
                var page = await _session.QueryAsync(new PersistenceWorkspaceQuery(item.Scope, PersistenceView.Current,
                    Offset: 0, PageSize: 1, PeriodId: item.Period.PeriodId), token);
                if (!Current()) return;
                countsByNode[current] = new(page.CategoryCounts);
                rootTotal += page.ViewCounts.Values.Sum();
            }
            if (!Current()) return;
            // A query for one view also returns both unfiltered view totals. Publish the
            // assessed root before loading the second view's category breakdown.
            Root.Count(rootTotal);
            rootCountKnown = true;
            OnPropertyChanged(nameof(Display));
            for (var index = 0; index < desired.Length; index++)
            {
                var item = desired[index];
                var periodNode = nodes[index];
                var changes = periodNode.Children.Single(node => node.View == PersistenceView.Changes);
                var page = await _session.QueryAsync(new PersistenceWorkspaceQuery(item.Scope, PersistenceView.Changes,
                    Offset: 0, PageSize: 1, PeriodId: item.Period.PeriodId), token);
                if (!Current()) return;
                countsByNode[changes] = new(page.CategoryCounts);
            }
            if (!Current()) return;
            // Reuse retained node objects: WPF expansion and selection survive snapshot refresh.
            foreach (var removed in Children.Where(node => !nodes.Contains(node)).ToArray()) Children.Remove(removed);
            for (var index = 0; index < nodes.Count; index++)
            {
                var node = nodes[index];
                node.UpdateTitle(titles[node]);
                var existing = Children.IndexOf(node);
                if (existing < 0) Children.Insert(index, node);
                else if (existing != index) Children.Move(existing, index);
                foreach (var viewNode in node.Children)
                {
                    var counts = countsByNode[viewNode];
                    viewNode.Count(counts.Values.Sum());
                    foreach (var child in viewNode.Children) child.Count(counts.GetValueOrDefault(child.Category!, 0));
                }
                node.Count(node.Children.Sum(child => countsByNode[child].Values.Sum()));
            }
            _countRevision = revision; Status = "Recorded Persistence counts from the assessed capture.";
        }
        catch (OperationCanceledException) { }
        catch (Exception error) { if (Current()) { _countRevision = revision; foreach (var node in Nodes().Where(node => !rootCountKnown || !ReferenceEquals(node, Root))) node.Count(null); Status = "Persistence counts unavailable: " + error.Message; } }
        finally
        {
            if (_loadingRevision == revision) _loadingRevision = -1;
            if (Current())
            {
                ProjectSelectors();
                OnPropertyChanged(nameof(Display)); OnPropertyChanged(nameof(Status));
            }
        }
        bool Current() => !token.IsCancellationRequested && !_disposed && !_suspended && !_session.Suspended && !_manager.ReadsSuspended && revision == _session.Revision;
    }
    private static PersistenceExplorerNode CreatePeriod(EvidenceIdentity scope, PersistencePeriod period, bool multiple)
    {
        var node = new PersistenceExplorerNode(PeriodTitle(scope, period, multiple), periodId: period.PeriodId, scope: scope);
        foreach (var view in Enum.GetValues<PersistenceView>())
        {
            var child = new PersistenceExplorerNode(view.ToString(), view, periodId: period.PeriodId, scope: scope);
            foreach (var (name, category) in new[] { ("Registry Run", "Run"), ("Registry RunOnce", "RunOnce"), ("Scheduled Tasks", "ScheduledTasks"), ("Services", "Services"), ("Drivers", "Drivers"), ("Startup folders", "Startup"), ("WMI subscriptions", "WMI"), ("Winlogon", "Winlogon"), ("IFEO", "IFEO"), ("AppInit", "AppInit"), ("LSA", "LSA") }) child.Children.Add(new(name, view, category, period.PeriodId, scope));
            node.Children.Add(child);
        }
        return node;
    }
    private static string PeriodTitle(EvidenceIdentity scope, PersistencePeriod period, bool multiple)
    {
        var timestamp = period.StartedUtc?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'") ?? "Baseline time unavailable";
        return timestamp + (multiple ? $" · Host {scope.HostId} · Capture {scope.CaptureId} · Source {scope.SourceIdentityId}" : "");
    }
    private IEnumerable<PersistenceExplorerNode> Nodes()
    {
        IEnumerable<PersistenceExplorerNode> Walk(PersistenceExplorerNode node) => new[] { node }.Concat(node.Children.SelectMany(Walk));
        return Walk(Root);
    }
    internal void Invalidate() { _countRevision = _loadingRevision = -1; _request.Cancel(); foreach (var node in Nodes()) node.Count(null); OnPropertyChanged(nameof(Display)); }
    internal async Task QuiesceAsync(CancellationToken token) { _suspended = true; _loadingRevision = -1; _request.Cancel(); await _work.WaitAsync(token); }
    internal void Resume() { _suspended = false; Reload(); }
    public void Dispose() { _disposed = true; _request.Cancel(); _manager.ActiveContextChanged -= Rebind; if (_subscribed != null) _subscribed.Refreshed -= Reload; }
}
