using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services.NetworkWorkspace;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal class NetworkExplorerNode(string title, NetworkProcessScope? scope, long revision, bool byProcess = false, NetworkFacet? facet = null) : ViewModelBase
{
    private long? _count;
    private bool _green, _descendant;
    private string _title=title;
    private bool _selected;
    public string Title {get=>_title;private set=>SetProperty(ref _title,value);}
    public bool IsSelected {get=>_selected;set=>SetProperty(ref _selected,value);}
    internal object StableKey => EndpointQuery is { } q ? (q.Kind,q.PollId,q.FromUtcTicks,q.ToUtcTicks,q.Scope,q.SourceRunId,q.SnapshotId) : (Scope,ByProcess,Facet);
    internal void UpdatePresentation(NetworkExplorerNode incoming){Title=incoming.Title;Revision=incoming.Revision;UpdateCount(incoming.ObservationCount);}
    public string Display => $"{Title} ({_count ?? 0:N0})";
    public string ToolTip => EndpointQuery!=null || this is NetworkEndpointDirectory
        ? $"{Title}; {_count ?? 0:N0} recorded OS endpoint rows. Coverage and actual family windows are shown in the Listing and Details; browsing does not collect."
        : Facet is { Dimension: NetworkDimension.Time, FromUtcTicks: { } from, ToUtcTicks: { } to }
        ? $"{new DateTime(from, DateTimeKind.Utc):O} inclusive to {(to <= DateTime.MaxValue.Ticks ? new DateTime(to, DateTimeKind.Utc).ToString("O") : "end of supported time")} exclusive; {_count ?? 0:N0} recorded observations."
        : $"{Title}; {_count ?? 0:N0} recorded observations.";
    public NetworkProcessScope? Scope { get; } = scope;
    public NetworkFacet? Facet { get; } = facet;
    internal NetworkEndpointQuery? EndpointQuery {get;init;}
    public bool CanToggleGreen => true;
    public long Revision { get; internal set; } = revision;
    public bool ByProcess { get; } = byProcess;
    public bool IsGreenIncludedDirectly => _green;
    public bool HasGreenIncludedDescendant => _descendant;
    public string ScopeGlyph => _green ? "G" : "";
    public string ScopeStateDescription => "Toggle green Network selection; alternatives within a view combine with OR, views and column filters with AND. Counts omit this view's green and navigation criteria.";
    internal NetworkGreenSelector Selector => new(Scope, ByProcess, Facet: Facet);
    internal void UpdateCount(long? count) { _count = count; OnPropertyChanged(nameof(Display)); OnPropertyChanged(nameof(ToolTip)); }
    internal long? ObservationCount => _count;
    internal void ProjectGreen(IReadOnlyList<NetworkGreenSelector> selectors)
    {
        _green = NetworkGreenSelector.Includes(selectors, Selector);
        _descendant = this is NetworkProcessDirectory && selectors.Any(s => !s.IsExcluded && s != Selector && Selector.Covers(s));
        OnPropertyChanged(nameof(IsGreenIncludedDirectly)); OnPropertyChanged(nameof(HasGreenIncludedDescendant)); OnPropertyChanged(nameof(ScopeGlyph));
    }
    internal void ProjectEndpointGreen(IReadOnlyList<NetworkEndpointGreenSelector> selectors)
    {
        var selector = EndpointQuery == null ? null : new NetworkEndpointGreenSelector(EndpointQuery);
        _green = selector != null && NetworkEndpointGreenSelector.Includes(selectors, selector);
        _descendant = selector != null && this is NetworkEndpointDirectory && selectors.Any(s => !s.IsExcluded && s != selector && selector.Covers(s));
        OnPropertyChanged(nameof(IsGreenIncludedDirectly));OnPropertyChanged(nameof(HasGreenIncludedDescendant));OnPropertyChanged(nameof(ScopeGlyph));
    }
}

// The existing directory presentation is shared by the process and flat facet views.
internal sealed class NetworkProcessDirectory(string title, NetworkDimension dimension, Action expand) :
    NetworkExplorerNode(title, null, 0, dimension == NetworkDimension.Process,
        dimension == NetworkDimension.Process ? null : new(dimension))
{
    private bool _expanded;
    public NetworkDimension Dimension { get; } = dimension;
    internal long LoadedGeneration { get; set; } = -1;
    internal int Pages { get; set; } = 1;
    internal int LoadedPages { get; set; }
    public bool IsExpanded { get => _expanded; set { if (SetProperty(ref _expanded, value) && value) expand(); } }
    public ObservableCollection<object> Children { get; } = [];
}

internal sealed record NetworkDirectoryMore(IAsyncRelayCommand Command)
{
    public string Display => "Load more groups…";
}
internal sealed class NetworkEndpointDirectory(string title,long revision,Action? expand=null) : NetworkExplorerNode(title,null,revision)
{
    private bool _expanded;
    public bool IsExpanded {get=>_expanded;set{if(SetProperty(ref _expanded,value)&&value)expand?.Invoke();}}
    public ObservableCollection<object> Children {get;}=[];
}

internal sealed class NetworkExplorerViewModel : ViewModelBase, IDisposable
{
    private readonly WorkspaceManager _manager;
    private readonly NetworkWorkspaceReadSession _session;
    private CancellationTokenSource _request = new();
    private Task _work = Task.CompletedTask;
    private NetworkWorkspaceViewModel? _subscribed;
    private bool _disposed, _suspended, _expanded, _reload;
    private long _generation, _countGeneration = -1;
    private long? _count;
    private long _eventCount, _rootCountGeneration = -1;
    private string _status = "";
    public bool IsExpanded { get => _expanded; set { if (SetProperty(ref _expanded, value) && value) _ = LoadAsync(); } }
    public string Display => $"Network ({_count ?? 0:N0})";
    internal Task PendingWork => _work;
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public ObservableCollection<object> Children { get; } = [];
    public NetworkExplorerNode All { get; }
    public NetworkProcessDirectory Processes { get; }
    public NetworkEndpointDirectory ListenerHistory {get;}
    public NetworkEndpointDirectory ConnectionSnapshots {get;}
    private int _endpointPages=1;
    internal IReadOnlyList<NetworkProcessDirectory> Directories { get; }
    public IAsyncRelayCommand<NetworkExplorerNode> SelectCommand { get; }
    public IAsyncRelayCommand<NetworkExplorerNode> OpenNewCommand { get; }
    public IAsyncRelayCommand<NetworkExplorerNode> ToggleGreenCommand { get; }
    internal NetworkExplorerViewModel(WorkspaceManager manager, NetworkWorkspaceReadSession session)
    {
        _manager = manager; _session = session;
        All = new("All recorded event activity", null, session.Revision);
        Processes = new("Network activity by process", NetworkDimension.Process, () => _ = LoadAsync());
        ListenerHistory=new("Listener history",session.Revision){EndpointQuery=new(EndpointScopeKind.ListenerHistory)};
        ConnectionSnapshots=new("Connection snapshots (UTC)",session.Revision,()=>_ = LoadAsync()){EndpointQuery=new(EndpointScopeKind.ConnectionSnapshots)};
        Directories = new[] { Processes }.Concat(new[]
        {
            (NetworkDimension.Provider, "Provider"), (NetworkDimension.DestinationPort, "Destination ports"), (NetworkDimension.Protocol, "Protocols"),
            (NetworkDimension.Direction, "Direction"), (NetworkDimension.AddressScope, "Remote address scope"),
            (NetworkDimension.Conversation, "Conversations"), (NetworkDimension.Time, "Time buckets")
        }.Select(pair => new NetworkProcessDirectory(pair.Item2, pair.Item1, () => _ = LoadAsync()))).ToArray();
        SelectCommand = new AsyncRelayCommand<NetworkExplorerNode>(node => NavigateAsync(node, false));
        OpenNewCommand = new AsyncRelayCommand<NetworkExplorerNode>(node => NavigateAsync(node, true));
        ToggleGreenCommand = new AsyncRelayCommand<NetworkExplorerNode>(node => NavigateAsync(node, false, true));
        manager.ActiveContextChanged += Rebind;
        Invalidate();
    }
    private async Task NavigateAsync(NetworkExplorerNode? node, bool openNew, bool green = false)
    {
        if (node == null || node.Revision != _session.Revision || _suspended) return;
        if(node is NetworkEndpointDirectory directory && node.EndpointQuery==null){directory.IsExpanded=true;return;}
        await _manager.Navigation.NavigateAsync(new(WorkspaceTypeId.Network, _manager.Navigation.Capture,
            Mode: openNew ? WorkspaceNavigationMode.OpenNew : WorkspaceNavigationMode.Reuse,
            NetworkScope: node.Scope, NetworkTitle: node.Title, NetworkRevision: node.Revision,
            NetworkByProcess: node.ByProcess, NetworkFacet: node.Facet,NetworkEndpoints:node.EndpointQuery), green);
    }
    private void Rebind()
    {
        if (_subscribed != null) _subscribed.ScopeChanged -= ScopeChanged;
        _subscribed = _manager.ActiveInstance as NetworkWorkspaceViewModel;
        if (_subscribed != null) _subscribed.ScopeChanged += ScopeChanged;
        ScopeChanged();
    }
    private void ScopeChanged()
    {
        _generation++;
        _count = null;
        OnPropertyChanged(nameof(Display));
        ProjectSelectors();
        ScheduleCountRefresh();
    }
    private void ProjectSelectors()
    {
        var selectors = _subscribed?.GreenSelectors ?? [];
        All.ProjectGreen(selectors);
        foreach (var directory in Directories)
        {
            directory.ProjectGreen(selectors);
            foreach (var child in directory.Children.OfType<NetworkExplorerNode>()) child.ProjectGreen(selectors);
        }
        foreach (var node in EndpointNodes()) node.ProjectEndpointGreen(_subscribed?.EndpointGreenSelectors ?? []);
    }
    private IEnumerable<NetworkExplorerNode> EndpointNodes()
    {
        IEnumerable<NetworkExplorerNode> Visit(NetworkExplorerNode node)
        {
            yield return node;
            if (node is NetworkEndpointDirectory directory)
                foreach (var child in directory.Children.OfType<NetworkExplorerNode>())
                    foreach (var nested in Visit(child)) yield return nested;
        }
        return Visit(ListenerHistory).Concat(Visit(ConnectionSnapshots));
    }
    internal void BindLegacy(IEnumerable<ExplorerNodeViewModel> roots)
    {
        foreach (var old in Children.OfType<ExplorerNodeViewModel>().ToArray()) Children.Remove(old);
        foreach (var node in roots.SelectMany(r => r.Children)) Children.Add(node);
    }
    internal void Invalidate(bool captureChanged=true)
    {
        _generation++; _countGeneration = -1; _count = null;
        if(!captureChanged)
        {
            _endpointPages=1;
            All.Revision=_session.Revision;All.UpdateCount(null);
            foreach(var node in EndpointNodes()){node.Revision=_session.Revision;node.UpdateCount(null);}
            foreach(var directory in Directories)
            {
                directory.Revision=_session.Revision;directory.LoadedGeneration=-1;directory.Pages=1;directory.LoadedPages=0;directory.UpdateCount(null);
                foreach(var child in directory.Children.OfType<NetworkExplorerNode>()){child.Revision=_session.Revision;child.UpdateCount(null);}
            }
            OnPropertyChanged(nameof(Display));ProjectSelectors();ScheduleCountRefresh();return;
        }
        All.Revision = _session.Revision; All.UpdateCount(null);
        ListenerHistory.Revision=ConnectionSnapshots.Revision=_session.Revision;_endpointPages=1;
        ListenerHistory.UpdateCount(null);ConnectionSnapshots.UpdateCount(null);
        ListenerHistory.Children.Clear();
        ListenerHistory.Children.Add(new NetworkExplorerNode("TCP listeners",null,_session.Revision){EndpointQuery=new(EndpointScopeKind.TcpListeners)});
        ListenerHistory.Children.Add(new NetworkExplorerNode("UDP endpoints",null,_session.Revision){EndpointQuery=new(EndpointScopeKind.UdpEndpoints)});
        ConnectionSnapshots.Children.Clear();ConnectionSnapshots.Children.Add(new EventsCategoryPlaceholder("Expand to read recorded snapshots; no collection starts here."));
        if (Children.Count == 0) { Children.Add(Directories.Single(d => d.Dimension == NetworkDimension.Provider)); Children.Add(All); foreach (var directory in Directories.Where(d => d.Dimension != NetworkDimension.Provider)) Children.Add(directory); }
        if(!Children.Contains(ListenerHistory)){Children.Add(ListenerHistory);Children.Add(ConnectionSnapshots);}
        foreach (var directory in Directories)
        {
            directory.Revision = _session.Revision; directory.LoadedGeneration = -1; directory.Pages = 1;
            directory.UpdateCount(null); directory.Children.Clear();
            directory.Children.Add(new EventsCategoryPlaceholder("Expand to read recorded Network groups."));
        }
        Status = ""; OnPropertyChanged(nameof(Display)); ProjectSelectors(); ScheduleCountRefresh();
    }
    private void ScheduleCountRefresh() => _ = LoadAsync();
    private bool CollapsedWithoutDesk => !IsExpanded && _subscribed == null && !ListenerHistory.IsExpanded
        && !ConnectionSnapshots.IsExpanded && Directories.All(d => !d.IsExpanded);
    internal Task LoadAsync(bool reset = false)
    {
        if (_disposed || _suspended || _session.Suspended || _manager.ReadsSuspended || !_session.HasBinding) return Task.CompletedTask;
        if (reset) Invalidate();
        _reload = true;
        if (!_work.IsCompleted) return _work;
        _work = RunAsync(); return _work;
    }
    internal bool IsRecalculating {get;private set;}
    private async Task RunAsync()
    {
        while (_reload && !_disposed && !_suspended)
        {
            _reload = false;
            var token = _request.Token; var revision = _session.Revision; var generation = _generation;
            var query = _subscribed?.CaptureQuery() ?? new NetworkAnalysisQuery();
            bool Current() => !token.IsCancellationRequested && !_suspended && !_disposed && !_session.Suspended && !_manager.ReadsSuspended && revision == _session.Revision && generation == _generation;
            try
            {
                if (CollapsedWithoutDesk)
                {
                    if (_rootCountGeneration == generation) continue;
                    // Count bounded pages through the capture owner; child discovery stays lazy.
                    var all = await _session.QueryAsync(query with { Offset = 0, PageSize = 1 }, false, token);
                    if (!Current()) continue;
                    if (all.Status.State != NetworkProcessingState.Ready) throw new InvalidOperationException(all.Status.Detail);
                    var listenerRows = await _session.EndpointsAsync(ListenerHistory.EndpointQuery! with { Offset = 0, PageSize = 1 }, token);
                    if (!Current()) continue;
                    var snapshotRows = await _session.EndpointsAsync(ConnectionSnapshots.EndpointQuery! with { Offset = 0, PageSize = 1 }, token);
                    if (!Current()) continue;
                    _eventCount = all.MatchingRecords;
                    All.UpdateCount(_eventCount);
                    ListenerHistory.UpdateCount(listenerRows.MatchingRows);
                    ConnectionSnapshots.UpdateCount(snapshotRows.MatchingRows);
                    _count = _eventCount + listenerRows.MatchingRows + snapshotRows.MatchingRows;
                    _rootCountGeneration = generation;
                    Status = ""; OnPropertyChanged(nameof(Display));
                    continue;
                }
                if(ConnectionSnapshots.IsExpanded)
                {
                    var polls=new List<NetworkEndpointPoll>();
                    for(var page=0;page<_endpointPages;page++)polls.AddRange(await _session.EndpointPollsAsync(page*128,token));
                    if(!Current())continue;
                    var desiredSnapshots=new ObservableCollection<object>();
                    foreach(var date in polls.GroupBy(p=>(p.SnapshotStartUtc??p.WindowStartUtc).Date).OrderByDescending(g=>g.Key))
                    {
                        var day=new NetworkEndpointDirectory(date.Key.ToString("yyyy-MM-dd 'UTC'"),revision){EndpointQuery=new(EndpointScopeKind.ConnectionSnapshots,
                            FromUtcTicks:date.Key.Ticks,ToUtcTicks:date.Key.AddDays(1).Ticks)};
                        foreach(var hour in date.GroupBy(p=>(p.SnapshotStartUtc??p.WindowStartUtc).Hour).OrderByDescending(g=>g.Key))
                        {
                            var start=date.Key.AddHours(hour.Key);
                            var group=new NetworkEndpointDirectory(start.ToString("HH:00 'UTC'"),revision){EndpointQuery=new(EndpointScopeKind.ConnectionSnapshots,FromUtcTicks:start.Ticks,ToUtcTicks:start.AddHours(1).Ticks)};
                            foreach(var cycle in hour.GroupBy(p=>string.IsNullOrEmpty(p.SnapshotId)?p.PollId:p.SnapshotId))
                            {
                                var first=cycle.First();var title=$"{first.SnapshotStartUtc??first.WindowStartUtc:HH:mm:ss.fff} UTC — "+string.Join(", ",new[]{EndpointFamily.TcpV4,EndpointFamily.TcpV6}.Select(f=>$"{f} {cycle.FirstOrDefault(p=>p.Family==f)?.Outcome.ToString()??"unknown"}"));
                                group.Children.Add(new NetworkExplorerNode(title,null,revision){EndpointQuery=new(EndpointScopeKind.ConnectionSnapshots,
                                    PollId:string.IsNullOrEmpty(first.SnapshotId)?first.PollId:null,
                                    FromUtcTicks:(first.SnapshotStartUtc??first.WindowStartUtc).Ticks,
                                    ToUtcTicks:(first.SnapshotStartUtc??first.WindowStartUtc).AddTicks(1).Ticks,
                                    Scope:first.Scope,SourceRunId:first.SourceRunId,SnapshotId:string.IsNullOrEmpty(first.SnapshotId)?null:first.SnapshotId)});
                            }
                            day.Children.Add(group);
                        }
                        desiredSnapshots.Add(day);
                    }
                    ApplyChildren(ConnectionSnapshots.Children,desiredSnapshots);
                    // Paging bounds discovery, not visibility of the active desk's criteria.
                    // Retain exact checked/excluded scopes; counts below still use bounded queries.
                    foreach(var selected in (_subscribed?.EndpointGreenSelectors ?? []).Where(s=>
                        s.Query.Kind==EndpointScopeKind.ConnectionSnapshots && s.Query.FromUtcTicks.HasValue))
                        RetainEndpointSelector(selected.Query,revision);
                    if(polls.Select(p=>string.IsNullOrEmpty(p.SnapshotId)?p.PollId:p.SnapshotId).Distinct().Count()==_endpointPages*128 && !ConnectionSnapshots.Children.OfType<NetworkDirectoryMore>().Any())ConnectionSnapshots.Children.Add(new NetworkDirectoryMore(new AsyncRelayCommand(()=>{_endpointPages++;return LoadAsync();})));
                }
                if (_countGeneration != generation)
                {
                    var all = await _session.QueryAsync(query with { Offset = 0, PageSize = 1 }, false, token);
                    if (!Current()) continue;
                    if (all.Status.State != NetworkProcessingState.Ready) throw new InvalidOperationException(all.Status.Detail);
                    _eventCount = all.MatchingRecords; All.UpdateCount(_eventCount);
                    foreach (var directory in Directories)
                    {
                        var adaptive = NetworkAnalysisService.AdaptiveQuery(query, directory.Dimension);
                        var count = await _session.QueryAsync(adaptive with { Offset = 0, PageSize = 1,
                            ResolvedProcessesOnly = directory.Dimension == NetworkDimension.Process || adaptive.ResolvedProcessesOnly }, false, token);
                        if (!Current()) break;
                        if (count.Status.State != NetworkProcessingState.Ready) throw new InvalidOperationException(count.Status.Detail);
                        directory.UpdateCount(count.MatchingRecords);
                    }
                    if (!Current()) continue;
                    _countGeneration = generation;
                }
                long listenerCount = 0, snapshotCount = 0;
                foreach (var node in EndpointNodes())
                {
                    if (node.EndpointQuery == null) continue;
                    // Endpoint selectors are adaptive alternatives within their own recorded source view.
                    var count = await _session.EndpointsAsync(node.EndpointQuery with { Text = _subscribed?.Text,
                        Offset = 0, PageSize = 1, Columns = _subscribed?.EndpointColumns }, token);
                    if (!Current()) break;
                    node.UpdateCount(count.MatchingRows);
                    if (ReferenceEquals(node, ListenerHistory)) listenerCount = count.MatchingRows;
                    if (ReferenceEquals(node, ConnectionSnapshots)) snapshotCount = count.MatchingRows;
                    node.ProjectEndpointGreen(_subscribed?.EndpointGreenSelectors ?? []);
                }
                if (!Current()) continue;
                _count = _eventCount + listenerCount + snapshotCount;
                if (!Current()) continue;
                OnPropertyChanged(nameof(Display));
                foreach (var directory in Directories.Where(d => d.IsExpanded && (d.LoadedGeneration != generation || d.LoadedPages != d.Pages)))
                {
                    var requestedPages = directory.Pages;
                    var desired = new List<NetworkExplorerNode>(); bool more = false;
                    for (long offset = 0; ; offset += 128)
                    {
                        if (directory.Dimension == NetworkDimension.Process)
                        {
                            var rows = await _session.ProcessesAsync(offset, token, query);
                            if (!Current()) break;
                            foreach (var row in rows)
                            {
                                var node = new NetworkExplorerNode(row.ProcessName, row.Scope, revision);
                                node.UpdateCount(row.Observations); desired.Add(node);
                            }
                            if (rows.Count < 128) break;
                        }
                        else
                        {
                            var rows = await _session.FacetsAsync(query with { Offset = offset, PageSize = 128 }, directory.Dimension, token);
                            if (!Current()) break;
                            foreach (var row in rows)
                            {
                                var node = new NetworkExplorerNode(row.Title, null, revision, facet: row.Facet);
                                node.UpdateCount(row.Observations); desired.Add(node);
                            }
                            if (rows.Count < 128) break;
                            if (offset + 128 >= requestedPages * 128L) { more = true; break; }
                        }
                    }
                    if (!Current()) break;
                    // Retain checked groups even when another dimension reduces their count to zero,
                    // or when a conversation is outside the currently displayed group pages.
                    foreach (var selected in (query.GreenSelectors ?? []).Concat(directory.Children.OfType<NetworkExplorerNode>().Where(n=>n.IsSelected).Select(n=>n.Selector)).Distinct().Where(s => s.Dimension == directory.Dimension && (s.Scope != null || s.Facet?.Key != null)))
                    {
                        if (desired.Any(n => n.Selector == (selected with { IsExcluded = false }))) continue;
                        var adaptive = NetworkAnalysisService.AdaptiveQuery(query, directory.Dimension);
                        var count = await _session.QueryAsync(adaptive with { Offset = 0, PageSize = 1, ProcessScope = selected.Scope, FacetScope = selected.Facet }, false, token);
                        if (!Current()) break;
                        if (count.Status.State != NetworkProcessingState.Ready) throw new InvalidOperationException(count.Status.Detail);
                        var old = directory.Children.OfType<NetworkExplorerNode>().FirstOrDefault(n => n.Scope == selected.Scope && n.Facet == selected.Facet);
                        var node = old ?? new NetworkExplorerNode(selected.Facet == null ? selected.Scope!.ProcessEntityId : NetworkAnalysisService.FacetTitle(selected.Facet), selected.Scope, revision, facet: selected.Facet);
                        node.UpdateCount(count.MatchingRecords); desired.Add(node);
                    }
                    if (!Current()) break;
                    var existing = directory.Children.OfType<NetworkExplorerNode>().ToDictionary(n => n.Selector);
                    for (var i = 0; i < desired.Count; i++)
                    {
                        if (existing.TryGetValue(desired[i].Selector, out var old))
                        { old.UpdatePresentation(desired[i]); desired[i] = old; }
                        desired[i].ProjectGreen(query.GreenSelectors ?? []);
                    }
                    ApplyChildren(directory.Children,new ObservableCollection<object>(desired));
                    if (more) directory.Children.Add(new NetworkDirectoryMore(new AsyncRelayCommand(() =>
                    { directory.Pages++; directory.LoadedGeneration = -1; return LoadAsync(); })));
                    if (desired.Count == 0) directory.Children.Add(new EventsCategoryPlaceholder("No recorded observations match the other view filters."));
                    directory.LoadedGeneration = generation;
                    directory.LoadedPages = requestedPages;
                }
                if (Current()) Status = "";
            }
            catch (OperationCanceledException)
            {
                if (Current()) { _count = null; _rootCountGeneration = -1; Status = "Network count canceled."; OnPropertyChanged(nameof(Display)); }
            }
            catch (Exception error)
            {
                if (Current())
                {
                    _count = null; _rootCountGeneration = -1;
                    Status = "Network directory unavailable: " + error.Message;
                    OnPropertyChanged(nameof(Display));
                }
            }
        }
    }
    private void ApplyChildren(ObservableCollection<object> current,ObservableCollection<object> incoming)
    {
        IsRecalculating=true;
        try{ReconcileChildren(current,incoming);}
        finally{IsRecalculating=false;}
    }
    private static bool Retained(NetworkExplorerNode node) => node.IsSelected || node switch
    {
        NetworkEndpointDirectory d=>d.IsExpanded || d.Children.OfType<NetworkExplorerNode>().Any(Retained),
        NetworkProcessDirectory d=>d.IsExpanded || d.Children.OfType<NetworkExplorerNode>().Any(Retained),
        _=>false
    };
    internal static void ReconcileChildren(ObservableCollection<object> current,ObservableCollection<object> incoming)
    {
        var existing=current.OfType<NetworkExplorerNode>().ToDictionary(n=>n.StableKey);
        var desired=new List<object>();
        foreach(var item in incoming)
        {
            if(item is NetworkExplorerNode node && existing.TryGetValue(node.StableKey,out var old))
            {
                old.UpdatePresentation(node);
                if(old is NetworkEndpointDirectory oldDirectory && node is NetworkEndpointDirectory newDirectory)
                    ReconcileChildren(oldDirectory.Children,newDirectory.Children);
                desired.Add(old);
            }
            else desired.Add(item);
        }
        foreach(var retained in current.OfType<NetworkExplorerNode>().Where(n=>Retained(n) && !desired.Contains(n)))
        {
            retained.UpdateCount(0);
            if(retained is NetworkEndpointDirectory directory)ReconcileChildren(directory.Children,[]);
            desired.Add(retained);
        }
        // Remove obsolete items and insert new ones without detaching surviving WPF containers.
        foreach(var item in current.Where(item=>!desired.Contains(item)).ToArray())current.Remove(item);
        for(var i=0;i<desired.Count;i++)
        {
            var index=current.IndexOf(desired[i]);
            if(index<0)current.Insert(i,desired[i]);
            else if(index!=i)current.Move(index,i);
        }
    }
    private void RetainEndpointSelector(NetworkEndpointQuery query,long revision)
    {
        if(EndpointNodes().Any(n=>n.EndpointQuery==query))return;
        var start=new DateTime(query.FromUtcTicks!.Value,DateTimeKind.Utc);
        var dayQuery=new NetworkEndpointQuery(EndpointScopeKind.ConnectionSnapshots,
            FromUtcTicks:start.Date.Ticks,ToUtcTicks:start.Date.AddDays(1).Ticks);
        var day=ConnectionSnapshots.Children.OfType<NetworkEndpointDirectory>().FirstOrDefault(n=>n.EndpointQuery==dayQuery);
        if(day==null)
        {
            day=new NetworkEndpointDirectory(start.Date.ToString("yyyy-MM-dd 'UTC'"),revision){EndpointQuery=dayQuery};
            ConnectionSnapshots.Children.Add(day);
        }
        if(query==dayQuery)return;
        var hourStart=start.Date.AddHours(start.Hour);
        var hourQuery=new NetworkEndpointQuery(EndpointScopeKind.ConnectionSnapshots,
            FromUtcTicks:hourStart.Ticks,ToUtcTicks:hourStart.AddHours(1).Ticks);
        var hour=day.Children.OfType<NetworkEndpointDirectory>().FirstOrDefault(n=>n.EndpointQuery==hourQuery);
        if(hour==null)
        {
            hour=new NetworkEndpointDirectory(hourStart.ToString("HH:00 'UTC'"),revision){EndpointQuery=hourQuery};
            day.Children.Add(hour);
        }
        if(query==hourQuery)return;
        hour.Children.Add(new NetworkExplorerNode(start.ToString("HH:mm:ss.fff 'UTC'"),null,revision){EndpointQuery=query});
    }
    internal async Task QuiesceAsync(CancellationToken token)
    {
        _suspended = true; _request.Cancel(); _count = null; _rootCountGeneration = -1;
        OnPropertyChanged(nameof(Display));
        await _work.WaitAsync(token);
    }
    internal void Resume()
    {
        _request.Dispose(); _request = new(); _suspended = false;
        if (All.Revision != _session.Revision) Invalidate(captureChanged:false);
        Rebind();
    }
    public void Dispose()
    {
        _disposed = true; _request.Cancel();
        if (_subscribed != null) _subscribed.ScopeChanged -= ScopeChanged;
        _manager.ActiveContextChanged -= Rebind; Children.Clear();
    }
}
