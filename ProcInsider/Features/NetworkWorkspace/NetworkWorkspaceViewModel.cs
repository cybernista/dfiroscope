using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Models;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.ViewModels;
using ProcInsider.Services;
using ProcInsider.Services.Ai;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class NetworkWorkspaceViewModel : WorkspaceInstanceViewModel
{
    private readonly NetworkWorkspaceReadSession _session;
    private readonly HashSet<Task> _work=[];
    private CancellationTokenSource _request=new();
    private CancellationTokenSource _overviewRequest=new();
    private CancellationTokenSource _pivotRequest=new();
    private readonly WorkspaceNavigationService? _navigation;
    private readonly Func<WorkspaceInstanceViewModel, ProcessConversationViewModel>? _createObjectConversation;
    private ProcessConversationViewModel? _objectConversation;
    public bool IsAiAvailable => _createObjectConversation != null;
    public ProcessConversationViewModel? ObjectConversationViewModel
    {
        get
        {
            if (_createObjectConversation == null || IsDisposed) return null;
            if (_objectConversation == null)
            {
                _objectConversation = _createObjectConversation(this);
                _objectConversation.SelectObject(SelectedEndpoint is { } endpoint && IsEndpointScope
                    ? EvidenceObjectAgentTools.NetworkContext(endpoint) : null);
            }
            return _objectConversation;
        }
    }
    public IAsyncRelayCommand<NetworkEndpointHistoryRow> ReviewRecordCommand { get; }
    public IAsyncRelayCommand<NetworkEndpointHistoryRow> ChatAboutCommand { get; }
    public IAsyncRelayCommand<NetworkEndpointHistoryRow> FindRelatedProcessActivityCommand { get; }
    internal bool ReadsSuspended => _suspended || _session.Suspended;
    public IAsyncRelayCommand<NetworkEndpointHistoryRow> GoToEndpointProcessCommand {get;}
    public ProcessDescriptionViewModel? ProcessOverview {get;}
    public int DetailsTabIndex {get;set;}
    private string _overviewStatus="Select a recorded Network observation.";
    public string OverviewStatus {get=>_overviewStatus;private set=>SetProperty(ref _overviewStatus,value);}
    private bool _suspended,_loaded,_busy;
    private long _requestGeneration,_offset,_matching;
    internal long RequestGeneration => _requestGeneration;
    private string _text="",_status="Open recorded Network evidence to inspect observations.";
    private NetworkSort _sort=NetworkSort.CapturedUtc;
    private bool _descending=true;
    private NetworkObservation? _selected;
    private string? _retainedRowIdentity,_retainedEndpointIdentity;
    private NetworkProcessScope? _scope;
    private bool _resolvedProcessesOnly;
    private NetworkFacet? _facet;
    private IReadOnlyList<NetworkGreenSelector> _green=[];
    internal IReadOnlyList<NetworkGreenSelector> GreenSelectors=>_green;
    internal event Action? ScopeChanged;
    private IReadOnlyList<NetworkColumnFilter> _columns=[];
    public ObservableCollection<NetworkObservation> Rows {get;}=[];
    public ObservableCollection<NetworkEndpointHistoryRow> EndpointRows {get;}=[];
    private NetworkEndpointQuery? _endpointScope;
    private IReadOnlyList<NetworkEndpointGreenSelector> _endpointGreen = [];
    internal IReadOnlyList<NetworkEndpointGreenSelector> EndpointGreenSelectors => _endpointGreen;
    internal NetworkEndpointQuery? CaptureEndpointQuery() => _endpointScope == null ? null :
        _endpointScope with { Text = Text, GreenSelectors = _endpointGreen, Columns = EndpointColumns };
    private NetworkEndpointHistoryRow? _selectedEndpoint;
    public bool IsEndpointScope=>_endpointScope!=null;
    public EndpointSort EndpointSort {get;set;}=EndpointSort.ObservedUtc;
    public NetworkEndpointHistoryRow? SelectedEndpoint
    {
        get=>_selectedEndpoint;
        set{if(SetProperty(ref _selectedEndpoint,value)){_objectConversation?.SelectObject(value is { } endpoint && IsEndpointScope ? EvidenceObjectAgentTools.NetworkContext(endpoint) : null);if(value==null)InspectorPaneViewModel.Clear("Select a recorded OS endpoint.");else InspectorPaneViewModel.Load(EndpointPayload(value));UpdateOverview();}}
    }
    public InspectorPaneViewModel InspectorPaneViewModel {get;}=new();
    public string Text {get=>_text;set=>SetProperty(ref _text,value);}
    public NetworkSort Sort {get=>_sort;set=>SetProperty(ref _sort,value);}
    public bool Descending {get=>_descending;set=>SetProperty(ref _descending,value);}
    public Array SortOptions=>Enum.GetValues<NetworkSort>();
    public IReadOnlyDictionary<string,ColumnFilterViewModel> HeaderFilters {get;}
    public IReadOnlyDictionary<string,ColumnFilterViewModel> EndpointHeaderFilters {get;}
    public IReadOnlyDictionary<string,ColumnFilterViewModel> PropertiesHeaderFilters {get;}
    public ICollectionView PropertiesView {get;}
    internal IReadOnlyList<NetworkEndpointColumnFilter> EndpointColumns => EndpointHeaderFilters.Where(p=>p.Value.IsActive).Select(p=>new NetworkEndpointColumnFilter(Enum.Parse<EndpointSort>(p.Key),p.Value.Criteria)).ToArray();
    private static string PropertyValue(PropertyItemViewModel row,string column) => column switch { "Group"=>row.Group,"Name"=>row.Name,"Value"=>row.Value,_=>throw new ArgumentOutOfRangeException(nameof(column)) };
    public ListingColumnSettings ListingColumns {get;}=new();
    public string Status {get=>_status;private set=>SetProperty(ref _status,value);}
    public bool IsBusy {get=>_busy;private set=>SetProperty(ref _busy,value);}
    public long MatchingRecords {get=>_matching;private set=>SetProperty(ref _matching,value);}
    public long Offset=>_offset;
    public double VerticalOffset {get;set;}
    public double HorizontalOffset {get;set;}
    internal Dictionary<string,(double Width,int Order)> ColumnLayout {get;}=[];
    public double PropertiesOffset {get;set;}
    public NetworkProcessScope? Scope=>_scope;
    internal bool LastRefreshSucceeded {get;private set;}
    public IAsyncRelayCommand RefreshCommand {get;}
    public IAsyncRelayCommand ApplyCommand {get;}
    public IAsyncRelayCommand ClearFiltersCommand {get;}
    public IRelayCommand ClearPropertiesCommand {get;}
    public IAsyncRelayCommand NextCommand {get;}
    public IAsyncRelayCommand PreviousCommand {get;}
    public NetworkObservation? SelectedRow
    {
        get=>_selected;
        set {if(SetProperty(ref _selected,value)) {if(!IsEndpointScope)_objectConversation?.SelectObject(null);if(value==null)InspectorPaneViewModel.Clear("Select a recorded Network observation.");else InspectorPaneViewModel.Load(Payload(value));UpdateOverview();}}
    }
    internal NetworkWorkspaceViewModel(WorkspaceTypeMetadata type,int ordinal,NetworkWorkspaceReadSession session,ProcessDescriptionViewModel? overview=null,WorkspaceNavigationService? navigation=null,
        Func<WorkspaceInstanceViewModel, ProcessConversationViewModel>? createObjectConversation=null):base(type,ordinal)
    {
        _session=session;ProcessOverview=overview;NavigationDescription="All network activity";
        _navigation=navigation;
        _createObjectConversation=createObjectConversation;
        ReviewRecordCommand=new AsyncRelayCommand<NetworkEndpointHistoryRow>(row=>RunObjectActionAsync(row,ProcessConversationAction.ReviewRecord),CanRunObjectAction);
        ChatAboutCommand = new AsyncRelayCommand<NetworkEndpointHistoryRow>(row => RunObjectActionAsync(row, ProcessConversationAction.ChatAbout), CanRunObjectAction);
        FindRelatedProcessActivityCommand=new AsyncRelayCommand<NetworkEndpointHistoryRow>(row=>RunObjectActionAsync(row,ProcessConversationAction.FindRelatedActivity),CanRunObjectAction);
        GoToEndpointProcessCommand=new AsyncRelayCommand<NetworkEndpointHistoryRow>(GoToEndpointProcessAsync,
            row=>row?.Observation.Native.Ownership==EndpointOwnership.VerifiedLifetime && !string.IsNullOrWhiteSpace(row.Observation.Native.ProcessEntityId),
            AsyncRelayCommandOptions.AllowConcurrentExecutions);
        HeaderFilters=Enum.GetValues<NetworkColumn>().ToDictionary(c=>c.ToString(),c=>new ColumnFilterViewModel(c.ToString(),
            c==NetworkColumn.CapturedUtc?ColumnFilterKind.Timestamp:c is NetworkColumn.ProcessId or NetworkColumn.SourcePort or NetworkColumn.DestinationPort?ColumnFilterKind.Number:ColumnFilterKind.Values,
            async(search,sort,token)=>{var values=await _session.ValuesAsync(CaptureQuery() with{Offset=0,PageSize=257},c,token,search,sort);return new ColumnFilterValuePage(values.Take(256).Select(v=>new ColumnFilterValue(v.Value,v.Count)).ToArray(),values.Count>256);},
            ()=>{SetColumnFilters(HeaderFilters!.Where(p=>p.Value.IsActive).Select(p=>new NetworkColumnFilter(Enum.Parse<NetworkColumn>(p.Key),p.Value.Criteria)).ToArray());_ = RefreshAsync();}));
        EndpointHeaderFilters=Enum.GetValues<EndpointSort>().ToDictionary(c=>c.ToString(),c=>new ColumnFilterViewModel(c.ToString(),
            c is EndpointSort.ObservedUtc or EndpointSort.LastObservedUtc or EndpointSort.FirstAbsentUtc ? ColumnFilterKind.Timestamp :
            c is EndpointSort.LocalPort or EndpointSort.ProcessId or EndpointSort.TcpState ? ColumnFilterKind.Number : ColumnFilterKind.Values,
            (search,sort,token)=>_session.EndpointValuesAsync(CaptureEndpointQuery() ?? new(EndpointScopeKind.ListenerHistory),c,search,sort,token),
            ()=>{_offset=0;_loaded=false;ScopeChanged?.Invoke();_ = RefreshAsync();}));
        PropertiesView=new ListCollectionView(InspectorPaneViewModel.Properties);
        PropertiesHeaderFilters=new[]{"Group","Name","Value"}.ToDictionary(c=>c,c=>new ColumnFilterViewModel(c,ColumnFilterKind.Values,
            (search,sort,token)=>{token.ThrowIfCancellationRequested();return Task.FromResult(ColumnFilterValuePage.FromValues(
                InspectorPaneViewModel.Properties.Where(row=>PropertiesHeaderFilters!.Where(p=>p.Key!=c).All(p=>p.Value.Criteria.Matches(PropertyValue(row,p.Key))))
                .Select(row=>PropertyValue(row,c)).Where(v=>ColumnTextFilter.Matches(v,search)),sort));},()=>PropertiesView.Refresh()));
        PropertiesView.Filter=row=>row is PropertyItemViewModel property && PropertiesHeaderFilters.All(p=>p.Value.Criteria.Matches(PropertyValue(property,p.Key)));
        RefreshCommand=new AsyncRelayCommand(()=>RefreshAsync(true));
        ApplyCommand=new AsyncRelayCommand(()=>{_offset=0;return RefreshAsync(false);});
        ClearFiltersCommand=new AsyncRelayCommand(()=>
        {
            foreach(var filter in (IsEndpointScope ? EndpointHeaderFilters : HeaderFilters).Values) filter.Reset(false);
            Text="";
            if(!IsEndpointScope) _columns=[];
            _offset=0;_loaded=false;
            ScopeChanged?.Invoke();
            return RefreshAsync(false);
        });
        ClearPropertiesCommand=new RelayCommand(()=>
        {
            foreach(var filter in PropertiesHeaderFilters.Values) filter.Reset(false);
            PropertiesView.Refresh();
        });
        NextCommand=new AsyncRelayCommand(()=>{if(_offset+128<MatchingRecords)_offset+=128;return RefreshAsync(false);});
        PreviousCommand=new AsyncRelayCommand(()=>{_offset=Math.Max(0,_offset-128);return RefreshAsync(false);});
    }
    private bool CanRunObjectAction(NetworkEndpointHistoryRow? row) => _createObjectConversation != null &&
        !IsDisposed && !ReadsSuspended && IsEndpointScope && row != null && EndpointRows.Contains(row);
    private async Task RunObjectActionAsync(NetworkEndpointHistoryRow? row,ProcessConversationAction action)
    {
        if(!CanRunObjectAction(row))return;
        SelectedEndpoint=row;
        ShowObjectConversation();
        if(ObjectConversationViewModel is { } conversation)await conversation.RunActionAsync(action);
    }
    internal void ShowObjectConversation(){if(!IsAiAvailable || IsDisposed)return;DetailsTabIndex=2;OnPropertyChanged(nameof(DetailsTabIndex));}
    internal async Task GoToEndpointProcessAsync(NetworkEndpointHistoryRow? row)
    {
        _pivotRequest.Cancel();_pivotRequest.Dispose();_pivotRequest=new();
        var token=_pivotRequest.Token;var revision=_session.Revision;var capture=Context;
        if(row==null || _navigation==null || IsDisposed || ReadsSuspended || !EndpointRows.Contains(row))
        {Status="The recorded endpoint target is unavailable or stale.";return;}
        var contextRevision=_navigation.ContextRevision;var actionGeneration=_navigation.ActionGeneration;
        try
        {
            var process=await _session.EndpointProcessAsync(row,token);
            token.ThrowIfCancellationRequested();
            if(IsDisposed || ReadsSuspended || capture!=Context || revision!=_session.Revision ||
                contextRevision!=_navigation.ContextRevision || actionGeneration!=_navigation.ActionGeneration)
            {if(!IsDisposed)Status="Exact process navigation was superseded by a source/read-context change.";return;}
            if(process==null){Status="No exact captured process is available for this endpoint; no investigation was opened.";return;}
            var result=new TelemetrySearchResult { Kind="PROCESS",ProcessEntityId=process.ProcessEntityId,
                ProcessKey=process.GetUniqueKey(),ProcessId=process.ProcessId,ProcessName=process.ProcessName };
            var outcome=await _navigation.NavigateAsync(new(WorkspaceTypeId.Processes,capture,
                Scope:new ExplorerScope {Kind=ExplorerScopeKind.AllProcesses,Title="All Processes"},Process:result,
                Mode:WorkspaceNavigationMode.OpenNew,NetworkRevision:revision,NetworkSource:this,SourceCancellation:token,
                ExpectedContextRevision:contextRevision,ExpectedActionGeneration:actionGeneration));
            if(!token.IsCancellationRequested && revision==_session.Revision && !IsDisposed)Status=outcome.Outcome==ViewerNavigationOutcome.Superseded
                ?"Exact process navigation was superseded by a source/read-context change.":_navigation.Status;
        }
        catch(OperationCanceledException){if(!IsDisposed && token==_pivotRequest.Token)Status="Exact process navigation was superseded by a source/read-context change.";}
        catch(Exception error){if(!token.IsCancellationRequested)Status="Exact process navigation unavailable: "+error.Message;}
    }
    private void UpdateOverview()
    {
        _overviewRequest.Cancel();_overviewRequest.Dispose();_overviewRequest=new();
        if(ProcessOverview==null)return;
        ProcessOverview.CancelPendingPresentationRequests();
        _ = ProcessOverview.LoadForProcessSelectionAsync(null,CancellationToken.None);
        OverviewStatus="Select a recorded Network observation.";
        var row=SelectedRow;var endpoint=SelectedEndpoint;var token=_overviewRequest.Token;var revision=_session.Revision;
        if(row==null && endpoint==null || IsDisposed || _suspended)return;
        _session.BindOverview(ProcessOverview);
        OverviewStatus="Loading captured process overview.";
        var task=LoadAsync();_work.Add(task);_ = ObserveAsync(task);
        async Task ObserveAsync(Task work){try{await work;}finally{_work.Remove(work);}}
        async Task LoadAsync()
        {
            try
            {
                var process=endpoint!=null?await _session.EndpointProcessAsync(endpoint,token):await _session.ProcessAsync(row!,token);
                token.ThrowIfCancellationRequested();
                if(IsDisposed || _suspended || revision!=_session.Revision)return;
                if(process==null){OverviewStatus="No exact captured process is available for this observation.";return;}
                await ProcessOverview.LoadForProcessSelectionAsync(new ProcessRowViewModel(process),token);
                token.ThrowIfCancellationRequested();
                OverviewStatus="";
            }
            catch(OperationCanceledException){}
            catch(Exception error){if(!token.IsCancellationRequested)OverviewStatus="Process overview unavailable: "+error.Message;}
        }
    }
    internal NetworkAnalysisQuery CaptureQuery()=>new(Text:Text,Sort:Sort,Descending:Descending,Offset:_offset,ProcessScope:_scope,Columns:_columns,
        ResolvedProcessesOnly:_resolvedProcessesOnly,GreenSelectors:_green,FacetScope:_facet);
    internal void SetScope(NetworkProcessScope? scope,string title,bool resolvedProcessesOnly=false,NetworkFacet? facet=null,bool notify=true)
    {
        _pivotRequest.Cancel();
        _retainedRowIdentity=_retainedEndpointIdentity=null;
        _endpointScope=null;_endpointGreen=[];EndpointRows.Clear();SelectedEndpoint=null;OnPropertyChanged(nameof(IsEndpointScope));
        _scope=scope;_resolvedProcessesOnly=resolvedProcessesOnly;_facet=facet;_green=[];NavigationDescription=title;_offset=0;_loaded=false;
        Rows.Clear();MatchingRecords=0;SelectedRow=null;
        if(notify)ScopeChanged?.Invoke();
    }
    internal void SetEndpointScope(NetworkEndpointQuery query,string title,bool notify=true)
    {
        _retainedRowIdentity=_retainedEndpointIdentity=null;
        _pivotRequest.Cancel();_scope=null;_resolvedProcessesOnly=false;_facet=null;_green=[];
        Rows.Clear();SelectedRow=null;EndpointRows.Clear();SelectedEndpoint=null;MatchingRecords=0;
        _endpointScope=query;_endpointGreen=[];NavigationDescription=title;_offset=0;_loaded=false;
        OnPropertyChanged(nameof(IsEndpointScope));if(notify)ScopeChanged?.Invoke();
    }
    internal void ToggleEndpointGreen(NetworkEndpointQuery query)
    {
        var connection = query.Kind == EndpointScopeKind.ConnectionSnapshots;
        var selectors = IsEndpointScope && (_endpointScope!.Kind == EndpointScopeKind.ConnectionSnapshots) == connection
            ? _endpointGreen.ToList() : [];
        var selector = new NetworkEndpointGreenSelector(query);
        var included = NetworkEndpointGreenSelector.Includes(selectors, selector);
        selectors.RemoveAll(s => selector.Covers(s));
        var inherited = NetworkEndpointGreenSelector.Includes(selectors, selector);
        if (!included != inherited) selectors.Add(selector with { IsExcluded = included });
        SetEndpointScope(new(connection ? EndpointScopeKind.ConnectionSnapshots : EndpointScopeKind.ListenerHistory),
            selectors.Count == 0 ? connection ? "Connection snapshots (UTC)" : "Listener history" : "Green endpoint selection",notify:false);
        _endpointGreen = selectors.ToArray();ScopeChanged?.Invoke();
    }
    internal void ToggleGreen(NetworkGreenSelector selector)
    {
        var selectors=_green.ToList();var included=NetworkGreenSelector.Includes(selectors,selector);
        selectors.RemoveAll(s=>selector.Dimension==null ? !s.IsExcluded || s.Dimension==null : selector.Covers(s));
        var inherited=NetworkGreenSelector.Includes(selectors,selector);
        if(!included!=inherited)selectors.Add(selector with{IsExcluded=included});
        SetScope(null,selectors.Count==0?"All network activity":"Green Network selection",notify:false);
        _green=selectors.ToArray();ScopeChanged?.Invoke();
    }
    internal void SetColumnFilters(IReadOnlyList<NetworkColumnFilter> filters){_columns=filters;_offset=0;_loaded=false;ScopeChanged?.Invoke();}
    internal Task<IReadOnlyList<NetworkValueCount>> ValuesAsync(NetworkColumn column,long offset,CancellationToken token)=>_session.ValuesAsync(CaptureQuery() with {Offset=offset},column,token);
    internal Task LoadAsync()=>_loaded?Task.CompletedTask:RefreshAsync(false);
    internal Task RefreshAsync(bool reconcile=false)
    {
        _pivotRequest.Cancel();
        if(IsDisposed || _suspended || _session.Suspended)return Task.CompletedTask;
        _request.Cancel();_request.Dispose();_request=new();var token=_request.Token;var request=++_requestGeneration;var binding=_session.Revision;
        var task=RunAsync();_work.Add(task);return ObserveAsync(task);
        async Task ObserveAsync(Task work){try{await work;}finally{_work.Remove(work);}}
        async Task RunAsync()
        {
            IsBusy=true;LastRefreshSucceeded=false;Status="Loading recorded Network observations; requested criteria are pending.";
            try
            {
                if(_endpointScope!=null)
                {
                    var endpointPage=await _session.EndpointsAsync(CaptureEndpointQuery()! with{Sort=EndpointSort,Descending=Descending,Offset=_offset},token);
                    token.ThrowIfCancellationRequested();
                    if(IsDisposed || _suspended || binding!=_session.Revision || request!=_requestGeneration)return;
                    var selectedEndpointIdentity=SelectedEndpoint?.Observation.ObservationId??_retainedEndpointIdentity;EndpointRows.Clear();foreach(var row in endpointPage.Rows)EndpointRows.Add(row);
                    SelectedEndpoint=EndpointRows.FirstOrDefault(r=>r.Observation.ObservationId==selectedEndpointIdentity);
                    _retainedEndpointIdentity=endpointPage.Supported?null:selectedEndpointIdentity;
                    MatchingRecords=endpointPage.MatchingRows;OnPropertyChanged(nameof(Offset));_loaded=true;LastRefreshSucceeded=endpointPage.Supported;Status=endpointPage.Diagnostic;
                    if(endpointPage.Supported)ScopeChanged?.Invoke();
                    return;
                }
                var page=await _session.QueryAsync(CaptureQuery(),reconcile,token);
                token.ThrowIfCancellationRequested();
                if(IsDisposed || _suspended || binding!=_session.Revision || request!=_requestGeneration)return;
                if(page.Status.State!=NetworkProcessingState.Ready){Status=Unapplied($"{page.Status.State}: {page.Status.Detail}");return;}
                var selected=SelectedRow?.Source.PersistentIdentity??_retainedRowIdentity;Rows.Clear();foreach(var row in page.Records)Rows.Add(row);
                SelectedRow=Rows.FirstOrDefault(row=>row.Source.PersistentIdentity==selected);
                _retainedRowIdentity=null;
                MatchingRecords=page.MatchingRecords;OnPropertyChanged(nameof(Offset));_loaded=true;LastRefreshSucceeded=true;
                ScopeChanged?.Invoke();
                Status=MatchingRecords==0?$"No supported recorded Network observations match this scope and filters; {page.Status.MalformedRecords:N0} malformed source records. Collection availability is unknown from absent records; Sysmon 3/22 require recorded Sysmon events, and WFP requires matching Security audit policy (permitted listen/bind uses success; blocked operations and packet drops use failure auditing).":$"{MatchingRecords:N0} recorded observations; {page.Status.MalformedRecords:N0} malformed source records. Captured events do not establish active connections or successful communication. Missing sources have unknown coverage; Permitted WFP listen/bind requires success auditing; blocked operations and packet drops require their matching failure auditing.";
            }
            catch(OperationCanceledException){if(request==_requestGeneration&&!_suspended)Status=Unapplied("Network request canceled.");}
            catch(Exception error){if(request==_requestGeneration&&!IsDisposed)Status=Unapplied($"Network unavailable: {error.Message}");}
            finally{if(request==_requestGeneration)IsBusy=false;}
        }
    }
    private string Unapplied(string detail)=>Rows.Count>0 || EndpointRows.Count>0
        ? $"Previous displayed page and count retained; requested criteria were not applied. {detail}"
        : $"No displayed observations; requested criteria were not applied. {detail}";
    internal sealed record RetainedState(NetworkObservation[] Rows,NetworkObservation? Selection,string Status,long Matching,bool Loaded,
        NetworkEndpointHistoryRow[] EndpointRows,NetworkEndpointHistoryRow? EndpointSelection,NetworkEndpointQuery? EndpointScope,EndpointSort EndpointSort,
        IReadOnlyList<NetworkEndpointGreenSelector> EndpointGreen,string? RetainedRowIdentity,string? RetainedEndpointIdentity);
    internal RetainedState Retain()=>new(Rows.ToArray(),SelectedRow,Status,MatchingRecords,_loaded,EndpointRows.ToArray(),SelectedEndpoint,_endpointScope,EndpointSort,_endpointGreen,_retainedRowIdentity,_retainedEndpointIdentity);
    internal void Restore(RetainedState state){Rows.Clear();foreach(var row in state.Rows)Rows.Add(row);SelectedRow=state.Selection;
        EndpointRows.Clear();foreach(var row in state.EndpointRows)EndpointRows.Add(row);_endpointScope=state.EndpointScope;_endpointGreen=state.EndpointGreen;EndpointSort=state.EndpointSort;SelectedEndpoint=state.EndpointSelection;
        _retainedRowIdentity=state.RetainedRowIdentity;_retainedEndpointIdentity=state.RetainedEndpointIdentity;
        OnPropertyChanged(nameof(IsEndpointScope));Status=state.Status;MatchingRecords=state.Matching;_loaded=state.Loaded;
        _objectConversation?.SelectObject(SelectedEndpoint is { } endpoint && IsEndpointScope ? EvidenceObjectAgentTools.NetworkContext(endpoint) : null);}
    internal void Invalidate(bool captureChanged)
    {
        _loaded=false;
        _retainedRowIdentity=captureChanged?null:SelectedRow?.Source.PersistentIdentity??_retainedRowIdentity;
        _retainedEndpointIdentity=captureChanged?null:SelectedEndpoint?.Observation.ObservationId??_retainedEndpointIdentity;
        EndpointRows.Clear();SelectedEndpoint=null;Rows.Clear();SelectedRow=null;MatchingRecords=0;
        if(captureChanged)
        {
            _endpointScope=null;_endpointGreen=[];OnPropertyChanged(nameof(IsEndpointScope));
            _scope=null;_resolvedProcessesOnly=false;_facet=null;_green=[];_offset=0;Text="";_columns=[];
            foreach(var header in HeaderFilters.Values.Concat(EndpointHeaderFilters.Values).Concat(PropertiesHeaderFilters.Values))header.Reset(false);
            NavigationDescription="All network activity";
        }
        else foreach(var header in HeaderFilters.Values.Concat(EndpointHeaderFilters.Values).Concat(PropertiesHeaderFilters.Values))header.Close();
        Status="Recorded Network evidence changed; refresh this investigation.";
        ScopeChanged?.Invoke();
    }
    internal async Task QuiesceAsync(CancellationToken token){_suspended=true;_objectConversation?.SelectObject(null);_pivotRequest.Cancel();_request.Cancel();_overviewRequest.Cancel();ProcessOverview?.CancelPendingPresentationRequests();foreach(var filter in HeaderFilters.Values.Concat(EndpointHeaderFilters.Values).Concat(PropertiesHeaderFilters.Values))filter.Close();await Task.WhenAll(_work.ToArray()).WaitAsync(token);while(_objectConversation?.IsBusy==true)await Task.Delay(10,token);}
    internal void Resume(){_suspended=false;if(Context!=null && SelectedEndpoint is { } endpoint && IsEndpointScope)_objectConversation?.SelectObject(EvidenceObjectAgentTools.NetworkContext(endpoint));UpdateOverview();}
    public override void Dispose(){if(IsDisposed)return;IsDisposed=true;_suspended=true;_retainedRowIdentity=_retainedEndpointIdentity=null;foreach(var filter in HeaderFilters.Values.Concat(EndpointHeaderFilters.Values).Concat(PropertiesHeaderFilters.Values))filter.Close();_pivotRequest.Cancel();_request.Cancel();_overviewRequest.Cancel();ProcessOverview?.Shutdown();Rows.Clear();SelectedRow=null;EndpointRows.Clear();SelectedEndpoint=null;_objectConversation?.Dispose();}
    private static InspectorPayload EndpointPayload(NetworkEndpointHistoryRow row)
    {
        var p=row.Poll;var s=p.Scope;var n=row.Observation.Native;
        string Time(DateTime? value)=>value?.ToString("O")??"Unknown / not observed";
        return new(){ArtifactKind=InspectorArtifactKind.NetworkCapture,TargetKind="OS endpoint observation",TargetTable="NetworkEndpointObservations",
            TargetId=row.Observation.ObservationId,CaseId=s.CaseId,EvidenceSessionId=s.EvidenceSessionId,CaptureId=s.CaptureId,
            SourceIdentityId=s.SourceIdentityId,HostId=s.HostId,ExecutionRootId=s.ExecutionRootId,SourceRunId=p.SourceRunId,IngestionJobId=p.IngestionJobId.ToString("D"),
            ProcessId=n.ProcessId,Header=n.IsListener?"Observed listener / UDP binding":"Sampled TCP endpoint",
            Subtitle="OS table samples cannot prove exact socket lifetime, traffic direction, reachability, or activity between samples.",
            Properties=new PropertyItemViewModel[]{new("Native","Family",n.Family.ToString()),new("Native","Local endpoint",n.LocalPresentation),
                new("Native","Remote endpoint",n.RemoteAddress==null?"Not applicable":n.RemotePresentation),
                new("Native evidence","Local address",n.LocalAddress),new("Native evidence","Local scope ID",n.LocalScopeId.ToString()),new("Native evidence","Remote address",n.RemoteAddress??"Not applicable"),new("Native evidence","Remote scope ID",n.RemoteScopeId?.ToString()??"Not applicable"),new("Native","TCP state",n.TcpState?.ToString()??"Not applicable (UDP)"),
                new("Native","Owning PID observed",n.ProcessId.ToString()),new("Native","Context-bind creation UTC",Time(n.NativeCreationUtc)+"; not TCP handshake time"),
                new("Ownership","Resolution",n.Ownership.ToString()),new("Ownership","Exact process entity",string.IsNullOrEmpty(n.ProcessEntityId)?"Unresolved":n.ProcessEntityId),
                new("Ownership","Verified process start UTC",Time(n.ProcessStartUtc)),new("History","First observed UTC",Time(row.FirstObservedUtc)),
                new("Captured process","Name",n.ProcessNameDisplay),new("Captured process","Image path",n.ImagePathDisplay),new("Captured process","Command line",n.CommandLineDisplay),
                new("Captured process","Name state",n.Metadata?.NameState.ToString()??"Not recorded"),new("Captured process","Image state",n.Metadata?.ImageState.ToString()??"Not recorded"),
                new("Captured process","Command line state",n.Metadata?.CommandLineState.ToString()??"Not recorded"),new("Captured process","Acquisition method",n.Metadata?.Method??"Not recorded"),
                new("Captured process","Metadata window start UTC",Time(n.Metadata?.WindowStartUtc)),new("Captured process","Metadata window end UTC",Time(n.Metadata?.WindowEndUtc)),
                new("History","Last observed UTC",Time(row.LastObservedUtc)),new("History","First absent enumeration start UTC",Time(row.FirstAbsentWindowStartUtc)),
                new("History","First absent enumeration end UTC",Time(row.FirstAbsentUtc)),new("History","Continuity",row.FirstAbsentUtc!=null?"No longer observed in a complete enumeration; not process exit":row.HasContinuityGap?"Coverage ended / gap; endpoint status unknown":"Observed samples only; socket continuity and current status unknown"),
                new("Coverage","Actual family window start UTC",Time(p.WindowStartUtc)),new("Coverage","Actual family window end UTC",Time(p.WindowEndUtc)),
                new("Coverage","Outcome",p.Outcome.ToString()),new("Coverage","Diagnostic",p.Diagnostic),new("Provenance","Poll ID",p.PollId),
                new("Provenance","Snapshot ID",p.SnapshotId),new("Provenance","Segment ID",p.SegmentId),new("Provenance","Episode ID",row.Observation.EpisodeId),
                new("Provenance","Source run",p.SourceRunId),new("Provenance","Ingestion job",p.IngestionJobId.ToString("D")),new("Scope","Case",s.CaseId),
                new("Scope","Evidence session",s.EvidenceSessionId),new("Scope","Capture",s.CaptureId),new("Scope","Host",s.HostId),new("Scope","Execution root",s.ExecutionRootId),new("Scope","Source identity",s.SourceIdentityId)} };
    }
    private static InspectorPayload Payload(NetworkObservation row)
    {
        var s=row.Source;
        return new(){ArtifactKind=InspectorArtifactKind.Event,TargetKind="Event",TargetTable=s.SourceTable,TargetId=s.SequenceId.ToString(System.Globalization.CultureInfo.InvariantCulture),CaseId=s.CaseId,EvidenceSessionId=s.EvidenceSessionId,CaptureId=s.CaptureId,SourceIdentityId=s.SourceIdentityId,HostId=s.HostId,ExecutionRootId=s.ExecutionRootId,SourceRunId=s.SourceRunId,IngestionJobId=s.IngestionJobId,ProcessId=row.ProcessId??0,ProcessName=row.ProcessName,Header=row.ObservationDisplay,Subtitle=row.Diagnostic,
            Properties=new[]{new PropertyItemViewModel("Native","Provider",row.Provider),new("Native","Channel",row.Channel),new("Native","Event ID",row.NativeEventId.ToString()),new("DNS","Query name",row.QueryName??"Not applicable / unavailable"),new("DNS","Query status",row.QueryStatus??"Not applicable / unavailable"),new("DNS","Query results",row.QueryResults??"Not applicable / unavailable"),new("WFP","Native PID",row.NativeProcessId??"Not applicable / unavailable"),new("WFP","Direction",row.NativeDirection??"Not applicable / unavailable"),new("WFP","Filter runtime ID",row.FilterRunTimeId??"Not applicable / unavailable"),new("WFP","Layer",row.LayerName??"Not applicable / unavailable"),new("WFP","Layer runtime ID",row.LayerRunTimeId??"Not applicable / unavailable"),new PropertyItemViewModel("Observation","Captured UTC",row.CapturedUtc.ToString("O")),new("Observation","Direction",row.Direction.ToString()),new("Observation","Protocol",row.Protocol??"Unavailable"),new("Observation","Source endpoint",row.Kind is NetworkObservationKind.CapturedDnsQuery or NetworkObservationKind.CapturedBlockedListen or NetworkObservationKind.CapturedBlockedBind or NetworkObservationKind.CapturedAllowedListen or NetworkObservationKind.CapturedAllowedBind?"Not applicable":string.IsNullOrEmpty(row.SourceEndpoint.Presentation)?"Unavailable":row.SourceEndpoint.Presentation),new("Observation","Destination endpoint",row.Kind is NetworkObservationKind.CapturedDnsQuery or NetworkObservationKind.CapturedBlockedListen or NetworkObservationKind.CapturedBlockedBind or NetworkObservationKind.CapturedAllowedListen or NetworkObservationKind.CapturedAllowedBind?"Not applicable":string.IsNullOrEmpty(row.DestinationEndpoint.Presentation)?"Unavailable":row.DestinationEndpoint.Presentation),new("Observation","Local endpoint",row.Kind==NetworkObservationKind.CapturedDnsQuery?"Not applicable":string.IsNullOrEmpty(row.LocalEndpoint?.Presentation)?"Undetermined":row.LocalEndpoint.Presentation),new("Observation","Remote endpoint",row.Kind is NetworkObservationKind.CapturedDnsQuery or NetworkObservationKind.CapturedBlockedListen or NetworkObservationKind.CapturedBlockedBind or NetworkObservationKind.CapturedAllowedListen or NetworkObservationKind.CapturedAllowedBind?"Not applicable":string.IsNullOrEmpty(row.RemoteEndpoint?.Presentation)?"Undetermined":row.RemoteEndpoint.Presentation),new("Process","Durable entity",string.IsNullOrEmpty(row.ProcessEntityId)?"Unresolved":row.ProcessEntityId),new("Process","Native GUID",row.ProcessGuid),new("Process","Native PID",row.ProcessId?.ToString()??"Unavailable"),new("Process","Image",row.ProcessImage),new("Process","User",row.UserName),new("Evidence","Table",s.SourceTable),new("Evidence","Sequence",s.SequenceId.ToString()),new("Evidence","Case",s.CaseId),new("Evidence","Session",s.EvidenceSessionId),new("Evidence","Capture",s.CaptureId),new("Evidence","Source",s.SourceIdentityId),new("Evidence","Host",s.HostId),new("Evidence","Execution root",s.ExecutionRootId),new("Evidence","Source run",s.SourceRunId),new("Evidence","Ingestion job",s.IngestionJobId),new("Evidence","Native record ID",s.RawRecordIdText),new("Diagnostic","Interpretation",row.Diagnostic)}.Concat((row.NativeFields??new Dictionary<string,string>()).Select(p=>new PropertyItemViewModel("Native fields",p.Key,p.Value))).ToArray()};
    }
}
