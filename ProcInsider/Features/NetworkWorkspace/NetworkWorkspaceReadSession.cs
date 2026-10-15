using ProcInsider.Features.NetworkWorkspace;
using ProcInsider.Services;
using ProcInsider.Services.NetworkWorkspace;
using ProcInsider.Services.Presentation;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>One lazy analysis owner for the active capture; instances never own or dispose this reader.</summary>
internal sealed class NetworkWorkspaceReadSession
{
    private readonly ProcInsider.ViewModels.ProcessingOperationsViewModel _operations;
    internal NetworkWorkspaceReadSession(ProcInsider.ViewModels.ProcessingOperationsViewModel? operations=null) => _operations=operations??new();
    private readonly SemaphoreSlim _gate = new(1,1);
    private NetworkAnalysisService? _reader;
    private ViewerCaptureBinding? _capture;
    private SqliteStagingQueryService? _query;
    private long _revision;
    internal bool Suspended { get; private set; }
    internal long Revision => _revision;
    internal bool HasBinding => _capture != null && _query != null;
    internal bool HasReader => _reader != null;
    internal sealed record RetainedBinding(ViewerCaptureBinding? Capture, SqliteStagingQueryService? Query,long Revision);
    internal RetainedBinding Retain() => new(_capture,_query,_revision);
    internal void Restore(RetainedBinding binding) { if(_reader!=null)throw new InvalidOperationException("Network reads must drain before rollback.");_capture=binding.Capture;_query=binding.Query;_revision=binding.Revision; }
    internal void Bind(ViewerCaptureBinding? capture, SqliteStagingQueryService? query=null)
    {
        if(_reader!=null) throw new InvalidOperationException("Network reads must drain before binding changes.");
        _capture=capture;_query=query??capture?.Query;_revision++;
    }
    private async Task<NetworkAnalysisService> ReaderAsync(CancellationToken token)
    {
        if(Suspended || _capture==null || _query==null) throw new InvalidOperationException("No assessed Network snapshot or archive is available.");
        if(_reader!=null) return _reader;
        var revision=_revision;var capture=_capture;var query=_query;
        _reader=await NetworkAnalysisService.CreateAsync(query,new("",capture.Paths.SessionId,"",
            NetworkAnalysisService.GetPackageContextId(capture.Paths),query.ReadContext.DatabasePath),capture.Paths,
            ()=>!Suspended && revision==_revision && ReferenceEquals(query,_query),token).ConfigureAwait(false);
        return _reader;
    }
    internal async Task<NetworkAnalysisPage> QueryAsync(NetworkAnalysisQuery query,bool refresh,CancellationToken token)
    {
        using var operation=_operations.Begin("Network: listing and count",token);
        token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            // Explicit refresh reassesses the current canonical source after permitted snapshot
            // index maintenance; it must never retain a reader whose byte fingerprint is obsolete.
            if(refresh && _reader!=null){await _reader.DisposeAsync().ConfigureAwait(false);_reader=null;}
            var fresh=_reader==null;var reader=await ReaderAsync(token).ConfigureAwait(false);
            if(fresh || refresh) await reader.ReconcileAsync(token).ConfigureAwait(false);
            return await reader.QueryAsync(query,token).ConfigureAwait(false);
        }
        finally {_gate.Release();}
    }
    internal async Task<IReadOnlyList<NetworkProcessActivity>> ProcessesAsync(long offset,CancellationToken token,NetworkAnalysisQuery? query=null)
    {
        using var operation=_operations.Begin("Network: process groups",token);
        token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try {var fresh=_reader==null;var reader=await ReaderAsync(token).ConfigureAwait(false);if(fresh)await reader.ReconcileAsync(token).ConfigureAwait(false);return await reader.QueryProcessesAsync(offset,128,token,query).ConfigureAwait(false);}
        finally {_gate.Release();}
    }
    internal async Task<NetworkEndpointPage> EndpointsAsync(NetworkEndpointQuery query,CancellationToken token)
    {
        using var operation=_operations.Begin("Network: endpoint listing and count",token);
        token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if(Suspended || _query==null) throw new InvalidOperationException("No assessed endpoint snapshot or archive is available.");
            var revision=_revision;var reader=_query;
            var result=await Task.Run(()=>reader.NetworkEndpointQueries.Query(query,token),token).ConfigureAwait(false);
            if(Suspended || revision!=_revision || !ReferenceEquals(reader,_query))throw new OperationCanceledException(token);
            return result;
        }
        finally{_gate.Release();}
    }
    internal async Task<ColumnFilterValuePage> EndpointValuesAsync(NetworkEndpointQuery query,EndpointSort column,string? search,ColumnFilterValueSort sort,CancellationToken token)
    {
        using var operation=_operations.Begin("Network: endpoint filter values",token);token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if(Suspended || _query==null)throw new InvalidOperationException("No assessed endpoint snapshot or archive is available.");
            return await Task.Run(()=>_query.NetworkEndpointQueries.Values(query,column,search,sort,token),token).ConfigureAwait(false);
        }
        finally{_gate.Release();}
    }
    internal async Task<IReadOnlyList<NetworkEndpointPoll>> EndpointPollsAsync(long offset,CancellationToken token)
    {
        using var operation=_operations.Begin("Network: snapshot groups",token);
        token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if(Suspended || _query==null) throw new InvalidOperationException("No assessed endpoint snapshot or archive is available.");
            return await Task.Run(()=>_query.NetworkEndpointQueries.GetPolls(offset,128,token),token).ConfigureAwait(false);
        }
        finally{_gate.Release();}
    }
    internal async Task<ProcInsider.Models.ProcessInfo?> EndpointProcessAsync(NetworkEndpointHistoryRow row,CancellationToken token)
    {
        using var operation=_operations.Begin("Network: recorded endpoint owner",token);
        token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if(Suspended || _query==null || row.Observation.Native.Ownership!=EndpointOwnership.VerifiedLifetime || string.IsNullOrWhiteSpace(row.Observation.Native.ProcessEntityId)) return null;
            var revision=_revision;var reader=_query;
            var result=await reader.GetProcessByEntityIdAsync(row.Observation.Native.ProcessEntityId).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();var p=result.Process;var s=row.Poll.Scope;
            if(Suspended || revision!=_revision || !ReferenceEquals(reader,_query)) throw new OperationCanceledException(token);
            if(p==null || p.ProcessEntityId!=row.Observation.Native.ProcessEntityId || p.ProcessId!=row.Observation.Native.ProcessId ||
                p.CaseId!=s.CaseId || p.EvidenceSessionId!=s.EvidenceSessionId || p.HostId!=s.HostId || p.ExecutionRootId!=s.ExecutionRootId || p.StartTimeUtc!=row.Observation.Native.ProcessStartUtc) return null;
            return p.ToProcessInfo();
        }
        finally{_gate.Release();}
    }
    internal async Task<IReadOnlyList<NetworkFacetCount>> FacetsAsync(NetworkAnalysisQuery query,NetworkDimension dimension,CancellationToken token)
    {
        using var operation=_operations.Begin("Network: facet counts",token);
        token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try {var fresh=_reader==null;var reader=await ReaderAsync(token).ConfigureAwait(false);if(fresh)await reader.ReconcileAsync(token).ConfigureAwait(false);return await reader.QueryFacetsAsync(query,dimension,token).ConfigureAwait(false);}
        finally {_gate.Release();}
    }
    internal async Task<IReadOnlyList<NetworkValueCount>> ValuesAsync(NetworkAnalysisQuery query,NetworkColumn column,CancellationToken token,string? search=null,ColumnFilterValueSort sort=ColumnFilterValueSort.CountDescending)
    {
        using var operation=_operations.Begin("Network: column filter values",token);
        token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try {var fresh=_reader==null;var reader=await ReaderAsync(token).ConfigureAwait(false);if(fresh)await reader.ReconcileAsync(token).ConfigureAwait(false);return await reader.QueryValuesAsync(query,column,token,search,sort).ConfigureAwait(false);}
        finally {_gate.Release();}
    }
    internal void BindOverview(ProcInsider.ViewModels.ProcessDescriptionViewModel overview)
    {
        overview.SetAnnotationStore(_capture?.Annotations, reloadSelection: false);
        if (_capture != null) overview.SetWorkspace(_capture.Paths, _capture.CaptureGeneration);
    }
    internal async Task<ProcInsider.Models.ProcessInfo?> ProcessAsync(NetworkObservation row, CancellationToken token)
    {
        using var operation=_operations.Begin("Network: recorded event owner",token);
        token=operation.Token;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (Suspended || _query == null || string.IsNullOrWhiteSpace(row.ProcessEntityId)) return null;
            var result = await _query.GetProcessByEntityIdAsync(row.ProcessEntityId).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            var process = result.Process;
            if (process == null || process.EvidenceSessionId != row.Source.EvidenceSessionId || process.HostId != row.Source.HostId) return null;
            return process.ToProcessInfo();
        }
        finally { _gate.Release(); }
    }
    internal async Task QuiesceAsync()
    {
        Suspended=true;_operations.CancelAll();
        await _gate.WaitAsync().ConfigureAwait(false);
        try {if(_reader!=null) {await _reader.DisposeAsync().ConfigureAwait(false);_reader=null;}}
        finally {_gate.Release();}
    }
    internal void Resume()=>Suspended=false;
}
