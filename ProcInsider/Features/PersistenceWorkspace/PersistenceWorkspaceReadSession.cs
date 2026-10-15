using ProcInsider.Features.PersistenceWorkspace;
using ProcInsider.Models;
using ProcInsider.Services;
using ProcInsider.Services.Presentation;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>Shares only an assessed binding, never analyst selection or criteria.</summary>
internal sealed class PersistenceWorkspaceReadSession
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ViewerCaptureBinding? _capture;
    private SqliteStagingQueryService? _query;
    internal long Revision { get; private set; }
    internal long SnapshotGeneration { get; private set; }
    internal bool Suspended { get; private set; }
    internal ViewerCaptureBinding? Capture => _capture;
    internal sealed record RetainedBinding(ViewerCaptureBinding? Capture, SqliteStagingQueryService? Query, long Revision, long SnapshotGeneration);
    internal RetainedBinding Retain() => new(_capture, _query, Revision, SnapshotGeneration);
    internal void Restore(RetainedBinding binding) { _capture = binding.Capture; _query = binding.Query; Revision = binding.Revision; SnapshotGeneration = binding.SnapshotGeneration; }
    internal void Bind(ViewerCaptureBinding? capture, ViewerReadBinding? snapshot = null)
    {
        _capture = capture; _query = snapshot?.QueryService ?? capture?.Query;
        SnapshotGeneration = snapshot?.SnapshotGeneration ?? 0; Revision++;
    }
    internal Task<IReadOnlyList<EvidenceIdentity>> ScopesAsync(CancellationToken token)
    {
        var session = _capture?.Paths.SessionId ?? "";
        return ReadAsync(reader => reader.Scopes(session, token), token);
    }
    internal Task<PersistenceWorkspacePage> QueryAsync(PersistenceWorkspaceQuery query, CancellationToken token) => ReadAsync(reader => reader.Query(query, token), token);
    internal Task<bool> IsJobAcceptedAsync(EvidenceIdentity scope, Guid jobId, CancellationToken token)
        => ReadAsync(reader => reader.IsJobAccepted(scope, jobId, token), token);
    internal Task<IReadOnlyList<PersistencePeriod>> PeriodsAsync(EvidenceIdentity scope, long offset, int pageSize, CancellationToken token)
        => ReadAsync(reader => reader.Periods(scope, offset, pageSize, token), token);
    internal async Task<IReadOnlyList<PersistencePeriod>> AllPeriodsAsync(EvidenceIdentity scope, CancellationToken token)
    {
        var result = new List<PersistencePeriod>();
        for (long offset = 0; ; offset += 512)
        {
            var page = await PeriodsAsync(scope, offset, 512, token);
            result.AddRange(page);
            if (page.Count < 512) return result;
        }
    }
    internal Task<ColumnFilterValuePage> ValuesAsync(PersistenceWorkspaceQuery query, PersistenceColumn column, string? search, ColumnFilterValueSort sort, CancellationToken token) => ReadAsync(reader => reader.Values(query, column, search, sort, token), token);
    internal Task<PersistenceObjectDetail> DetailAsync(PersistenceObjectReference reference, CancellationToken token) => ReadAsync(reader => reader.Detail(reference, token), token);
    internal Task<PersistenceHistoryPage> HistoryAsync(PersistenceHistoryQuery query, CancellationToken token) => ReadAsync(reader => reader.History(query, token), token);
    internal Task<ColumnFilterValuePage> HistoryValuesAsync(PersistenceHistoryQuery query, PersistenceColumn column, string? search, ColumnFilterValueSort sort, CancellationToken token) => ReadAsync(reader => reader.HistoryValues(query, column, search, sort, token), token);
    private async Task<T> ReadAsync<T>(Func<IPersistenceWorkspaceQueryService, T> read, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (Suspended || _capture == null || _query == null) throw new InvalidOperationException("No assessed Persistence snapshot or archive is available.");
            var revision = Revision; var query = _query;
            var result = await Task.Run(() => read(query.PersistenceQueries), token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (Suspended || revision != Revision || !ReferenceEquals(query, _query)) throw new OperationCanceledException(token);
            return result;
        }
        finally { _gate.Release(); }
    }
    internal async Task QuiesceAsync() { Suspended = true; await _gate.WaitAsync().ConfigureAwait(false); _gate.Release(); }
    internal void Resume() => Suspended = false;
}
