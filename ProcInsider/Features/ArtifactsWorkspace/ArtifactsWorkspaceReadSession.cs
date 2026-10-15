using ProcInsider.Models;
using ProcInsider.Services;
using ProcInsider.Services.Presentation;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>Shares only the assessed snapshot binding; each Artifacts workspace owns its filters and selection.</summary>
internal sealed class ArtifactsWorkspaceReadSession
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ViewerCaptureBinding? _capture;
    private SqliteStagingQueryService? _query;
    internal long Revision { get; private set; }
    internal bool Suspended { get; private set; }
    internal sealed record RetainedBinding(ViewerCaptureBinding? Capture, SqliteStagingQueryService? Query, long Revision);
    internal RetainedBinding Retain() => new(_capture, _query, Revision);
    internal void Restore(RetainedBinding binding) { _capture = binding.Capture; _query = binding.Query; Revision = binding.Revision; }
    internal void Bind(ViewerCaptureBinding? capture, ViewerReadBinding? snapshot = null)
    {
        _capture = capture; _query = snapshot?.QueryService ?? capture?.Query; Revision++;
    }
    internal Task<ForensicArtifactResultPage> QueryAsync(ForensicArtifactResultQuery query, CancellationToken token)
        => ReadAsync(reader => reader.ArtifactEvidenceQueries.QueryForensicArtifactResults(query, token), token);
    internal Task<ColumnFilterValuePage> ValuesAsync(ForensicArtifactResultQuery query, ForensicArtifactResultColumn column, string? search, ColumnFilterValueSort sort, CancellationToken token)
        => ReadAsync(reader => reader.ArtifactEvidenceQueries.GetForensicArtifactResultValues(query, column, search, sort, token, retainColumnFilter: true), token);
    internal Task<ForensicArtifactResultDetail> DetailAsync(string artifactId, CancellationToken token)
        => ReadAsync(reader => reader.ArtifactEvidenceQueries.GetForensicArtifactResultDetail(artifactId, token), token);
    internal Task<ForensicArtifactResultPropertiesPage> PropertiesAsync(string artifactId, ForensicArtifactResultPropertyQuery query, CancellationToken token)
        => ReadAsync(reader => reader.ArtifactEvidenceQueries.GetForensicArtifactResultProperties(artifactId, query, token), token);
    private async Task<T> ReadAsync<T>(Func<SqliteStagingQueryService, T> read, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (Suspended || _capture == null || _query == null) throw new InvalidOperationException("No assessed Artifacts snapshot or archive is available.");
            var revision = Revision; var query = _query;
            var result = await Task.Run(() => read(query), token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (Suspended || revision != Revision || !ReferenceEquals(query, _query)) throw new OperationCanceledException(token);
            return result;
        }
        finally { _gate.Release(); }
    }
    internal async Task QuiesceAsync() { Suspended = true; await _gate.WaitAsync().ConfigureAwait(false); _gate.Release(); }
    internal void Resume() => Suspended = false;
}
