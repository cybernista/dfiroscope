using System.IO;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.Services.Presentation;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>Lazy read owner shared by Events instances and Explorer; never owns the capture facade.</summary>
internal sealed class EventsWorkspaceReadSession(FeatureAccessService access)
{
    private IEventsWorkspaceQueryService? _reader;
    private SqliteStagingQueryService? _query;
    private long _revision;
    internal EventsReadBinding? Binding { get; private set; }
    internal bool KnownEmpty => Binding == null || (_query == null && _boundWithoutEvidenceDatabase);
    private bool _boundWithoutEvidenceDatabase;
    internal bool Suspended { get; private set; }
    internal bool HasReader => _reader != null;
    internal sealed record RetainedBinding(SqliteStagingQueryService? Query, EventsReadBinding? Binding, bool BoundWithoutEvidenceDatabase);
    internal RetainedBinding Retain() => new(_query, Binding, _boundWithoutEvidenceDatabase);
    internal void Restore(RetainedBinding retained) { _query = retained.Query; Binding = retained.Binding; _boundWithoutEvidenceDatabase = retained.BoundWithoutEvidenceDatabase; }

    internal void Bind(ViewerCaptureBinding? capture, ViewerReadBinding? snapshot = null)
    {
        if (_reader != null) throw new InvalidOperationException("Events reads must drain before rebinding.");
        _query = snapshot?.QueryService ?? capture?.Query;
        _boundWithoutEvidenceDatabase = capture != null && snapshot == null &&
            capture.Query == null && IsConfirmedMissing(capture.Paths.LiveDatabasePath);
        Binding = capture == null ? null : new(null, capture.Paths.SessionId, null, capture.CaptureGeneration,
            snapshot?.SnapshotGeneration ?? ++_revision);
    }

    private static bool IsConfirmedMissing(string path)
    {
        try { File.GetAttributes(path); return false; }
        catch (FileNotFoundException) { return true; }
        catch (DirectoryNotFoundException) { return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    internal IEventsWorkspaceQueryService Reader
    {
        get
        {
            if (Suspended || _query == null || Binding == null) throw new InvalidOperationException("No validated Events snapshot or archive is available.");
            var binding = Binding;
            var query = _query;
            return _reader ??= new EventsWorkspaceQueryService(access.Catalog, query, binding,
                    () => !Suspended && Binding == binding && ReferenceEquals(query, _query));
        }
    }

    internal async Task QuiesceAsync()
    {
        Suspended = true;
        // Query service disposal serializes behind already admitted reads and releases the held transaction.
        if (_reader is { } reader) { await reader.DisposeAsync().ConfigureAwait(false); _reader = null; }
    }
    internal void Resume() => Suspended = false;
}
