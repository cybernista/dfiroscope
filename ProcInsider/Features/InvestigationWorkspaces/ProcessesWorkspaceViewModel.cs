using System.Collections.ObjectModel;
using System.Windows.Data;
using ProcInsider.Models;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services;
using ProcInsider.Services.Presentation;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class ProcessesWorkspaceViewModel : WorkspaceInstanceViewModel
{
    private string _selectedEntity = string.Empty;
    private string _selectedKey = string.Empty;
    private long _loadRevision;
    private bool _needsLoad;
    private CancellationTokenSource _reads = new();
    private int _loads;
    private bool _suspended;
    private Task? _loadTask;
    public ProcessPresentationViewModel Presentation { get; }
    internal ViewerProcessViewportAnchor? Viewport { get; set; }
    internal ProcessesWorkspaceViewModel(WorkspaceTypeMetadata type, int ordinal, ProcessPresentationViewModel presentation)
        : base(type, ordinal) => Presentation = presentation;

    internal void CapturePosition() => Viewport = Presentation.CaptureProcessViewportAnchor() ?? Viewport;
    internal sealed record RetainedState(string Entity, string Key, bool NeedsLoad);
    internal RetainedState CaptureRetainedState() => new(_selectedEntity, _selectedKey, _needsLoad);
    internal void RestoreRetainedState(RetainedState state, bool reloadSupportingViews)
    {
        _selectedEntity = state.Entity;
        _selectedKey = state.Key;
        _needsLoad = state.NeedsLoad;
        if (reloadSupportingViews)
        {
            _selectedEntity = Presentation.SelectedProcess?.ProcessInfo.ProcessEntityId ?? state.Entity;
            _selectedKey = Presentation.SelectedProcess?.ProcessKey ?? state.Key;
            _needsLoad = true;
            Presentation.ProcessListingStatus = "Previous snapshot restored; supporting views reload on activation.";
        }
    }
    internal void InvalidateRows(bool retainPreviousCollection = false)
    {
        _selectedEntity = Presentation.SelectedProcess?.ProcessInfo.ProcessEntityId ?? _selectedEntity;
        _selectedKey = Presentation.SelectedProcess?.ProcessKey ?? _selectedKey;
        Interlocked.Increment(ref _loadRevision);
        var previous = Presentation.DetachVirtualizedProcessListing();
        if (!retainPreviousCollection) previous?.Dispose();
        Presentation.Processes = new ObservableCollection<ProcessRowViewModel>();
        Presentation.ProcessesView = CollectionViewSource.GetDefaultView(Presentation.Processes);
        Presentation.SelectedProcess = null;
        Presentation.TotalProcessCount = 0;
        Presentation.ProcessListingStatus = "Evidence generation changed; load this workspace to continue.";
        Presentation.InspectorPaneViewModel.Clear("Select evidence from the current generation.");
        Presentation.ClearSnapshotBackedViews();
        _needsLoad = true;
    }
    internal void CaptureChanged()
    {
        NavigationDescription = "All Processes";
        Interlocked.Increment(ref _loadRevision);
        _selectedEntity = _selectedKey = string.Empty;
        Viewport = null;
        _needsLoad = true;
    }
    internal Task LoadAsync()
    {
        // WPF selection binding can reenter activation while the manager is opening a tab.
        // Both callers must await one load instead of superseding each other's query.
        return _loadTask is { IsCompleted: false } ? _loadTask : _loadTask = LoadCoreAsync();
    }
    private async Task LoadCoreAsync()
    {
        if (IsDisposed || _suspended || !_needsLoad || Presentation._processListingService == null) return;
        var revision = Interlocked.Increment(ref _loadRevision);
        var context = Context;
        var token = _reads.Token;
        Interlocked.Increment(ref _loads);
        try
        {
            await Presentation.ExecuteDbRefreshAsync();
            token.ThrowIfCancellationRequested();
            if (IsDisposed || revision != Volatile.Read(ref _loadRevision) || context != Context) return;
            var collection = Presentation._virtualizedProcessListing;
            var listing = Presentation._processListingService;
            if (collection == null || listing == null) return;
            var interaction = Presentation._snapshotPresentationInteractionGeneration;
            var queryGeneration = Presentation._processListingQueryGeneration;
            // Preserve page coordinates; GetLoadedRows() flattens noncontiguous cached pages.
            var query = Presentation.BuildCurrentListingQuery();
            var pageZeroRows = Enumerable.Range(0, Math.Min(query.PageSize, collection.Count)).Select(collection.GetLoadedItem).ToArray();
            var pageZero = pageZeroRows.All(row => row != null)
                ? new ProcessListingWindow { Rows = pageZeroRows.Cast<ProcessRowViewModel>().ToArray(), TotalCount = collection.Count, PageSize = query.PageSize }
                : await listing.GetPageAsync(new ProcessListingQuery { Filters = query.Filters, Sort = query.Sort,
                    Offset = 0, PageSize = query.PageSize, IncludeTotalCount = false }, token);
            var resolver = new ProcessListingAnchorResolver(listing, query, pageZero);
            var anchor = await resolver.ResolveAsync(_selectedEntity, _selectedKey, token);
            if (anchor.Index >= 0) await collection.EnsureRangeAsync(anchor.Index, 1, token);
            var viewport = Viewport;
            if (viewport != null)
            {
                var position = await resolver.ResolveAsync(viewport.ProcessEntityId, viewport.ProcessKey, token);
                if (position.Index >= 0) await collection.EnsureRangeAsync(position.Index, 1, token);
            }
            token.ThrowIfCancellationRequested();
            if (IsDisposed || revision != Volatile.Read(ref _loadRevision) || context != Context ||
                !ReferenceEquals(collection, Presentation._virtualizedProcessListing)) return;
            if (interaction == Presentation._snapshotPresentationInteractionGeneration && queryGeneration == Presentation._processListingQueryGeneration)
            {
                var selected = anchor.Index < 0 ? null : collection.GetLoadedItem(anchor.Index);
                if (selected != null && (!string.IsNullOrEmpty(_selectedEntity)
                        ? selected.ProcessInfo.ProcessEntityId != _selectedEntity : selected.ProcessKey != _selectedKey))
                    throw new InvalidOperationException("The restored row does not match the retained process identity.");
                Presentation.SelectedProcess = selected;
                if (anchor.Index < 0 && (_selectedEntity.Length != 0 || _selectedKey.Length != 0))
                    Presentation.ProcessListingStatus = "The previous selection is missing or filtered out; no replacement was selected.";
            }
            await Presentation.RefreshSnapshotBackedViewsAsync(token);
            token.ThrowIfCancellationRequested();
            if (revision == Volatile.Read(ref _loadRevision) && context == Context) _needsLoad = false;
            }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsDisposed && revision == Volatile.Read(ref _loadRevision))
                Presentation.ProcessListingStatus = $"Workspace reload failed: {ex.Message}";
        }
        finally { Interlocked.Decrement(ref _loads); }
    }
    internal async Task QuiesceAsync(CancellationToken token)
    {
        _suspended = true;
        Interlocked.Increment(ref _loadRevision);
        _reads.Cancel();
        await Presentation.QuiesceAsync(token);
        while (Volatile.Read(ref _loads) != 0) await Task.Delay(10, token);
    }
    internal void Resume()
    {
        if (!_suspended || IsDisposed) return;
        _reads.Dispose();
        _reads = new();
        _suspended = false;
        Presentation.ResumeReads();
    }
    internal void MarkLoaded() => _needsLoad = false;
    public override void Dispose()
    {
        if (IsDisposed) return;
        IsDisposed = true;
        _reads.Cancel();
        _reads.Dispose();
        Interlocked.Increment(ref _loadRevision);
        Presentation.Dispose();
    }
}
