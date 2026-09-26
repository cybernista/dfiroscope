using ProcInsider.Services.Presentation;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class WorkspaceSnapshotParticipant(WorkspaceManager manager)
{
    private ProcessesWorkspaceViewModel[]? _pending;
    private ViewerReadBinding? _candidate;
    private Dictionary<ProcessesWorkspaceViewModel, ProcessesWorkspaceViewModel.RetainedState>? _priorStates;
    private ProcInsider.Services.ExplorerCountRefreshPayload? _priorMetadata;
    private readonly HashSet<ProcessesWorkspaceViewModel> _invalidated = [];
    private EventsWorkspaceReadSession.RetainedBinding? _priorEventsBinding;
    private Dictionary<EventsWorkspaceViewModel, EventsWorkspaceViewModel.RetainedState>? _priorEvents;
    private EventsWorkspaceViewModel? _preparedActive;
    internal async Task QuiesceAsync(CancellationToken token)
    {
        manager.ReadsSuspended = true;
        if (manager.EventsExplorer is { } explorer) await explorer.QuiesceAsync(token);
        foreach (var events in manager.Instances.OfType<EventsWorkspaceViewModel>().ToArray()) await events.QuiesceAsync(token);
        if (manager.EventsSession is { } session) await session.QuiesceAsync();
        foreach (var instance in manager.Instances.OfType<ProcessesWorkspaceViewModel>().ToArray())
            await instance.QuiesceAsync(token);
    }
    internal void Publish(ViewerReadBinding binding, InvestigationWorkspaceFeatureModule.PreparedEventsWorkspace? prepared = null)
    {
        if (_pending != null) throw new InvalidOperationException("Workspace publication is already pending.");
        _pending = manager.Instances.OfType<ProcessesWorkspaceViewModel>().ToArray();
        _candidate = binding;
        _priorMetadata = manager.ExplorerMetadata;
        _priorStates = _pending.ToDictionary(instance => instance, instance => instance.CaptureRetainedState());
        _priorEventsBinding = manager.EventsSession?.Retain();
        _priorEvents = manager.Instances.OfType<EventsWorkspaceViewModel>().ToDictionary(x => x, x => x.Retain());
        manager.EventsSession?.Bind(manager.CaptureBinding, binding);
        if (prepared != null && ReferenceEquals(prepared.Instance, manager.ActiveInstance) && ReferenceEquals(prepared.Query, binding.QueryService) &&
            prepared.Page.Binding.SnapshotGeneration == binding.SnapshotGeneration && prepared.Request == prepared.Instance.CaptureQuery())
        {
            _preparedActive = prepared.Instance;
            prepared.Instance.ApplyPrepared(prepared.Page);
        }
        foreach (var instance in _pending)
        {
            instance.Presentation.BeginPublication();
            instance.Presentation.PublishReadBinding(binding);
        }
    }
    internal void Commit()
    {
        if (_pending == null) return;
        foreach (var instance in _pending)
        {
            if (ReferenceEquals(instance, manager.ActiveInstance)) instance.MarkLoaded();
            else
            {
                _invalidated.Add(instance);
                instance.InvalidateRows(retainPreviousCollection: true);
            }
        }
        // Observable participant changes must all succeed before predecessor collections are released.
        if (_candidate is { } eventsCandidate)
        {
            foreach (var events in manager.Instances.OfType<EventsWorkspaceViewModel>().Where(x => !ReferenceEquals(x, _preparedActive))) events.Invalidate(captureChanged: false);
            manager.EventsExplorer?.Invalidate();
        }
        foreach (var instance in _pending) instance.Presentation.CommitPublication();
        if (manager.CaptureBinding is { } capture && _candidate is { } candidate)
            manager.CaptureBinding = capture with { Query = candidate.QueryService, Listing = candidate.ListingService };
        _pending = null;
        _candidate = null;
        _priorStates = null;
        _priorMetadata = null;
        _priorEventsBinding = null; _priorEvents = null;
        _preparedActive = null;
        _invalidated.Clear();
    }
    internal void Abort()
    {
        if (_pending is { } pending)
        {
            if (_priorEventsBinding is { } retained) manager.EventsSession?.Restore(retained);
            if (_priorEvents is { } events) foreach (var pair in events) pair.Key.Restore(pair.Value);
            _priorEventsBinding = null; _priorEvents = null;
            _preparedActive = null;
            foreach (var instance in pending)
            {
                instance.Presentation.AbortPublication();
                if (_priorStates?.TryGetValue(instance, out var state) == true) instance.RestoreRetainedState(state, _invalidated.Contains(instance));
            }
            manager.ExplorerMetadata = _priorMetadata;
            var restoredMetadata = _priorMetadata ?? new ProcInsider.Services.ExplorerCountRefreshPayload(new(), []);
            manager.ExplorerSections.ApplyMetadata(restoredMetadata);
            foreach (var instance in pending) instance.Presentation.ApplyExplorerMetadata(restoredMetadata);
            _pending = null;
            _candidate = null;
            _priorStates = null;
            _priorMetadata = null;
            _invalidated.Clear();
            return;
        }
        manager.ReadsSuspended = false;
        manager.EventsSession?.Resume();
        manager.EventsExplorer?.Resume();
        foreach (var events in manager.Instances.OfType<EventsWorkspaceViewModel>()) events.Resume();
        foreach (var instance in manager.Instances.OfType<ProcessesWorkspaceViewModel>()) instance.Resume();
        if (manager.ActiveInstance is { } active) _ = manager.ActivateAsync(active);
    }
}
