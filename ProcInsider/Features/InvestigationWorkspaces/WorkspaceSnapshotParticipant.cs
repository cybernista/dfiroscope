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
    private NetworkWorkspaceReadSession.RetainedBinding? _priorNetworkBinding;
    private Dictionary<NetworkWorkspaceViewModel,NetworkWorkspaceViewModel.RetainedState>? _priorNetwork;
    private PersistenceWorkspaceReadSession.RetainedBinding? _priorPersistenceBinding;
    private Dictionary<PersistenceWorkspaceViewModel, PersistenceWorkspaceViewModel.RetainedState>? _priorPersistence;
    private PersistenceWorkspaceViewModel? _preparedPersistence;
    private ArtifactsWorkspaceReadSession.RetainedBinding? _priorArtifactsBinding;
    private Dictionary<ArtifactsWorkspaceViewModel, ArtifactsWorkspaceViewModel.RetainedState>? _priorArtifacts;
    internal async Task QuiesceAsync(CancellationToken token)
    {
        manager.ReadsSuspended = true;
        foreach (var ai in manager.Instances.OfType<AiWorkspaceViewModel>()) ai.Cancel();
        if (manager.PersistenceExplorer is { } persistenceExplorer) await persistenceExplorer.QuiesceAsync(token);
        foreach (var persistence in manager.Instances.OfType<PersistenceWorkspaceViewModel>()) await persistence.QuiesceAsync(token);
        if (manager.PersistenceSession is { } persistenceSession) await persistenceSession.QuiesceAsync();
        if (manager.ArtifactsExplorer is { } artifactsExplorer) await artifactsExplorer.QuiesceAsync(token);
        foreach (var artifacts in manager.Instances.OfType<ArtifactsWorkspaceViewModel>()) await artifacts.QuiesceAsync(token);
        if (manager.ArtifactsSession is { } artifactsSession) await artifactsSession.QuiesceAsync();
        if(manager.NetworkExplorer is { } networkExplorer)await networkExplorer.QuiesceAsync(token);
        foreach(var network in manager.Instances.OfType<NetworkWorkspaceViewModel>().ToArray())await network.QuiesceAsync(token);
        if(manager.NetworkSession is { } networkSession)await networkSession.QuiesceAsync();
        if (manager.EventsExplorer is { } explorer) await explorer.QuiesceAsync(token);
        foreach (var events in manager.Instances.OfType<EventsWorkspaceViewModel>().ToArray()) await events.QuiesceAsync(token);
        if (manager.EventsSession is { } session) await session.QuiesceAsync();
        foreach (var instance in manager.Instances.OfType<ProcessesWorkspaceViewModel>().ToArray())
            await instance.QuiesceAsync(token);
    }
    internal void Publish(ViewerReadBinding binding, InvestigationWorkspaceFeatureModule.PreparedEventsWorkspace? prepared = null, InvestigationWorkspaceFeatureModule.PreparedPersistenceWorkspace? persistencePrepared = null)
    {
        if (_pending != null) throw new InvalidOperationException("Workspace publication is already pending.");
        _pending = manager.Instances.OfType<ProcessesWorkspaceViewModel>().ToArray();
        _candidate = binding;
        _priorMetadata = manager.ExplorerMetadata;
        _priorPersistenceBinding = manager.PersistenceSession?.Retain();
        _priorPersistence = manager.Instances.OfType<PersistenceWorkspaceViewModel>().ToDictionary(x => x, x => x.Retain());
        manager.PersistenceSession?.Bind(manager.CaptureBinding, binding);
        _priorArtifactsBinding = manager.ArtifactsSession?.Retain();
        _priorArtifacts = manager.Instances.OfType<ArtifactsWorkspaceViewModel>().ToDictionary(x => x, x => x.Retain());
        manager.ArtifactsSession?.Bind(manager.CaptureBinding, binding);
        if (persistencePrepared != null && ReferenceEquals(persistencePrepared.Instance, manager.ActiveInstance) && ReferenceEquals(persistencePrepared.Query, binding.QueryService) &&
            persistencePrepared.Context == persistencePrepared.Instance.Context && binding.CaptureGeneration == persistencePrepared.Context.CaptureGeneration &&
            persistencePrepared.ReadRevision == _priorPersistenceBinding?.Revision && persistencePrepared.Instance.MatchesQuery(persistencePrepared.Request))
        {
            _preparedPersistence = persistencePrepared.Instance; persistencePrepared.Instance.Apply(persistencePrepared.Page);
        }
        _priorStates = _pending.ToDictionary(instance => instance, instance => instance.CaptureRetainedState());
        _priorEventsBinding = manager.EventsSession?.Retain();
        _priorEvents = manager.Instances.OfType<EventsWorkspaceViewModel>().ToDictionary(x => x, x => x.Retain());
        _priorNetworkBinding=manager.NetworkSession?.Retain();
        _priorNetwork=manager.Instances.OfType<NetworkWorkspaceViewModel>().ToDictionary(x=>x,x=>x.Retain());
        manager.NetworkSession?.Bind(manager.CaptureBinding,binding.QueryService);
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
        foreach(var network in manager.Instances.OfType<NetworkWorkspaceViewModel>())network.Invalidate(false);
        foreach (var persistence in manager.Instances.OfType<PersistenceWorkspaceViewModel>().Where(x => !ReferenceEquals(x, _preparedPersistence))) persistence.Invalidate(false);
        foreach (var artifacts in manager.Instances.OfType<ArtifactsWorkspaceViewModel>()) artifacts.Invalidate(false);
        manager.PersistenceExplorer?.Invalidate();
        manager.ArtifactsExplorer?.Invalidate();
        manager.NetworkExplorer?.Invalidate(captureChanged:false);
        if (manager.CaptureBinding is { } capture && _candidate is { } candidate)
            manager.CaptureBinding = capture with { Query = candidate.QueryService, Listing = candidate.ListingService };
        _pending = null;
        _candidate = null;
        _priorStates = null;
        _priorMetadata = null;
        _priorEventsBinding = null; _priorEvents = null;
        _priorNetworkBinding=null;_priorNetwork=null;
        _priorPersistenceBinding = null; _priorPersistence = null; _preparedPersistence = null;
        _priorArtifactsBinding = null; _priorArtifacts = null;
        _preparedActive = null;
        _invalidated.Clear();
    }
    internal void Abort()
    {
        if (_pending is { } pending)
        {
            if (_priorPersistenceBinding is { } persistenceBinding) manager.PersistenceSession?.Restore(persistenceBinding);
            if (_priorPersistence is { } persistenceStates) foreach (var pair in persistenceStates) pair.Key.Restore(pair.Value);
            if (_priorArtifactsBinding is { } artifactsBinding) manager.ArtifactsSession?.Restore(artifactsBinding);
            if (_priorArtifacts is { } artifactsStates) foreach (var pair in artifactsStates) pair.Key.Restore(pair.Value);
            _priorPersistenceBinding = null; _priorPersistence = null; _preparedPersistence = null;
            _priorArtifactsBinding = null; _priorArtifacts = null;
            if(_priorNetworkBinding is { } networkBinding)manager.NetworkSession?.Restore(networkBinding);
            if(_priorNetwork is { } networkStates)foreach(var pair in networkStates)pair.Key.Restore(pair.Value);
            _priorNetworkBinding=null;_priorNetwork=null;
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
        manager.PersistenceSession?.Resume(); manager.PersistenceExplorer?.Resume();
        manager.ArtifactsSession?.Resume();
        manager.ArtifactsExplorer?.Resume();
        foreach (var artifacts in manager.Instances.OfType<ArtifactsWorkspaceViewModel>()) artifacts.Resume();
        foreach (var persistence in manager.Instances.OfType<PersistenceWorkspaceViewModel>()) persistence.Resume();
        manager.NetworkSession?.Resume();manager.NetworkExplorer?.Resume();
        foreach(var network in manager.Instances.OfType<NetworkWorkspaceViewModel>())network.Resume();
        manager.EventsSession?.Resume();
        manager.EventsExplorer?.Resume();
        foreach (var events in manager.Instances.OfType<EventsWorkspaceViewModel>()) events.Resume();
        foreach (var instance in manager.Instances.OfType<ProcessesWorkspaceViewModel>()) instance.Resume();
        if (manager.ActiveInstance is { } active) _ = manager.ActivateAsync(active);
    }
}
