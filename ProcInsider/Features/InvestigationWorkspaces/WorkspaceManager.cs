using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services.Presentation;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class WorkspaceManager : ViewModelBase, IDisposable
{
    private readonly WorkspaceRegistry _registry;
    private readonly ObservableCollection<WorkspaceInstanceViewModel> _instances = [];
    private WorkspaceInstanceViewModel? _active;
    private int _ordinal;
    private long _activationOrder;
    private bool _disposed;
    internal bool ReadsSuspended { get; set; }
    internal ViewerCaptureBinding? CaptureBinding { get; set; }
    internal ProcInsider.Services.ExplorerCountRefreshPayload? ExplorerMetadata { get; set; }
    internal EventsWorkspaceReadSession? EventsSession { get; set; }
    internal PersistenceWorkspaceReadSession? PersistenceSession { get; set; }
    public PersistenceExplorerViewModel? PersistenceExplorer { get; internal set; }
    public bool PersistenceAvailable => IsAvailable(WorkspaceTypeId.Persistence);
    public IAsyncRelayCommand OpenPersistenceCommand { get; }
    internal ArtifactsWorkspaceReadSession? ArtifactsSession { get; set; }
    public ArtifactsExplorerViewModel? ArtifactsExplorer { get; internal set; }
    public bool ArtifactsAvailable => IsAvailable(WorkspaceTypeId.Artifacts);
    public IAsyncRelayCommand OpenArtifactsCommand { get; }
    internal NetworkWorkspaceReadSession? NetworkSession {get;set;}
    public NetworkExplorerViewModel? NetworkExplorer {get;internal set;}
    public bool NetworkAvailable=>IsAvailable(WorkspaceTypeId.Network);
    public IAsyncRelayCommand OpenNetworkCommand {get;}
    public EventsExplorerViewModel? EventsExplorer { get; internal set; }
    public bool EventsAvailable => IsAvailable(WorkspaceTypeId.Events);
    public IAsyncRelayCommand OpenEventsCommand { get; }
    public WorkspaceNavigationService Navigation { get; internal set; } = null!;
    public ExplorerSectionsViewModel ExplorerSections { get; internal set; } = null!;
    public ViewerSharedActions SharedActions { get; internal set; } = new();
    internal bool IsAvailable(WorkspaceTypeId type) => !_disposed && _registry.IsAvailable(type);
    public ReadOnlyObservableCollection<WorkspaceInstanceViewModel> Instances { get; }
    public WorkspaceInstanceViewModel? ActiveInstance => _active;
    public ProcessPresentationViewModel? ActivePresentation => (_active as ProcessesWorkspaceViewModel)?.Presentation;
    public bool IsEmpty => _instances.Count == 0;
    internal bool IsChangingInstances { get; private set; }
    public long ContextRevision { get; private set; }
    public event Action? ActiveContextChanged;
    public event Action? ActiveContextChanging;
    public IAsyncRelayCommand OpenProcessesCommand { get; }
    public IAsyncRelayCommand OpenAiCommand { get; }
    public bool AiAvailable => IsAvailable(WorkspaceTypeId.Ai);
    public IAsyncRelayCommand<WorkspaceInstanceViewModel> ActivateCommand { get; }
    public IAsyncRelayCommand<WorkspaceInstanceViewModel> CloseCommand { get; }

    internal WorkspaceManager(WorkspaceRegistry registry)
    {
        _registry = registry;
        Instances = new(_instances);
        OpenAiCommand = new AsyncRelayCommand(async () => { await Navigation.OpenAiWorkspaceAsync(); }, () => AiAvailable);
        OpenProcessesCommand = new AsyncRelayCommand(async () => { await OpenProcessesAsync(); });
        OpenEventsCommand = new AsyncRelayCommand(async () => { await OpenEventsAsync(); }, () => EventsAvailable);
        OpenPersistenceCommand = new AsyncRelayCommand(async () => { await OpenPersistenceAsync(); }, () => PersistenceAvailable);
        OpenArtifactsCommand = new AsyncRelayCommand(async () => { await OpenArtifactsAsync(); }, () => ArtifactsAvailable);
        OpenNetworkCommand=new AsyncRelayCommand(async()=>{await OpenNetworkAsync();},()=>NetworkAvailable);
        ActivateCommand = new AsyncRelayCommand<WorkspaceInstanceViewModel>(ActivateAsync);
        CloseCommand = new AsyncRelayCommand<WorkspaceInstanceViewModel>(CloseAsync);
    }
    internal async Task<AiWorkspaceViewModel> OpenAiAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var context = AssistantWorkspaceContext.Capture(this);
        var instance = (AiWorkspaceViewModel)_registry.Create(WorkspaceTypeId.Ai, ++_ordinal);
        try
        {
            instance.Context = CaptureBinding is { } capture ? new(capture.Paths.SessionId, capture.CaptureGeneration) : null;
            instance.SubmissionContext = context is null ? null : context with { Workspace = "AI" };
            _instances.Add(instance); OnPropertyChanged(nameof(IsEmpty));
            await ActivateAsync(instance);
            instance.ShowGeneral();
            return instance;
        }
        catch { _instances.Remove(instance); instance.Dispose(); throw; }
    }
    internal async Task<ArtifactsWorkspaceViewModel> OpenArtifactsAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var instance = (ArtifactsWorkspaceViewModel)_registry.Create(WorkspaceTypeId.Artifacts, ++_ordinal);
        try
        {
            instance.Context = CaptureBinding is { } capture ? new(capture.Paths.SessionId, capture.CaptureGeneration) : null;
            if (ReadsSuspended) await instance.QuiesceAsync(CancellationToken.None);
            _instances.Add(instance); OnPropertyChanged(nameof(IsEmpty)); await ActivateAsync(instance); return instance;
        }
        catch { _instances.Remove(instance); instance.Dispose(); throw; }
    }
    internal async Task<NetworkWorkspaceViewModel> OpenNetworkAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed,this);
        var instance=(NetworkWorkspaceViewModel)_registry.Create(WorkspaceTypeId.Network,++_ordinal);
        try
        {
            instance.Context=CaptureBinding is { } capture?new(capture.Paths.SessionId,capture.CaptureGeneration):null;
            if(ReadsSuspended)await instance.QuiesceAsync(CancellationToken.None);
            _instances.Add(instance);OnPropertyChanged(nameof(IsEmpty));await ActivateAsync(instance);return instance;
        }
        catch{_instances.Remove(instance);instance.Dispose();throw;}
    }
    internal async Task<PersistenceWorkspaceViewModel> OpenPersistenceAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var instance = (PersistenceWorkspaceViewModel)_registry.Create(WorkspaceTypeId.Persistence, ++_ordinal);
        try
        {
            instance.InvestigationChanged += () => { if (ReferenceEquals(_active, instance)) ContextRevision++; };
            instance.Context = CaptureBinding is { } capture ? new(capture.Paths.SessionId, capture.CaptureGeneration) : null;
            if (ReadsSuspended) await instance.QuiesceAsync(CancellationToken.None);
            _instances.Add(instance); OnPropertyChanged(nameof(IsEmpty)); await ActivateAsync(instance); return instance;
        }
        catch { _instances.Remove(instance); instance.Dispose(); throw; }
    }
    internal async Task<EventsWorkspaceViewModel> OpenEventsAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var instance = (EventsWorkspaceViewModel)_registry.Create(WorkspaceTypeId.Events, ++_ordinal);
        try
        {
            instance.SharedActions = SharedActions;
            instance.InvestigationChanged += () => { if (ReferenceEquals(_active, instance)) ContextRevision++; };
            instance.FiltersChanged += () =>
            {
                if (!ReferenceEquals(_active, instance)) return;
                EventsExplorer?.ReloadExpanded();
            };
            instance.RefreshSucceeded += () =>
            {
                if (!ReferenceEquals(_active, instance)) return;
                EventsExplorer?.ReloadExpanded();
            };
            instance.Context = CaptureBinding is { } capture ? new(capture.Paths.SessionId, capture.CaptureGeneration) : null;
            instance.BindAnnotations(CaptureBinding?.Annotations);
            if (ReadsSuspended) await instance.QuiesceAsync(CancellationToken.None);
            _instances.Add(instance);
            OnPropertyChanged(nameof(IsEmpty));
            await ActivateAsync(instance);
            return instance;
        }
        catch { _instances.Remove(instance); instance.Dispose(); throw; }
    }
    internal async Task<ProcessesWorkspaceViewModel> OpenProcessesAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var instance = (ProcessesWorkspaceViewModel)_registry.Create(WorkspaceTypeId.Processes, ++_ordinal);
        try
        {
            if (ReadsSuspended) await instance.QuiesceAsync(CancellationToken.None);
            if (CaptureBinding is { } binding)
            {
                instance.Context = new(binding.Paths.SessionId, binding.CaptureGeneration);
                instance.Presentation.BindCapture(binding);
                instance.CaptureChanged();
            }
            if (ExplorerMetadata is { } metadata) instance.Presentation.ApplyExplorerMetadata(metadata);
            _instances.Add(instance);
            OnPropertyChanged(nameof(IsEmpty));
            await ActivateAsync(instance);
            return instance;
        }
        catch { _instances.Remove(instance); instance.Dispose(); throw; }
    }
    internal async Task ActivateAsync(WorkspaceInstanceViewModel? instance)
    {
        if (_disposed || instance == null || instance.IsDisposed || !_instances.Contains(instance)) return;
        if (!ReferenceEquals(instance, _active))
        {
            ActiveContextChanging?.Invoke();
            (_active as ProcessesWorkspaceViewModel)?.CapturePosition();
            _active = instance;
            instance.ActivationOrder = ++_activationOrder;
            ContextRevision++;
            OnPropertyChanged(nameof(ActiveInstance));
            OnPropertyChanged(nameof(ActivePresentation));
            ActiveContextChanged?.Invoke();
        }
        if (!ReadsSuspended && instance is ProcessesWorkspaceViewModel process) await process.LoadAsync();
        if (!ReadsSuspended && instance is EventsWorkspaceViewModel events) await events.LoadAsync();
        if (!ReadsSuspended && instance is PersistenceWorkspaceViewModel persistence) await persistence.LoadAsync();
        if (!ReadsSuspended && instance is ArtifactsWorkspaceViewModel artifacts) await artifacts.LoadAsync();
        if (!ReadsSuspended && instance is NetworkWorkspaceViewModel network) await network.LoadAsync();
    }
    internal async Task CloseAsync(WorkspaceInstanceViewModel? instance)
    {
        if (_disposed || instance == null || !_instances.Contains(instance)) return;
        if (ReferenceEquals(instance, _active)) ActiveContextChanging?.Invoke();
        if (instance is ProcessesWorkspaceViewModel process) await process.QuiesceAsync(CancellationToken.None, preserveSharedAiExecution: true);
        if (instance is EventsWorkspaceViewModel events) await events.QuiesceAsync(CancellationToken.None);
        if (instance is PersistenceWorkspaceViewModel persistence) await persistence.QuiesceAsync(CancellationToken.None);
        if (instance is ArtifactsWorkspaceViewModel artifacts) await artifacts.QuiesceAsync(CancellationToken.None);
        if (instance is NetworkWorkspaceViewModel network) await network.QuiesceAsync(CancellationToken.None);
        var wasActive = ReferenceEquals(instance, _active);
        var next = wasActive ? _instances.Where(x => !ReferenceEquals(x, instance))
            .OrderByDescending(x => x.ActivationOrder).ThenBy(x => x.CreationOrder).FirstOrDefault() : null;
        IsChangingInstances = true;
        try
        {
            if (!_instances.Remove(instance)) return;
            if (wasActive)
            {
                _active = null;
                ContextRevision++;
                OnPropertyChanged(nameof(ActiveInstance));
                OnPropertyChanged(nameof(ActivePresentation));
                ActiveContextChanged?.Invoke();
            }
        }
        finally { IsChangingInstances = false; }
        instance.Dispose();
        OnPropertyChanged(nameof(IsEmpty));
        if (next != null)
            await ActivateAsync(next);
    }
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var instance in _instances) instance.Dispose();
        EventsExplorer?.Dispose();
        PersistenceExplorer?.Dispose();
        PersistenceSession?.QuiesceAsync().GetAwaiter().GetResult();
        ArtifactsSession?.QuiesceAsync().GetAwaiter().GetResult();
        ArtifactsExplorer?.Dispose();
        NetworkExplorer?.Dispose();
        NetworkSession?.QuiesceAsync().GetAwaiter().GetResult();
        // Query service runs on the pool and its disposal has no Dispatcher continuation.
        EventsSession?.QuiesceAsync().GetAwaiter().GetResult();
        _instances.Clear();
        _active = null;
        ActiveContextChanged = null;
        ActiveContextChanging = null;
    }
}
