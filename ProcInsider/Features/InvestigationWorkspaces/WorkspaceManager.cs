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
    public IAsyncRelayCommand<WorkspaceInstanceViewModel> ActivateCommand { get; }
    public IAsyncRelayCommand<WorkspaceInstanceViewModel> CloseCommand { get; }

    internal WorkspaceManager(WorkspaceRegistry registry)
    {
        _registry = registry;
        Instances = new(_instances);
        OpenProcessesCommand = new AsyncRelayCommand(async () => { await OpenProcessesAsync(); });
        OpenEventsCommand = new AsyncRelayCommand(async () => { await OpenEventsAsync(); }, () => EventsAvailable);
        ActivateCommand = new AsyncRelayCommand<WorkspaceInstanceViewModel>(ActivateAsync);
        CloseCommand = new AsyncRelayCommand<WorkspaceInstanceViewModel>(CloseAsync);
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
    }
    internal async Task CloseAsync(WorkspaceInstanceViewModel? instance)
    {
        if (_disposed || instance == null || !_instances.Contains(instance)) return;
        if (ReferenceEquals(instance, _active)) ActiveContextChanging?.Invoke();
        if (instance is ProcessesWorkspaceViewModel process) await process.QuiesceAsync(CancellationToken.None);
        if (instance is EventsWorkspaceViewModel events) await events.QuiesceAsync(CancellationToken.None);
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
        // Query service runs on the pool and its disposal has no Dispatcher continuation.
        EventsSession?.QuiesceAsync().GetAwaiter().GetResult();
        _instances.Clear();
        _active = null;
        ActiveContextChanged = null;
        ActiveContextChanging = null;
    }
}
