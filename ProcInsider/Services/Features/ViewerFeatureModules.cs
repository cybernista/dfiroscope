using System.Collections.Specialized;
using System.ComponentModel;
using System.Windows.Threading;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Ai;
using ProcInsider.ViewModels;

namespace ProcInsider.Services.Features;

/// <summary>
/// Lazily constructed module for selected-process module and handle inspection.
/// It owns its background capture services and every subscription created during activation.
/// </summary>
public sealed class ModulesAndHandlesFeatureModule : IDisposable
{
    private readonly NotifyCollectionChangedEventHandler _artifactCollectionChanged;
    private readonly EventHandler _captureStatusChanged;
    private bool _disposed;

    public ModulesAndHandlesFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        NotifyCollectionChangedEventHandler artifactCollectionChanged,
        EventHandler captureStatusChanged)
    {
        _artifactCollectionChanged = artifactCollectionChanged;
        _captureStatusChanged = captureStatusChanged;

        ModulesViewModel = new ModulesViewModel(
            inspectorPaneViewModel,
            projectionService);
        HandlesViewModel = new HandlesViewModel(
            inspectorPaneViewModel,
            projectionService);

        ModulesViewModel.Modules.CollectionChanged += _artifactCollectionChanged;
        HandlesViewModel.Handles.CollectionChanged += _artifactCollectionChanged;
        ModulesViewModel.CaptureStatusChanged += _captureStatusChanged;
        HandlesViewModel.CaptureStatusChanged += _captureStatusChanged;
    }

    public ModulesViewModel ModulesViewModel { get; }
    public HandlesViewModel HandlesViewModel { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ModulesViewModel.Modules.CollectionChanged -= _artifactCollectionChanged;
        HandlesViewModel.Handles.CollectionChanged -= _artifactCollectionChanged;
        ModulesViewModel.CaptureStatusChanged -= _captureStatusChanged;
        HandlesViewModel.CaptureStatusChanged -= _captureStatusChanged;
        ModulesViewModel.Clear();
        HandlesViewModel.Clear();
    }
}

/// <summary>
/// Projection-only lifecycle owner for one event source. Live ingress remains agent-local and the
/// module never creates another event-family module.
/// </summary>
public abstract class EventSourceFeatureModule : IDisposable
{
    private bool _disposed;

    protected EventSourceFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        string source,
        Action<(string ProcessKey, int ProcessId, string ProcessName)>? backfill = null)
    {
        ViewModel = new EventsViewModel(
            projectionService,
            inspectorPaneViewModel,
            source,
            backfill);
    }

    public EventsViewModel ViewModel { get; }

    public virtual void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ViewModel.Clear();
    }
}

public sealed class RuntimeEventsFeatureModule : EventSourceFeatureModule
{
    public RuntimeEventsFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
        : base(projectionService, inspectorPaneViewModel, "Runtime")
    {
    }
}

public sealed class EtwEventsFeatureModule : EventSourceFeatureModule
{
    public EtwEventsFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
        : base(projectionService, inspectorPaneViewModel, "ETW")
    {
    }
}

public sealed class WindowsSecurityEventsFeatureModule : EventSourceFeatureModule
{
    public WindowsSecurityEventsFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        Action<(string ProcessKey, int ProcessId, string ProcessName)> backfill)
        : base(projectionService, inspectorPaneViewModel, "Security", backfill)
    {
        ConfigProfileService = new ConfigProfileService();
        SecurityMonitoringService = new SecurityMonitoringService(ConfigProfileService);
        DetailsWorkflow = new ProcInsider.Features.WindowsSecurityDetails.SecurityDetailsWorkflow(ViewModel);
    }

    public ConfigProfileService ConfigProfileService { get; }
    public SecurityMonitoringService SecurityMonitoringService { get; }
    public ProcInsider.Features.WindowsSecurityDetails.SecurityDetailsWorkflow DetailsWorkflow { get; }
    public override void Dispose() { DetailsWorkflow.Dispose(); base.Dispose(); }
}

public sealed class PowerShellEventsFeatureModule : EventSourceFeatureModule
{
    public PowerShellEventsFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        Action<(string ProcessKey, int ProcessId, string ProcessName)> backfill)
        : base(projectionService, inspectorPaneViewModel, "PowerShell", backfill)
    {
    }
}

public sealed class WindowsOtherEventsFeatureModule : EventSourceFeatureModule
{
    public WindowsOtherEventsFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        Action<(string ProcessKey, int ProcessId, string ProcessName)> backfill)
        : base(projectionService, inspectorPaneViewModel, "WindowsOther", backfill)
    {
    }
}

public sealed class SysmonEventsFeatureModule : EventSourceFeatureModule
{
    public SysmonEventsFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        Action<(string ProcessKey, int ProcessId, string ProcessName)> backfill)
        : base(projectionService, inspectorPaneViewModel, "Sysmon", backfill)
    {
    }
}

/// <summary>
/// Retained composer for the event-telemetry gate. It owns the Runtime, ETW, PowerShell,
/// WindowsOther, and Sysmon modules as one publication unit. Windows Security is never composed
/// here and activates only through its source-owned publication group.
/// </summary>
public sealed class EventTelemetryFeatureModule : IDisposable
{
    private bool _disposed;

    public EventTelemetryFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        Action<(string ProcessKey, int ProcessId, string ProcessName)> backfillPowerShell,
        Action<(string ProcessKey, int ProcessId, string ProcessName)> backfillOtherWindows,
        Action<(string ProcessKey, int ProcessId, string ProcessName)> backfillSysmon)
    {
        ConfigProfileService = new ConfigProfileService();
        PowerShellAuditingService = new PowerShellAuditingService(ConfigProfileService);
        SysmonService = new SysmonService(ConfigProfileService);

        RuntimeEventsModule = new RuntimeEventsFeatureModule(projectionService, inspectorPaneViewModel);
        EtwEventsModule = new EtwEventsFeatureModule(projectionService, inspectorPaneViewModel);
        PowerShellEventsModule = new PowerShellEventsFeatureModule(
            projectionService,
            inspectorPaneViewModel,
            backfillPowerShell);
        WindowsOtherEventsModule = new WindowsOtherEventsFeatureModule(
            projectionService,
            inspectorPaneViewModel,
            backfillOtherWindows);
        SysmonEventsModule = new SysmonEventsFeatureModule(
            projectionService,
            inspectorPaneViewModel,
            backfillSysmon);
        SystemActivityViewModel = new SystemActivityViewModel(projectionService, inspectorPaneViewModel);
    }

    public ConfigProfileService ConfigProfileService { get; }
    public PowerShellAuditingService PowerShellAuditingService { get; }
    public SysmonService SysmonService { get; }
    public RuntimeEventsFeatureModule RuntimeEventsModule { get; }
    public EtwEventsFeatureModule EtwEventsModule { get; }
    public PowerShellEventsFeatureModule PowerShellEventsModule { get; }
    public WindowsOtherEventsFeatureModule WindowsOtherEventsModule { get; }
    public SysmonEventsFeatureModule SysmonEventsModule { get; }
    public EventsViewModel RuntimeEventsViewModel => RuntimeEventsModule.ViewModel;
    public EventsViewModel EtwEventsViewModel => EtwEventsModule.ViewModel;
    public EventsViewModel PowerShellEventsViewModel => PowerShellEventsModule.ViewModel;
    public EventsViewModel OtherWindowsEventsViewModel => WindowsOtherEventsModule.ViewModel;
    public EventsViewModel SysmonEventsViewModel => SysmonEventsModule.ViewModel;
    public SystemActivityViewModel SystemActivityViewModel { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        RuntimeEventsModule.Dispose();
        EtwEventsModule.Dispose();
        PowerShellEventsModule.Dispose();
        WindowsOtherEventsModule.Dispose();
        SysmonEventsModule.Dispose();
        SystemActivityViewModel.Clear();
    }
}

public sealed class AgentFeatureModule : IDisposable
{
    private readonly PropertyChangedEventHandler _agentPropertyChanged;
    private readonly EventHandler _statusTimerTick;
    private bool _disposed;

    public AgentFeatureModule(
        PropertyChangedEventHandler agentPropertyChanged,
        EventHandler statusTimerTick,
        string viewerReleaseId,
        InvestigationSessionPaths sessionPaths)
    {
        _agentPropertyChanged = agentPropertyChanged;
        _statusTimerTick = statusTimerTick;
        AgentsViewModel = new AgentsViewModel();
        AgentClient = new AgentNamedPipeClient(
            viewerReleaseId: viewerReleaseId);
        AgentStatusClient = new AgentNamedPipeClient(
            timeout: TimeSpan.FromSeconds(2),
            viewerReleaseId: viewerReleaseId);
        AgentRecoveryClient = new AgentNamedPipeClient(
            timeout: TimeSpan.FromSeconds(3),
            viewerReleaseId: viewerReleaseId);
        AgentShutdownControlClient = new AgentNamedPipeClient(
            AgentContracts.ShutdownControlPipeName,
            timeout: TimeSpan.FromSeconds(2),
            viewerReleaseId: viewerReleaseId);
        BindSession(sessionPaths);
        StatusTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(3)
        };
        AgentsViewModel.PropertyChanged += _agentPropertyChanged;
        StatusTimer.Tick += _statusTimerTick;
    }

    public AgentsViewModel AgentsViewModel { get; }
    public AgentNamedPipeClient AgentClient { get; }
    public AgentNamedPipeClient AgentStatusClient { get; }
    public AgentNamedPipeClient AgentRecoveryClient { get; }
    public AgentNamedPipeClient AgentShutdownControlClient { get; }
    public DispatcherTimer StatusTimer { get; }

    public void BindSession(InvestigationSessionPaths sessionPaths)
    {
        AgentClient.BindSession(sessionPaths);
        AgentStatusClient.BindSession(sessionPaths);
        AgentRecoveryClient.BindSession(sessionPaths);
        AgentShutdownControlClient.BindSession(sessionPaths);
    }

    public void UnbindSession()
    {
        AgentClient.UnbindSession();
        AgentStatusClient.UnbindSession();
        AgentRecoveryClient.UnbindSession();
        AgentShutdownControlClient.UnbindSession();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        StatusTimer.Stop();
        StatusTimer.Tick -= _statusTimerTick;
        AgentsViewModel.PropertyChanged -= _agentPropertyChanged;
        AgentsViewModel.ResetSessionState("Agent feature deactivated.");
        UnbindSession();
    }
}

public sealed class DumpsAndPeFeatureModule : IDisposable
{
    private readonly PropertyChangedEventHandler _memoryDumpPropertyChanged;
    private bool _disposed;

    public DumpsAndPeFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        PropertyChangedEventHandler memoryDumpPropertyChanged)
    {
        _memoryDumpPropertyChanged = memoryDumpPropertyChanged;
        MemoryDumpsViewModel = new MemoryDumpsViewModel(projectionService, inspectorPaneViewModel);
        PeAnalysisViewModel = new PeAnalysisViewModel(projectionService, inspectorPaneViewModel);
        MemoryDumpsViewModel.PropertyChanged += _memoryDumpPropertyChanged;
    }

    public MemoryDumpsViewModel MemoryDumpsViewModel { get; }
    public PeAnalysisViewModel PeAnalysisViewModel { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        MemoryDumpsViewModel.PropertyChanged -= _memoryDumpPropertyChanged;
        MemoryDumpsViewModel.Clear();
        PeAnalysisViewModel.Clear();
    }
}

public sealed class NetworkAndZeekFeatureModule : IDisposable
{
    private readonly PropertyChangedEventHandler _propertyChanged;
    private readonly EventHandler _refreshed;
    private bool _disposed;

    public NetworkAndZeekFeatureModule(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel,
        Func<NetworkCaptureRecord, bool> isActiveCapture,
        Func<NetworkCaptureRecord, bool> isFinalizingCapture,
        PropertyChangedEventHandler propertyChanged,
        EventHandler refreshed)
    {
        _propertyChanged = propertyChanged;
        _refreshed = refreshed;
        ViewModel = new NetworkCapturesViewModel(projectionService, inspectorPaneViewModel);
        ViewModel.SetActiveNetworkCapturePredicate(isActiveCapture);
        ViewModel.SetFinalizingNetworkCapturePredicate(isFinalizingCapture);
        ViewModel.PropertyChanged += _propertyChanged;
        ViewModel.Refreshed += _refreshed;
    }

    public NetworkCapturesViewModel ViewModel { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ViewModel.PropertyChanged -= _propertyChanged;
        ViewModel.Refreshed -= _refreshed;
        ViewModel.Clear();
    }
}

public sealed class AiFeatureModule : IDisposable
{
    private bool _disposed;

    public AiFeatureModule(
        InvestigationSessionPaths sessionPaths,
        TelemetryProjectionService projectionService,
        AnnotationDatabaseService? annotationStore,
        ApplicationCatalogService? applicationCatalog,
        InspectorPaneViewModel inspectorPaneViewModel,
        FeatureAccessService featureAccess)
    {
        Service = new AiInvestigationService(sessionPaths.AiSettingsPath, sessionPaths.AiSecretPath);
        EvidencePackBuilder = new AiEvidencePackBuilder(projectionService, annotationStore, applicationCatalog);
        InvestigationViewModel = new AiInvestigationViewModel(
            Service,
            EvidencePackBuilder,
            annotationStore,
            featureAccess);
        DetailsViewModel = new AiDetailsInvestigationViewModel(
            Service,
            inspectorPaneViewModel,
            annotationStore,
            featureAccess);
        ChatViewModel = new AiChatViewModel(Service, annotationStore, featureAccess);
    }

    public AiInvestigationService Service { get; }
    public AiEvidencePackBuilder EvidencePackBuilder { get; }
    public AiInvestigationViewModel InvestigationViewModel { get; }
    public AiDetailsInvestigationViewModel DetailsViewModel { get; }
    public AiChatViewModel ChatViewModel { get; }

    public void SetWorkspace(InvestigationSessionPaths sessionPaths, AnnotationDatabaseService? annotationStore)
    {
        Service.SetStoragePaths(sessionPaths.AiSettingsPath, sessionPaths.AiSecretPath);
        EvidencePackBuilder.SetAnnotationStore(annotationStore);
        InvestigationViewModel.SetAnnotationStore(annotationStore);
        InvestigationViewModel.ReloadSettings();
        DetailsViewModel.SetAnnotationStore(annotationStore);
        DetailsViewModel.ReloadSettings();
        ChatViewModel.SetAnnotationStore(annotationStore);
        ChatViewModel.ReloadSettings();
    }

    public void DetachWorkspace()
    {
        InvestigationViewModel.CancelInvestigation();
        DetailsViewModel.CancelInvestigation();
        ChatViewModel.Cancel();
        InvestigationViewModel.SetAnnotationStore(null);
        DetailsViewModel.SetAnnotationStore(null);
        ChatViewModel.SetAnnotationStore(null);
        InvestigationViewModel.Clear();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        InvestigationViewModel.CancelInvestigation();
        DetailsViewModel.Dispose();
        ChatViewModel.Dispose();
        InvestigationViewModel.Dispose();
    }
}

public sealed class SecurityMonitoringFeatureModule
{
    public SecurityMonitoringFeatureModule()
    {
        ConfigProfileService = new ConfigProfileService();
        PowerShellAuditingService = new PowerShellAuditingService(ConfigProfileService);
        SysmonService = new SysmonService(ConfigProfileService);
        SecurityMonitoringService = new SecurityMonitoringService(ConfigProfileService);
    }

    public ConfigProfileService ConfigProfileService { get; }
    public PowerShellAuditingService PowerShellAuditingService { get; }
    public SysmonService SysmonService { get; }
    public SecurityMonitoringService SecurityMonitoringService { get; }
}
