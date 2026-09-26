using System.Windows;
using ProcInsider.Services.Ai;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Services.Presentation;

/// <summary>Shared services and semantic callbacks supplied by the capture composition root.</summary>
internal sealed class ProcessPresentationServices
{
    public ViewerSharedActions SharedActions { get; init; } = new();
    public required FeatureAccessService Access { get; init; }
    public required FeatureActivationRegistry SharedModules { get; init; }
    public required ViewerFeatureRegistry SharedDefinitions { get; init; }
    public required Action<ProcessPresentationViewModel> PresentationStateChanged { get; init; }
    public Action<object?, System.ComponentModel.PropertyChangedEventArgs>? SelectedDataStateChanged { get; init; }
    public Action? NetworkRefreshed { get; init; }
    public required TelemetryProjectionService Projection { get; init; }
    public required FeaturePublicationViewModel Publication { get; init; }
    public required Func<long> CaptureGeneration { get; init; }
    public required Func<AnnotationDatabaseService?> AnnotationStore { get; init; }
    public required Func<InvestigationSessionPaths> SessionPaths { get; init; }
    public required ApplicationCatalogService? ApplicationCatalog { get; init; }
    public required Func<ExplorerScope, Task<IReadOnlyList<ExplorerNodeViewModel>>> LoadExplorerChildren { get; init; }
    public required Func<NetworkCaptureRecord, bool> IsActiveNetworkCapture { get; init; }
    public required Func<NetworkCaptureRecord, bool> IsFinalizingNetworkCapture { get; init; }
    public required Action<ViewerPresentationRegistrationContext> ConfigureContributions { get; init; }
    public required Func<string> GetStatus { get; init; }
    public required Action<string> SetStatus { get; init; }
    public required Func<SigmaViewModel> Sigma { get; init; }
    public required Func<IReadOnlyList<ProcessInfo>, ExplorerScopeCounts> BuildExplorerScopeCounts { get; init; }
    public required Func<ExplorerCountRefreshTrigger, bool, Task> RefreshExplorerCountsCallback { get; init; }
    public Task RefreshExplorerCounts(ExplorerCountRefreshTrigger trigger, bool force = false) => RefreshExplorerCountsCallback(trigger, force);
    public required Func<ExplorerScope, Task> LoadCorrelationEvidence { get; init; }
    public required Action<ProcessPresentationViewModel> QueueSelectedDataEnrichment { get; init; }
    public required Action<ProcessPresentationViewModel> SelectionChanged { get; init; }
}

/// <summary>Configuration shared by Security row presenters; contains no selected-row state.</summary>
public sealed class WindowsSecurityPresentationServices
{
    public ConfigProfileService ConfigProfileService { get; } = new();
    public SecurityMonitoringService SecurityMonitoringService { get; }
    public ProcInsider.Features.WindowsSecurityDetails.SecurityDetailsStore DetailsStore { get; }
    internal ProcInsider.Features.NativeEventProfiles.NativeEventProfileStore Profiles { get; }
    internal WindowsSecurityPresentationServices(ProcInsider.Features.NativeEventProfiles.NativeEventProfileStore? profiles = null)
    {
        Profiles = profiles ?? new ProcInsider.Features.NativeEventProfiles.NativeEventProfileStore(SessionPathService.GetNativeEventProfilesPath());
        SecurityMonitoringService = new SecurityMonitoringService(ConfigProfileService);
        DetailsStore = new ProcInsider.Features.WindowsSecurityDetails.SecurityDetailsStore(
            SessionPathService.GetWindowsSecurityDetailsDefinitionsPath());
    }
}

/// <summary>Existing monitoring configuration, independent of process event rows.</summary>
public sealed class EventTelemetryPresentationServices
{
    public ConfigProfileService ConfigProfileService { get; } = new();
    public PowerShellAuditingService PowerShellAuditingService { get; }
    public SysmonService SysmonService { get; }
    internal ProcInsider.Features.NativeEventProfiles.NativeEventProfileStore Profiles { get; }
    internal EventTelemetryPresentationServices(ProcInsider.Features.NativeEventProfiles.NativeEventProfileStore? profiles = null)
    {
        Profiles = profiles ?? new ProcInsider.Features.NativeEventProfiles.NativeEventProfileStore(SessionPathService.GetNativeEventProfilesPath());
        PowerShellAuditingService = new PowerShellAuditingService(ConfigProfileService);
        SysmonService = new SysmonService(ConfigProfileService);
    }
}

/// <summary>Creates fresh selected-row presenters and lazy feature registrations for one view.</summary>
internal sealed class ProcessPresentationFactory
{
    private static void RegisterModules(ProcessPresentationViewModel p, ProcessPresentationServices services)
    {
        var registry = p._featureModules;
        void Backfill((string ProcessKey, int ProcessId, string ProcessName) target) =>
            services.SetStatus("Agent backfill is unavailable. Refresh the recorded evidence to inspect " + target.ProcessName + ".");
        void Changed(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            p.RefreshDataTabCounts();
            services.SelectedDataStateChanged?.Invoke(sender, e);
            services.PresentationStateChanged(p);
        }
        void MemoryImagesChanged(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
        {
            if (sender is System.Collections.ICollection images && p._explorerTabSet.TryGet(ExplorerTabKeys.Memory, out var descriptor))
                descriptor?.UpdateCount(images.Count);
            p.RefreshDataTabCounts();
        }
        registry.ActivationFailed += (_, e) => services.SetStatus($"Optional feature '{e.FeatureId}' could not activate: {e.Exception.Message}");
        registry.DeactivationFailed += (_, e) => services.SetStatus($"Optional feature '{e.FeatureId}' cleanup reported an error: {e.Exception.Message}");
        registry.Register(FeatureIds.ModulesAndHandles, () => new ModulesAndHandlesFeatureModule(
            services.Projection, p.InspectorPaneViewModel,
            (_, _) => { p.UpdateSelectedProcessArtifactCounts(); p.RefreshDataTabCounts(); },
            (_, _) => p.RefreshSelectedProcessRow()));
        registry.Register(FeatureIds.EventTelemetry, () => new EventTelemetryFeatureModule(
            services.Projection, p.InspectorPaneViewModel, Backfill, Backfill, Backfill,
            services.SharedModules.GetOrActivate<EventTelemetryPresentationServices>(FeatureIds.EventTelemetry)));
        registry.Register(FeatureIds.RuntimeEvents, () => new RuntimeEventsFeatureModule(services.Projection, p.InspectorPaneViewModel));
        registry.Register(FeatureIds.EtwEvents, () => new EtwEventsFeatureModule(services.Projection, p.InspectorPaneViewModel));
        registry.Register(FeatureIds.WindowsSecurityEvents, () => new WindowsSecurityEventsFeatureModule(
            services.Projection, p.InspectorPaneViewModel, Backfill,
            services.SharedModules.GetOrActivate<WindowsSecurityPresentationServices>(FeatureIds.WindowsSecurityEvents)));
        registry.Register(FeatureIds.PowerShellEvents, () => new PowerShellEventsFeatureModule(services.Projection, p.InspectorPaneViewModel, Backfill));
        registry.Register(FeatureIds.WindowsOtherEvents, () => new WindowsOtherEventsFeatureModule(services.Projection, p.InspectorPaneViewModel, Backfill));
        registry.Register(FeatureIds.SysmonEvents, () => new SysmonEventsFeatureModule(services.Projection, p.InspectorPaneViewModel, Backfill));
        registry.Register(FeatureIds.DumpsAndPeAnalysis, () => new DumpsAndPeFeatureModule(services.Projection, p.InspectorPaneViewModel, Changed));
        registry.Register(FeatureIds.NetworkAndZeek, () => new NetworkAndZeekFeatureModule(
            services.Projection, p.InspectorPaneViewModel, services.IsActiveNetworkCapture, services.IsFinalizingNetworkCapture,
            Changed, (sender, _) =>
            {
                if (sender is NetworkCapturesViewModel network && p._explorerTabSet.TryGet(ExplorerTabKeys.Network, out var descriptor))
                    descriptor?.UpdateCount(network.NetworkCaptures.Count);
                p.RefreshDataTabCounts();
                services.NetworkRefreshed?.Invoke();
            }));
        registry.Register(FeatureIds.SystemMemoryAndVolatility, () =>
        {
            var viewModel = new MemoryInvestigationViewModel(services.Projection, p.InspectorPaneViewModel);
            viewModel.PropertyChanged += Changed;
            viewModel.MemoryImages.CollectionChanged += MemoryImagesChanged;
            return viewModel;
        }, viewModel =>
        {
            viewModel.PropertyChanged -= Changed;
            viewModel.MemoryImages.CollectionChanged -= MemoryImagesChanged;
            viewModel.Clear();
        });
        registry.Register(FeatureIds.FilesystemArtifacts,
            () => new FilesystemArtifactsViewModel(services.Projection, p.InspectorPaneViewModel), viewModel => viewModel.Clear());
        registry.Register(FeatureIds.AiAssistance, () => new AiFeatureModule(services.SessionPaths(), services.Projection,
            services.AnnotationStore(), services.ApplicationCatalog, p.InspectorPaneViewModel, services.Access,
            services.SharedModules.GetOrActivate<AiInvestigationService>(FeatureIds.AiAssistance)));
    }

    internal ProcessPresentationViewModel Create(ProcessPresentationServices services)
    {
        var presentation = new ProcessPresentationViewModel(services)
        {
            ProcessPropertiesViewModel = new ProcessPropertiesViewModel(),
            InspectorPaneViewModel = new InspectorPaneViewModel(),
            ProcessRiskDetailsViewModel = services.Access.IsPublished(FeatureIds.ProcessRiskScore) ? new ProcessRiskDetailsViewModel() : null
        };
        try
        {
        RegisterModules(presentation, services);
        NsrlLookupViewModel? nsrlLookupViewModel = null;
        if (services.Access.IsPublished(FeatureIds.KnownFileReferenceData))
        {
            var knownFileLookupSettings = new KnownFileLookupSettingsService();
            nsrlLookupViewModel = new NsrlLookupViewModel(
                knownFileLookupSettings,
                new HashLookupRestProviderFactory(),
                () =>
                {
                    var lifecycleControl = new Services.KnownFiles.NsrlControlPipeClient();
                    return new NsrlReferenceDataViewModel(
                        new Services.KnownFiles.KnownFileServerLifecycleService(lifecycleControl),
                        new Services.KnownFiles.NsrlControlPipeClient(),
                        message => MessageBox.Show(
                            message,
                            "Managed NSRL Reference Data",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Warning) == MessageBoxResult.Yes);
                });
        }
        presentation.ProcessDescriptionViewModel = new ProcessDescriptionViewModel(
            services.AnnotationStore(),
            () => presentation.AiFeature?.Service,
            services.Access,
            services.ApplicationCatalog,
            new ApplicationComparisonEvidenceService(services.Projection),
            nsrlLookupViewModel,
            aiEvidencePackBuilderFactory: () => presentation.AiFeature?.EvidencePackBuilder,
            confirmReplace: message => MessageBox.Show(
                message,
                "Replace App Info Override",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) == MessageBoxResult.Yes);
        presentation.ProcessDescriptionViewModel.SetWorkspace(
            services.SessionPaths(),
            services.CaptureGeneration());
        presentation.NotesViewModel = new ProcessNotesViewModel(services.AnnotationStore());
        presentation.NotesViewModel.NoteSaved += (_, _) => { _ = services.RefreshExplorerCounts(ExplorerCountRefreshTrigger.AnnotationMutation); };
        presentation.ProcessStatisticsViewModel = new ProcessStatisticsViewModel(services.Projection, presentation.InspectorPaneViewModel);
        presentation.ExplorerViewModel = new ExplorerViewModel(presentation.OnExplorerScopeSelected, services.LoadExplorerChildren, services.Access);
        var context = new ViewerPresentationRegistrationContext(presentation, services.Access, services.ApplicationCatalog, services.SessionPaths);
        services.ConfigureContributions(context);
        presentation.RegistrationContext = context;
        var localDefinitions = new ViewerFeatureRegistry(services.Access.Catalog, context.Definitions, context.RequiredFeatureIds);
        localDefinitions.RegisterActivations(presentation._featureModules);
        presentation._explorerTabSet = CreateExplorerTabSet(presentation, services);
        presentation._dataTabSet = CreateDataTabSet(presentation, services, localDefinitions);
        presentation.AppInfoExtensionTabs = localDefinitions.CreateTabDescriptors(FeatureTabSurface.AppInfo, presentation._featureModules).Where(tab => services.Access.IsPublished(tab.FeatureId)).ToArray();
        presentation._selectedProcessFanOutCoordinator = new SelectedProcessFanOutCoordinator(services.CaptureGeneration(), presentation);
        presentation._viewerNavigationCoordinator = new ViewerNavigationCoordinator(presentation._explorerTabSet, presentation._dataTabSet, services.Publication.ReleaseId, presentation);
        presentation._viewerNavigationCoordinator.StateChanged += presentation.OnViewerNavigationStateChanged;
        presentation.ApplyViewerNavigationState(presentation._viewerNavigationCoordinator.State);
        presentation._selectedProcessFanOutCoordinator.StateChanged += presentation.OnSelectedProcessFanOutStateChanged;
        presentation._featureModules.Activated += presentation.OnFeatureModuleActivated;

        presentation.ProcessesView = System.Windows.Data.CollectionViewSource.GetDefaultView(presentation.Processes);
        presentation.ProcessesView.Filter = presentation.FilterProcess;
        return presentation;
        }
        catch { presentation.Dispose(); throw; }
    }


    private static FeatureTabSet CreateExplorerTabSet(ProcessPresentationViewModel presentation, ProcessPresentationServices services)
    {
        List<FeatureTabDescriptor> descriptors =
        [
            new(
                ExplorerTabKeys.Explore,
                "Explore",
                FeatureIds.ProcessListing,
                0,
                () => presentation.ExplorerViewModel),
            new(
                ExplorerTabKeys.Agents,
                "Agents",
                FeatureIds.AgentsAndCapture,
                100,
                () => services.SharedModules.GetOrActivate<AgentFeatureModule>(FeatureIds.AgentsAndCapture)?.AgentsViewModel),
            new(
                ExplorerTabKeys.Sigma,
                "Sigma",
                FeatureIds.SearchAndSigma,
                300,
                () => presentation.SigmaViewModel,
                showCount: true),
            new(
                ExplorerTabKeys.Ai,
                "AI",
                FeatureIds.AiAssistance,
                400,
                () => presentation.AiFeature == null ? null : presentation),
            new(
                ExplorerTabKeys.Network,
                "Network",
                FeatureIds.NetworkAndZeek,
                500,
                () => presentation.NetworkCapturesViewModel,
                showCount: true),
            new(
                ExplorerTabKeys.Memory,
                "Memory",
                FeatureIds.SystemMemoryAndVolatility,
                600,
                () => presentation.MemoryInvestigationViewModel,
                showCount: true)
        ];
        descriptors.AddRange(services.SharedDefinitions.CreateTabDescriptors(
            FeatureTabSurface.Explorer,
            services.SharedModules));

        return new FeatureTabSet(
            services.Access.Catalog,
            FeatureTabSurface.Explorer,
            descriptors,
            ExplorerTabKeys.Explore);
    }


    private static FeatureTabSet CreateDataTabSet(ProcessPresentationViewModel presentation, ProcessPresentationServices services, ViewerFeatureRegistry definitions)
    {
        List<FeatureTabDescriptor> descriptors =
        [
            new(DataTabKeys.AppInfo, "App Info", FeatureIds.SelectedProcessDetails, 0, () => new ProcInsider.Views.Features.SelectedProcess.DataProcessAppInfoView { DataContext = presentation }),
            new(DataTabKeys.Notes, "📝 Notes", FeatureIds.SelectedProcessDetails, 100, () => new ProcInsider.Views.Features.SelectedProcess.DataProcessNotesView { DataContext = presentation.NotesViewModel }),
            new(DataTabKeys.Modules, "Loaded Modules", FeatureIds.ModulesAndHandles, 400, () => new ProcInsider.Views.Features.Artifacts.DataModulesView { DataContext = presentation.ModulesViewModel }, showCount: true),
            new(DataTabKeys.Handles, "Handles", FeatureIds.ModulesAndHandles, 500, () => new ProcInsider.Views.Features.Artifacts.DataHandlesView { DataContext = presentation.HandlesViewModel }, showCount: true),
            new(DataTabKeys.MemoryDumps, "Dumps", FeatureIds.DumpsAndPeAnalysis, 600, () => new ProcInsider.Views.Features.Artifacts.DataMemoryDumpsView { DataContext = presentation.MemoryDumpsViewModel }, showCount: true),
            new(DataTabKeys.PeAnalysis, "PE Analysis", FeatureIds.DumpsAndPeAnalysis, 700, () => new ProcInsider.Views.Features.Artifacts.DataPeAnalysisView { DataContext = presentation.PeAnalysisViewModel }, showCount: true),
            new(DataTabKeys.SystemMemory, "System Memory", FeatureIds.SystemMemoryAndVolatility, 800, () => new ProcInsider.Views.Features.Memory.DataSystemMemoryView { DataContext = presentation.MemoryInvestigationViewModel }, showCount: true),
            new(DataTabKeys.Network, "Network Captures", FeatureIds.NetworkAndZeek, 900, () => new ProcInsider.Views.Features.Network.DataNetworkCapturesView { DataContext = presentation.NetworkCapturesViewModel }, showCount: true),
            new(DataTabKeys.Filesystem, "Filesystem Artifacts", FeatureIds.FilesystemArtifacts, 1000, () => new ProcInsider.Views.Features.Filesystem.DataFilesystemArtifactsView { DataContext = presentation.FilesystemArtifactsViewModel }, showCount: true),
            new(DataTabKeys.SystemActivity, "System Activity", FeatureIds.EventTelemetry, 1100, () => new ProcInsider.Views.Features.Events.DataSystemActivityView { DataContext = presentation.SystemActivityViewModel }, showCount: true),
            new(DataTabKeys.RuntimeEvents, "Runtime Events", FeatureIds.EventTelemetry, 1200, () => new ProcInsider.Views.Features.Events.DataRuntimeEventsView { DataContext = presentation.EventsViewModel }, showCount: true),
            new(DataTabKeys.EtwEvents, "ETW Providers", FeatureIds.EventTelemetry, 1300, () => new ProcInsider.Views.Features.Events.DataEtwEventListView { DataContext = presentation.EtwProviderEventsViewModel }, showCount: true),
            new(DataTabKeys.SecurityEvents, "Windows Audit Log", FeatureIds.WindowsSecurityEvents, 1400, () => new ProcInsider.Views.Features.Events.DataWindowsSecurityEventsView { DataContext = presentation.WindowsAuditLogViewModel }, showCount: true),
            new(DataTabKeys.PowerShellEvents, "PowerShell Logs", FeatureIds.EventTelemetry, 1500, () => new ProcInsider.Views.Features.Events.DataEventListView { DataContext = presentation.PowerShellLogViewModel }, showCount: true),
            new(DataTabKeys.WindowsOtherEvents, "Windows Logs (Other)", FeatureIds.EventTelemetry, 1600, () => new ProcInsider.Views.Features.Events.DataEventListView { DataContext = presentation.WindowsOtherLogViewModel }, showCount: true),
            new(DataTabKeys.SysmonEvents, "Sysmon", FeatureIds.EventTelemetry, 1700, () => new ProcInsider.Views.Features.Events.DataEventListView { DataContext = presentation.SysmonEventsViewModel }, showCount: true),
            new(DataTabKeys.Ai, "AI", FeatureIds.AiAssistance, 1800, () => new ProcInsider.Views.Features.Ai.DataAiInvestigationView { DataContext = presentation.AiInvestigationViewModel })
        ];
        descriptors.AddRange(services.SharedDefinitions.CreateTabDescriptors(
            FeatureTabSurface.Data,
            services.SharedModules));
        descriptors.AddRange(definitions.CreateTabDescriptors(
            FeatureTabSurface.Data,
            presentation._featureModules));

        return new FeatureTabSet(
            services.Access.Catalog,
            FeatureTabSurface.Data,
            descriptors,
            DataTabKeys.AppInfo,
            allowEmpty: true);
    }

}

/// <summary>Explicit session-owned actions/settings inherited by reusable presentation controls.</summary>
public sealed class ViewerSharedActions : System.ComponentModel.INotifyPropertyChanged
{
    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    internal void SourcePropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs args) =>
        PropertyChanged?.Invoke(this, args);
    public System.Windows.Input.ICommand? AddAgentCommand { get; internal init; }
    public System.Windows.Input.ICommand? AnalyzeSelectedDumpPeCommand { get; internal init; }
    public System.Windows.Input.ICommand? AnalyzeSelectedProcessImageCommand { get; internal init; }
    public System.Windows.Input.ICommand? CancelStopAgentCommand { get; internal init; }
    public System.Windows.Input.ICommand? CheckAgentMonitoringConfigurationCommand { get; internal init; }
    public System.Windows.Input.ICommand? ConfirmStopAgentCommand { get; internal init; }
    public System.Windows.Input.ICommand? CopySelectedZeekWiresharkFilterCommand { get; internal init; }
    public System.Windows.Input.ICommand? DeployAgentCommand { get; internal init; }
    public System.Windows.Input.ICommand? DumpSystemMemoryCommand { get; internal init; }
    public System.Windows.Input.ICommand? ExportSelectedZeekFlowPcapCommand { get; internal init; }
    public System.Windows.Input.ICommand? OpenSelectedZeekPcapCommand { get; internal init; }
    public System.Windows.Input.ICommand? OpenSelectedZeekProcessCommand { get; internal init; }
    public System.Windows.Input.ICommand? PauseAgentConfiguredCaptureCommand { get; internal init; }
    public System.Windows.Input.ICommand? QueueArtifactFileImportCommand { get; internal init; }
    public System.Windows.Input.ICommand? QueueArtifactFolderImportCommand { get; internal init; }
    public System.Windows.Input.ICommand? QueueMemoryImageImportCommand { get; internal init; }
    public System.Windows.Input.ICommand? QueueProcessMonitorImportCommand { get; internal init; }
    public System.Windows.Input.ICommand? QueueSelectedMemoryImageVolatilityAnalysisCommand { get; internal init; }
    public System.Windows.Input.ICommand? QueueSelectedProcessDumpCommand { get; internal init; }
    public System.Windows.Input.ICommand? QueueSelectedZeekAnalysisCommand { get; internal init; }
    public System.Windows.Input.ICommand? RePairAgentCommand { get; internal init; }
    public System.Windows.Input.ICommand? ReconnectRunningLocalAgentCommand { get; internal init; }
    public System.Windows.Input.ICommand? RefreshSelectedHandlesCommand { get; internal init; }
    public System.Windows.Input.ICommand? RefreshSelectedModulesCommand { get; internal init; }
    public System.Windows.Input.ICommand? RefreshViewFromStagingCommand { get; internal init; }
    public System.Windows.Input.ICommand? RevokeAgentPairingCommand { get; internal init; }
    public System.Windows.Input.ICommand? SelectProcessMonitorExecutableCommand { get; internal init; }
    public System.Windows.Input.ICommand? ShowAgentHealthCommand { get; internal init; }
    public System.Windows.Input.ICommand? StartAgentCaptureOptionCommand { get; internal init; }
    public System.Windows.Input.ICommand? StartAgentConfiguredCaptureCommand { get; internal init; }
    public System.Windows.Input.ICommand? StartNetworkCaptureCommand { get; internal init; }
    public System.Windows.Input.ICommand? StopAgentCaptureOptionCommand { get; internal init; }
    public System.Windows.Input.ICommand? StopAgentCommand { get; internal init; }
    public System.Windows.Input.ICommand? StopAgentConfiguredCaptureCommand { get; internal init; }
    public System.Windows.Input.ICommand? StopNetworkCaptureCommand { get; internal init; }
    internal Func<FeaturePublicationViewModel> GetFeaturePublication { private get; init; } = () => new FeaturePublicationViewModel(new FeatureAccessService(CurrentEducationalReleaseProfile.Catalog));
    public FeaturePublicationViewModel FeaturePublication { get => GetFeaturePublication(); }
    internal Func<System.Collections.ObjectModel.ObservableCollection<ConfigProfileDefinition>> GetEtwCaptureProfiles { private get; init; } = () => new();
    public System.Collections.ObjectModel.ObservableCollection<ConfigProfileDefinition> EtwCaptureProfiles { get => GetEtwCaptureProfiles(); }
    internal Func<ConfigProfileDefinition?> GetSelectedEtwCaptureProfile { private get; init; } = () => null;
    internal Action<ConfigProfileDefinition?> SetSelectedEtwCaptureProfile { private get; init; } = _ => { };
    public ConfigProfileDefinition? SelectedEtwCaptureProfile { get => GetSelectedEtwCaptureProfile(); set => SetSelectedEtwCaptureProfile(value); }
    internal Func<bool> GetHasEtwCaptureProfiles { private get; init; } = () => false;
    public bool HasEtwCaptureProfiles { get => GetHasEtwCaptureProfiles(); }
    internal Func<bool> GetIsAgentViewerConnected { private get; init; } = () => false;
    public bool IsAgentViewerConnected { get => GetIsAgentViewerConnected(); }
    internal Func<string> GetProcessMonitorExecutablePath { private get; init; } = () => string.Empty;
    public string ProcessMonitorExecutablePath { get => GetProcessMonitorExecutablePath(); }
    internal Func<string> GetNetworkCaptureStateDisplay { private get; init; } = () => string.Empty;
    public string NetworkCaptureStateDisplay { get => GetNetworkCaptureStateDisplay(); }
    internal Func<string> GetZeekWslDistributionName { private get; init; } = () => string.Empty;
    internal Action<string> SetZeekWslDistributionName { private get; init; } = _ => { };
    public string ZeekWslDistributionName { get => GetZeekWslDistributionName(); set => SetZeekWslDistributionName(value); }
    internal Func<string> GetZeekWslCommand { private get; init; } = () => string.Empty;
    internal Action<string> SetZeekWslCommand { private get; init; } = _ => { };
    public string ZeekWslCommand { get => GetZeekWslCommand(); set => SetZeekWslCommand(value); }
}
