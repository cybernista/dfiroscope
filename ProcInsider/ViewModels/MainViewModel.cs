using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using ProcInsider.Features.BaselineComparison;
using ProcInsider.Features.Infrastructure;
using ProcInsider.Features.Search;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Ai;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

/// <summary>
/// Main view model for the application.
/// Coordinates process tracking, filtering, sorting, and child view models.
/// </summary>
public partial class MainViewModel : ViewModelBase,
    IViewerNavigationRuntime,
    ISelectedProcessFanOutConsumerProvider
{
    public event Action<ProcessRowViewModel>? ProcessRowNavigationRequested;
    public event Func<ViewerProcessViewportAnchor?>? ProcessViewportAnchorCaptureRequested;
    public event Action<ProcessRowViewModel, double>? ProcessViewportAnchorRestoreRequested;

    private const string ProcessBookmarkKind = "Process";
    private const string NoProcessScopedSelectionKey = "__procinsider_no_process_scope__";
    private const string UnknownProcessOwnerKey = "unknown";
    private const string UnknownProcessOwnerDisplayName = "Unknown / unresolved owner";
    private const string UnknownAgentCommandOutcomeDiagnostic =
        "The request reached the agent command transport, but no authenticated authoritative command outcome could be confirmed. Refresh agent status before retrying.";
    private static readonly TimeSpan AgentLateExitContinuationTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan AgentStartupHealthPollInterval = TimeSpan.FromMilliseconds(500);
    private const int AgentStartupHealthAttempts = 8;
    private static readonly TimeSpan SnapshotAgeRefreshInterval = TimeSpan.FromSeconds(30);

    private enum CaptureRunState
    {
        Off,
        Starting,
        Running,
        Stopping,
        Failed
    }

    private sealed class MutableOwnerSummary
    {
        public string OwnerKey { get; init; } = string.Empty;
        public string DisplayName { get; init; } = string.Empty;
        public string Domain { get; init; } = string.Empty;
        public string Sid { get; init; } = string.Empty;
        public int ProcessCount { get; set; }
        public string CaseId { get; init; } = string.Empty;
        public string EvidenceSessionId { get; init; } = string.Empty;
        public string CaptureId { get; init; } = string.Empty;
        public string SourceIdentityId { get; init; } = string.Empty;
        public string HostId { get; init; } = string.Empty;
        public string ExecutionRootId { get; init; } = string.Empty;

        public ExplorerProcessOwnerSummary ToRecord()
        {
            return new ExplorerProcessOwnerSummary
            {
                OwnerKey = OwnerKey,
                DisplayName = DisplayName,
                Domain = Domain,
                Sid = Sid,
                ProcessCount = ProcessCount,
                CaseId = CaseId,
                EvidenceSessionId = EvidenceSessionId,
                CaptureId = CaptureId,
                SourceIdentityId = SourceIdentityId,
                HostId = HostId,
                ExecutionRootId = ExecutionRootId
            };
        }
    }

    // Services
    private readonly FeatureAccessService _featureAccess;
    private readonly FeatureActivationRegistry _featureModules;
    private readonly ViewerFeatureRegistry _viewerFeatures;
    private readonly FeatureTabSet _explorerTabSet;
    private readonly FeatureTabSet _dataTabSet;
    private readonly ViewerNavigationCoordinator _viewerNavigationCoordinator;
    private readonly InfrastructureCaseWorkspaceFeatureDependencies? _infrastructureCaseWorkspaceDependencies;
    private InfrastructureCaseWorkspaceViewModel? _infrastructureWorkspace;
    private readonly SelectedProcessFanOutCoordinator _selectedProcessFanOutCoordinator;
    private readonly ExplorerCountRefreshCoordinator _explorerCountRefreshCoordinator = new();
    private bool _isApplyingViewerNavigationState;
    private readonly ProcessFilterService _filterService;
    private readonly IViewerExternalProcessService _externalProcessService;
    private AnnotationDatabaseService? _annotationStore;
    private readonly ApplicationCatalogService? _applicationCatalog;
    private readonly LocalAgentProcessLifecycleService _localAgentProcessLifecycle;
    private readonly ViewerAgentCommandExecutor _viewerAgentCommandExecutor;
    private readonly Func<IReadOnlyList<AgentPairingDiscoveryRecord>> _discoverLocalAgentPairings;
    private LocalAgentRecoveryCoordinator? _localAgentRecoveryCoordinator;
    private LocalAgentControlCoordinator? _localAgentControlCoordinator;
    private readonly AgentCaptureWorkflowCoordinator _agentCaptureWorkflowCoordinator;
    private readonly ViewerAgentCaptureActionService _agentCaptureActionService;
    private readonly Lazy<ViewerHostMonitoringActionService> _hostMonitoringActionService;
    private readonly ViewerAgentEvidenceActionService _agentEvidenceActionService;
    private readonly ViewerAgentToolActionService _agentToolActionService;
    private readonly Lazy<ViewerMemoryActionService> _agentMemoryActionService;
    private readonly ArtifactEnrichmentWorkflowCoordinator _artifactEnrichmentWorkflowCoordinator;
    private readonly ViewerWorkspaceLifecycleCoordinator _captureWorkspaceCoordinator;
    private readonly LiveSnapshotRefreshCoordinator _liveSnapshotRefreshCoordinator = new();
    private readonly ViewerSnapshotFollowCoordinator _snapshotFollowCoordinator;
    private InvestigationSessionPaths _sessionPaths;
    private CapturePackageInfo? _activeCapturePackageInfo;
    private SqliteStagingQueryService? _sqliteStagingQueryService;
    private ProcessListingService? _processListingService;
    private VirtualizedProcessCollection? _virtualizedProcessListing;
    private CancellationTokenSource? _processListingRefreshCts;
    private CancellationTokenSource? _agentLateExitObservationCts;
    private Task? _agentLateExitObservationTask;
    private long _agentLateExitObservationGeneration;
    private bool _isLocalAgentSetupInProgress;
    private long _processListingQueryGeneration;
    private long _snapshotPresentationInteractionGeneration;
    private bool _isPublishingSnapshotPresentation;
    private readonly TelemetryProjectionService _telemetryProjectionService;
    private bool _isLoadingSysmonSettings;
    private AgentShutdownTarget? _lastVerifiedAgentShutdownTarget;
    private readonly AgentTerminationIntentState _agentTerminationIntentState = new();
    private Guid? _activeImportJobId;
    private Guid? _activeProcessDumpJobId;
    private Guid? _activeZeekAnalysisJobId;
    private Guid? _activeArtifactImportJobId;
    private Guid? _activeProcessMonitorImportJobId;
    private Guid? _activeMemoryAcquisitionJobId;
    private Guid? _activeMemoryImageImportJobId;
    private Guid? _activeVolatilityAnalysisJobId;
    private Guid? _activeSqliteBenchmarkJobId;
    private readonly DispatcherTimer _snapshotAgeTimer;
    private int _activeDbRefreshCount;
    private int _activeExplorerRefreshCount;
    private bool _hasActiveQueryDatabase;
    private long _explorerCountInputGeneration;

    // Debounce timer for DB-backed process grid refreshes (e.g. on every keystroke).
    private DispatcherTimer? _dbRefreshDebounceTimer;
    private ExplorerScope _activeExplorerScope = new()
    {
        Kind = ExplorerScopeKind.AllProcesses,
        Title = "All Processes",
        Description = "All staged and live process records."
    };
    private readonly Dictionary<string, ExplorerScope> _includedScopes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ExplorerScope> _excludedScopes = new(StringComparer.Ordinal);
    private readonly HashSet<string> _includedProcessKeys = new(StringComparer.Ordinal);
    private readonly HashSet<string> _excludedProcessKeys = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _includedProcessLabels = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _excludedProcessLabels = new(StringComparer.Ordinal);

    private ModulesAndHandlesFeatureModule? ModulesAndHandlesFeature =>
        _featureModules.GetOrActivate<ModulesAndHandlesFeatureModule>(FeatureIds.ModulesAndHandles);
    private EventTelemetryFeatureModule? EventTelemetryFeature =>
        _featureModules.GetOrActivate<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry);
    private AgentFeatureModule? AgentFeature =>
        _featureModules.GetOrActivate<AgentFeatureModule>(FeatureIds.AgentsAndCapture);
    private DumpsAndPeFeatureModule? DumpsAndPeFeature =>
        _featureModules.GetOrActivate<DumpsAndPeFeatureModule>(FeatureIds.DumpsAndPeAnalysis);
    private NetworkAndZeekFeatureModule? NetworkAndZeekFeature =>
        _featureModules.GetOrActivate<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek);
    private AiFeatureModule? AiFeature =>
        _featureModules.GetOrActivate<AiFeatureModule>(FeatureIds.AiAssistance);
    private BaselineComparisonFeatureModule? BaselineComparisonFeature =>
        _featureModules.GetOrActivate<BaselineComparisonFeatureModule>(FeatureIds.BaselineComparison);
    private SearchFeatureModule? SearchFeature =>
        _featureModules.GetOrActivate<SearchFeatureModule>(FeatureIds.SearchAndSigma);
    private SecurityMonitoringFeatureModule? SecurityMonitoringFeature =>
        _featureModules.GetOrActivate<SecurityMonitoringFeatureModule>(FeatureIds.SecurityMonitoringConfiguration);

    private ConfigProfileService _configProfileService =>
        SecurityMonitoringFeature?.ConfigProfileService ?? EventTelemetryFeature?.ConfigProfileService!;
    private PowerShellAuditingService _powerShellAuditingService =>
        SecurityMonitoringFeature?.PowerShellAuditingService ?? EventTelemetryFeature?.PowerShellAuditingService!;
    private SysmonService _sysmonService =>
        SecurityMonitoringFeature?.SysmonService ?? EventTelemetryFeature?.SysmonService!;
    private SecurityMonitoringService _securityMonitoringService =>
        SecurityMonitoringFeature?.SecurityMonitoringService!;
    private AiInvestigationService _aiInvestigationService => AiFeature?.Service!;
    private SigmaRuleParser _sigmaRuleParser =>
        _featureModules.GetOrActivate<SigmaRuleParser>(FeatureIds.SearchAndSigma)!;
    private AgentNamedPipeClient _agentClient => AgentFeature?.AgentClient!;
    private AgentNamedPipeClient _agentStatusClient => AgentFeature?.AgentStatusClient!;
    private AgentNamedPipeClient _agentRecoveryClient => AgentFeature?.AgentRecoveryClient!;
    private AgentNamedPipeClient _agentShutdownControlClient => AgentFeature?.AgentShutdownControlClient!;
    private DispatcherTimer _agentStatusTimer => AgentFeature?.StatusTimer!;

    // Process data
    private readonly Dictionary<string, ProcessRowViewModel> _processViewModels = new();

    [ObservableProperty]
    private ObservableCollection<ProcessRowViewModel> processes = new();

    [ObservableProperty]
    private ICollectionView? processesView;

    [ObservableProperty]
    private string processListingStatus = "Process listing is not loaded.";

    [ObservableProperty]
    private bool isProcessListingLoading;

    [ObservableProperty]
    private ProcessRowViewModel? selectedProcess;

    // Filter text for each column
    [ObservableProperty]
    private string filterProcessName = string.Empty;

    [ObservableProperty]
    private string filterPid = string.Empty;

    [ObservableProperty]
    private string filterParentPid = string.Empty;

    [ObservableProperty]
    private string filterParentProcessName = string.Empty;

    [ObservableProperty]
    private string filterProcessPath = string.Empty;

    [ObservableProperty]
    private string filterCommandLine = string.Empty;

    [ObservableProperty]
    private string filterUserName = string.Empty;

    [ObservableProperty]
    private string filterSessionId = string.Empty;

    [ObservableProperty]
    private string filterArchitecture = string.Empty;

    [ObservableProperty]
    private string filterStartTime = string.Empty;

    [ObservableProperty]
    private string filterEndTime = string.Empty;

    [ObservableProperty]
    private string filterStatus = string.Empty;

    [ObservableProperty]
    private string filterCpuUsage = string.Empty;

    [ObservableProperty]
    private string filterMemoryUsage = string.Empty;

    [ObservableProperty]
    private string filterCompanyName = string.Empty;

    [ObservableProperty]
    private string filterFileDescription = string.Empty;

    [ObservableProperty]
    private string filterSha256Hash = string.Empty;

    // Sorting state
    private string _currentSortColumn = "Tree";
    private bool _sortAscending = true;

    // Status
    [ObservableProperty]
    private string statusMessage = "Initializing...";

    [ObservableProperty]
    private string activeSessionFolder = string.Empty;

    [ObservableProperty]
    private string activeSessionDetail = string.Empty;

    [ObservableProperty]
    private string liveDatabasePath = string.Empty;

    [ObservableProperty]
    private string snapshotDatabasePath = string.Empty;

    [ObservableProperty]
    private string snapshotTimestampDisplay = "Snapshot: not loaded";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsManualSnapshotMode))]
    [NotifyPropertyChangedFor(nameof(IsFollowCaptureMode))]
    private ViewerSnapshotFollowMode snapshotFollowMode = ViewerSnapshotFollowMode.Manual;

    public bool IsManualSnapshotMode => SnapshotFollowMode == ViewerSnapshotFollowMode.Manual;

    public bool IsFollowCaptureMode => SnapshotFollowMode == ViewerSnapshotFollowMode.Follow;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsFollowIntervalOneMinute))]
    [NotifyPropertyChangedFor(nameof(IsFollowIntervalTwoMinutes))]
    [NotifyPropertyChangedFor(nameof(IsFollowIntervalFiveMinutes))]
    [NotifyPropertyChangedFor(nameof(IsFollowIntervalTenMinutes))]
    private int snapshotFollowIntervalMinutes = 1;

    public bool IsFollowIntervalOneMinute => SnapshotFollowIntervalMinutes == 1;
    public bool IsFollowIntervalTwoMinutes => SnapshotFollowIntervalMinutes == 2;
    public bool IsFollowIntervalFiveMinutes => SnapshotFollowIntervalMinutes == 5;
    public bool IsFollowIntervalTenMinutes => SnapshotFollowIntervalMinutes == 10;

    [ObservableProperty]
    private bool canEnableFollowCapture;

    [ObservableProperty]
    private bool isSnapshotFollowIntervalEnabled;

    [ObservableProperty]
    private string snapshotFollowStatusText = "Manual / Pinned — current snapshot not yet loaded";

    [ObservableProperty]
    private string snapshotFollowStatusDetail = "Manual snapshot mode is pinned.";

    [ObservableProperty]
    private ViewerDetailsTabKey selectedDetailsTabKey = ViewerDetailsTabKey.Object;

    private string _snapshotPresentationContextNotice = string.Empty;

    private string AgentStatusMessage { get; set; } = "Agent: not connected";

    private string AgentJobStatusMessage { get; set; } = "Jobs: idle";

    [ObservableProperty]
    private bool isAgentConnected;

    [ObservableProperty]
    private bool isAgentViewerConnected;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConnectedAgentStatusMessage))]
    private int connectedAgentCount;

    [ObservableProperty]
    private bool isAgentShutdownInProgress;

    [ObservableProperty]
    private bool isLocalAgentProcessDetected;

    private bool _localAgentStartBlockedByDiscoveryConflict;

    [ObservableProperty]
    private bool isLocalAgentRecoveryInProgress;

    private Guid? _activeLiveCaptureJobId
    {
        get => _agentCaptureWorkflowCoordinator.GetTrackedJobId(JobKind.LiveCapture);
        set => _agentCaptureWorkflowCoordinator.TrackCaptureJob(JobKind.LiveCapture, value);
    }

    private Guid? _activeNetworkCaptureJobId
    {
        get => _agentCaptureWorkflowCoordinator.GetTrackedJobId(JobKind.NetworkCapture);
        set => _agentCaptureWorkflowCoordinator.TrackCaptureJob(JobKind.NetworkCapture, value);
    }

    private Guid? _activeProcessMonitorCaptureJobId
    {
        get => _agentCaptureWorkflowCoordinator.GetTrackedJobId(JobKind.ProcessMonitorCapture);
        set => _agentCaptureWorkflowCoordinator.TrackCaptureJob(JobKind.ProcessMonitorCapture, value);
    }

    private sealed record AgentShutdownTarget(
        int ProcessId,
        DateTime StartedAtUtc,
        string DatabasePath,
        string SessionId);

    internal bool IsAgentLateExitObservationActive =>
        _agentLateExitObservationTask is { IsCompleted: false };

    private enum LocalAgentRecoveryOrigin
    {
        Startup,
        Manual
    }

    [ObservableProperty]
    private bool isRefreshing;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StagingLoadProgressText))]
    private bool isStagingLoadInProgress;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StagingLoadProgressText))]
    private int stagingLoadProgressCurrent;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StagingLoadProgressText))]
    private int stagingLoadProgressTotal = 1;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StagingLoadProgressText))]
    private string stagingLoadProgressMessage = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StagingLoadProgressText))]
    private bool isStagingLoadProgressIndeterminate;

    [ObservableProperty]
    private bool isSnapshotAnalysisPreparationInProgress;

    [ObservableProperty]
    private string snapshotAnalysisPreparationText = string.Empty;

    [ObservableProperty]
    private int refreshIntervalSeconds = 10;

    [ObservableProperty]
    private int totalProcessCount;

    [ObservableProperty]
    private int runningProcessCount;

    [ObservableProperty]
    private int exitedProcessCount;

    [ObservableProperty]
    private DateTime lastRefreshTime;

    [ObservableProperty]
    private bool isScriptBlockLoggingEnabled;

    [ObservableProperty]
    private bool isModuleLoggingEnabled;

    [ObservableProperty]
    private bool isTranscriptionEnabled;

    [ObservableProperty]
    private string transcriptPath = @"C:\PS_transcripts";

    [ObservableProperty]
    private bool isEtwCollectionEnabled;

    [ObservableProperty]
    private bool isWindowsAuditLogCollectionEnabled = true;

    [ObservableProperty]
    private bool isPowerShellLogCollectionEnabled = true;

    [ObservableProperty]
    private bool isWindowsOtherLogCollectionEnabled = true;

    [ObservableProperty]
    private bool isModuleCollectionEnabled;

    [ObservableProperty]
    private bool isHandleCollectionEnabled;

    [ObservableProperty]
    private bool isSysmonIntegrationEnabled = true;

    [ObservableProperty]
    private bool isSysmonInstalled;

    [ObservableProperty]
    private bool isSysmonRunning;

    [ObservableProperty]
    private bool isSysmonChannelAvailable;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NetworkCaptureStateDisplay))]
    private bool isNetworkCaptureActive;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProcessMonitorCaptureStateDisplay))]
    private bool isProcessMonitorCaptureActive;

    [ObservableProperty]
    private string processMonitorExecutablePath = string.Empty;

    [ObservableProperty]
    private string zeekWslDistributionName = "Ubuntu";

    [ObservableProperty]
    private string zeekWslCommand = "zeek";

    [ObservableProperty]
    private string zeekExecutablePath = string.Empty;

    [ObservableProperty]
    private string sysmonConfigPath = string.Empty;

    public ObservableCollection<ConfigProfileDefinition> EtwCaptureProfiles { get; } = new();

    public string StagingLoadProgressText
    {
        get
        {
            var message = string.IsNullOrWhiteSpace(StagingLoadProgressMessage)
                ? "Preparing..."
                : StagingLoadProgressMessage;
            if (IsStagingLoadProgressIndeterminate || StagingLoadProgressTotal <= 0)
            {
                return message;
            }

            var progress = $"{StagingLoadProgressCurrent:N0} / {StagingLoadProgressTotal:N0}";
            return string.IsNullOrWhiteSpace(StagingLoadProgressMessage)
                ? progress
                : $"{message} ({progress})";
        }
    }

    [ObservableProperty]
    private bool hasEtwCaptureProfiles;

    [ObservableProperty]
    private ConfigProfileDefinition? selectedEtwCaptureProfile;

    [ObservableProperty]
    private string etwCaptureProfileStatus = "ETW profile: default bundled profile";

    public ObservableCollection<ConfigProfileDefinition> SysmonConfigProfiles { get; } = new();

    [ObservableProperty]
    private bool hasSysmonConfigProfiles;

    public ObservableCollection<ConfigProfileDefinition> SecurityMonitoringPolicyProfiles { get; } = new();

    [ObservableProperty]
    private bool hasSecurityMonitoringPolicyProfiles;

    public ObservableCollection<ConfigProfileDefinition> PowerShellAuditingProfiles { get; } = new();

    [ObservableProperty]
    private bool hasPowerShellAuditingProfiles;

    public ObservableCollection<ConfigProfileDefinition> EventLogPolicyProfiles { get; } = new();

    [ObservableProperty]
    private bool hasEventLogPolicyProfiles;

    // Child view models
    public ProcessPropertiesViewModel ProcessPropertiesViewModel { get; }
    public ProcessDescriptionViewModel ProcessDescriptionViewModel { get; }
    public ProcessNotesViewModel NotesViewModel { get; }
    public ModulesViewModel ModulesViewModel => ModulesAndHandlesFeature?.ModulesViewModel!;
    public HandlesViewModel HandlesViewModel => ModulesAndHandlesFeature?.HandlesViewModel!;
    public EventsViewModel EventsViewModel => EventTelemetryFeature?.RuntimeEventsViewModel!;
    public EventsViewModel EtwProviderEventsViewModel => EventTelemetryFeature?.EtwEventsViewModel!;
    public EventsViewModel WindowsAuditLogViewModel => EventTelemetryFeature?.SecurityEventsViewModel!;
    public EventsViewModel PowerShellLogViewModel => EventTelemetryFeature?.PowerShellEventsViewModel!;
    public EventsViewModel WindowsOtherLogViewModel => EventTelemetryFeature?.OtherWindowsEventsViewModel!;
    public EventsViewModel SysmonEventsViewModel => EventTelemetryFeature?.SysmonEventsViewModel!;
    public MemoryDumpsViewModel MemoryDumpsViewModel => DumpsAndPeFeature?.MemoryDumpsViewModel!;
    public PeAnalysisViewModel PeAnalysisViewModel => DumpsAndPeFeature?.PeAnalysisViewModel!;
    public ProcessStatisticsViewModel ProcessStatisticsViewModel { get; }
    public MemoryInvestigationViewModel MemoryInvestigationViewModel =>
        _featureModules.GetOrActivate<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility)!;
    public NetworkCapturesViewModel NetworkCapturesViewModel => NetworkAndZeekFeature?.ViewModel!;
    public FilesystemArtifactsViewModel FilesystemArtifactsViewModel =>
        _featureModules.GetOrActivate<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts)!;
    public SystemActivityViewModel SystemActivityViewModel => EventTelemetryFeature?.SystemActivityViewModel!;
    public SearchViewModel SearchViewModel => SearchFeature?.ViewModel!;
    public SigmaViewModel SigmaViewModel =>
        _featureModules.GetOrActivate<SigmaViewModel>(FeatureIds.SearchAndSigma)!;
    public AgentsViewModel AgentsViewModel => AgentFeature?.AgentsViewModel!;
    public ExplorerViewModel ExplorerViewModel { get; }
    public InspectorPaneViewModel InspectorPaneViewModel { get; }
    public ProcessRiskDetailsViewModel? ProcessRiskDetailsViewModel { get; }
    public AiInvestigationViewModel AiInvestigationViewModel => AiFeature?.InvestigationViewModel!;
    public AiDetailsInvestigationViewModel AiDetailsInvestigationViewModel => AiFeature?.DetailsViewModel!;
    public AiChatViewModel AiChatViewModel => AiFeature?.ChatViewModel!;
    public SnapshotComparisonViewModel SnapshotComparisonViewModel => BaselineComparisonFeature?.ViewModel!;
    public FeaturePublicationViewModel FeaturePublication { get; }

    public IReadOnlyList<FeatureTabDescriptor> ExplorerTabs => _viewerNavigationCoordinator.ExplorerTabs;
    public IReadOnlyList<FeatureTabDescriptor> DataTabs => _viewerNavigationCoordinator.DataTabs;
    public IReadOnlyList<FeatureTabDescriptor> AppInfoExtensionTabs { get; private set; } =
        Array.Empty<FeatureTabDescriptor>();

    public InfrastructureCaseWorkspaceViewModel? InfrastructureWorkspace => _infrastructureWorkspace;

    public bool IsInfrastructureWorkspaceActive => _infrastructureWorkspace?.IsWorkspaceReady == true;

    public bool IsStandaloneWorkspaceActive => !IsInfrastructureWorkspaceActive;

    [ObservableProperty]
    private FeatureTabDescriptor? selectedDataTab;

    [ObservableProperty]
    private FeatureTabDescriptor? selectedExplorerTab;

    [ObservableProperty]
    private ExplorerAiSection selectedExplorerAiSection = ExplorerAiSection.Chat;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DataTabs))]
    private bool isNetworkDataTabVisible;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DataTabs))]
    private bool isFilesystemDataTabVisible;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BookmarkSelectedProcessLabel))]
    private bool isSelectedProcessBookmarked;

    public string BookmarkSelectedProcessLabel => IsSelectedProcessBookmarked ? "Remove Bookmark" : "Bookmark";

    [ObservableProperty]
    private string scopedSelectionStatus = "Green scopes: none active; all evidence visible.";

    [ObservableProperty]
    private string scopedSelectionDetail = "No green scope or exclusion filters are active.";

    public bool IsLiveCaptureEnabled =>
        IsEtwCollectionEnabled ||
        IsWindowsAuditLogCollectionEnabled ||
        IsPowerShellLogCollectionEnabled ||
        IsWindowsOtherLogCollectionEnabled ||
        IsSysmonIntegrationEnabled;

    public bool IsArtifactEnrichmentEnabled => IsModuleCollectionEnabled || IsHandleCollectionEnabled;
    public string LiveCaptureStateDisplay =>
        _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.LiveCapture).StatusText;
    public string ArtifactEnrichmentStateDisplay => IsArtifactEnrichmentEnabled
        ? "Enrichment preference: On (agent-owned)"
        : "Enrichment preference: Off";
    public string NetworkCaptureStateDisplay =>
        _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.NetworkCapture).StatusText;
    public string ProcessMonitorCaptureStateDisplay =>
        _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.ProcessMonitorCapture).StatusText;
    public string ConnectedAgentStatusMessage => $"Connected agents: {ConnectedAgentCount:N0}";

    public CaptureWorkspaceMode CaptureWorkspaceMode => _captureWorkspaceCoordinator.Mode;

    public string CaptureWorkspaceModeDisplay => CaptureWorkspaceMode switch
    {
        CaptureWorkspaceMode.LiveCapture => "LIVE CAPTURE",
        CaptureWorkspaceMode.ArchivedCapture => "ARCHIVED CAPTURE (SEALED)",
        CaptureWorkspaceMode.Switching => "SWITCHING CAPTURE",
        _ => "NO CAPTURE"
    };

    public string ActiveCaptureIdentityDisplay
    {
        get
        {
            var current = _captureWorkspaceCoordinator.Current;
            return string.IsNullOrWhiteSpace(current.SessionId)
                ? CaptureWorkspaceModeDisplay
                : $"{CaptureWorkspaceModeDisplay}: {current.SessionId}";
        }
    }

    public MainViewModel(
        IFeatureCatalog? featureCatalog = null,
        IViewerExternalProcessService? externalProcessService = null,
        LocalAgentProcessLifecycleService? localAgentProcessLifecycle = null,
        Func<IReadOnlyList<AgentPairingDiscoveryRecord>>? discoverLocalAgentPairings = null,
        InfrastructureCaseWorkspaceFeatureDependencies? infrastructureCaseWorkspaceDependencies = null)
    {
        _featureAccess = new FeatureAccessService(
            featureCatalog ?? CurrentEducationalReleaseProfile.RuntimeCatalog);
        _featureModules = new FeatureActivationRegistry(_featureAccess);
        _featureModules.ActivationFailed += (_, e) =>
            StatusMessage = $"Optional feature '{e.FeatureId}' could not activate: {e.Exception.Message}";
        _featureModules.DeactivationFailed += (_, e) =>
            StatusMessage = $"Optional feature '{e.FeatureId}' cleanup reported an error: {e.Exception.Message}";
        FeaturePublication = new FeaturePublicationViewModel(_featureAccess);
        _infrastructureCaseWorkspaceDependencies = infrastructureCaseWorkspaceDependencies;

        // Initialize services
        _filterService = new ProcessFilterService();
        _externalProcessService = externalProcessService ?? new ViewerExternalProcessService();
        _localAgentProcessLifecycle = localAgentProcessLifecycle ?? new LocalAgentProcessLifecycleService();
        _discoverLocalAgentPairings = discoverLocalAgentPairings ?? (() => AgentPairingStore.Discover());
        _sessionPaths = SessionPathService.CreateDefaultSession();
        _telemetryProjectionService = new TelemetryProjectionService();
        _liveSnapshotRefreshCoordinator.StateChanged += OnLiveSnapshotRefreshStateChanged;
        _activeCapturePackageInfo = TryInspectCapturePackage(_sessionPaths.SessionRoot);
        _captureWorkspaceCoordinator = new ViewerWorkspaceLifecycleCoordinator(
            _sessionPaths,
            _activeCapturePackageInfo);
        _captureWorkspaceCoordinator.StateChanged += OnWorkspaceLifecycleStateChanged;
        _snapshotFollowCoordinator = new ViewerSnapshotFollowCoordinator(
            new DelegateViewerSnapshotFollowRuntime(RunViewerSnapshotRefreshAsync));
        _snapshotFollowCoordinator.StateChanged += OnSnapshotFollowStateChanged;
        _snapshotFollowCoordinator.BindWorkspace(CreateSnapshotFollowWorkspace(
            _captureWorkspaceCoordinator.State));
        ApplySnapshotFollowState(_snapshotFollowCoordinator.State);
        _viewerAgentCommandExecutor = new ViewerAgentCommandExecutor(
            new DelegateViewerAgentCommandRuntime(
                IsViewerAgentCommandContextCurrent,
                sessionPaths => _agentClient.BindSession(sessionPaths),
                (commandKind, cancellationToken) =>
                    _agentClient.GetHealthExchangeAsync(commandKind, cancellationToken),
                identity => _localAgentProcessLifecycle.VerifyRunning(identity),
                LocalAgentProcessLifecycleService.IsSupportedAgentExecutablePath,
                (command, expectedEndpoint, expectedPairingGeneration, cancellationToken) =>
                    _agentClient.SubmitCommandExchangeAsync(
                        command,
                        expectedEndpoint,
                        expectedPairingGeneration,
                        cancellationToken)));
        var sharedAgentActionRuntime = new DelegateViewerAgentCaptureActionRuntime(
                target =>
                    target.WorkspaceGeneration == _captureWorkspaceCoordinator.Generation &&
                    string.Equals(
                        Path.GetFullPath(target.SessionRoot),
                        Path.GetFullPath(_sessionPaths.SessionRoot),
                        StringComparison.OrdinalIgnoreCase),
                (command, action, requireViewerConnection, cancellationToken) =>
                    SubmitAgentCommandAsync(
                        command,
                        action,
                        startAgentIfNeeded: false,
                        requireViewerConnection: requireViewerConnection,
                        observeWorkflow: false,
                        cancellationToken: cancellationToken),
                cancellationToken => _agentStatusClient.GetHealthAsync(cancellationToken),
                (jobId, cancellationToken) =>
                    _agentStatusClient.GetJobStatusAsync(jobId, cancellationToken));
        _agentCaptureActionService = new ViewerAgentCaptureActionService(sharedAgentActionRuntime);
        _hostMonitoringActionService = new Lazy<ViewerHostMonitoringActionService>(() =>
            new ViewerHostMonitoringActionService(
                new DelegateViewerHostMonitoringActionRuntime(
                    target =>
                        target.WorkspaceGeneration == _captureWorkspaceCoordinator.Generation &&
                        string.Equals(
                            Path.GetFullPath(target.SessionRoot),
                            Path.GetFullPath(_sessionPaths.SessionRoot),
                            StringComparison.OrdinalIgnoreCase),
                    (command, action, requireViewerConnection, cancellationToken) =>
                        sharedAgentActionRuntime.ExecuteCommandAsync(
                            command,
                            action,
                            requireViewerConnection,
                            cancellationToken))));
        _agentEvidenceActionService = new ViewerAgentEvidenceActionService(sharedAgentActionRuntime);
        _agentCaptureWorkflowCoordinator = new AgentCaptureWorkflowCoordinator(
            _captureWorkspaceCoordinator.Generation,
            new DelegateAgentCaptureWorkflowRuntime(
                cancellationToken => _agentClient.GetHealthAsync(cancellationToken),
                cancellationToken => _agentStatusClient.GetHealthAsync(cancellationToken),
                (jobId, cancellationToken) => _agentStatusClient.GetJobStatusAsync(jobId, cancellationToken),
                (command, action, startAgentIfNeeded, requireViewerConnection, cancellationToken) =>
                    SubmitAgentCommandAsync(
                        command,
                        action,
                        startAgentIfNeeded,
                        requireViewerConnection,
                        observeWorkflow: false,
                        cancellationToken: cancellationToken),
                AssessAgentCaptureHealth));
        _agentToolActionService = new ViewerAgentToolActionService(
            new DelegateViewerAgentCaptureActionRuntime(
                sharedAgentActionRuntime.IsCurrent,
                async (command, action, requireViewerConnection, cancellationToken) =>
                {
                    var captureRequest = command switch
                    {
                        ProcInsider.Models.Agent.StartNetworkCaptureCommand => new AgentCaptureCommandRequest(
                            JobKind.NetworkCapture,
                            AgentCapturePendingAction.Start,
                            command,
                            action,
                            StartAgentIfNeeded: false,
                            RequireViewerConnection: requireViewerConnection),
                        ProcInsider.Models.Agent.StopNetworkCaptureCommand => new AgentCaptureCommandRequest(
                            JobKind.NetworkCapture,
                            AgentCapturePendingAction.Stop,
                            command,
                            action,
                            StartAgentIfNeeded: false,
                            RequireViewerConnection: requireViewerConnection),
                        ProcInsider.Models.Agent.StartProcessMonitorCaptureCommand => new AgentCaptureCommandRequest(
                            JobKind.ProcessMonitorCapture,
                            AgentCapturePendingAction.Start,
                            command,
                            action,
                            StartAgentIfNeeded: false,
                            RequireViewerConnection: requireViewerConnection),
                        ProcInsider.Models.Agent.StopProcessMonitorCaptureCommand => new AgentCaptureCommandRequest(
                            JobKind.ProcessMonitorCapture,
                            AgentCapturePendingAction.Stop,
                            command,
                            action,
                            StartAgentIfNeeded: false,
                            RequireViewerConnection: requireViewerConnection),
                        _ => null
                    };
                    if (captureRequest != null)
                    {
                        var capture = await _agentCaptureWorkflowCoordinator
                            .ExecuteCaptureCommandAsync(captureRequest, cancellationToken);
                        return capture.Response;
                    }

                    return await SubmitAgentCommandAsync(
                        command,
                        action,
                        startAgentIfNeeded: command is QueueZeekAnalysisCommand,
                        requireViewerConnection: requireViewerConnection,
                        observeWorkflow: false,
                        cancellationToken: cancellationToken);
                },
                cancellationToken => _agentStatusClient.GetHealthAsync(cancellationToken),
                (jobId, cancellationToken) =>
                    _agentStatusClient.GetJobStatusAsync(jobId, cancellationToken)));
        _agentMemoryActionService = new Lazy<ViewerMemoryActionService>(() =>
            new ViewerMemoryActionService(
                new DelegateViewerAgentCaptureActionRuntime(
                    sharedAgentActionRuntime.IsCurrent,
                    (command, action, requireViewerConnection, cancellationToken) =>
                        SubmitAgentCommandAsync(
                            command,
                            action,
                            startAgentIfNeeded: command is QueueVolatilityAnalysisCommand,
                            requireViewerConnection: requireViewerConnection,
                            observeWorkflow: false,
                            cancellationToken: cancellationToken),
                    cancellationToken => _agentStatusClient.GetHealthAsync(cancellationToken),
                    (jobId, cancellationToken) =>
                        _agentStatusClient.GetJobStatusAsync(jobId, cancellationToken))));
        _agentCaptureWorkflowCoordinator.StateChanged += OnAgentCaptureWorkflowStateChanged;
        _artifactEnrichmentWorkflowCoordinator = new ArtifactEnrichmentWorkflowCoordinator(
            _captureWorkspaceCoordinator.Generation,
            new DelegateArtifactEnrichmentWorkflowRuntime(
                (command, action, startAgentIfNeeded, requireViewerConnection, cancellationToken) =>
                    SubmitAgentCommandAsync(
                        command,
                        action,
                        startAgentIfNeeded,
                        requireViewerConnection,
                        observeWorkflow: false,
                        cancellationToken: cancellationToken),
                (jobId, cancellationToken) => _agentStatusClient.GetJobStatusAsync(jobId, cancellationToken),
                () => _agentCaptureWorkflowCoordinator.Control,
                (jobKind, action) => _agentCaptureWorkflowCoordinator.BeginPendingJob(jobKind, action)));
        _artifactEnrichmentWorkflowCoordinator.StateChanged += OnArtifactEnrichmentWorkflowStateChanged;
        ProcessMonitorExecutablePath = Environment.ExpandEnvironmentVariables(
            ProcessMonitorService.ResolveEnvironmentPath().Value);
        _annotationStore = TryInitializeAnnotationDatabase(_sessionPaths.AnnotationDatabasePath);
        _applicationCatalog = TryOpenApplicationCatalog();
        LiveDatabasePath = _sessionPaths.LiveDatabasePath;
        SnapshotDatabasePath = _sessionPaths.SnapshotDatabasePath;
        ActiveSessionFolder = $"Capture: {_sessionPaths.SessionRoot}";
        UpdateActiveSessionDetail();
        _annotationStore?.ImportBookmarksFromEvidenceDatabase(
            _sessionPaths.LiveDatabasePath,
            CaptureOpenContext.AgentWritableLive,
            _activeCapturePackageInfo?.CompatibilityMetadata,
            _sessionPaths.SessionId);
        _sqliteStagingQueryService = null;
        _processListingService = null;

        // Initialize child view models
        ProcessPropertiesViewModel = new ProcessPropertiesViewModel();
        InspectorPaneViewModel = new InspectorPaneViewModel();
        ProcessRiskDetailsViewModel = _featureAccess.IsPublished(FeatureIds.ProcessRiskScore)
            ? new ProcessRiskDetailsViewModel()
            : null;
        var viewerFeatureDefinitions = new List<IViewerFeatureDefinition>
        {
            BaselineComparisonFeatureModule.CreateDefinition(
                    () => _sessionPaths,
                    () => new BaselineRiskProjectionUpdateService(
                        _telemetryProjectionService,
                        () => _sessionPaths.SessionId,
                        () => _captureWorkspaceCoordinator.Generation,
                        () => _liveSnapshotRefreshCoordinator.State.Generation),
                    OnBaselineRiskProjectionUpdated),
            SearchFeatureModule.CreateDefinition(CreateSearchFeatureModule),
            InfrastructureCaseWorkspaceFeatureModule.CreateDefinition(
                CreateInfrastructureCaseWorkspaceFeatureModule)
        };
        var requiredViewerFeatureIds = new List<FeatureId>
        {
            FeatureIds.BaselineComparison,
            FeatureIds.SearchAndSigma,
            FeatureIds.InfrastructureCaseWorkspaces
        };
        AddCompiledPrivateViewerFeatureDefinitions(
            viewerFeatureDefinitions,
            requiredViewerFeatureIds);
        _viewerFeatures = new ViewerFeatureRegistry(
            _featureAccess.Catalog,
            viewerFeatureDefinitions,
            requiredViewerFeatureIds);
        RegisterOptionalFeatureModules();
        NsrlLookupViewModel? nsrlLookupViewModel = null;
        if (_featureAccess.IsPublished(FeatureIds.KnownFileReferenceData))
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
        ProcessDescriptionViewModel = new ProcessDescriptionViewModel(
            _annotationStore,
            () => AiFeature?.Service,
            _featureAccess,
            _applicationCatalog,
            new ApplicationComparisonEvidenceService(_telemetryProjectionService),
            nsrlLookupViewModel,
            aiEvidencePackBuilderFactory: () => AiFeature?.EvidencePackBuilder,
            confirmReplace: message => MessageBox.Show(
                message,
                "Replace App Info Override",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) == MessageBoxResult.Yes);
        ProcessDescriptionViewModel.SetWorkspace(
            _sessionPaths,
            _captureWorkspaceCoordinator.Generation);
        NotesViewModel = new ProcessNotesViewModel(_annotationStore);
        NotesViewModel.NoteSaved += OnProcessNoteSaved;
        ProcessStatisticsViewModel = new ProcessStatisticsViewModel(_telemetryProjectionService, InspectorPaneViewModel);
        ExplorerViewModel = new ExplorerViewModel(OnExplorerScopeSelected, LoadExplorerChildrenAsync, _featureAccess);
        _explorerTabSet = CreateExplorerTabSet();
        _dataTabSet = CreateDataTabSet();
        AppInfoExtensionTabs = new ReadOnlyCollection<FeatureTabDescriptor>(
            _viewerFeatures.CreateTabDescriptors(
                    FeatureTabSurface.AppInfo,
                    _featureModules)
                .Where(descriptor => _featureAccess.IsPublished(descriptor.FeatureId))
                .ToArray());
        _viewerNavigationCoordinator = new ViewerNavigationCoordinator(
            _explorerTabSet,
            _dataTabSet,
            FeaturePublication.ReleaseId,
            this);
        _viewerNavigationCoordinator.StateChanged += OnViewerNavigationStateChanged;
        ApplyViewerNavigationState(_viewerNavigationCoordinator.State);
        _selectedProcessFanOutCoordinator = new SelectedProcessFanOutCoordinator(
            _captureWorkspaceCoordinator.Generation,
            this);
        _selectedProcessFanOutCoordinator.StateChanged += OnSelectedProcessFanOutStateChanged;
        _featureModules.Activated += OnFeatureModuleActivated;

        // Set up collection view for filtering
        ProcessesView = CollectionViewSource.GetDefaultView(Processes);
        ProcessesView.Filter = FilterProcess;

        if (_featureAccess.IsPublished(FeatureIds.EventTelemetry) && EventTelemetryFeature != null)
        {
            LoadPowerShellAuditingSettings();
            LoadSysmonSettings();
            LoadEtwCaptureProfiles();
        }

        if (_featureAccess.IsPublished(FeatureIds.SecurityMonitoringConfiguration) && SecurityMonitoringFeature != null)
        {
            LoadSecurityMonitoringProfileManifests();
        }

        _snapshotAgeTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = SnapshotAgeRefreshInterval
        };
        _snapshotAgeTimer.Tick += (_, _) =>
        {
            if (_liveSnapshotRefreshCoordinator.ActiveSnapshotUtc.HasValue)
            {
                UpdateActiveSessionDetail();
                ApplySnapshotFollowState(_snapshotFollowCoordinator.State);
            }
        };

    }

    private void RegisterOptionalFeatureModules()
    {
        _featureModules.Register(
            FeatureIds.ModulesAndHandles,
            () => new ModulesAndHandlesFeatureModule(
                _telemetryProjectionService,
                InspectorPaneViewModel,
                OnSelectedArtifactCollectionChanged,
                OnSelectedArtifactCaptureStatusChanged));
        _featureModules.Register(
            FeatureIds.EventTelemetry,
            () => new EventTelemetryFeatureModule(
                _telemetryProjectionService,
                InspectorPaneViewModel,
                BackfillSecurityEventsForProcess,
                BackfillPowerShellEventsForProcess,
                BackfillOtherWindowsEventsForProcess,
                BackfillSysmonEventsForProcess));
        _featureModules.Register(
            FeatureIds.AgentsAndCapture,
            () => new AgentFeatureModule(
                OnAgentFeaturePropertyChanged,
                OnAgentStatusTimerTick,
                _featureAccess.Catalog.ReleaseId,
                _sessionPaths));
        _featureModules.Register(FeatureIds.SearchAndSigma, () => new SigmaRuleParser());
        _featureModules.Register(
            FeatureIds.SearchAndSigma,
            CreateSigmaViewModel,
            DeactivateSigmaViewModel);
        _featureModules.Register(
            FeatureIds.DumpsAndPeAnalysis,
            () => new DumpsAndPeFeatureModule(
                _telemetryProjectionService,
                InspectorPaneViewModel,
                OnMemoryDumpFeaturePropertyChanged));
        _featureModules.Register(
            FeatureIds.NetworkAndZeek,
            () => new NetworkAndZeekFeatureModule(
                _telemetryProjectionService,
                InspectorPaneViewModel,
                IsActiveNetworkCaptureRow,
                IsFinalizingNetworkCaptureRow,
                OnNetworkFeaturePropertyChanged,
                OnNetworkFeatureRefreshed));
        _featureModules.Register(
            FeatureIds.SystemMemoryAndVolatility,
            CreateMemoryInvestigationViewModel,
            DeactivateMemoryInvestigationViewModel);
        _featureModules.Register(
            FeatureIds.FilesystemArtifacts,
            () => new FilesystemArtifactsViewModel(_telemetryProjectionService, InspectorPaneViewModel),
            viewModel => viewModel.Clear());
        _viewerFeatures.RegisterActivations(_featureModules);
        _featureModules.Register(
            FeatureIds.AiAssistance,
            () => new AiFeatureModule(
                _sessionPaths,
                _telemetryProjectionService,
                _annotationStore,
                _applicationCatalog,
                InspectorPaneViewModel,
                _featureAccess));
        _featureModules.Register(
            FeatureIds.SecurityMonitoringConfiguration,
            () => new SecurityMonitoringFeatureModule());
    }

    private FeatureTabSet CreateExplorerTabSet()
    {
        List<FeatureTabDescriptor> descriptors =
        [
            new(
                ExplorerTabKeys.Explore,
                "Explore",
                FeatureIds.ProcessListing,
                0,
                () => ExplorerViewModel),
            new(
                ExplorerTabKeys.Agents,
                "Agents",
                FeatureIds.AgentsAndCapture,
                100,
                () => AgentsViewModel),
            new(
                ExplorerTabKeys.Sigma,
                "Sigma",
                FeatureIds.SearchAndSigma,
                300,
                () => SigmaViewModel,
                showCount: true),
            new(
                ExplorerTabKeys.Ai,
                "AI",
                FeatureIds.AiAssistance,
                400,
                () => AiFeature == null ? null : this),
            new(
                ExplorerTabKeys.Network,
                "Network",
                FeatureIds.NetworkAndZeek,
                500,
                () => NetworkCapturesViewModel,
                showCount: true),
            new(
                ExplorerTabKeys.Memory,
                "Memory",
                FeatureIds.SystemMemoryAndVolatility,
                600,
                () => MemoryInvestigationViewModel,
                showCount: true)
        ];
        descriptors.AddRange(_viewerFeatures.CreateTabDescriptors(
            FeatureTabSurface.Explorer,
            _featureModules));

        return new FeatureTabSet(
            _featureAccess.Catalog,
            FeatureTabSurface.Explorer,
            descriptors,
            ExplorerTabKeys.Explore);
    }

    private FeatureTabSet CreateDataTabSet()
    {
        List<FeatureTabDescriptor> descriptors =
        [
            new(DataTabKeys.AppInfo, "App Info", FeatureIds.SelectedProcessDetails, 0, () => new Views.Features.SelectedProcess.DataProcessAppInfoView { DataContext = this }),
            new(DataTabKeys.Notes, "📝 Notes", FeatureIds.SelectedProcessDetails, 100, () => new Views.Features.SelectedProcess.DataProcessNotesView { DataContext = NotesViewModel }),
            new(DataTabKeys.Modules, "Loaded Modules", FeatureIds.ModulesAndHandles, 400, () => new Views.Features.Artifacts.DataModulesView { DataContext = ModulesViewModel }, showCount: true),
            new(DataTabKeys.Handles, "Handles", FeatureIds.ModulesAndHandles, 500, () => new Views.Features.Artifacts.DataHandlesView { DataContext = HandlesViewModel }, showCount: true),
            new(DataTabKeys.MemoryDumps, "Dumps", FeatureIds.DumpsAndPeAnalysis, 600, () => new Views.Features.Artifacts.DataMemoryDumpsView { DataContext = MemoryDumpsViewModel }, showCount: true),
            new(DataTabKeys.PeAnalysis, "PE Analysis", FeatureIds.DumpsAndPeAnalysis, 700, () => new Views.Features.Artifacts.DataPeAnalysisView { DataContext = PeAnalysisViewModel }, showCount: true),
            new(DataTabKeys.SystemMemory, "System Memory", FeatureIds.SystemMemoryAndVolatility, 800, () => new Views.Features.Memory.DataSystemMemoryView { DataContext = MemoryInvestigationViewModel }, showCount: true),
            new(DataTabKeys.Network, "Network Captures", FeatureIds.NetworkAndZeek, 900, () => new Views.Features.Network.DataNetworkCapturesView { DataContext = NetworkCapturesViewModel }, showCount: true),
            new(DataTabKeys.Filesystem, "Filesystem Artifacts", FeatureIds.FilesystemArtifacts, 1000, () => new Views.Features.Filesystem.DataFilesystemArtifactsView { DataContext = FilesystemArtifactsViewModel }, showCount: true),
            new(DataTabKeys.SystemActivity, "System Activity", FeatureIds.EventTelemetry, 1100, () => new Views.Features.Events.DataSystemActivityView { DataContext = SystemActivityViewModel }, showCount: true),
            new(DataTabKeys.RuntimeEvents, "Runtime Events", FeatureIds.EventTelemetry, 1200, () => new Views.Features.Events.DataRuntimeEventsView { DataContext = EventsViewModel }, showCount: true),
            new(DataTabKeys.EtwEvents, "ETW Providers", FeatureIds.EventTelemetry, 1300, () => new Views.Features.Events.DataEtwEventListView { DataContext = EtwProviderEventsViewModel }, showCount: true),
            new(DataTabKeys.SecurityEvents, "Windows Audit Log", FeatureIds.EventTelemetry, 1400, () => new Views.Features.Events.DataEventListView { DataContext = WindowsAuditLogViewModel }, showCount: true),
            new(DataTabKeys.PowerShellEvents, "PowerShell Logs", FeatureIds.EventTelemetry, 1500, () => new Views.Features.Events.DataEventListView { DataContext = PowerShellLogViewModel }, showCount: true),
            new(DataTabKeys.WindowsOtherEvents, "Windows Logs (Other)", FeatureIds.EventTelemetry, 1600, () => new Views.Features.Events.DataEventListView { DataContext = WindowsOtherLogViewModel }, showCount: true),
            new(DataTabKeys.SysmonEvents, "Sysmon", FeatureIds.EventTelemetry, 1700, () => new Views.Features.Events.DataEventListView { DataContext = SysmonEventsViewModel }, showCount: true),
            new(DataTabKeys.Ai, "AI", FeatureIds.AiAssistance, 1800, () => new Views.Features.Ai.DataAiInvestigationView { DataContext = AiInvestigationViewModel })
        ];
        descriptors.AddRange(_viewerFeatures.CreateTabDescriptors(
            FeatureTabSurface.Data,
            _featureModules));

        return new FeatureTabSet(
            _featureAccess.Catalog,
            FeatureTabSurface.Data,
            descriptors,
            DataTabKeys.AppInfo,
            allowEmpty: true);
    }

    private SearchFeatureModule CreateSearchFeatureModule()
    {
        var module = new SearchFeatureModule(
            new SearchQueryService(_telemetryProjectionService),
            NavigateToSearchResult,
            _featureAccess,
            count =>
            {
                UpdateExplorerTabCount(ExplorerTabKeys.Search, count);
                RefreshExplorerAnalysisCountsFromCache();
            });
        ApplySearchAvailability(module, _liveSnapshotRefreshCoordinator.State);
        return module;
    }

    private InfrastructureCaseWorkspaceFeatureModule CreateInfrastructureCaseWorkspaceFeatureModule()
    {
        if (_infrastructureCaseWorkspaceDependencies == null)
        {
            throw new InvalidOperationException(
                "InfrastructureCaseWorkspacePackageCompositionUnavailable");
        }

        var access = new InfrastructureModeAccessService(
            _featureAccess.Catalog,
            CurrentInfrastructureModeProfile.Definition,
            CurrentInfrastructureModeProfile.Definition.CreateIdentity(InfrastructureComponentKind.Viewer));
        if (!InfrastructureCaseWorkspaceFeatureModule.TryCreate(
                access,
                _infrastructureCaseWorkspaceDependencies,
                out var module,
                out var decision) || module == null)
        {
            throw new InvalidOperationException($"{decision.ErrorCode}: {decision.Message}");
        }

        if (_infrastructureWorkspace != null)
        {
            _infrastructureWorkspace.PropertyChanged -= OnInfrastructureWorkspacePropertyChanged;
        }
        _infrastructureWorkspace = module.ViewModel;
        _infrastructureWorkspace.PropertyChanged += OnInfrastructureWorkspacePropertyChanged;
        OnPropertyChanged(nameof(InfrastructureWorkspace));
        OnPropertyChanged(nameof(IsInfrastructureWorkspaceActive));
        OnPropertyChanged(nameof(IsStandaloneWorkspaceActive));

        return module;
    }

    private void OnInfrastructureWorkspacePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(InfrastructureCaseWorkspaceViewModel.IsWorkspaceReady))
        {
            return;
        }

        OnPropertyChanged(nameof(IsInfrastructureWorkspaceActive));
        OnPropertyChanged(nameof(IsStandaloneWorkspaceActive));
    }

    private SigmaViewModel CreateSigmaViewModel()
    {
        var viewModel = new SigmaViewModel(
            _telemetryProjectionService,
            _sigmaRuleParser,
            NavigateToSearchResult,
            _featureAccess,
            new SigmaRiskProjectionUpdateService(
                _telemetryProjectionService,
                () => _sessionPaths.SessionId,
                () => _captureWorkspaceCoordinator.Generation));
        viewModel.PropertyChanged += OnSigmaFeaturePropertyChanged;
        viewModel.RiskProjectionUpdated += OnSigmaRiskProjectionUpdated;
        return viewModel;
    }

    private void DeactivateSigmaViewModel(SigmaViewModel viewModel)
    {
        viewModel.PropertyChanged -= OnSigmaFeaturePropertyChanged;
        viewModel.RiskProjectionUpdated -= OnSigmaRiskProjectionUpdated;
        viewModel.Clear();
    }

    private void OnSigmaRiskProjectionUpdated(
        object? sender,
        SigmaRiskProjectionUpdateResult result)
    {
        if (result.Completed && IsCurrentAnalysisDatabase(result.DatabasePath))
        {
            _ = RefreshViewsAfterAnalysisAsync(result.DatabasePath);
        }
    }

    private void OnBaselineRiskProjectionUpdated(BaselineRiskProjectionUpdateResult result)
    {
        if (result.Completed && IsCurrentAnalysisDatabase(result.DatabasePath))
        {
            _ = RefreshViewsAfterAnalysisAsync(result.DatabasePath);
        }
    }

    public bool IsFeatureActivated(FeatureId featureId) => _featureModules.IsActivated(featureId);

    private MemoryInvestigationViewModel CreateMemoryInvestigationViewModel()
    {
        var viewModel = new MemoryInvestigationViewModel(_telemetryProjectionService, InspectorPaneViewModel);
        viewModel.PropertyChanged += OnMemoryInvestigationFeaturePropertyChanged;
        viewModel.MemoryImages.CollectionChanged += OnMemoryImagesCollectionChanged;
        return viewModel;
    }

    private void DeactivateMemoryInvestigationViewModel(MemoryInvestigationViewModel viewModel)
    {
        viewModel.PropertyChanged -= OnMemoryInvestigationFeaturePropertyChanged;
        viewModel.MemoryImages.CollectionChanged -= OnMemoryImagesCollectionChanged;
        viewModel.Clear();
    }

    private void OnSelectedArtifactCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        UpdateSelectedProcessArtifactCounts();
        RefreshDataTabCounts();
    }

    private void OnSelectedArtifactCaptureStatusChanged(object? sender, EventArgs e) =>
        RefreshSelectedProcessRow();

    private async void OnAgentStatusTimerTick(object? sender, EventArgs e)
    {
        if (!IsAgentViewerConnected && !IsLocalAgentRecoveryInProgress)
        {
            RefreshDetectedLocalAgentPresence(projectNewDetection: true);
        }

        await PollAgentStatusAsync();
    }

    private void OnAgentCaptureWorkflowStateChanged(
        object? sender,
        AgentCaptureWorkflowStateChangedEventArgs e)
    {
        void ApplyState()
        {
            IsAgentConnected = e.State.IsReachable;
            IsAgentViewerConnected = e.State.IsViewerAttached;
            ConnectedAgentCount = AgentsViewModel.IsInfrastructureProjectionActive
                ? AgentsViewModel.InfrastructureConnectedAgentCount
                : e.State.AuthenticatedConnectedAgentCount;
            ApplyAgentCaptureControlProjection(e.State.Control);
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            ApplyState();
        }
        else
        {
            _ = dispatcher.BeginInvoke(ApplyState, DispatcherPriority.Background);
        }
    }

    private void OnArtifactEnrichmentWorkflowStateChanged(
        object? sender,
        ArtifactEnrichmentWorkflowStateChangedEventArgs e)
    {
        StartArtifactEnrichmentCommand.NotifyCanExecuteChanged();
        StopArtifactEnrichmentCommand.NotifyCanExecuteChanged();
    }

    private void OnAgentFeaturePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(AgentsViewModel.IsInfrastructureProjectionActive) or
            nameof(AgentsViewModel.InfrastructureConnectedAgentCount))
        {
            ConnectedAgentCount = AgentsViewModel.IsInfrastructureProjectionActive
                ? AgentsViewModel.InfrastructureConnectedAgentCount
                : _agentCaptureWorkflowCoordinator.State.AuthenticatedConnectedAgentCount;
            return;
        }

        if (e.PropertyName != nameof(AgentsViewModel.SelectedAgent))
        {
            return;
        }

        ClearPendingAgentTermination();
        DeployAgentCommand.NotifyCanExecuteChanged();
        RePairAgentCommand.NotifyCanExecuteChanged();
        RevokeAgentPairingCommand.NotifyCanExecuteChanged();
        StopAgentCommand.NotifyCanExecuteChanged();
        RefreshAgentRegistryHealthCommand.NotifyCanExecuteChanged();
        ShowAgentHealthCommand.NotifyCanExecuteChanged();
        ReverseAgentMonitoringDeploymentCommand.NotifyCanExecuteChanged();
        StartAgentConfiguredCaptureCommand.NotifyCanExecuteChanged();
        PauseAgentConfiguredCaptureCommand.NotifyCanExecuteChanged();
        StopAgentConfiguredCaptureCommand.NotifyCanExecuteChanged();
        StartAgentSqliteBenchmarkCommand.NotifyCanExecuteChanged();
        CancelAgentSqliteBenchmarkCommand.NotifyCanExecuteChanged();
        StartAgentCaptureOptionCommand.NotifyCanExecuteChanged();
        StopAgentCaptureOptionCommand.NotifyCanExecuteChanged();
        StartNetworkCaptureCommand.NotifyCanExecuteChanged();
        StopNetworkCaptureCommand.NotifyCanExecuteChanged();
        StartProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        StopProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        QueueProcessMonitorImportCommand.NotifyCanExecuteChanged();
        StartArtifactEnrichmentCommand.NotifyCanExecuteChanged();
        StopArtifactEnrichmentCommand.NotifyCanExecuteChanged();
    }

    private void OnMemoryDumpFeaturePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MemoryDumpsViewModel.SelectedMemoryDump))
        {
            AnalyzeSelectedDumpPeCommand.NotifyCanExecuteChanged();
        }
    }

    private void OnSigmaFeaturePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SigmaViewModel.Findings) && sender is SigmaViewModel sigma)
        {
            UpdateExplorerTabCount(ExplorerTabKeys.Sigma, sigma.Findings.Count);
            RefreshExplorerAnalysisCountsFromCache();
        }
    }

    private void OnNetworkFeaturePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(NetworkCapturesViewModel.SelectedNetworkCapture))
        {
            QueueSelectedZeekAnalysisCommand.NotifyCanExecuteChanged();
        }

        if (e.PropertyName == nameof(NetworkCapturesViewModel.SelectedZeekArtifact))
        {
            OpenSelectedZeekProcessCommand.NotifyCanExecuteChanged();
            OpenSelectedZeekPcapCommand.NotifyCanExecuteChanged();
            CopySelectedZeekWiresharkFilterCommand.NotifyCanExecuteChanged();
            ExportSelectedZeekFlowPcapCommand.NotifyCanExecuteChanged();
        }
    }

    private void OnNetworkFeatureRefreshed(object? sender, EventArgs e)
    {
        if (sender is NetworkCapturesViewModel network)
        {
            UpdateExplorerTabCount(ExplorerTabKeys.Network, network.NetworkCaptures.Count);
            UpdateDataTabCount(DataTabKeys.Network, network.NetworkCaptures.Count);
        }

        ReconcileNetworkCaptureStateFromRows();
    }

    private void OnMemoryImagesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (sender is System.Collections.ICollection images)
        {
            UpdateExplorerTabCount(ExplorerTabKeys.Memory, images.Count);
            UpdateDataTabCount(DataTabKeys.SystemMemory, images.Count);
        }
    }

    private void OnMemoryInvestigationFeaturePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MemoryInvestigationViewModel.SelectedMemoryImage))
        {
            QueueSelectedMemoryImageVolatilityAnalysisCommand.NotifyCanExecuteChanged();
        }
    }

    /// <summary>
    /// Initializes the view model and starts monitoring.
    /// </summary>
    [RelayCommand]
    public async Task InitializeAsync()
    {
        StatusMessage = "Viewer ready. Click Refresh from db to load a snapshot.";
        AgentStatusMessage = "Agent: not connected";
        AgentJobStatusMessage = "Jobs: connect to an agent for status";
        var localAgentRecoveryReportedStatus = false;
        if (AgentFeature is { } agentFeature)
        {
            localAgentRecoveryReportedStatus = await RecoverRunningLocalAgentAsync(
                LocalAgentRecoveryOrigin.Startup);
            agentFeature.StatusTimer.Start();
        }

        _snapshotAgeTimer.Start();
        if (EventTelemetryFeature is { } eventFeature)
        {
            eventFeature.SystemActivityViewModel.Clear();
        }

        ExplorerViewModel.ResetCounts();
        ResetExplorerTabCounts();
        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
        {
            network.ViewModel.Clear();
        }

        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            filesystem.Clear();
        }

        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory))
        {
            memory.Clear();
        }
        if (!localAgentRecoveryReportedStatus)
        {
            StatusMessage = "Viewer is empty until Refresh from db or Open capture. Use Agents -> Add, then select Start Agent to launch the local agent idle.";
        }
    }

    /// <summary>
    /// Stops monitoring and cleans up.
    /// </summary>
    public void Shutdown()
    {
        ClearPendingAgentTermination();
        CancelLateAgentExitObservation();
        _snapshotAgeTimer.Stop();
        _snapshotFollowCoordinator.BindWorkspace(
            CreateSnapshotFollowWorkspace(
                _captureWorkspaceCoordinator.State,
                isShuttingDown: true));
        ProcessDescriptionViewModel.Shutdown();
        _viewerNavigationCoordinator.StateChanged -= OnViewerNavigationStateChanged;
        _selectedProcessFanOutCoordinator.StateChanged -= OnSelectedProcessFanOutStateChanged;
        _agentCaptureWorkflowCoordinator.StateChanged -= OnAgentCaptureWorkflowStateChanged;
        _artifactEnrichmentWorkflowCoordinator.StateChanged -= OnArtifactEnrichmentWorkflowStateChanged;
        _featureModules.Activated -= OnFeatureModuleActivated;
        if (_infrastructureWorkspace != null)
        {
            _infrastructureWorkspace.PropertyChanged -= OnInfrastructureWorkspacePropertyChanged;
            _infrastructureWorkspace = null;
            OnPropertyChanged(nameof(InfrastructureWorkspace));
            OnPropertyChanged(nameof(IsInfrastructureWorkspaceActive));
            OnPropertyChanged(nameof(IsStandaloneWorkspaceActive));
        }
        _captureWorkspaceCoordinator.StateChanged -= OnWorkspaceLifecycleStateChanged;
        _liveSnapshotRefreshCoordinator.StateChanged -= OnLiveSnapshotRefreshStateChanged;
        _snapshotFollowCoordinator.StateChanged -= OnSnapshotFollowStateChanged;
        NotesViewModel.NoteSaved -= OnProcessNoteSaved;
        _viewerNavigationCoordinator.Dispose();
        _selectedProcessFanOutCoordinator.Dispose();
        _explorerCountRefreshCoordinator.Dispose();
        _agentCaptureWorkflowCoordinator.Dispose();
        _agentCaptureActionService.Dispose();
        _agentEvidenceActionService.Dispose();
        _agentToolActionService.Dispose();
        if (_agentMemoryActionService.IsValueCreated)
        {
            _agentMemoryActionService.Value.Dispose();
        }
        _artifactEnrichmentWorkflowCoordinator.Dispose();
        _localAgentControlCoordinator?.Dispose();
        _localAgentRecoveryCoordinator?.Dispose();
        _localAgentProcessLifecycle.Dispose();
        _featureModules.Dispose();
        _captureWorkspaceCoordinator.Dispose();
        _snapshotFollowCoordinator.Dispose();
        _liveSnapshotRefreshCoordinator.Dispose();
    }

    public CrashDiagnosticContext CreateCrashDiagnosticContext(string lifecycleState)
    {
        var captureState = _agentCaptureWorkflowCoordinator.Control.State;
        var captureActive = IsNetworkCaptureActive ||
                            IsProcessMonitorCaptureActive ||
                            captureState is AgentCaptureRunState.Starting or
                                AgentCaptureRunState.Running or
                                AgentCaptureRunState.Stopping or
                                AgentCaptureRunState.Draining;
        var workspace = _captureWorkspaceCoordinator.Current;
        return new CrashDiagnosticContext
        {
            WorkspaceMode = workspace.Mode,
            SessionId = string.IsNullOrWhiteSpace(workspace.SessionId)
                ? _sessionPaths.SessionId
                : workspace.SessionId,
            ViewerLifecycleState = lifecycleState,
            AgentConnectedSnapshot = IsAgentConnected || IsAgentViewerConnected,
            CaptureActiveSnapshot = captureActive,
            ActiveSessionPaths = _sessionPaths
        };
    }

    public async Task<string?> GetAgentShutdownPromptAsync()
    {
        var shutdownTarget = CreateVerifiedShutdownTarget();
        if (shutdownTarget == null && IsAgentViewerConnected)
        {
            var health = await _agentClient.GetHealthAsync();
            var healthSnapshot = health.Health;
            if (health.Success &&
                healthSnapshot != null &&
                IsAgentHealthForActiveSession(
                    healthSnapshot,
                    out _,
                    out var activeDatabasePath))
            {
                RememberVerifiedAgentShutdownTarget(healthSnapshot, activeDatabasePath);
                shutdownTarget = CreateVerifiedShutdownTarget();
            }
        }

        if (shutdownTarget == null)
        {
            return null;
        }

        LocalAgentProcessResult process;
        try
        {
            process = _localAgentProcessLifecycle.VerifyRunning(
                new LocalAgentProcessIdentity(
                    shutdownTarget.ProcessId,
                    shutdownTarget.StartedAtUtc,
                    GetCompatibleAgentExecutableCandidates().ToArray()));
        }
        catch (Exception ex)
        {
            process = new LocalAgentProcessResult(
                LocalAgentProcessOutcome.InspectionFailure,
                shutdownTarget.ProcessId,
                IsRunning: false,
                IsStopped: false,
                Forced: false,
                $"The exact local-agent process could not be inspected: {ex.Message}");
        }

        var decision = ViewerCloseAgentShutdownPolicy.Evaluate(shutdownTarget, process);
        if (decision.Outcome == ViewerCloseAgentShutdownOutcome.ExactProcessStopped)
        {
            MarkAgentStoppedAfterShutdown(
                GetConnectedAgent(),
                $"Local agent PID {shutdownTarget.ProcessId} had already exited before Viewer close. {decision.Detail}");
            return null;
        }

        if (decision.Outcome == ViewerCloseAgentShutdownOutcome.ExactIdentityRejected)
        {
            _lastVerifiedAgentShutdownTarget = null;
            AgentsViewModel.MarkAgentViewerDisconnected(
                GetConnectedAgent(),
                "The previously authenticated local-agent process identity was replaced or reused before Viewer close.");
            RefreshDetectedLocalAgentPresence(projectNewDetection: true);
            return null;
        }

        if (!decision.ShouldPrompt)
        {
            return null;
        }

        var activeJobs = GetTrackedActiveAgentJobs();
        var jobSummary = activeJobs.Count == 0
            ? "No active jobs are currently tracked by the viewer."
            : $"Viewer-tracked active jobs: {string.Join(", ", activeJobs)}.";

        return
            $"{ProductIdentity.AgentDisplayName} was authenticated for this session (PID {shutdownTarget.ProcessId}).\n\n" +
            $"Close-time identity check: {decision.Detail}\n" +
            $"{jobSummary}\n\n" +
            $"Close {ProductIdentity.AgentDisplayName} too?\n\n" +
            $"Choose Leave Agent Running to keep it running after {ProductIdentity.DisplayName} closes, or Cancel to return to {ProductIdentity.DisplayName}.";
    }

    public Task<bool> ShutdownAgentForActiveSessionAsync()
    {
        return StopConnectedAgentAsync(
            GetConnectedAgent(),
            "Viewer is closing.",
            requireViewerConnection: false);
    }

    [RelayCommand(CanExecute = nameof(CanAddAgent))]
    private async Task AddAgentAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.AgentsAndCapture, "Connect / Add Agent"))
        {
            return;
        }

        if (!IsLocalAgentRecoveryInProgress && !IsAgentViewerConnected)
        {
            var discovery = GetLocalAgentRecoveryCoordinator().Discover();
            ApplyLocalAgentDiscoveryState(discovery);
            if (discovery.BlocksAdd)
            {
                await RecoverRunningLocalAgentAsync(LocalAgentRecoveryOrigin.Manual);
                return;
            }
        }

        if (!CanAddAgent())
        {
            StatusMessage = IsAgentViewerConnected
                ? "The local agent is already connected; Connect / Add Agent is unavailable."
                : "Another local-agent setup or secure recovery operation is already in progress.";
            return;
        }

        if (!TryBeginLocalAgentSetup("Connect / Add Agent"))
        {
            return;
        }

        try
        {
            var dialog = CreateLocalAgentSetupDialog(agent: null, isExistingAgentSetup: false);
            if (dialog.ShowDialog() != true)
            {
                StatusMessage = "Connect / Add canceled.";
                return;
            }

            if (dialog.SelectedAgentTargetKind != ProcInsider.AddAgentTargetKind.Local)
            {
                StatusMessage = "Remote agents are reserved for a future transport implementation.";
                return;
            }

            if (_captureWorkspaceCoordinator.Mode != CaptureWorkspaceMode.LiveCapture)
            {
                var switched = await SwitchToFreshLiveCaptureWorkspaceAsync(
                    "Connect / Add Agent requires a new live capture workspace.");
                if (!switched)
                {
                    return;
                }
            }

            var agent = AgentsViewModel.AddOrUpdateLocalAgent();
            AgentsViewModel.ApplyLocalPairing(_agentClient.InspectPairing());
            await RunLocalAgentSetupAsync(agent, dialog, initiatedByAdd: true);
        }
        finally
        {
            EndLocalAgentSetup();
        }
    }

    [RelayCommand(CanExecute = nameof(CanDeployAgent))]
    private async Task DeployAgentAsync(AgentRegistryEntryViewModel? agent)
    {
        if (!RequireFeaturePublished(FeatureIds.AgentsAndCapture, "Start Agent"))
        {
            return;
        }

        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanDeployAgent(agent))
        {
            StatusMessage = "Select a stopped local-agent row in an active live workspace before using Start Agent.";
            return;
        }

        if (!TryBeginLocalAgentSetup("Start Agent"))
        {
            return;
        }

        try
        {
            var targetAgent = agent!;
            if (!IsSupportedLocalAgent(targetAgent, "agent setup"))
            {
                return;
            }

            var dialog = CreateLocalAgentSetupDialog(targetAgent, isExistingAgentSetup: true);
            if (dialog.ShowDialog() != true)
            {
                StatusMessage = "Start Agent setup canceled.";
                return;
            }

            await RunLocalAgentSetupAsync(targetAgent, dialog, initiatedByAdd: false);
        }
        finally
        {
            EndLocalAgentSetup();
        }
    }

    private ProcInsider.AddAgentDialog CreateLocalAgentSetupDialog(
        AgentRegistryEntryViewModel? agent,
        bool isExistingAgentSetup)
    {
        var hostMonitoringPublished =
            _featureAccess.IsPublished(FeatureIds.SecurityMonitoringConfiguration);
        return new ProcInsider.AddAgentDialog(
            _featureAccess.Catalog,
            hostMonitoringPublished
                ? CreateHostMonitoringConfigurationSettings(agent?.HostMonitoringConfiguration)
                : null,
            agent?.CaptureOptions,
            agent?.AgentMemoryLimitMegabytes ?? 500,
            isExistingAgentSetup)
        {
            Owner = Application.Current?.MainWindow
        };
    }

    private async Task<bool> RunLocalAgentSetupAsync(
        AgentRegistryEntryViewModel agent,
        ProcInsider.AddAgentDialog dialog,
        bool initiatedByAdd)
    {
        var workspaceGeneration = _captureWorkspaceCoordinator.Generation;
        var captureOptions = dialog.GetCaptureOptions();
        var monitoringSettings = dialog.IsHostMonitoringPublished
            ? dialog.GetMonitoringConfiguration()
            : null;
        agent.AgentMemoryLimitMegabytes = dialog.SelectedAgentMemoryMegabytes;
        agent.ApplyCaptureOptionSelections(captureOptions);
        AgentStatusMessage = "Agent: local setup requested";
        AgentJobStatusMessage = initiatedByAdd
            ? "Jobs: starting agent after add"
            : "Jobs: starting agent from selected row";
        StatusMessage = initiatedByAdd
            ? $"Local agent added. Starting {ProductIdentity.AgentDisplayName} for the active session..."
            : $"Starting the selected {ProductIdentity.AgentDisplayName}, then connecting the viewer and applying the confirmed setup...";
        NotifyAgentCommandCanExecuteChanged();

        var captureRequested = HasSelectedConfigurableCaptureOptions(captureOptions);
        var captureStarted = false;
        LocalAgentRecoveredBinding? authenticatedBinding = null;
        var setup = new LocalAgentSetupCoordinator(
            new DelegateLocalAgentSetupRuntime(
                () => DispatchLocalAgentSetup(
                    () => IsCurrentLocalAgentSetupTarget(agent, workspaceGeneration)),
                () => DispatchLocalAgentSetupAsync(async () =>
                    {
                        authenticatedBinding = await StartSelectedLocalAgentAsync(
                            agent,
                            initiatedByAdd);
                        return authenticatedBinding != null;
                    }),
                () => DispatchLocalAgentSetupAsync(
                    () => AttachVerifiedLocalAgentSetupBindingAsync(
                        agent,
                        authenticatedBinding)),
                () => DispatchLocalAgentSetupAsync(
                    () => SaveAgentMonitoringConfigurationAsync(
                        agent,
                        requireViewerConnection: true,
                        monitoringSettings)),
                () => DispatchLocalAgentSetupAsync(
                    () => DeploySavedAgentMonitoringConfigurationAsync(
                        agent,
                        showConfirmation: false)),
                () => DispatchLocalAgentSetupAsync(
                    () => SaveAgentCaptureConfigurationAsync(
                        agent,
                        requireViewerConnection: true,
                        captureOptions)),
                () => DispatchLocalAgentSetup(() =>
                    {
                        var availability = EvaluateAgentConfiguredCaptureAvailability(agent);
                        return new LocalAgentSetupAvailability(
                            availability.CanStart,
                            availability.StartUnavailableReason);
                    }),
                () => DispatchLocalAgentSetupAsync(async () =>
                    {
                        captureStarted = await StartSavedAgentConfiguredCaptureAsync(agent);
                        return captureStarted;
                    })));
        var result = await setup.ExecuteAsync(new LocalAgentSetupRequest(
            initiatedByAdd
                ? LocalAgentSetupOrigin.Add
                : LocalAgentSetupOrigin.SelectedRowStart,
            HasMonitoringConfiguration: monitoringSettings != null,
            DeployMonitoring: monitoringSettings?.HasRequestedDeployment == true,
            HasSelectedCaptureSources: captureRequested));

        if (result.Outcome == LocalAgentSetupOutcome.Superseded)
        {
            return RejectSupersededLocalAgentSetup();
        }

        if (result.Outcome == LocalAgentSetupOutcome.Rejected)
        {
            if (result.Stage == LocalAgentSetupStage.AttachVerifiedViewer)
            {
                StatusMessage = initiatedByAdd
                    ? "Local agent was added and started, but its authenticated binding could not be attached to the still-current viewer target."
                    : "The selected local agent started, but its authenticated binding could not be attached to the still-current viewer target.";
            }

            // The lifecycle owner already projected the precise start/reuse rejection.
            // Do not replace that actionable identity/UAC/session detail with a stage name.
            return false;
        }

        var origin = initiatedByAdd ? "Local agent Add" : "Selected-row Start Agent";
        if (result.PartialFailures.Count > 0)
        {
            StatusMessage =
                $"{origin} partially completed: the exact agent is viewer-connected, but {string.Join("; ", result.PartialFailures)}.";
        }
        else if (captureRequested && captureStarted)
        {
            StatusMessage =
                $"{origin} completed: the exact agent is viewer-connected and configured capture start was accepted; authoritative health will reconcile Running/Degraded state.";
        }
        else
        {
            StatusMessage =
                $"{origin} completed: the exact agent is viewer-connected and remains idle because no configurable capture source was selected.";
        }

        AgentsViewModel.StatusMessage = StatusMessage;
        NotifyAgentCommandCanExecuteChanged();
        return result.Succeeded;
    }

    private static T DispatchLocalAgentSetup<T>(Func<T> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        var dispatcher = Application.Current?.Dispatcher;
        return dispatcher == null || dispatcher.CheckAccess()
            ? action()
            : dispatcher.Invoke(action, DispatcherPriority.Background);
    }

    private static Task<T> DispatchLocalAgentSetupAsync<T>(Func<Task<T>> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        var dispatcher = Application.Current?.Dispatcher;
        return dispatcher == null || dispatcher.CheckAccess()
            ? action()
            : dispatcher.InvokeAsync(action, DispatcherPriority.Background).Task.Unwrap();
    }

    private bool IsCurrentLocalAgentSetupTarget(
        AgentRegistryEntryViewModel agent,
        long workspaceGeneration) =>
        _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.LiveCapture &&
        _captureWorkspaceCoordinator.Generation == workspaceGeneration &&
        IsLocalAgentControlTarget(agent) &&
        AgentsViewModel.Agents.Contains(agent);

    private bool RejectSupersededLocalAgentSetup()
    {
        StatusMessage =
            "The active workspace or explicit local-agent row changed while setup was in progress; the stale completion was not projected and no additional setup stage was started.";
        return false;
    }

    private bool TryBeginLocalAgentSetup(string action)
    {
        if (_isLocalAgentSetupInProgress)
        {
            StatusMessage = $"Another local-agent setup is already in progress; {action} was not started again.";
            return false;
        }

        _isLocalAgentSetupInProgress = true;
        NotifyAgentCommandCanExecuteChanged();
        return true;
    }

    private void EndLocalAgentSetup()
    {
        _isLocalAgentSetupInProgress = false;
        NotifyAgentCommandCanExecuteChanged();
    }

    private async Task<LocalAgentRecoveredBinding?> StartSelectedLocalAgentAsync(
        AgentRegistryEntryViewModel? agent,
        bool initiatedByAdd)
    {
        if (_captureWorkspaceCoordinator.Mode != CaptureWorkspaceMode.LiveCapture)
        {
            StatusMessage = "Start Agent requires a live capture workspace. Use Add Agent to create a fresh live session from an archived capture.";
            return null;
        }

        if (!IsSupportedLocalAgent(agent, "agent deployment"))
        {
            return null;
        }

        var targetAgent = agent!;

        if (IsAgentShutdownInProgress)
        {
            StatusMessage = "Agent shutdown is in progress; cannot start the selected agent.";
            return null;
        }

        AgentStatusMessage = "Agent: starting";
        AgentJobStatusMessage = "Jobs: waiting for agent health";
        StatusMessage = $"{ProductIdentity.AgentDisplayName} start/reuse requested; validating the exact live session, pairing, process, and authenticated health...";

        var control = await GetLocalAgentControlCoordinator().StartAsync(
            new LocalAgentStartRequest(
                CreateLocalAgentControlTarget(),
                targetAgent.AgentMemoryLimitMegabytes));
        if (!control.Succeeded || control.Binding == null)
        {
            if (control.Outcome == LocalAgentControlOutcome.Superseded)
            {
                StatusMessage = "The active session changed while local-agent start was in progress; the stale result was not projected.";
                return null;
            }

            if (control.Pairing != null)
            {
                AgentsViewModel.ApplyLocalPairing(control.Pairing);
            }

            AgentsViewModel.MarkLocalAgentUnavailable(
                $"Local agent start was not verified: {control.Diagnostic}");
            AgentStatusMessage = control.Outcome switch
            {
                LocalAgentControlOutcome.Busy => "Agent: lifecycle busy",
                LocalAgentControlOutcome.Canceled => "Agent: start canceled",
                LocalAgentControlOutcome.Superseded => "Agent: session changed",
                LocalAgentControlOutcome.Unavailable => "Agent: unavailable",
                _ => "Agent: start rejected"
            };
            AgentJobStatusMessage = $"Agent start was not verified. {control.Diagnostic}";
            StatusMessage = $"{ProductIdentity.AgentDisplayName} start was not verified: {control.Diagnostic}";
            NotifyAgentCommandCanExecuteChanged();
            return null;
        }

        AgentsViewModel.ApplyLocalPairing(
            control.Binding.ProtectedPairing,
            authenticated: true);
        MarkLocalAgentStarted(
            targetAgent,
            control.Binding.AuthenticatedHealthResponse,
            alreadyRunning: control.Outcome == LocalAgentControlOutcome.Reused,
            initiatedByAdd);
        return control.Binding;
    }

    private Task<bool> AttachVerifiedLocalAgentSetupBindingAsync(
        AgentRegistryEntryViewModel agent,
        LocalAgentRecoveredBinding? binding)
    {
        if (binding == null)
        {
            StatusMessage = "The local-agent start completed without an authenticated binding; viewer attachment was blocked.";
            return Task.FromResult(false);
        }

        var attached = _agentCaptureWorkflowCoordinator.AttachVerified(
            agent.AgentId,
            binding.AuthenticatedHealthResponse);
        if (!attached.Succeeded ||
            attached.Response == null ||
            attached.Assessment?.Accepted != true)
        {
            var detail = FirstNonEmpty(
                attached.State.LastError,
                attached.Outcome.ToString());
            AgentsViewModel.MarkAgentViewerDisconnected(
                agent,
                $"Verified setup attachment failed: {detail}");
            AgentStatusMessage = "Agent: verified attachment rejected";
            AgentJobStatusMessage = detail;
            StatusMessage =
                "The exact local agent authenticated successfully, but its already-verified binding could not be projected into the current viewer workspace.";
            return Task.FromResult(false);
        }

        AgentsViewModel.MarkAgentViewerConnected(agent, attached.Response);
        UpdateAgentStatus(attached.Response, observeWorkflow: false);
        ClearLocalAgentStartDiscoveryConflict();
        IsLocalAgentProcessDetected = true;
        NotifyAgentCommandCanExecuteChanged();
        return Task.FromResult(true);
    }

    private void MarkLocalAgentStarted(
        AgentRegistryEntryViewModel agent,
        AgentIpcResponse health,
        bool alreadyRunning,
        bool initiatedByAdd)
    {
        ClearLocalAgentStartDiscoveryConflict();
        IsLocalAgentProcessDetected = true;
        agent.IsViewerConnected = false;
        UpdateAgentStatus(health);
        agent.DeploymentState = AgentDeploymentState.Deployed;

        var processDetail = health.Health == null
            ? "the active session"
            : $"PID {health.Health.ProcessId}";
        var endpointDetail = string.Equals(
            _agentClient.LastConnectedPipeName,
            AgentContracts.LegacyPipeName,
            StringComparison.Ordinal)
                ? $" through former pipe alias '{AgentContracts.LegacyPipeName}'"
                : $" through primary pipe '{AgentContracts.PipeName}'";
        var action = initiatedByAdd ? "added and started" : "started";
        var state = alreadyRunning ? "already running" : "deployed";
        AgentStatusMessage = $"Agent: {state} (not connected)";
        AgentJobStatusMessage = alreadyRunning
            ? $"Jobs: agent already running for {processDetail}"
            : $"Jobs: idle for {processDetail}";
        StatusMessage =
            $"Local agent {action}; {ProductIdentity.AgentDisplayName} is {state} for {processDetail}{endpointDetail}. Connecting the viewer and applying the confirmed setup selections...";
        AgentsViewModel.StatusMessage = StatusMessage;
        NotifyAgentCommandCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanRunSelectedDeployedAgentCommand))]
    private async Task RefreshAgentRegistryHealthAsync()
    {
        if (!AgentsViewModel.HasLocalAgent)
        {
            AgentsViewModel.StatusMessage = "No local agent registry entry is configured.";
            return;
        }

        var health = await _agentClient.GetHealthAsync();
        var isActiveSession = health.Health == null || IsAgentConnectedToActiveSession(health);
        AgentsViewModel.ApplyLocalHealth(health, isActiveSession);
        UpdateAgentStatus(health);
        if (health.Success && _agentCaptureWorkflowCoordinator.State.IsReachable)
        {
            _agentCaptureWorkflowCoordinator.MonitorDeployedAgent(
                AgentsViewModel.LocalAgentId);
        }
        NotifyAgentCommandCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanShowAgentHealth))]
    private async Task ShowAgentHealthAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!IsSupportedLocalAgent(agent, "agent health"))
        {
            return;
        }

        var (response, isActiveSession) = await RefreshAgentHealthDialogAsync(CancellationToken.None);

        var dialog = new ProcInsider.AgentHealthDialog(
            AgentHealthDialogViewModel.Create(
                agent!,
                response,
                isActiveSession,
                RefreshAgentHealthDialogAsync,
                _featureAccess.Catalog),
            this)
        {
            Owner = GetDialogOwner(),
            Tag = this
        };

        dialog.ShowDialog();
    }

    private async Task<(AgentIpcResponse Response, bool IsActiveSession)> RefreshAgentHealthDialogAsync(
        CancellationToken cancellationToken)
    {
        var response = await _agentClient.GetHealthAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        var isActiveSession = response.Health != null && IsAgentConnectedToActiveSession(response);
        AgentsViewModel.ApplyLocalHealth(response, response.Health == null || isActiveSession);
        UpdateAgentStatus(response);
        NotifyAgentCommandCanExecuteChanged();
        return (response, isActiveSession);
    }

    [RelayCommand(CanExecute = nameof(CanShowSqlitePerformance))]
    private async Task ShowSqlitePerformanceAsync(AgentRegistryEntryViewModel? agent)
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "SQLite performance"))
        {
            return;
        }

        agent ??= AgentsViewModel.SelectedAgent;
        if (!IsSupportedLocalAgent(agent, "SQLite performance"))
        {
            return;
        }

        SqlitePerformanceDialogViewModel? previous = null;

        async Task<SqlitePerformanceDialogViewModel> RefreshAsync(CancellationToken cancellationToken)
        {
            AgentIpcResponse response;
            try
            {
                response = await _agentClient.GetHealthAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                response = AgentIpcResponse.Failure(Guid.Empty, "SqlitePerformanceRefreshFailed", ex.Message);
            }

            if (response.Success)
            {
                var isActiveSessionForProjection = response.Health == null || IsAgentConnectedToActiveSession(response);
                AgentsViewModel.ApplyLocalHealth(response, isActiveSessionForProjection);
                UpdateAgentStatus(response);
                NotifyAgentCommandCanExecuteChanged();
            }

            var viewModel = SqlitePerformanceDialogViewModel.Create(agent!, response, previous);
            previous = viewModel;
            return viewModel;
        }

        var initialViewModel = await RefreshAsync(CancellationToken.None);
        var dialog = new ProcInsider.SqlitePerformanceDialog(initialViewModel, RefreshAsync)
        {
            Owner = GetDialogOwner(),
            Tag = this
        };
        dialog.ShowDialog();
    }

    private void ShowAgentMonitoringStatusDialog(AgentRegistryEntryViewModel agent)
    {
        var dialog = new ProcInsider.AgentMonitoringStatusDialog(agent, this)
        {
            Owner = GetDialogOwner(),
            Title = $"Monitoring Status - {agent.DisplayName}"
        };

        dialog.ShowDialog();
    }

    [RelayCommand(CanExecute = nameof(CanReconnectRunningLocalAgent))]
    private async Task ReconnectRunningLocalAgentAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.AgentsAndCapture, "Reconnect Agent"))
        {
            return;
        }

        await RecoverRunningLocalAgentAsync(LocalAgentRecoveryOrigin.Manual);
    }

    private async Task<bool> RecoverRunningLocalAgentAsync(LocalAgentRecoveryOrigin origin)
    {
        if (IsLocalAgentRecoveryInProgress || IsAgentViewerConnected)
        {
            return IsAgentViewerConnected;
        }

        IsLocalAgentRecoveryInProgress = true;
        try
        {
            var request = new LocalAgentRecoveryRequest(
                _featureAccess.Catalog,
                FeaturePublication.ReleaseId,
                _captureWorkspaceCoordinator.Generation,
                GetCompatibleAgentExecutableCandidates().ToArray());
            var control = await GetLocalAgentControlCoordinator().ReconnectAsync(
                new LocalAgentReconnectRequest(request));
            var recovery = control.Recovery ?? new LocalAgentRecoveryResult(
                control.Outcome switch
                {
                    LocalAgentControlOutcome.Busy => LocalAgentRecoveryOutcome.Busy,
                    LocalAgentControlOutcome.Canceled => LocalAgentRecoveryOutcome.Canceled,
                    LocalAgentControlOutcome.Superseded => LocalAgentRecoveryOutcome.Superseded,
                    LocalAgentControlOutcome.Absent => LocalAgentRecoveryOutcome.Absent,
                    LocalAgentControlOutcome.InternalFailure => LocalAgentRecoveryOutcome.InternalFailure,
                    _ => LocalAgentRecoveryOutcome.FinalValidationRejected
                },
                control.Diagnostic,
                new LocalAgentDiscoveryResult(
                    LocalAgentDiscoveryOutcome.DiscoveryUnavailable,
                    Array.Empty<AgentPairingDiscoveryRecord>(),
                    Array.Empty<LocalAgentRecoveryCandidate>(),
                    Array.Empty<LocalAgentRecoveryConflict>(),
                    control.Diagnostic));
            ApplyLocalAgentDiscoveryState(recovery.Discovery);
            if (!recovery.Recovered)
            {
                return ProjectLocalAgentRecoveryFailure(recovery, origin);
            }

            var binding = recovery.Binding!;
            if (_captureWorkspaceCoordinator.Generation != request.WorkspaceGeneration)
            {
                StatusMessage = "The active workspace changed while local-agent recovery was validating the prospective target; no recovered binding was attached.";
                return true;
            }

            await BeginStagingLoadOperationAsync("Activating the authenticated local-agent workspace...");
            try
            {
                var transition = await _captureWorkspaceCoordinator.ActivatePreparedLiveCaptureAsync(
                    new ViewerWorkspaceActivation(
                        CaptureWorkspaceMode.LiveCapture,
                        binding.SessionPaths,
                        binding.PackageInfo),
                    CreateWorkspaceTransitionCallbacks(),
                    new Progress<ViewerWorkspaceLifecycleProgress>(progress =>
                        UpdateStagingLoadProgress(
                            progress.CurrentStep,
                            progress.TotalSteps,
                            progress.Message,
                            progress.IsIndeterminate)));
                if (!transition.Succeeded)
                {
                    StatusMessage = transition.PreviousWorkspaceReleased
                        ? $"Authenticated live workspace activation failed after the previous workspace was released: {transition.Error}"
                        : $"Authenticated live workspace activation failed; the current workspace was kept: {transition.Error}";
                    return true;
                }

                if (!string.Equals(_sessionPaths.SessionId, binding.SessionPaths.SessionId, StringComparison.Ordinal) ||
                    !string.Equals(
                        SessionPathService.NormalizeLiveDatabaseIdentity(_sessionPaths.LiveDatabasePath),
                        SessionPathService.NormalizeLiveDatabaseIdentity(binding.SessionPaths.LiveDatabasePath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    StatusMessage = "The activated live workspace does not match the authenticated recovery binding; viewer attachment was blocked.";
                    return true;
                }

                var agent = AgentsViewModel.AddOrUpdateLocalAgent();
                AgentsViewModel.ApplyLocalPairing(binding.ProtectedPairing);
                var attached = _agentCaptureWorkflowCoordinator.AttachVerified(
                    agent.AgentId,
                    binding.AuthenticatedHealthResponse);
                if (!attached.Succeeded || attached.Response == null || attached.Assessment?.Accepted != true)
                {
                    AgentsViewModel.MarkAgentViewerDisconnected(
                        agent,
                        $"Recovery attachment failed: {FirstNonEmpty(attached.State.LastError, attached.Outcome.ToString())}");
                    StatusMessage = "The authenticated local-agent workspace was activated, but the prevalidated binding could not be projected as a viewer attachment.";
                    return true;
                }

                AgentsViewModel.MarkAgentViewerConnected(agent, attached.Response);
                UpdateAgentStatus(attached.Response, observeWorkflow: false);
                await LoadConnectedAgentMonitoringConfigurationAsync(agent);
                ClearLocalAgentStartDiscoveryConflict();
                IsLocalAgentProcessDetected = true;
                NotifyAgentCommandCanExecuteChanged();
                StatusMessage = origin == LocalAgentRecoveryOrigin.Startup
                    ? "The running local agent was securely recovered, its exact live workspace was reopened, and the viewer attached automatically. No process was started and capture or host configuration was not changed."
                    : "The exact live workspace was reopened and the viewer securely reconnected to the existing paired agent without starting another process. Capture and host configuration were not changed.";
                return true;
            }
            catch (Exception ex)
            {
                StatusMessage = $"Authenticated local-agent workspace activation failed without starting another process: {ex.Message}";
                return true;
            }
            finally
            {
                EndStagingLoadOperation();
            }
        }
        finally
        {
            IsLocalAgentRecoveryInProgress = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanManageAgentPairing))]
    private async Task RePairAgentAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanManageAgentPairing(agent))
        {
            StatusMessage = "Connect with the existing valid pairing before rotating it. Missing, corrupt, expired, or revoked pairing requires verified agent replacement.";
            return;
        }

        var confirm = MessageBox.Show(
            Application.Current?.MainWindow,
            "Rotate this local-agent pairing? The exact running agent and session will be revalidated first. Capture, configuration, and evidence state are unchanged.",
            "Rotate Agent Pairing",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (confirm != MessageBoxResult.Yes)
        {
            StatusMessage = "Agent pairing rotation canceled.";
            return;
        }

        var control = await GetLocalAgentControlCoordinator().RotatePairingAsync(
            new LocalAgentPairingRequest(CreateLocalAgentControlTarget(), Confirmed: true));
        if (!control.Succeeded)
        {
            if (control.Response != null)
            {
                UpdateAgentStatus(control.Response, observeWorkflow: false);
            }

            StatusMessage = $"Local-agent re-pair failed closed: {control.Diagnostic}";
            return;
        }

        var status = control.Pairing!;
        AgentsViewModel.ApplyLocalPairing(status, authenticated: true);
        StatusMessage = $"Local-agent pairing rotated to generation {status.PairingGeneration}; the agent process and capture state were unchanged.";
    }

    [RelayCommand(CanExecute = nameof(CanManageAgentPairing))]
    private async Task RevokeAgentPairingAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanManageAgentPairing(agent))
        {
            StatusMessage = "Only a connected, authenticated local agent pairing can be revoked.";
            return;
        }

        var confirm = MessageBox.Show(
            Application.Current?.MainWindow,
            "Revoke this local-agent pairing? The agent keeps running, but reconnect and commands will fail until the verified agent is replaced and paired again. Investigation evidence is not deleted.",
            "Revoke Agent Pairing",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (confirm != MessageBoxResult.Yes)
        {
            StatusMessage = "Agent pairing revocation canceled.";
            return;
        }

        var control = await GetLocalAgentControlCoordinator().RevokePairingAsync(
            new LocalAgentPairingRequest(CreateLocalAgentControlTarget(), Confirmed: true));
        if (!control.Succeeded)
        {
            if (control.Response != null)
            {
                UpdateAgentStatus(control.Response, observeWorkflow: false);
            }

            StatusMessage = $"Local-agent pairing revocation failed closed: {control.Diagnostic}";
            return;
        }

        _agentCaptureWorkflowCoordinator.Disconnect("The local-agent pairing was explicitly revoked.");
        AgentsViewModel.MarkAgentViewerDisconnected(agent, "The local-agent pairing was explicitly revoked.");
        AgentsViewModel.ApplyLocalPairing(new AgentPairingStoreResult(
            AgentPairingState.Revoked,
            control.Pairing?.PairingGeneration ?? agent!.PairingGeneration,
            control.Pairing?.ExpiresAtUtc,
            "The local-agent pairing was explicitly revoked."));
        AgentStatusMessage = "Agent: pairing revoked";
        AgentJobStatusMessage = "Jobs: protected reconnect and commands are blocked";
        StatusMessage = "Local-agent pairing revoked. The agent was not stopped and investigation evidence was not deleted.";
        NotifyAgentCommandCanExecuteChanged();
    }

    private async Task<bool> ConnectAgentForActiveSessionAsync(
        AgentRegistryEntryViewModel? agent,
        bool loadMonitoringConfiguration)
    {
        if (_captureWorkspaceCoordinator.Mode != CaptureWorkspaceMode.LiveCapture)
        {
            StatusMessage = "Agent connection is unavailable while an archived capture is loaded.";
            return false;
        }

        agent ??= AgentsViewModel.SelectedAgent;
        if (!IsSupportedLocalAgent(agent, "connect"))
        {
            return false;
        }

        var connectResult = await _agentCaptureWorkflowCoordinator.ConnectAsync(agent!.AgentId);
        var response = connectResult.Response;
        if (response == null)
        {
            AgentsViewModel.MarkAgentViewerDisconnected(
                agent,
                $"Connect failed: {FirstNonEmpty(connectResult.State.LastError, connectResult.Outcome.ToString())}");
            AgentStatusMessage = "Agent: connection canceled";
            AgentJobStatusMessage = FirstNonEmpty(connectResult.State.LastError, "Agent connection did not complete.");
            StatusMessage = AgentJobStatusMessage;
            return false;
        }

        if (!response.Success)
        {
            ApplyPairingStatusFromResponse(response);
            var detail = FormatAgentIpcFailure(response, "agent unavailable");
            AgentsViewModel.MarkAgentViewerDisconnected(agent, $"Connect failed: {detail}");
            AgentStatusMessage = $"Agent: unavailable ({response.ErrorCode})";
            AgentJobStatusMessage = detail;
            StatusMessage = "Could not connect to the local agent. Start it first or check whether another process owns the local pipe.";
            return false;
        }

        if (connectResult.Assessment?.IsReleaseCompatible != true)
        {
            var releaseMismatch = FormatAgentReleaseProfileMismatch(response.Health);
            AgentsViewModel.ApplyLocalHealth(response, isActiveSession: true);
            AgentsViewModel.MarkAgentViewerDisconnected(agent, $"Connect failed: {releaseMismatch}");
            AgentStatusMessage = "Agent: release mismatch";
            AgentJobStatusMessage = releaseMismatch;
            StatusMessage = releaseMismatch;
            return false;
        }

        if (connectResult.Assessment?.IsExpectedSession != true)
        {
            var mismatch = FormatAgentSessionMismatch(response.Health);
            AgentsViewModel.MarkAgentViewerDisconnected(agent, $"Connect failed: {mismatch}");
            AgentStatusMessage = string.IsNullOrWhiteSpace(response.Health?.DatabasePath)
                ? "Agent: session unverified"
                : "Agent: connected to another session";
            AgentJobStatusMessage = mismatch;
            StatusMessage = "The local agent is not verified for the active SQLite database; this viewer was not connected.";
            return false;
        }

        var identityVerification = VerifyLocalAgentProcess(response.Health);
        if (identityVerification.Outcome != LocalAgentProcessOutcome.VerifiedRunning)
        {
            var identityFailure = FormatLocalAgentIdentityFailure(identityVerification);
            AgentsViewModel.MarkAgentViewerDisconnected(
                agent,
                $"Connect failed: {identityFailure}");
            AgentStatusMessage = "Agent: process identity rejected";
            AgentJobStatusMessage = identityFailure;
            StatusMessage = "The reachable local agent failed exact same-user elevated process verification; this viewer was not connected.";
            return false;
        }

        AgentsViewModel.MarkAgentViewerConnected(agent, response);
        UpdateAgentStatus(response, observeWorkflow: false);
        StatusMessage = "Viewer connected to the local agent. Selected-process commands, polling, and graceful stop are enabled.";
        if (loadMonitoringConfiguration)
        {
            await LoadConnectedAgentMonitoringConfigurationAsync(agent);
        }

        NotifyAgentCommandCanExecuteChanged();
        return true;
    }

    [RelayCommand(CanExecute = nameof(CanStopAgent))]
    private void StopAgent(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanStopAgent(agent))
        {
            StatusMessage = "Reconnect to the selected local agent before terminating it.";
            return;
        }

        ArmPendingAgentTermination(agent!);
        StatusMessage =
            $"Termination is armed for the exact selected agent '{agent!.DisplayName}'. Click Confirm Terminate to request graceful IPC and writer drain, or Cancel.";
    }

    // Once visible, confirmation must reach this handler so stale/runtime gates can report a diagnostic.
    // Do not move those gates into ICommand.CanExecute, which silently discards a rejected WPF click.
    [RelayCommand]
    private async Task ConfirmStopAgentAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        var intentOutcome = _agentTerminationIntentState.TryConsume(
            agent == null ? null : CreateAgentTerminationIntentTarget(agent));
        ClearPendingAgentTermination();
        if (intentOutcome != AgentTerminationIntentConsumeOutcome.Consumed)
        {
            StatusMessage =
                intentOutcome == AgentTerminationIntentConsumeOutcome.NotArmed
                    ? "Agent termination confirmation was not armed. No shutdown request was sent."
                    : "Agent termination confirmation expired because the agent or capture workspace changed. No shutdown request was sent.";
            return;
        }

        await StopConnectedAgentAsync(
            agent,
            "Viewer Terminate Agent command.",
            requireViewerConnection: false);
    }

    [RelayCommand]
    private void CancelStopAgent(AgentRegistryEntryViewModel? agent)
    {
        ClearPendingAgentTermination();
        StatusMessage = "Agent termination canceled. No shutdown request was sent.";
    }

    [RelayCommand]
    private async Task CheckAgentMonitoringConfigurationAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanRunAgentConfigurationCommand(agent, AgentConfigurationTargetKind.HostMonitoring, "configuration checks"))
        {
            return;
        }

        var targetAgent = agent!;
        var result = await _hostMonitoringActionService.Value.CheckConfigurationAsync(
            CreateHostMonitoringActionTarget(targetAgent, requireViewerConnection: true),
            CreateHostMonitoringConfigurationDraft(targetAgent));
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        var response = result.Response;
        ApplyConfigurationCheckResponse(targetAgent, AgentConfigurationTargetKind.HostMonitoring, response);
        if (ShouldShowAgentMonitoringStatusDialog(response))
        {
            ShowAgentMonitoringStatusDialog(targetAgent);
        }
    }

    [RelayCommand]
    private async Task ConfigureAgentMonitoringAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanRunAgentConfigurationCommand(agent, AgentConfigurationTargetKind.HostMonitoring, "monitoring configuration"))
        {
            return;
        }

        var targetAgent = agent!;
        var settings = ShowHostMonitoringConfigurationDialog(
            targetAgent,
            "Apply",
            "Configure Monitoring",
            targetAgent.HostMonitoringConfiguration);
        if (settings == null)
        {
            StatusMessage = "Monitoring configuration canceled.";
            return;
        }

        if (!await SaveAgentMonitoringConfigurationAsync(targetAgent, requireViewerConnection: true, settings))
        {
            return;
        }

        await DeploySavedAgentMonitoringConfigurationAsync(targetAgent, showConfirmation: true);
    }

    [RelayCommand]
    private async Task DeployAgentMonitoringConfigurationAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanRunAgentConfigurationCommand(agent, AgentConfigurationTargetKind.HostMonitoring, "monitoring deployment"))
        {
            return;
        }

        await DeploySavedAgentMonitoringConfigurationAsync(agent!, showConfirmation: true);
    }

    private async Task<bool> DeploySavedAgentMonitoringConfigurationAsync(
        AgentRegistryEntryViewModel targetAgent,
        bool showConfirmation)
    {
        if (!HasSavedMonitoringConfiguration(targetAgent))
        {
            StatusMessage = "Save or configure monitoring before deploying it through the agent.";
            return false;
        }

        if (showConfirmation)
        {
            var warning =
                "Deploy monitoring configuration through the selected local agent?\n\n" +
                "This may change Sysmon configuration, Windows audit policy, command-line logging, event-log retention, PowerShell auditing, and scheduled dump policy.\n\n" +
                "Deployment does not start capture.";
            if (MessageBox.Show(warning, "Deploy Monitoring Configuration", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                StatusMessage = "Monitoring deployment canceled.";
                return false;
            }
        }

        var result = await _hostMonitoringActionService.Value.DeploySavedConfigurationAsync(
            CreateHostMonitoringActionTarget(targetAgent, requireViewerConnection: true));
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        var response = result.Response;
        ApplyMonitoringDeploymentResponse(targetAgent, response);
        return response?.MonitoringDeployment != null;
    }

    [RelayCommand(CanExecute = nameof(CanReverseAgentMonitoringDeployment))]
    private async Task ReverseAgentMonitoringDeploymentAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanRunAgentConfigurationCommand(agent, AgentConfigurationTargetKind.HostMonitoring, "monitoring reverse deployment"))
        {
            return;
        }

        var targetAgent = agent!;
        var warning =
            $"Reverse the {ProductIdentity.DisplayName} monitoring deployment through the selected local agent?\n\n" +
            "Only settings with recorded pre-deployment state are restored. Unsupported areas return manual cleanup guidance instead of guessing.";
        if (MessageBox.Show(warning, "Reverse Monitoring Deployment", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            StatusMessage = "Monitoring reverse deployment canceled.";
            return;
        }

        var result = await _hostMonitoringActionService.Value.ReverseSavedDeploymentAsync(
            CreateHostMonitoringActionTarget(targetAgent, requireViewerConnection: true));
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        ApplyMonitoringDeploymentResponse(targetAgent, result.Response);
    }

    private async Task LoadConnectedAgentMonitoringConfigurationAsync(AgentRegistryEntryViewModel targetAgent)
    {
        var result = await _hostMonitoringActionService.Value.GetConfigurationAsync(
            CreateHostMonitoringActionTarget(targetAgent, requireViewerConnection: false));
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        var response = result.Response;

        if (response?.HostMonitoringConfiguration != null)
        {
            ApplyHostMonitoringConfigurationResponse(targetAgent, response);
            StatusMessage = "Viewer connected to the local agent. Monitoring configuration and original baseline status were refreshed.";
        }
    }

    [RelayCommand]
    private async Task CheckAgentCaptureConfigurationAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanRunAgentConfigurationCommand(agent, AgentConfigurationTargetKind.Capture, "configuration checks"))
        {
            return;
        }

        var targetAgent = agent!;
        var result = await _agentCaptureActionService.CheckConfigurationAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: true),
            CreateCaptureConfigurationDraft(
                targetAgent,
                AgentCaptureOptionViewModel.CloneOptions(targetAgent.CaptureOptions)));
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        ApplyConfigurationCheckResponse(
            targetAgent,
            AgentConfigurationTargetKind.Capture,
            result.Response);
    }

    [RelayCommand]
    private async Task ConfigureAgentCaptureAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!CanRunAgentConfigurationCommand(agent, AgentConfigurationTargetKind.Capture, "capture configuration"))
        {
            return;
        }

        var targetAgent = agent!;
        var options = ShowCaptureConfigurationDialog(targetAgent, "Save", "Configure Capture");
        if (options == null)
        {
            StatusMessage = "Capture configuration canceled.";
            return;
        }

        targetAgent.ApplyCaptureOptionSelections(options);
        await SaveAgentCaptureConfigurationAsync(targetAgent, requireViewerConnection: true, options);
    }

    [RelayCommand(CanExecute = nameof(CanStartAgentConfiguredCapture))]
    private async Task StartAgentConfiguredCaptureAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!RequireDeployedAgentCommand(agent, "configured capture start"))
        {
            return;
        }

        var targetAgent = agent!;
        var availability = EvaluateAgentConfiguredCaptureAvailability(targetAgent);
        if (availability.CanResume)
        {
            var resumed = await _agentCaptureActionService.ResumeConfiguredCaptureAsync(
                CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: false));
            ApplyCaptureLifecycleResponse(targetAgent, resumed.Response);
            TrackConfiguredCaptureJobs(resumed.Response, affected: true);
            if (resumed.Response?.Success == true)
            {
                _agentCaptureWorkflowCoordinator.BeginPendingCapture(
                    AgentCapturePendingAction.Resume,
                    targetAgent.ActiveCaptureId);
                StatusMessage = "Configured capture resume accepted; acquisition is restarting under the existing provenance.";
            }
            else
            {
                StatusMessage = resumed.Diagnostic;
            }

            return;
        }

        if (!availability.CanStart)
        {
            StatusMessage = availability.StartUnavailableReason;
            return;
        }

        var options = ShowCaptureConfigurationDialog(targetAgent, "Start", "Start Capture");
        if (options == null)
        {
            StatusMessage = "Configured capture start canceled.";
            return;
        }

        targetAgent.ApplyCaptureOptionSelections(options);
        if (!await SaveAgentCaptureConfigurationAsync(targetAgent, requireViewerConnection: false, options))
        {
            return;
        }

        await StartSavedAgentConfiguredCaptureAsync(targetAgent);
    }

    private async Task<bool> StartSavedAgentConfiguredCaptureAsync(AgentRegistryEntryViewModel targetAgent)
    {
        var result = await _agentCaptureActionService.StartConfiguredCaptureAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: false));
        var response = result.Response;
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        ApplyCaptureLifecycleResponse(targetAgent, response);
        TrackConfiguredCaptureJobs(response);
        if (response?.Success == true)
        {
            _agentCaptureWorkflowCoordinator.BeginPendingCapture(
                AgentCapturePendingAction.Start,
                response.CaptureLifecycle?.CaptureId ?? targetAgent.ActiveCaptureId);
        }
        UpdateAgentCaptureRuntimeRows();
        return response?.Success == true && response.CaptureLifecycle != null;
    }

    [RelayCommand(CanExecute = nameof(CanPauseAgentConfiguredCapture))]
    private async Task PauseAgentConfiguredCaptureAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!RequireDeployedAgentCommand(agent, "configured capture pause"))
        {
            return;
        }

        var targetAgent = agent!;
        var availability = EvaluateAgentConfiguredCaptureAvailability(targetAgent);
        if (!availability.CanPause)
        {
            StatusMessage = availability.PauseUnavailableReason;
            return;
        }

        var paused = await _agentCaptureActionService.PauseConfiguredCaptureAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: false));
        ApplyCaptureLifecycleResponse(targetAgent, paused.Response);
        TrackConfiguredCaptureJobs(paused.Response, affected: true);
        if (paused.Response?.Success == true)
        {
            _agentCaptureWorkflowCoordinator.BeginPendingCapture(
                AgentCapturePendingAction.Pause,
                targetAgent.ActiveCaptureId);
            StatusMessage = "Configured capture pause accepted; collectors are stopping and accepted writes are draining.";
        }
        else
        {
            StatusMessage = paused.Diagnostic;
        }
    }

    [RelayCommand(CanExecute = nameof(CanStopAgentConfiguredCapture))]
    private async Task StopAgentConfiguredCaptureAsync(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        if (!RequireDeployedAgentCommand(agent, "configured capture stop"))
        {
            return;
        }

        var targetAgent = agent!;
        var availability = EvaluateAgentConfiguredCaptureAvailability(targetAgent);
        if (!availability.CanEnd)
        {
            StatusMessage = availability.EndUnavailableReason;
            return;
        }

        if (MessageBox.Show(
                "End this configured capture permanently? Pause Capture keeps the same capture, jobs, and source-run provenance available for resume.",
                "End Capture",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            StatusMessage = "Configured capture end canceled.";
            return;
        }

        var result = await _agentCaptureActionService.StopConfiguredCaptureAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: false));
        var response = result.Response;
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        ApplyCaptureLifecycleResponse(targetAgent, response);
        TrackConfiguredCaptureJobs(response, affected: true);
        if (response?.Success == true)
        {
            _agentCaptureWorkflowCoordinator.BeginPendingCapture(
                AgentCapturePendingAction.Stop,
                targetAgent.ActiveCaptureId);
            StatusMessage = "Configured capture stop accepted; waiting for authoritative stop/drain completion.";
        }
    }

    [RelayCommand(CanExecute = nameof(CanStartAgentSqliteBenchmark))]
    private async Task StartAgentSqliteBenchmarkAsync(AgentRegistryEntryViewModel? agent)
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "SQLite benchmark"))
        {
            return;
        }

        agent ??= AgentsViewModel.SelectedAgent;
        if (!RequireDeployedAgentCommand(agent, "SQLite benchmark"))
        {
            return;
        }

        var targetAgent = agent!;
        UpdateAgentBenchmarkPreflight(targetAgent);
        if (!CanStartAgentSqliteBenchmark(targetAgent))
        {
            var message = "A SQLite benchmark is already active.";
            targetAgent.ApplyBenchmarkUnavailable(message);
            StatusMessage = message;
            return;
        }

        var action = await _agentToolActionService.StartSqliteBenchmarkAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: false),
            new ViewerSqliteBenchmarkActionRequest());
        var response = action.Response;

        if (response?.Success == true)
        {
            _activeSqliteBenchmarkJobId = response.AcceptedJobId ?? response.Job?.JobId;
            if (response.Job != null)
            {
                ApplySqliteBenchmarkProgress(response.Job);
            }

            StatusMessage = "SQLite benchmark queued. Progress and report paths will appear in Agent health.";
            NotifySqliteBenchmarkStateChanged();
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            NotifySqliteBenchmarkStateChanged();
            return;
        }

        var detail = response == null
            ? FirstNonEmpty(action.Diagnostic, StatusMessage, "Agent unavailable for SQLite benchmark.")
            : FormatAgentIpcFailure(response, "agent did not start SQLite benchmark");
        targetAgent.ApplyBenchmarkUnavailable(detail);
        StatusMessage = detail;
        NotifySqliteBenchmarkStateChanged();
    }

    [RelayCommand(CanExecute = nameof(CanCancelAgentSqliteBenchmark))]
    private async Task CancelAgentSqliteBenchmarkAsync(AgentRegistryEntryViewModel? agent)
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "SQLite benchmark cancel"))
        {
            return;
        }

        agent ??= AgentsViewModel.SelectedAgent;
        if (!RequireDeployedAgentCommand(agent, "SQLite benchmark cancel"))
        {
            return;
        }

        if (!_activeSqliteBenchmarkJobId.HasValue)
        {
            StatusMessage = "No active SQLite benchmark is available to cancel.";
            return;
        }

        var captureResult = await _agentCaptureActionService.CancelJobAsync(
            CreateAgentCaptureActionTarget(agent!, requireViewerConnection: false),
            _activeSqliteBenchmarkJobId.Value);
        var response = captureResult.Response;
        if (!captureResult.Succeeded)
        {
            StatusMessage = captureResult.Diagnostic;
        }

        if (response?.Job != null)
        {
            ApplySqliteBenchmarkProgress(response.Job);
        }

        if (response?.Success == true)
        {
            StatusMessage = "SQLite benchmark cancellation requested.";
        }
        else if (PreserveUnknownAgentCommandOutcome(response))
        {
            NotifySqliteBenchmarkStateChanged();
            return;
        }
        else
        {
            var detail = response == null
                ? FirstNonEmpty(StatusMessage, "Agent unavailable for SQLite benchmark cancel.")
                : FormatAgentIpcFailure(response, "agent did not cancel SQLite benchmark");
            agent!.ApplyBenchmarkUnavailable(detail);
            StatusMessage = detail;
        }

        NotifySqliteBenchmarkStateChanged();
    }

    private async Task<bool> SaveAgentCaptureConfigurationAsync(
        AgentRegistryEntryViewModel targetAgent,
        bool requireViewerConnection,
        IReadOnlyList<AgentCaptureOptionViewModel>? captureOptions = null)
    {
        var draft = CreateCaptureConfigurationDraft(targetAgent, captureOptions);
        var result = await _agentCaptureActionService.SaveConfigurationAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection),
            draft);
        var response = result.Response;
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        ApplyCaptureConfigurationResponse(targetAgent, response);
        UpdateAgentCaptureRuntimeRows();
        return response?.CaptureConfiguration != null;
    }

    private async Task<bool> SaveAgentMonitoringConfigurationAsync(
        AgentRegistryEntryViewModel targetAgent,
        bool requireViewerConnection,
        HostMonitoringConfigurationViewModel? settings = null)
    {
        var draft = CreateHostMonitoringConfigurationDraft(targetAgent, settings);
        var result = await _hostMonitoringActionService.Value.SaveConfigurationAsync(
            CreateHostMonitoringActionTarget(targetAgent, requireViewerConnection),
            draft);
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        var response = result.Response;
        ApplyHostMonitoringConfigurationResponse(targetAgent, response);
        return response?.HostMonitoringConfiguration != null;
    }

    private bool CanRunAgentConfigurationCommand(AgentRegistryEntryViewModel? agent, AgentConfigurationTargetKind targetKind, string actionName)
    {
        var featureId = targetKind == AgentConfigurationTargetKind.HostMonitoring
            ? FeatureIds.SecurityMonitoringConfiguration
            : FeatureIds.AgentsAndCapture;
        if (!RequireFeaturePublished(featureId, actionName))
        {
            return false;
        }

        if (agent == null)
        {
            StatusMessage = $"Select an agent before running {actionName}.";
            return false;
        }

        if (!IsSupportedLocalAgent(agent, actionName))
        {
            AgentsViewModel.MarkConfigurationCheckUnavailable(
                agent,
                targetKind,
                $"Only the local named-pipe agent supports {actionName} in this build.");
            return false;
        }

        if (!IsAgentViewerConnected || !agent.IsViewerConnected)
        {
            var message = $"Connect to the selected agent before running {actionName}.";
            AgentsViewModel.MarkConfigurationCheckUnavailable(agent, targetKind, message);
            StatusMessage = message;
            return false;
        }

        return true;
    }

    private bool CanDeployAgent(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        return _featureAccess.CanExecute(FeatureIds.AgentsAndCapture, agent != null &&
               _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.LiveCapture &&
               !_isLocalAgentSetupInProgress &&
               !IsAgentShutdownInProgress &&
               !_localAgentStartBlockedByDiscoveryConflict &&
               !agent.IsViewerConnected &&
               IsLocalAgentControlTarget(agent) &&
               agent.DeploymentState is not AgentDeploymentState.Deployed and not AgentDeploymentState.Available);
    }

    private bool CanStopAgent(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        return !_agentTerminationIntentState.IsArmed &&
               CanStopAgentTarget(agent);
    }

    private bool CanStopAgentTarget(AgentRegistryEntryViewModel? agent) =>
        _featureAccess.CanExecute(FeatureIds.AgentsAndCapture, IsAgentViewerConnected &&
               !IsAgentShutdownInProgress &&
               !IsAgentLateExitObservationActive &&
               agent?.IsViewerConnected == true &&
               IsLocalAgentControlTarget(agent));

    private void ArmPendingAgentTermination(AgentRegistryEntryViewModel agent)
    {
        ClearPendingAgentTermination();
        _agentTerminationIntentState.Arm(CreateAgentTerminationIntentTarget(agent));
        agent.IsTerminationConfirmationPending = true;
        NotifyAgentTerminationCommandCanExecuteChanged();
    }

    private void ClearPendingAgentTermination()
    {
        _agentTerminationIntentState.Cancel();
        if (_featureModules.TryGetActivated<AgentFeatureModule>(
                FeatureIds.AgentsAndCapture,
                out var agentFeature))
        {
            foreach (var agent in agentFeature.AgentsViewModel.Agents)
            {
                agent.IsTerminationConfirmationPending = false;
            }
        }

        NotifyAgentTerminationCommandCanExecuteChanged();
    }

    private AgentTerminationIntentTarget CreateAgentTerminationIntentTarget(
        AgentRegistryEntryViewModel agent) =>
        new(
            agent.AgentId,
            agent.HostId,
            agent.TransportKind,
            agent.Endpoint,
            _captureWorkspaceCoordinator.Generation,
            _sessionPaths.SessionId,
            _sessionPaths.LiveDatabasePath);

    private void NotifyAgentTerminationCommandCanExecuteChanged()
    {
        StopAgentCommand.NotifyCanExecuteChanged();
    }

    private bool CanAddAgent() =>
        FeaturePublication.AgentsAndCapture &&
        !_isLocalAgentSetupInProgress &&
        !IsLocalAgentRecoveryInProgress &&
        !IsAgentViewerConnected;

    private bool CanReconnectRunningLocalAgent() =>
        FeaturePublication.AgentsAndCapture &&
        !IsLocalAgentRecoveryInProgress &&
        !IsAgentViewerConnected;

    private bool CanUseConnectedAgent()
    {
        return _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.LiveCapture &&
               IsAgentViewerConnected &&
               !IsAgentShutdownInProgress &&
               !IsAgentLateExitObservationActive;
    }

    private bool CanManageAgentPairing(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        return _featureAccess.CanExecute(
            FeatureIds.AgentsAndCapture,
            agent?.IsViewerConnected == true &&
            IsAgentViewerConnected &&
            IsLocalAgentControlTarget(agent) &&
            agent.PairingState is AgentPairingState.Ready or AgentPairingState.Connected);
    }

    private bool CanUseAgentCapture() =>
        _featureAccess.CanExecute(FeatureIds.AgentsAndCapture, CanUseConnectedAgent());

    private bool CanUseAiFeature() => FeaturePublication.AiAssistance;

    private bool CanUseSecurityMonitoringFeature() => FeaturePublication.SecurityMonitoringConfiguration;

    private bool CanUseEventTelemetryFeature() => FeaturePublication.EventTelemetry;

    private bool CanImportFilesystemArtifacts() =>
        _featureAccess.CanExecute(FeatureIds.FilesystemArtifacts, CanUseConnectedAgent());

    private bool CanUseSystemMemoryFeature() =>
        _featureAccess.CanExecute(FeatureIds.SystemMemoryAndVolatility, CanUseConnectedAgent());

    private bool CanRunArtifactEnrichmentFeature() =>
        (FeaturePublication.ModulesAndHandles || FeaturePublication.DumpsAndPeAnalysis) &&
        CanRunDerivedAgentCommand();

    private bool CanRefreshViewFromStaging()
    {
        return _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.LiveCapture &&
               !IsAgentShutdownInProgress &&
               !IsRefreshing;
    }

    private bool CanOpenSessionFolder()
    {
        return HasAvailableCaptureFolder();
    }

    private bool HasAvailableCaptureDatabase()
    {
        return File.Exists(_sessionPaths.LiveDatabasePath);
    }

    private bool HasAvailableCaptureFolder()
    {
        return HasActiveCaptureSession() &&
               Directory.Exists(_sessionPaths.SessionRoot);
    }

    private bool HasActiveCaptureSession()
    {
        return _captureWorkspaceCoordinator.Mode is CaptureWorkspaceMode.LiveCapture or CaptureWorkspaceMode.ArchivedCapture;
    }

    private bool CanRunSelectedDeployedAgentCommand()
    {
        return _featureAccess.CanExecute(
            FeatureIds.AgentsAndCapture,
            CanRunDeployedAgentCommand(AgentsViewModel.SelectedAgent));
    }

    private bool CanRunDerivedAgentCommand()
    {
        if (_captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.ArchivedCapture)
        {
            return !IsAgentShutdownInProgress &&
                   TryGetActiveLiveDatabasePath(out var databasePath) &&
                   File.Exists(databasePath);
        }

        return CanRunDeployedAgentCommand(AgentsViewModel.SelectedAgent);
    }

    private bool CanShowAgentHealth(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        return _featureAccess.CanExecute(FeatureIds.AgentsAndCapture, agent != null &&
               !IsAgentShutdownInProgress &&
               IsLocalAgentControlTarget(agent));
    }

    private bool CanShowSqlitePerformance(AgentRegistryEntryViewModel? agent) =>
        _featureAccess.CanExecute(FeatureIds.EventTelemetry, CanShowAgentHealth(agent));

    private bool CanStartAgentConfiguredCapture(AgentRegistryEntryViewModel? agent)
    {
        var availability = EvaluateAgentConfiguredCaptureAvailability(agent);
        return availability.CanStart || availability.CanResume;
    }

    private bool CanPauseAgentConfiguredCapture(AgentRegistryEntryViewModel? agent)
    {
        return EvaluateAgentConfiguredCaptureAvailability(agent).CanPause;
    }

    private bool CanStopAgentConfiguredCapture(AgentRegistryEntryViewModel? agent)
    {
        return EvaluateAgentConfiguredCaptureAvailability(agent).CanEnd;
    }

    private AgentConfiguredCaptureAvailability EvaluateAgentConfiguredCaptureAvailability(
        AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        var isSelectedLocalAgent = IsLocalAgentControlTarget(agent);
        var workflow = _agentCaptureWorkflowCoordinator.State;
        return AgentConfiguredCaptureAvailabilityPolicy.Evaluate(
            new AgentConfiguredCaptureAvailabilityContext
            {
                IsFeaturePublished = _featureAccess.CanExecute(
                    FeatureIds.AgentsAndCapture,
                    runtimePrerequisites: true),
                WorkspaceMode = _captureWorkspaceCoordinator.Mode,
                IsShutdownInProgress = IsAgentShutdownInProgress,
                HasSelectedLocalAgent = isSelectedLocalAgent,
                IsVerifiedAgentReachable = isSelectedLocalAgent &&
                    IsAgentCommandReachable(agent!) &&
                    workflow.IsReachable &&
                    string.Equals(
                        workflow.MonitoredAgentId,
                        agent!.AgentId,
                        StringComparison.Ordinal),
                PairingState = agent?.PairingState ?? AgentPairingState.Unknown,
                HasActiveSqliteBenchmark = _activeSqliteBenchmarkJobId.HasValue,
                Control = workflow.Control
            });
    }

    private ViewerAgentCaptureActionTarget CreateAgentCaptureActionTarget(
        AgentRegistryEntryViewModel agent,
        bool requireViewerConnection) =>
        new(
            agent.AgentId,
            FirstNonEmpty(agent.HostId, Environment.MachineName),
            _sessionPaths.SessionId,
            _sessionPaths.SessionRoot,
            _captureWorkspaceCoordinator.Generation,
            requireViewerConnection,
            _sessionPaths.DumpsDirectory,
            _sessionPaths.NetworkCapturesDirectory,
            _sessionPaths.ZeekDirectory,
            _sessionPaths.ProcessMonitorDirectory,
            _sessionPaths.BenchmarkDirectory,
            _sessionPaths.MemoryDirectory);

    private ViewerHostMonitoringActionTarget CreateHostMonitoringActionTarget(
        AgentRegistryEntryViewModel agent,
        bool requireViewerConnection) =>
        new(
            agent.AgentId,
            FirstNonEmpty(agent.HostId, Environment.MachineName),
            _sessionPaths.SessionId,
            _sessionPaths.SessionRoot,
            _captureWorkspaceCoordinator.Generation,
            requireViewerConnection);

    private bool IsAnyTrackedCaptureActive(bool includeStopping)
    {
        return _agentCaptureWorkflowCoordinator.Control.State switch
        {
            AgentCaptureRunState.Starting or AgentCaptureRunState.Running => true,
            AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining => includeStopping,
            _ => false
        };
    }

    private bool IsLiveCaptureActive(bool includeStopping)
    {
        return IsProjectedSourceActive(
            _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.LiveCapture),
            includeStopping);
    }

    private bool IsNetworkCaptureActiveForCommands(bool includeStopping)
    {
        return IsProjectedSourceActive(
            _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.NetworkCapture),
            includeStopping);
    }

    private bool IsProcessMonitorCaptureActiveForCommands(bool includeStopping)
    {
        return IsProjectedSourceActive(
            _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.ProcessMonitorCapture),
            includeStopping);
    }

    private static bool IsProjectedSourceActive(
        AgentCaptureSourceControlState source,
        bool includeStopping)
        => source.State is AgentCaptureRunState.Starting or AgentCaptureRunState.Running ||
           includeStopping && source.State is AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining;

    private bool CanStartLiveCapture()
    {
        var source = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.LiveCapture);
        return CanUseAgentCapture() && !_activeSqliteBenchmarkJobId.HasValue && source.CanStart;
    }

    private bool CanStopLiveCapture()
    {
        var source = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.LiveCapture);
        return CanUseAgentCapture() && source.CanStop;
    }

    private bool CanStartNetworkCapture()
    {
        var source = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.NetworkCapture);
        return CanRunNetworkTabAgentCommand() &&
               !_activeSqliteBenchmarkJobId.HasValue &&
               source.CanStart;
    }

    private bool CanStopNetworkCapture()
    {
        var source = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.NetworkCapture);
        return CanRunNetworkTabAgentCommand() && source.CanStop;
    }

    private bool CanStartProcessMonitorCapture()
    {
        var source = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.ProcessMonitorCapture);
        return CanRunProcessMonitorAgentCommand() &&
               !_activeSqliteBenchmarkJobId.HasValue &&
               source.CanStart;
    }

    private bool CanStopProcessMonitorCapture()
    {
        var source = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.ProcessMonitorCapture);
        return CanRunProcessMonitorAgentCommand() &&
               source.CanStop;
    }

    private bool CanRunNetworkTabAgentCommand()
    {
        var localAgent = GetLocalAgent();
        return _featureAccess.CanExecute(FeatureIds.NetworkAndZeek, localAgent != null &&
               _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.LiveCapture &&
               !IsAgentShutdownInProgress &&
               IsAgentCommandReachable(localAgent));
    }

    private bool CanRunProcessMonitorAgentCommand()
    {
        var localAgent = GetLocalAgent();
        return _featureAccess.CanExecute(FeatureIds.EventTelemetry, localAgent != null &&
               _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.LiveCapture &&
               !IsAgentShutdownInProgress &&
               IsAgentCommandReachable(localAgent));
    }

    private bool RequireFeaturePublished(FeatureId featureId, string actionName)
    {
        if (_featureAccess.TryAccess(featureId, out var unavailableMessage))
        {
            return true;
        }

        StatusMessage = $"{actionName} is unavailable. {unavailableMessage}";
        return false;
    }

    public bool TryNavigateToExplorerTab(FeatureTabKey tabKey, string actionName)
        => _viewerNavigationCoordinator.NavigateToExplorerTab(tabKey, actionName).Succeeded;

    public bool TryNavigateToDataTab(FeatureTabKey tabKey, string actionName)
        => _viewerNavigationCoordinator.NavigateToDataTab(tabKey, actionName).Succeeded;

    private void OnViewerNavigationStateChanged(
        object? sender,
        ViewerNavigationStateChangedEventArgs e)
        => ApplyViewerNavigationState(e.State);

    private void ApplyViewerNavigationState(ViewerNavigationState state)
    {
        var dataSelectionChanged = !ReferenceEquals(SelectedDataTab, state.DataSelection);
        _isApplyingViewerNavigationState = true;
        try
        {
            IsNetworkDataTabVisible = state.IncludeNetworkData;
            IsFilesystemDataTabVisible = state.IncludeFilesystemData;
            if (!ReferenceEquals(SelectedExplorerTab, state.ExplorerSelection))
            {
                SelectedExplorerTab = state.ExplorerSelection;
            }

            if (!ReferenceEquals(SelectedDataTab, state.DataSelection))
            {
                SelectedDataTab = state.DataSelection;
            }
        }
        finally
        {
            _isApplyingViewerNavigationState = false;
        }

        OnPropertyChanged(nameof(ExplorerTabs));
        OnPropertyChanged(nameof(DataTabs));
        if (!string.IsNullOrWhiteSpace(state.StatusMessage))
        {
            StatusMessage = state.StatusMessage;
        }

        if (dataSelectionChanged)
        {
            QueueSelectedDataTabEnrichmentIfNeeded();
        }
    }

    private bool CanRunDeployedAgentCommand(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        return agent != null &&
               _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.LiveCapture &&
               !IsAgentShutdownInProgress &&
               IsLocalAgentControlTarget(agent) &&
               IsAgentCommandReachable(agent);
    }

    private bool CanStartAgentSqliteBenchmark(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        return _featureAccess.CanExecute(
            FeatureIds.EventTelemetry,
            CanRunDeployedAgentCommand(agent) && !_activeSqliteBenchmarkJobId.HasValue);
    }

    private bool CanCancelAgentSqliteBenchmark(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        return _featureAccess.CanExecute(
            FeatureIds.EventTelemetry,
            CanRunDeployedAgentCommand(agent) && _activeSqliteBenchmarkJobId.HasValue);
    }

    private bool IsAgentCommandReachable(AgentRegistryEntryViewModel agent)
    {
        return agent.DeploymentState is AgentDeploymentState.Deployed or AgentDeploymentState.Available ||
               IsAgentViewerConnected && agent.IsViewerConnected;
    }

    private bool CanReverseAgentMonitoringDeployment(AgentRegistryEntryViewModel? agent)
    {
        agent ??= AgentsViewModel.SelectedAgent;
        return _featureAccess.CanExecute(FeatureIds.SecurityMonitoringConfiguration, agent != null &&
               !IsAgentShutdownInProgress &&
               IsAgentViewerConnected &&
               agent.IsViewerConnected &&
               agent.HasMonitoringOriginalState &&
               IsLocalAgentControlTarget(agent));
    }

    private bool RequireDeployedAgentCommand(AgentRegistryEntryViewModel? agent, string actionName)
    {
        if (!IsSupportedLocalAgent(agent, actionName))
        {
            return false;
        }

        if (IsAgentShutdownInProgress)
        {
            StatusMessage = $"Agent shutdown is in progress; cannot run {actionName}.";
            return false;
        }

        if (agent!.DeploymentState is AgentDeploymentState.Deployed or AgentDeploymentState.Available)
        {
            return true;
        }

        StatusMessage = $"Deploy the selected agent before running {actionName}.";
        return false;
    }

    private bool RequireNetworkTabAgentCommand(string actionName)
    {
        if (!RequireFeaturePublished(FeatureIds.NetworkAndZeek, actionName))
        {
            return false;
        }

        var localAgent = GetLocalAgent();
        if (localAgent == null)
        {
            StatusMessage = $"Add and deploy the local agent before running {actionName}.";
            return false;
        }

        if (IsAgentShutdownInProgress)
        {
            StatusMessage = $"Agent shutdown is in progress; cannot run {actionName}.";
            return false;
        }

        if (localAgent.DeploymentState is AgentDeploymentState.Deployed or AgentDeploymentState.Available)
        {
            return true;
        }

        StatusMessage = $"Deploy the local agent before running {actionName}.";
        return false;
    }

    private AgentRegistryEntryViewModel? GetLocalAgent()
    {
        var agentsViewModel = AgentFeature?.AgentsViewModel;
        return agentsViewModel?.Agents.FirstOrDefault(IsLocalAgentControlTarget);
    }

    private bool RequireConnectedAgent(string actionName)
    {
        if (IsAgentViewerConnected)
        {
            return true;
        }

        StatusMessage = $"Connect to an agent before running {actionName}.";
        return false;
    }

    private bool IsSupportedLocalAgent(AgentRegistryEntryViewModel? agent, string actionName)
    {
        if (agent == null)
        {
            StatusMessage = $"Select an agent before running {actionName}.";
            return false;
        }

        if (IsLocalAgentControlTarget(agent))
        {
            return true;
        }

        StatusMessage = $"Only the local named-pipe agent supports {actionName} in this build.";
        return false;
    }

    private static bool IsLocalAgentControlTarget(AgentRegistryEntryViewModel? agent) =>
        agent != null &&
        !agent.IsInfrastructureProjection &&
        agent.TransportKind == AgentTransportKind.LocalNamedPipe &&
        string.Equals(agent.AgentId, AgentsViewModel.LocalAgentId, StringComparison.Ordinal);

    private static bool HasSavedMonitoringConfiguration(AgentRegistryEntryViewModel agent)
    {
        return !string.IsNullOrWhiteSpace(agent.ConfigurationHash) &&
               !string.Equals(agent.ConfigurationHash, "pending", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasSavedCaptureConfiguration(AgentRegistryEntryViewModel agent)
    {
        return !string.IsNullOrWhiteSpace(agent.CaptureConfigurationHash) &&
               !string.Equals(agent.CaptureConfigurationHash, "pending", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasSelectedConfigurableCaptureOptions(IEnumerable<AgentCaptureOptionViewModel> captureOptions)
    {
        return captureOptions.Any(option => option.CanConfigure && option.IsIncluded);
    }

    private void ApplyHostMonitoringConfigurationResponse(
        AgentRegistryEntryViewModel agent,
        AgentIpcResponse? response)
    {
        if (response?.HostMonitoringConfiguration != null)
        {
            AgentsViewModel.ApplyHostMonitoringConfiguration(agent, response.HostMonitoringConfiguration);
            StatusMessage = agent.LastConfigurationCheckSummary;
            NotifyAgentCommandCanExecuteChanged();
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        var message = response == null
            ? FirstNonEmpty(StatusMessage, "Agent unavailable for monitoring configuration.")
            : FirstNonEmpty(response.ErrorMessage, response.ErrorCode, "Agent did not return a monitoring configuration.");
        AgentsViewModel.MarkConfigurationCheckUnavailable(agent, AgentConfigurationTargetKind.HostMonitoring, message);
        StatusMessage = message;
        NotifyAgentCommandCanExecuteChanged();
    }

    private void ApplyMonitoringDeploymentResponse(
        AgentRegistryEntryViewModel agent,
        AgentIpcResponse? response)
    {
        if (response?.MonitoringDeployment != null)
        {
            AgentsViewModel.ApplyMonitoringDeployment(agent, response.MonitoringDeployment);
            StatusMessage = agent.LastConfigurationCheckSummary;
            NotifyAgentCommandCanExecuteChanged();
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        var message = response == null
            ? FirstNonEmpty(StatusMessage, "Agent unavailable for monitoring deployment.")
            : FirstNonEmpty(response.ErrorMessage, response.ErrorCode, "Agent did not return monitoring deployment results.");
        AgentsViewModel.MarkConfigurationCheckUnavailable(agent, AgentConfigurationTargetKind.HostMonitoring, message);
        StatusMessage = message;
        NotifyAgentCommandCanExecuteChanged();
    }

    private void ApplyCaptureConfigurationResponse(
        AgentRegistryEntryViewModel agent,
        AgentIpcResponse? response)
    {
        if (response?.CaptureConfiguration != null)
        {
            AgentsViewModel.ApplyCaptureConfiguration(agent, response.CaptureConfiguration);
            StatusMessage = agent.CaptureStatusSummary;
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        var message = response == null
            ? FirstNonEmpty(StatusMessage, "Agent unavailable for capture configuration.")
            : FirstNonEmpty(response.ErrorMessage, response.ErrorCode, "Agent did not return a capture configuration.");
        AgentsViewModel.MarkConfigurationCheckUnavailable(agent, AgentConfigurationTargetKind.Capture, message);
        StatusMessage = message;
    }

    private void ApplyCaptureLifecycleResponse(
        AgentRegistryEntryViewModel agent,
        AgentIpcResponse? response)
    {
        if (response?.CaptureLifecycle != null)
        {
            AgentsViewModel.ApplyCaptureLifecycle(agent, response.CaptureLifecycle);
            StatusMessage = agent.CaptureStatusSummary;
            NotifyAgentCommandCanExecuteChanged();
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        var message = response == null
            ? FirstNonEmpty(StatusMessage, "Agent unavailable for configured capture.")
            : FirstNonEmpty(response.ErrorMessage, response.ErrorCode, "Agent did not return capture lifecycle results.");
        AgentsViewModel.MarkConfigurationCheckUnavailable(agent, AgentConfigurationTargetKind.Capture, message);
        StatusMessage = message;
        NotifyAgentCommandCanExecuteChanged();
    }

    private void TrackConfiguredCaptureJobs(AgentIpcResponse? response, bool affected = false)
    {
        if (response == null)
        {
            return;
        }

        var jobs = affected
            ? AgentIpcResponseJobProjection.GetAffectedJobs(response)
            : AgentIpcResponseJobProjection.GetAcceptedJobs(response);
        foreach (var job in jobs)
        {
            if (job.JobKind == JobKind.LiveCapture)
            {
                _activeLiveCaptureJobId = job.JobId;
                SetLiveCaptureRunState(CaptureRunStateFromJobState(
                    job.State,
                    affected ? CaptureRunState.Stopping : CaptureRunState.Starting));
            }
            else if (job.JobKind == JobKind.NetworkCapture)
            {
                _activeNetworkCaptureJobId = job.JobId;
                IsNetworkCaptureActive = true;
                SetNetworkCaptureRunState(CaptureRunStateFromJobState(
                    job.State,
                    affected ? CaptureRunState.Stopping : CaptureRunState.Starting));
            }
            else if (job.JobKind is JobKind.ModuleEnrichment or JobKind.HandleEnrichment)
            {
                _artifactEnrichmentWorkflowCoordinator.TrackJob(job.JobId, job.JobKind);
            }
            else if (job.JobKind == JobKind.PeAnalysis)
            {
                _artifactEnrichmentWorkflowCoordinator.TrackJob(job.JobId, job.JobKind);
            }
        }

        UpdateAgentCaptureRuntimeRows();
    }

    private void ApplyConfigurationCheckResponse(
        AgentRegistryEntryViewModel agent,
        AgentConfigurationTargetKind targetKind,
        AgentIpcResponse? response)
    {
        if (response?.ConfigurationCheck != null)
        {
            AgentsViewModel.ApplyConfigurationCheck(agent, response.ConfigurationCheck);
            StatusMessage = agent.LastConfigurationCheckSummary;
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        var message = response == null
            ? FirstNonEmpty(StatusMessage, "Agent unavailable for configuration check.")
            : FirstNonEmpty(response.ErrorMessage, response.ErrorCode, "Agent did not return a configuration check result.");
        AgentsViewModel.MarkConfigurationCheckUnavailable(agent, targetKind, message);
        StatusMessage = message;
    }

    /// <summary>
    /// Refreshes the process list.
    /// </summary>
    [RelayCommand]
    public async Task RefreshProcessesAsync()
    {
        await RefreshViewFromStagingAsync();
    }

    /// <summary>
    /// Updates the process list efficiently.
    /// </summary>
    private void UpdateProcessList(
        List<ProcessInfo> allProcesses,
        IReadOnlyDictionary<string, ProcessSourceEventCounts>? eventCountsByProcess = null,
        IReadOnlyDictionary<string, int>? moduleCountsByProcess = null,
        IReadOnlyDictionary<string, int>? handleCountsByProcess = null)
    {
        var selectedKey = SelectedProcess?.ProcessKey;
        var selectedProcessId = SelectedProcess?.ProcessId ?? 0;
        var selectedProcessName = SelectedProcess?.ProcessName;
        const bool refreshEventCounts = true;
        var currentKeys = new HashSet<string>();
        eventCountsByProcess ??= _telemetryProjectionService.GetEventCountsByProcess();
        moduleCountsByProcess ??= _telemetryProjectionService.GetModuleCountsByProcess();
        handleCountsByProcess ??= _telemetryProjectionService.GetHandleCountsByProcess();

        // Apply tree-aware ordering when the Tree column is active. Other column sorts are
        // handled by the ICollectionView so live row counters can be sorted too.
        var sortedProcesses = _filterService.SortProcesses(allProcesses, _currentSortColumn, _sortAscending);

        var orderedRows = new List<ProcessRowViewModel>(sortedProcesses.Count);

        // Update or add processes
        foreach (var proc in sortedProcesses)
        {
            var key = proc.GetUniqueKey();
            currentKeys.Add(key);

            if (_processViewModels.TryGetValue(key, out var existingVm))
            {
                // Update existing
                existingVm.UpdateFrom(proc);
                UpdateProcessRowCounts(existingVm, includeEventCounts: refreshEventCounts, eventCountsByProcess, moduleCountsByProcess, handleCountsByProcess);
                orderedRows.Add(existingVm);

                if (ReferenceEquals(existingVm, SelectedProcess))
                {
                    ProcessPropertiesViewModel.LoadProcess(existingVm);
                }
            }
            else
            {
                // Add new
                var vm = new ProcessRowViewModel(proc);
                UpdateProcessRowCounts(vm, includeEventCounts: true, eventCountsByProcess, moduleCountsByProcess, handleCountsByProcess);
                _processViewModels[key] = vm;
                orderedRows.Add(vm);
            }
        }

        // Remove processes that no longer exist (shouldn't happen, but safety check)
        var toRemove = _processViewModels.Keys.Where(k => !currentKeys.Contains(k)).ToList();
        foreach (var key in toRemove)
        {
            _processViewModels.Remove(key);
        }

        ReplaceProcessRows(orderedRows);

        // Update counts
        TotalProcessCount = allProcesses.Count;
        RunningProcessCount = allProcesses.Count(p => p.Status == ProcessStatus.Running);
        ExitedProcessCount = allProcesses.Count(p => p.Status == ProcessStatus.Exited);
        ExplorerViewModel.RefreshCounts(BuildExplorerScopeCountsFromMemory(allProcesses));

        RestoreSelectedProcess(selectedKey, selectedProcessId, selectedProcessName);
    }

    private List<ProcessInfo> GetProjectedProcesses()
    {
        return _telemetryProjectionService
            .GetProcessList(new ProcessProjectionQuery
            {
                IncludeExited = true,
                MaxCount = 10000
            })
            .ToList();
    }

    private void ReplaceProcessRows(List<ProcessRowViewModel> orderedRows)
    {
        Processes = new ObservableCollection<ProcessRowViewModel>(orderedRows);
        ProcessesView = CollectionViewSource.GetDefaultView(Processes);
        ProcessesView.Filter = FilterProcess;

        if (!string.Equals(_currentSortColumn, "Tree", StringComparison.OrdinalIgnoreCase))
        {
            ProcessesView.SortDescriptions.Add(new SortDescription(
                _currentSortColumn,
                _sortAscending ? ListSortDirection.Ascending : ListSortDirection.Descending));
        }

        ProcessesView.Refresh();
    }

    /// <summary>
    /// Filter predicate for the collection view.
    /// </summary>
    private bool FilterProcess(object obj)
    {
        if (obj is not ProcessRowViewModel vm)
            return false;

        // Check each filter
        if (!string.IsNullOrWhiteSpace(FilterProcessName) &&
            !vm.ProcessName.Contains(FilterProcessName, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterPid) &&
            !vm.ProcessId.ToString().Contains(FilterPid))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterParentPid) &&
            !vm.ParentProcessId.ToString().Contains(FilterParentPid))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterParentProcessName) &&
            !vm.ParentProcessName.Contains(FilterParentProcessName, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterProcessPath) &&
            !vm.ProcessPath.Contains(FilterProcessPath, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterCommandLine) &&
            !vm.CommandLine.Contains(FilterCommandLine, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterUserName) &&
            !vm.UserName.Contains(FilterUserName, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterSessionId) &&
            !vm.SessionId.ToString().Contains(FilterSessionId))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterArchitecture) &&
            !vm.Architecture.Contains(FilterArchitecture, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterStartTime) &&
            !vm.StartTimeDisplay.Contains(FilterStartTime, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterEndTime) &&
            !vm.EndTimeDisplay.Contains(FilterEndTime, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterStatus) &&
            !vm.StatusDisplay.Contains(FilterStatus, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterCpuUsage) &&
            !vm.CpuUsage.Contains(FilterCpuUsage, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterMemoryUsage) &&
            !vm.MemoryUsage.Contains(FilterMemoryUsage, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterCompanyName) &&
            !vm.CompanyName.Contains(FilterCompanyName, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterFileDescription) &&
            !vm.FileDescription.Contains(FilterFileDescription, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterSha256Hash) &&
            !vm.Sha256Hash.Contains(FilterSha256Hash, StringComparison.OrdinalIgnoreCase))
            return false;

        return IsProcessInActiveExplorerScope(vm) && IsProcessInScopedSelection(vm);
    }

    /// <summary>
    /// Clears Listing column filters without changing Explorer scope or green/exclude selection.
    /// </summary>
    [RelayCommand]
    public void ClearFilters()
    {
        FilterProcessName = string.Empty;
        FilterPid = string.Empty;
        FilterParentPid = string.Empty;
        FilterParentProcessName = string.Empty;
        FilterProcessPath = string.Empty;
        FilterCommandLine = string.Empty;
        FilterUserName = string.Empty;
        FilterSessionId = string.Empty;
        FilterArchitecture = string.Empty;
        FilterStartTime = string.Empty;
        FilterEndTime = string.Empty;
        FilterStatus = string.Empty;
        FilterCpuUsage = string.Empty;
        FilterMemoryUsage = string.Empty;
        FilterCompanyName = string.Empty;
        FilterFileDescription = string.Empty;
        FilterSha256Hash = string.Empty;

        // On the DB path a single ScheduleDbRefresh covers all cleared fields.
        // On the fallback path ProcessesView?.Refresh() is already triggered by
        // each OnFilter*Changed partial above; no extra call needed here.
        if (_processListingService != null)
        {
            ScheduleDbRefresh();
        }

        StatusMessage = "Cleared Listing column filters. Explorer green selection was unchanged.";
    }

    /// <summary>
    /// Reloads PowerShell auditing settings from the registry.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseSecurityMonitoringFeature))]
    public void RefreshPowerShellAuditing()
    {
        if (!RequireFeaturePublished(FeatureIds.SecurityMonitoringConfiguration, "Refresh PowerShell auditing")) return;
        var settings = LoadPowerShellAuditingSettings();
        StatusMessage = settings.IsAvailable
            ? "Refreshed read-only PowerShell auditing settings from the registry."
            : $"PowerShell auditing state is unavailable; existing display values were preserved. {settings.StatusDetail} {settings.Error}".Trim();
    }

    /// <summary>
    /// Reloads Sysmon integration and machine status.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseSecurityMonitoringFeature))]
    public void RefreshSysmonStatus()
    {
        if (!RequireFeaturePublished(FeatureIds.SecurityMonitoringConfiguration, "Refresh Sysmon status")) return;
        var settings = LoadSysmonSettings();
        LoadSecurityMonitoringProfileManifests();
        StatusMessage = settings.IsServiceStateAvailable
            ? "Refreshed Security Monitoring profiles, Sysmon integration, and read-only machine status."
            : $"Sysmon service state is unavailable; existing installed/running values were preserved. {settings.ServiceStatusDetail} {settings.ServiceError}".Trim();
    }

    private void RestoreSelectedProcess(string? selectedKey, int selectedProcessId, string? selectedProcessName)
    {
        if (string.IsNullOrWhiteSpace(selectedKey) && selectedProcessId <= 0)
        {
            return;
        }

        var restored = !string.IsNullOrWhiteSpace(selectedKey)
            ? Processes.FirstOrDefault(process => process.ProcessKey == selectedKey)
            : null;

        restored ??= Processes
            .Where(process => process.ProcessId == selectedProcessId)
            .Where(process => string.IsNullOrWhiteSpace(selectedProcessName) ||
                string.Equals(process.ProcessName, selectedProcessName, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(process => process.ProcessInfo.StartTime ?? DateTime.MinValue)
            .FirstOrDefault();

        if (restored == null || ReferenceEquals(restored, SelectedProcess))
        {
            return;
        }

        SelectedProcess = restored;
    }

    private void NavigateToSearchResult(TelemetrySearchResult result)
    {
        if (string.Equals(result.Kind, "Correlation", StringComparison.OrdinalIgnoreCase))
        {
            LoadCorrelationResultIntoInspector(result);
            return;
        }

        if ((string.Equals(result.Kind, "Sigma", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(result.Kind, "Event", StringComparison.OrdinalIgnoreCase)) &&
            result.CorrelationState is EvidenceCorrelationState.Unresolved or EvidenceCorrelationState.Ambiguous &&
            string.IsNullOrWhiteSpace(result.ProcessEntityId))
        {
            LoadCorrelationResultIntoInspector(result);
            return;
        }

        if (TryNavigateToIndependentArtifactResult(result))
        {
            return;
        }

        _ = _viewerNavigationCoordinator.NavigateToProcessResultAsync(result);
    }

    private bool TryNavigateToIndependentArtifactResult(TelemetrySearchResult result)
    {
        InspectorPayload? payload = null;
        var kind = result.Kind;
        if (string.Equals(kind, "NetworkCapture", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetNetworkCaptures(10000)
                .FirstOrDefault(item => string.Equals(item.CaptureId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new NetworkCaptureRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Network, "Open network capture search result");
        }
        else if (string.Equals(kind, "Zeek", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetZeekNetworkArtifacts(10000)
                .FirstOrDefault(item => string.Equals(item.ArtifactId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new ZeekNetworkArtifactRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Network, "Open Zeek search result");
        }
        else if (string.Equals(kind, "FilesystemArtifact", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetFilesystemArtifacts(10000)
                .FirstOrDefault(item => string.Equals(item.ArtifactId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new FilesystemArtifactRowViewModel(record).ToInspectorPayload();
            TryNavigateToDataTab(DataTabKeys.Filesystem, "Open filesystem search result");
        }
        else if (string.Equals(kind, "MemoryImage", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetMemoryImages(10000)
                .FirstOrDefault(item => string.Equals(item.ImageId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new MemoryImageRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open memory image search result");
        }
        else if (string.Equals(kind, "VolatilityRun", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetVolatilityPluginRuns(maxCount: 10000)
                .FirstOrDefault(item => string.Equals(item.RunId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new VolatilityPluginRunRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open Volatility run search result");
        }
        else if (string.Equals(kind, "MemoryProcess", StringComparison.OrdinalIgnoreCase))
        {
            var record = _telemetryProjectionService.GetMemoryProcesses(maxCount: 10000)
                .FirstOrDefault(item => string.Equals(item.ArtifactId, result.RecordKey, StringComparison.Ordinal));
            payload = record == null ? null : new MemoryProcessRowViewModel(record).ToInspectorPayload();
            TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open memory process search result");
        }
        else
        {
            return false;
        }

        if (payload == null)
        {
            StatusMessage = $"The {kind} search result is no longer present in staged evidence. Refresh and try again.";
            return true;
        }

        InspectorPaneViewModel.Load(payload);
        StatusMessage = $"Opened {kind} evidence from search: {result.Title}.";
        return true;
    }

    private ViewerLegacyProcessNavigationResult NavigateToSearchResultLegacy(TelemetrySearchResult result)
    {
        if (Processes.Count == 0)
        {
            UpdateProcessList(GetProjectedProcesses());
        }

        var target = FindVisibleProcessRow(result) ?? AddSearchResultProcessRow(result);
        if (target == null)
        {
            return new ViewerLegacyProcessNavigationResult(
                false,
                $"Search result process is not visible: {result.ProcessName} (PID {result.ProcessId}). Refresh staged data and try again.");
        }

        var clearedFilters = false;
        if (ProcessesView?.Contains(target) == false)
        {
            ClearFilters();
            clearedFilters = true;
        }

        SelectedProcess = target;
        _virtualizedProcessListing?.PreserveSelection(target);
        ProcessesView?.MoveCurrentTo(target);
        ProcessRowNavigationRequested?.Invoke(target);
        var statusMessage = clearedFilters
            ? $"Cleared filters and selected {target.ProcessName} (PID {target.ProcessId}) from search result."
            : $"Selected {target.ProcessName} (PID {target.ProcessId}) from search result.";
        return new ViewerLegacyProcessNavigationResult(
            true,
            statusMessage,
            target,
            clearedFilters);
    }

    ViewerProcessNavigationContext? IViewerNavigationRuntime.GetCurrentProcessNavigationContext()
    {
        var listingService = _processListingService;
        var collection = _virtualizedProcessListing;
        if (listingService == null || collection == null)
        {
            return null;
        }

        return new ViewerProcessNavigationContext(
            listingService,
            collection,
            _captureWorkspaceCoordinator.Generation,
            Volatile.Read(ref _processListingQueryGeneration));
    }

    bool IViewerNavigationRuntime.IsCurrentProcessNavigationContext(
        ViewerProcessNavigationContext context)
        => ReferenceEquals(context.Listing, _processListingService) &&
           ReferenceEquals(context.Collection, _virtualizedProcessListing) &&
           context.WorkspaceGeneration == _captureWorkspaceCoordinator.Generation &&
           context.QueryGeneration == Volatile.Read(ref _processListingQueryGeneration) &&
           context.QueryGeneration == context.Collection.QueryGeneration &&
           context.WorkspaceGeneration == context.Collection.WorkspaceGeneration;

    ProcessListingQuery IViewerNavigationRuntime.BuildCurrentProcessListingQuery()
        => BuildCurrentListingQuery();

    ProcessRowViewModel? IViewerNavigationRuntime.FindVisibleProcessRow(TelemetrySearchResult result)
        => FindVisibleProcessRow(result);

    async Task<ViewerProcessNavigationContext?> IViewerNavigationRuntime.ClearFiltersAndRebindProcessListingAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(ClearFilters);
        }
        else
        {
            ClearFilters();
        }

        _dbRefreshDebounceTimer?.Stop();
        await ExecuteDbRefreshAsync();
        cancellationToken.ThrowIfCancellationRequested();
        return ((IViewerNavigationRuntime)this).GetCurrentProcessNavigationContext();
    }

    void IViewerNavigationRuntime.ApplyProcessNavigationSelection(
        ViewerProcessNavigationContext context,
        ProcessRowViewModel row)
    {
        void Apply()
        {
            if (!((IViewerNavigationRuntime)this).IsCurrentProcessNavigationContext(context))
            {
                return;
            }

            SelectedProcess = row;
            context.Collection.PreserveSelection(row);
            ProcessesView?.MoveCurrentTo(row);
            ProcessRowNavigationRequested?.Invoke(row);
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(Apply);
        }
        else
        {
            Apply();
        }
    }

    ViewerLegacyProcessNavigationResult IViewerNavigationRuntime.NavigateLegacyProcessResult(
        TelemetrySearchResult result)
        => NavigateToSearchResultLegacy(result);

    private void LoadCorrelationResultIntoInspector(TelemetrySearchResult result)
    {
        InspectorPaneViewModel.Load(new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.CorrelationEvidence,
            TargetKind = result.EvidenceKind,
            TargetId = result.RecordKey,
            ArtifactId = result.RecordKey,
            ProcessId = result.ProcessId,
            ProcessName = result.ProcessName,
            Header = result.Title,
            Subtitle = result.CorrelationDiagnostics,
            EmptyStateMessage = "Select correlation evidence to inspect its decision diagnostics.",
            Properties = new List<PropertyItemViewModel>
            {
                new("Evidence", "Reference", result.RecordKey),
                new("Evidence", "Kind", result.EvidenceKind),
                new("Evidence", "Source", result.Source),
                new("Correlation", "State", result.CorrelationState?.ToString() ?? "Unresolved"),
                new("Correlation", "Method", result.CorrelationMethod),
                new("Correlation", "Candidate Count", result.CorrelationCandidateCount.ToString(CultureInfo.InvariantCulture)),
                new("Correlation", "Resolver Version", result.ResolverVersion),
                new("Process Hint", "PID", result.ProcessId > 0 ? result.ProcessId.ToString(CultureInfo.InvariantCulture) : string.Empty),
                new("Process Hint", "Name", result.ProcessName)
            },
            RawText = result.CorrelationDiagnostics
        });
        StatusMessage = $"Correlation evidence: {result.CorrelationState?.ToString() ?? "Unresolved"}; {result.CorrelationCandidateCount} candidate(s).";
    }

    private void OnExplorerScopeSelected(ExplorerScope scope)
    {
        MarkSnapshotPresentationInteraction();
        var requiredFeature = FeatureNavigationPolicy.GetFeatureForExplorerScope(scope);
        if (requiredFeature.HasValue &&
            !RequireFeaturePublished(requiredFeature.Value, $"Explorer scope '{scope.Title}'"))
        {
            _viewerNavigationCoordinator.SelectSafeFallbacks(StatusMessage);
            return;
        }

        _activeExplorerScope = scope;
        var isNetworkScope = IsNetworkScope(scope);
        var isFilesystemScope = IsFilesystemScope(scope);
        _viewerNavigationCoordinator.NavigateForExplorerScope(
            scope,
            isNetworkScope,
            isFilesystemScope);
        ProcessStatisticsViewModel.ApplyActiveScope(scope);

        SelectedProcess = null;
        RefreshDataForExplorerScope(scope);
        InspectorPaneViewModel.Clear(
            "Select a row in Data to inspect its additional properties.");

        if (_processListingService != null)
        {
            ScheduleDbRefresh();
        }
        else
        {
            ProcessesView?.Refresh();
        }

        StatusMessage = $"Explorer scope: {scope.Title}.";
    }


    private void RefreshDataForExplorerScope(ExplorerScope scope)
    {
        switch (scope.Kind)
        {
            case ExplorerScopeKind.NetworkRoot:
            case ExplorerScopeKind.NetworkCaptures:
            case ExplorerScopeKind.NetworkCapture:
            case ExplorerScopeKind.ZeekArtifacts:
                NetworkAndZeekFeature?.ViewModel.RefreshNetworkCaptures();
                break;
            case ExplorerScopeKind.FilesystemRoot:
            case ExplorerScopeKind.FilesystemEvidenceRoots:
            case ExplorerScopeKind.FilesystemArtifacts:
            case ExplorerScopeKind.FilesystemFolder:
                _featureModules.GetOrActivate<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts)
                    ?.RefreshArtifacts(scope);
                break;
            case ExplorerScopeKind.SystemActivityRoot:
            case ExplorerScopeKind.ActivityAuthentication:
            case ExplorerScopeKind.ActivitySuccessfulLogons:
            case ExplorerScopeKind.ActivityFailedLogons:
            case ExplorerScopeKind.ActivityRemoteInteractive:
            case ExplorerScopeKind.ActivityExplicitCredentialUse:
            case ExplorerScopeKind.ActivityPrivilegedLogons:
            case ExplorerScopeKind.ActivityAccounts:
            case ExplorerScopeKind.ActivityCreatedUsers:
            case ExplorerScopeKind.ActivityDisabledDeletedUsers:
            case ExplorerScopeKind.ActivityPasswordChanges:
            case ExplorerScopeKind.ActivityGroups:
            case ExplorerScopeKind.ActivityLocalAdministratorsChanges:
            case ExplorerScopeKind.ActivitySecurityGroupMembershipChanges:
            case ExplorerScopeKind.ActivityPolicyAudit:
            case ExplorerScopeKind.ActivityAuditPolicyChanged:
            case ExplorerScopeKind.ActivityLogIntegrity:
            case ExplorerScopeKind.ActivitySecurityLogCleared:
            case ExplorerScopeKind.ActivityServicesTasks:
            case ExplorerScopeKind.ActivityServicesInstalled:
            case ExplorerScopeKind.ActivityScheduledTasksChanged:
            case ExplorerScopeKind.UsersRoot:
            case ExplorerScopeKind.UserAccount:
                EventTelemetryFeature?.SystemActivityViewModel.RefreshActivities(scope);
                break;
            case ExplorerScopeKind.SearchResults:
                if (_featureModules.TryGetActivated<SearchFeatureModule>(FeatureIds.SearchAndSigma, out var search))
                {
                    search.ViewModel.SearchCommand.NotifyCanExecuteChanged();
                }
                break;
            case ExplorerScopeKind.SigmaFindings:
                if (_featureModules.TryGetActivated<SigmaViewModel>(FeatureIds.SearchAndSigma, out var sigma))
                {
                    sigma.RunRuleCommand.NotifyCanExecuteChanged();
                }
                break;
            case ExplorerScopeKind.UnresolvedEvidence:
            case ExplorerScopeKind.AmbiguousEvidence:
            case ExplorerScopeKind.CorrelationEvidenceGroup:
                _ = LoadCorrelationEvidenceResultsAsync(scope);
                break;
        }
    }

    [RelayCommand]
    private void IncludeCurrentExplorerScope()
    {
        var scopes = GetCurrentExplorerScopeSet().ToList();
        if (scopes.Count == 0)
        {
            StatusMessage = "Select an evidence scope before changing green selection.";
            return;
        }

        foreach (var scope in scopes)
        {
            _excludedScopes.Remove(scope.StableId);
            _includedScopes[scope.StableId] = scope;
        }

        RefreshScopedSelection($"Green-selected {FormatScopeActionCount(scopes.Count)}.");
    }

    [RelayCommand]
    private void ExcludeCurrentExplorerScope()
    {
        var scopes = GetCurrentExplorerScopeSet().ToList();
        if (scopes.Count == 0)
        {
            StatusMessage = "Select an evidence scope before changing green selection.";
            return;
        }

        foreach (var scope in scopes)
        {
            _includedScopes.Remove(scope.StableId);
            _excludedScopes[scope.StableId] = scope;
        }

        RefreshScopedSelection($"Excluded {FormatScopeActionCount(scopes.Count)}.");
    }

    [RelayCommand]
    private void ToggleExplorerGreenScope(ExplorerNodeViewModel? node)
    {
        if (node is not { IsPlaceholder: false } || !IsSelectableExplorerScope(node.Scope))
        {
            return;
        }

        var scopes = GetNodeAndLoadedDescendantScopes(node).ToArray();
        if (scopes.Length == 0)
        {
            return;
        }

        var removeGreen = node.SelectionState == ExplorerScopeSelectionState.GreenIncluded;
        var hasIncludedAncestor = removeGreen && HasGreenIncludedAncestor(node);
        foreach (var scope in scopes)
        {
            if (removeGreen)
            {
                _includedScopes.Remove(scope.StableId);
                if (hasIncludedAncestor)
                {
                    _excludedScopes[scope.StableId] = scope;
                }
                else
                {
                    _excludedScopes.Remove(scope.StableId);
                }
            }
            else
            {
                _excludedScopes.Remove(scope.StableId);
                _includedScopes[scope.StableId] = scope;
            }
        }

        RefreshScopedSelection(removeGreen
            ? $"Removed green selection from {FormatScopeActionCount(scopes.Length)}."
            : $"Green-selected {FormatScopeActionCount(scopes.Length)}.");
    }

    private static IEnumerable<ExplorerScope> GetNodeAndLoadedDescendantScopes(ExplorerNodeViewModel node)
    {
        foreach (var current in FlattenExplorerNode(node))
        {
            if (current is { IsPlaceholder: false } && IsSelectableExplorerScope(current.Scope))
            {
                yield return current.Scope;
            }
        }
    }

    private static IEnumerable<ExplorerNodeViewModel> FlattenExplorerNode(ExplorerNodeViewModel node)
    {
        yield return node;
        foreach (var child in node.Children)
        {
            foreach (var descendant in FlattenExplorerNode(child))
            {
                yield return descendant;
            }
        }
    }

    private bool HasGreenIncludedAncestor(ExplorerNodeViewModel target)
    {
        foreach (var root in ExplorerViewModel.RootNodes)
        {
            if (HasGreenIncludedAncestor(root, target, inheritedIncluded: false))
            {
                return true;
            }
        }

        return false;
    }

    private bool HasGreenIncludedAncestor(
        ExplorerNodeViewModel current,
        ExplorerNodeViewModel target,
        bool inheritedIncluded)
    {
        if (ReferenceEquals(current, target))
        {
            return inheritedIncluded;
        }

        var scopeId = current.Scope.StableId;
        var currentIncluded = inheritedIncluded ||
                              (_includedScopes.ContainsKey(scopeId) && !_excludedScopes.ContainsKey(scopeId));
        if (_excludedScopes.ContainsKey(scopeId))
        {
            currentIncluded = false;
        }

        foreach (var child in current.Children)
        {
            if (HasGreenIncludedAncestor(child, target, currentIncluded))
            {
                return true;
            }
        }

        return false;
    }

    [RelayCommand(CanExecute = nameof(CanChangeSelectedProcessScope))]
    private void IncludeSelectedProcess()
    {
        if (SelectedProcess == null)
        {
            return;
        }

        var label = FormatProcessLabel(SelectedProcess);
        _excludedProcessKeys.Remove(SelectedProcess.ProcessKey);
        _excludedProcessLabels.Remove(SelectedProcess.ProcessKey);
        _includedProcessKeys.Add(SelectedProcess.ProcessKey);
        _includedProcessLabels[SelectedProcess.ProcessKey] = label;
        RefreshScopedSelection($"Included {label}.");
    }

    [RelayCommand(CanExecute = nameof(CanChangeSelectedProcessScope))]
    private void ExcludeSelectedProcess()
    {
        if (SelectedProcess == null)
        {
            return;
        }

        var label = FormatProcessLabel(SelectedProcess);
        _includedProcessKeys.Remove(SelectedProcess.ProcessKey);
        _includedProcessLabels.Remove(SelectedProcess.ProcessKey);
        _excludedProcessKeys.Add(SelectedProcess.ProcessKey);
        _excludedProcessLabels[SelectedProcess.ProcessKey] = label;
        RefreshScopedSelection($"Excluded {label}.");
    }

    [RelayCommand(CanExecute = nameof(CanClearScopedSelection))]
    private void ClearScopedSelection()
    {
        _includedScopes.Clear();
        _excludedScopes.Clear();
        _includedProcessKeys.Clear();
        _excludedProcessKeys.Clear();
        _includedProcessLabels.Clear();
        _excludedProcessLabels.Clear();
        RefreshScopedSelection("Cleared include/exclude selection.");
    }

    private IEnumerable<ExplorerScope> GetCurrentExplorerScopeSet()
    {
        var scopes = ExplorerViewModel.SelectedScopes
            .Where(scope => IsSelectableExplorerScope(scope))
            .GroupBy(scope => scope.StableId, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToList();

        if (scopes.Count == 0 && IsSelectableExplorerScope(_activeExplorerScope))
        {
            scopes.Add(_activeExplorerScope);
        }

        return scopes;
    }

    private static bool IsSelectableExplorerScope(ExplorerScope scope)
    {
        return scope.Kind != ExplorerScopeKind.Placeholder &&
               scope.Kind != ExplorerScopeKind.Branch;
    }

    private bool CanChangeSelectedProcessScope()
    {
        return SelectedProcess != null && !string.IsNullOrWhiteSpace(SelectedProcess.ProcessKey);
    }

    private bool CanClearScopedSelection()
    {
        return HasScopedSelection();
    }

    private void RefreshScopedSelection(string statusMessage)
    {
        ApplyScopedSelectionStateToViews();
        UpdateScopedSelectionStatus();
        ClearScopedSelectionCommand.NotifyCanExecuteChanged();

        if (_processListingService != null)
        {
            ScheduleDbRefresh();
        }
        else
        {
            ProcessesView?.Refresh();
            if (SelectedProcess != null && !FilterProcess(SelectedProcess))
            {
                SelectedProcess = null;
            }
        }

        StatusMessage = statusMessage;
    }

    private void UpdateScopedSelectionStatus()
    {
        if (!HasScopedSelection())
        {
            ScopedSelectionStatus = "Green scopes: none active; all evidence visible.";
            ScopedSelectionDetail = "No green scope or exclusion filters are active.";
            return;
        }

        var greenCount = _includedScopes.Count + _includedProcessKeys.Count;
        var excludeCount = _excludedScopes.Count + _excludedProcessKeys.Count;
        ScopedSelectionStatus = $"Green scopes: {greenCount} active, {excludeCount} excluded.";
        ScopedSelectionDetail = BuildScopedSelectionDetail();
    }

    private bool HasScopedSelection()
    {
        return _includedScopes.Count > 0 ||
               _excludedScopes.Count > 0 ||
               _includedProcessKeys.Count > 0 ||
               _excludedProcessKeys.Count > 0;
    }

    private void ClearScopedSelectionState()
    {
        _includedScopes.Clear();
        _excludedScopes.Clear();
        _includedProcessKeys.Clear();
        _excludedProcessKeys.Clear();
        _includedProcessLabels.Clear();
        _excludedProcessLabels.Clear();
        ApplyScopedSelectionStateToViews();
        UpdateScopedSelectionStatus();
        ClearScopedSelectionCommand.NotifyCanExecuteChanged();
    }

    private void ApplyScopedSelectionStateToViews()
    {
        var includedScopes = _includedScopes.Values.ToList();
        var excludedScopes = _excludedScopes.Values.ToList();
        var hasGreenSelection = _includedScopes.Count > 0 || _includedProcessKeys.Count > 0;

        ExplorerViewModel.ApplyScopeSelectionState(_includedScopes.Keys, _excludedScopes.Keys);
        ProcessStatisticsViewModel.ApplyScopedSelection(
            includedScopes,
            excludedScopes,
            _includedProcessKeys,
            _excludedProcessKeys,
            hasGreenSelection);
        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            filesystem.ApplyScopedSelection(includedScopes, excludedScopes, hasGreenSelection);
        }

        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
        {
            network.ViewModel.ApplyScopedSelection(includedScopes, excludedScopes, hasGreenSelection);
        }

        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events))
        {
            events.SystemActivityViewModel.ApplyScopedSelection(includedScopes, excludedScopes, hasGreenSelection);
        }
    }

    private string BuildScopedSelectionDetail()
    {
        var included = BuildScopedSelectionItems(_includedScopes.Values, _includedProcessLabels.Values);
        var excluded = BuildScopedSelectionItems(_excludedScopes.Values, _excludedProcessLabels.Values);

        return $"Green-selected: {FormatScopedSelectionList(included)}. Excluded: {FormatScopedSelectionList(excluded)}.";
    }

    private static IEnumerable<string> BuildScopedSelectionItems(
        IEnumerable<ExplorerScope> scopes,
        IEnumerable<string> processLabels)
    {
        foreach (var scope in scopes.OrderBy(scope => scope.Title, StringComparer.OrdinalIgnoreCase))
        {
            yield return $"scope {scope.Title}";
        }

        foreach (var label in processLabels.OrderBy(label => label, StringComparer.OrdinalIgnoreCase))
        {
            yield return label;
        }
    }

    private static string FormatScopedSelectionList(IEnumerable<string> items)
    {
        var list = items.ToList();
        return list.Count == 0 ? "none" : string.Join("; ", list);
    }

    private static string FormatCount(int count, string noun)
    {
        return count == 1 ? $"1 {noun}" : $"{count} {noun}s";
    }

    private static string FormatScopeActionCount(int count)
    {
        return count == 1 ? "1 Explorer scope" : $"{count} Explorer scopes";
    }

    private static string FormatProcessLabel(ProcessRowViewModel process)
    {
        return $"{process.ProcessName} (PID {process.ProcessId})";
    }

    private static ExplorerScope CreateAllProcessesScope()
    {
        return new ExplorerScope
        {
            Kind = ExplorerScopeKind.AllProcesses,
            ScopeId = "process:all",
            Title = "All Processes",
            Description = "All staged and live process records."
        };
    }

    private static FeatureTabKey GetDataTabForScope(ExplorerScope scope) =>
        DataTabNavigationPolicy.GetTabKey(scope);

    private static bool IsNetworkScope(ExplorerScope scope)
    {
        return scope.Kind is ExplorerScopeKind.NetworkRoot or
            ExplorerScopeKind.NetworkCaptures or
            ExplorerScopeKind.NetworkCapture or
            ExplorerScopeKind.ZeekArtifacts;
    }

    private static bool IsFilesystemScope(ExplorerScope scope)
    {
        return scope.Kind is ExplorerScopeKind.FilesystemRoot or
            ExplorerScopeKind.FilesystemEvidenceRoots or
            ExplorerScopeKind.FilesystemArtifacts or
            ExplorerScopeKind.FilesystemFolder;
    }

    private static bool IsSystemActivityScope(ExplorerScope scope)
    {
        return scope.Kind is ExplorerScopeKind.SystemActivityRoot or
            ExplorerScopeKind.ActivityAuthentication or
            ExplorerScopeKind.ActivitySuccessfulLogons or
            ExplorerScopeKind.ActivityFailedLogons or
            ExplorerScopeKind.ActivityRemoteInteractive or
            ExplorerScopeKind.ActivityExplicitCredentialUse or
            ExplorerScopeKind.ActivityPrivilegedLogons or
            ExplorerScopeKind.ActivityAccounts or
            ExplorerScopeKind.ActivityCreatedUsers or
            ExplorerScopeKind.ActivityDisabledDeletedUsers or
            ExplorerScopeKind.ActivityPasswordChanges or
            ExplorerScopeKind.ActivityGroups or
            ExplorerScopeKind.ActivityLocalAdministratorsChanges or
            ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or
            ExplorerScopeKind.ActivityPolicyAudit or
            ExplorerScopeKind.ActivityAuditPolicyChanged or
            ExplorerScopeKind.ActivityLogIntegrity or
            ExplorerScopeKind.ActivitySecurityLogCleared or
            ExplorerScopeKind.ActivityServicesTasks or
            ExplorerScopeKind.ActivityServicesInstalled or
            ExplorerScopeKind.ActivityScheduledTasksChanged or
            ExplorerScopeKind.UsersRoot or
            ExplorerScopeKind.UserAccount;
    }

    private bool IsProcessInActiveExplorerScope(ProcessRowViewModel process)
    {
        return DoesProcessMatchScope(process, _activeExplorerScope);
    }

    private bool IsProcessInScopedSelection(ProcessRowViewModel process)
    {
        var includedScopes = GetProcessListingIncludedScopes();
        var hasAnyGreenSelection = _includedProcessKeys.Count > 0 ||
                                   _includedScopes.Count > 0 ||
                                   ExplorerViewModel.VisibleIncludedScopes.Count > 0;
        if (hasAnyGreenSelection)
        {
            if (_includedProcessKeys.Count == 0 && includedScopes.Count == 0)
            {
                return false;
            }

            if (_includedProcessKeys.Count > 0 && !_includedProcessKeys.Contains(process.ProcessKey))
            {
                return false;
            }

            foreach (var scopeGroup in includedScopes.GroupBy(GetScopedSelectionGroupKey))
            {
                if (!scopeGroup.Any(scope => DoesProcessMatchScope(process, scope)))
                {
                    return false;
                }
            }
        }

        if (_excludedProcessKeys.Contains(process.ProcessKey))
        {
            return false;
        }

        return !GetProcessListingExcludedScopes()
            .Any(scope => DoesProcessMatchScope(process, scope));
    }

    private bool DoesProcessMatchScope(ProcessRowViewModel process, ExplorerScope scope)
    {
        if (!MatchesIdentityScope(process, scope))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(scope.ProcessKey) &&
            !IsProcessInSubtree(process.ProcessKey, scope.ProcessKey))
        {
            return false;
        }

        if (scope.Status.HasValue && process.ProcessInfo.Status != scope.Status.Value)
        {
            return false;
        }

        if (scope.ArtifactScope == ExplorerArtifactScope.Modules && process.ModuleCount <= 0)
        {
            return false;
        }

        if (scope.ArtifactScope == ExplorerArtifactScope.Handles && process.HandleCount <= 0)
        {
            return false;
        }

        if (scope.Kind == ExplorerScopeKind.Bookmarked && !IsProcessBookmarked(process.ProcessKey))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(scope.OwnerKey) &&
            !string.Equals(NormalizeProcessOwnerKey(process.UserName), scope.OwnerKey, StringComparison.Ordinal))
        {
            return false;
        }

        return scope.EventSource switch
        {
            "Runtime" => process.RuntimeEventCount > 0,
            "ETW" => process.EtwEventCount > 0,
            "Security" => process.SecurityEventCount > 0,
            "PowerShell" => process.PowerShellEventCount > 0,
            "WindowsOther" => process.OtherWindowsEventCount > 0,
            "Sysmon" => process.SysmonEventCount > 0,
            _ => true
        };
    }

    private async Task RefreshExplorerCountsAsync(
        ExplorerCountRefreshTrigger trigger,
        bool force = false)
    {
        if (_captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.Switching)
        {
            return;
        }

        Interlocked.Increment(ref _activeExplorerRefreshCount);
        try
        {
            if (!_hasActiveQueryDatabase)
            {
                ExplorerViewModel.ResetCounts();
                ResetExplorerTabCounts();
                return;
            }

            if (_sqliteStagingQueryService != null)
            {
                var queryService = _sqliteStagingQueryService;
                var workspaceGeneration = _captureWorkspaceCoordinator.Generation;
                var inputGeneration = Volatile.Read(ref _explorerCountInputGeneration);
                var refresh = await _explorerCountRefreshCoordinator.RefreshAsync(
                    new ExplorerCountRefreshRequest(
                        queryService,
                        workspaceGeneration,
                        inputGeneration,
                        trigger,
                        force),
                    async cancellationToken =>
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var counts = await queryService.GetExplorerScopeCountsAsync();
                        cancellationToken.ThrowIfCancellationRequested();
                        var roots = await queryService.GetEvidenceRootsAsync();
                        cancellationToken.ThrowIfCancellationRequested();
                        return new ExplorerCountRefreshPayload(counts, roots);
                    });
                if (!refresh.Succeeded)
                {
                    if (refresh.Outcome == ExplorerCountRefreshOutcome.Failed)
                    {
                        ExplorerViewModel.StatusMessage =
                            $"Explorer count refresh failed; previous valid counts were kept: {refresh.Error}";
                    }

                    return;
                }

                var payload = refresh.Payload;
                if (payload == null ||
                    !ReferenceEquals(refresh.Request.QueryBinding, queryService) ||
                    refresh.Request.WorkspaceGeneration != workspaceGeneration ||
                    refresh.Request.InputGeneration != inputGeneration ||
                    workspaceGeneration != _captureWorkspaceCoordinator.Generation ||
                    inputGeneration != Volatile.Read(ref _explorerCountInputGeneration) ||
                    !ReferenceEquals(queryService, _sqliteStagingQueryService))
                {
                    return;
                }

                ApplyExplorerCounts(AddAnalysisCounts(payload.Counts));
                ExplorerViewModel.RefreshEvidenceRoots(payload.EvidenceRoots);
                return;
            }

            ExplorerViewModel.ResetCounts();
            ResetExplorerTabCounts();
        }
        catch (Exception ex)
        {
            if (_captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.Switching)
            {
                return;
            }

            ExplorerViewModel.StatusMessage = $"Explorer count refresh failed: {ex.Message}";
        }
        finally
        {
            Interlocked.Decrement(ref _activeExplorerRefreshCount);
        }
    }

    private Task RefreshExplorerCountsForChangedInputsAsync(
        ExplorerCountRefreshTrigger trigger,
        bool force = false)
    {
        Interlocked.Increment(ref _explorerCountInputGeneration);
        return RefreshExplorerCountsAsync(trigger, force);
    }

    private void RefreshExplorerAnalysisCountsFromCache()
    {
        var queryService = _sqliteStagingQueryService;
        if (queryService == null || !_hasActiveQueryDatabase)
        {
            return;
        }

        var workspaceGeneration = _captureWorkspaceCoordinator.Generation;
        var inputGeneration = Volatile.Read(ref _explorerCountInputGeneration);
        if (_explorerCountRefreshCoordinator.TryGetCachedPayload(
                queryService,
                workspaceGeneration,
                inputGeneration,
                out var payload) &&
            payload != null)
        {
            ApplyExplorerCounts(AddAnalysisCounts(payload.Counts));
        }
    }

    private void OnProcessNoteSaved(object? sender, EventArgs e)
    {
        _ = RefreshExplorerCountsForChangedInputsAsync(
            ExplorerCountRefreshTrigger.AnnotationMutation);
    }

    private void ApplyExplorerCounts(ExplorerScopeCounts counts)
    {
        ExplorerViewModel.RefreshCounts(counts);
        UpdateExplorerTabCount(ExplorerTabKeys.Search, counts.SearchResultCount);
        UpdateExplorerTabCount(ExplorerTabKeys.Sigma, counts.SigmaFindingCount);
        UpdateExplorerTabCount(ExplorerTabKeys.Network, counts.NetworkCaptureCount);
        UpdateExplorerTabCount(ExplorerTabKeys.Memory, counts.MemoryImageCount);
        RefreshDataTabCounts();
    }

    private void ResetExplorerTabCounts()
    {
        UpdateExplorerTabCount(ExplorerTabKeys.Search, 0);
        UpdateExplorerTabCount(ExplorerTabKeys.Sigma, 0);
        UpdateExplorerTabCount(ExplorerTabKeys.Network, 0);
        UpdateExplorerTabCount(ExplorerTabKeys.Memory, 0);
        foreach (var descriptor in _dataTabSet.Items.Where(descriptor => descriptor.Count.HasValue))
        {
            descriptor.UpdateCount(0);
        }
    }

    private void UpdateExplorerTabCount(FeatureTabKey key, int count)
    {
        if (_explorerTabSet.TryGet(key, out var descriptor))
        {
            descriptor?.UpdateCount(count);
        }
    }

    private void UpdateDataTabCount(FeatureTabKey key, int count)
    {
        if (_dataTabSet.TryGet(key, out var descriptor))
        {
            descriptor?.UpdateCount(count);
        }
    }

    private void RefreshDataTabCounts()
    {
        if (_featureModules.TryGetActivated<ModulesAndHandlesFeatureModule>(FeatureIds.ModulesAndHandles, out var artifacts))
        {
            UpdateDataTabCount(DataTabKeys.Modules, artifacts.ModulesViewModel.Modules.Count);
            UpdateDataTabCount(DataTabKeys.Handles, artifacts.HandlesViewModel.Handles.Count);
        }

        if (_featureModules.TryGetActivated<DumpsAndPeFeatureModule>(FeatureIds.DumpsAndPeAnalysis, out var dumpsAndPe))
        {
            UpdateDataTabCount(DataTabKeys.MemoryDumps, dumpsAndPe.MemoryDumpsViewModel.MemoryDumps.Count);
            UpdateDataTabCount(DataTabKeys.PeAnalysis, dumpsAndPe.PeAnalysisViewModel.PeAnalyses.Count);
        }

        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory))
        {
            UpdateDataTabCount(DataTabKeys.SystemMemory, memory.MemoryImages.Count);
        }

        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
        {
            UpdateDataTabCount(DataTabKeys.Network, network.ViewModel.NetworkCaptures.Count);
        }

        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            UpdateDataTabCount(DataTabKeys.Filesystem, filesystem.Artifacts.Count);
        }

        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events))
        {
            UpdateDataTabCount(DataTabKeys.SystemActivity, events.SystemActivityViewModel.VisibleActivityCount);
            UpdateDataTabCount(DataTabKeys.RuntimeEvents, events.RuntimeEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.EtwEvents, events.EtwEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.SecurityEvents, events.SecurityEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.PowerShellEvents, events.PowerShellEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.WindowsOtherEvents, events.OtherWindowsEventsViewModel.VisibleEventCount);
            UpdateDataTabCount(DataTabKeys.SysmonEvents, events.SysmonEventsViewModel.VisibleEventCount);
        }
    }

    private ExplorerScopeCounts BuildExplorerScopeCountsFromMemory(IReadOnlyList<ProcessInfo> processes)
    {
        var eventCounts = _telemetryProjectionService.GetEventCountsByProcess();
        var moduleCounts = _telemetryProjectionService.GetModuleCountsByProcess();
        var handleCounts = _telemetryProjectionService.GetHandleCountsByProcess();
        var stats = _telemetryProjectionService.GetStats();
        var systemActivityCounts = _telemetryProjectionService.GetSystemActivityScopeCounts();
        var systemActivityAccountCount = _telemetryProjectionService.GetSystemActivityAccounts(new SystemActivityQuery(), maxCount: 0).Count;
        var sourceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["Runtime"] = eventCounts.Count(pair => pair.Value.RuntimeEventCount > 0),
            ["ETW"] = eventCounts.Count(pair => pair.Value.EtwEventCount > 0),
            ["Security"] = eventCounts.Count(pair => pair.Value.SecurityEventCount > 0),
            ["PowerShell"] = eventCounts.Count(pair => pair.Value.PowerShellEventCount > 0),
            ["WindowsOther"] = eventCounts.Count(pair => pair.Value.OtherWindowsEventCount > 0),
            ["Sysmon"] = eventCounts.Count(pair => pair.Value.SysmonEventCount > 0)
        };

        return new ExplorerScopeCounts
        {
            TotalProcesses = processes.Count,
            RunningProcesses = processes.Count(process => process.Status == ProcessStatus.Running),
            ExitedProcesses = processes.Count(process => process.Status == ProcessStatus.Exited),
            NotFoundProcesses = processes.Count(process => process.Status == ProcessStatus.NotFound),
            ModuleProcesses = moduleCounts.Count(pair => pair.Value > 0),
            HandleProcesses = handleCounts.Count(pair => pair.Value > 0),
            BookmarkedProcesses = _annotationStore?.CountProcessAnnotationTargets() ?? 0,
            MemoryDumpCount = stats.MemoryDumpCount,
            MemoryImageCount = stats.MemoryImageCount,
            PeAnalysisCount = stats.PeAnalysisCount,
            NetworkCaptureCount = stats.NetworkCaptureCount,
            ZeekNetworkArtifactCount = stats.ZeekNetworkArtifactCount,
            FilesystemArtifactCount = stats.FilesystemArtifactCount,
            SearchResultCount = _featureModules.TryGetActivated<SearchFeatureModule>(FeatureIds.SearchAndSigma, out var search)
                ? search.ViewModel.Results.Count : 0,
            SigmaFindingCount = _featureModules.TryGetActivated<SigmaViewModel>(FeatureIds.SearchAndSigma, out var sigma)
                ? sigma.Findings.Count : 0,
            UnresolvedEvidenceCount = 0,
            AmbiguousEvidenceCount = 0,
            SystemActivityCount = systemActivityCounts.TryGetValue(SystemActivityScopeKind.All, out var activityCount)
                ? activityCount
                : 0,
            SystemActivityAccountCount = systemActivityAccountCount,
            SystemActivityCountsByScope = systemActivityCounts,
            EventProcessesBySource = sourceCounts
        };
    }

    private ExplorerScopeCounts AddAnalysisCounts(ExplorerScopeCounts counts)
    {
        return new ExplorerScopeCounts
        {
            TotalProcesses = counts.TotalProcesses,
            RunningProcesses = counts.RunningProcesses,
            ExitedProcesses = counts.ExitedProcesses,
            NotFoundProcesses = counts.NotFoundProcesses,
            ModuleProcesses = counts.ModuleProcesses,
            HandleProcesses = counts.HandleProcesses,
            BookmarkedProcesses = counts.BookmarkedProcesses,
            MemoryDumpCount = counts.MemoryDumpCount,
            MemoryImageCount = counts.MemoryImageCount,
            PeAnalysisCount = counts.PeAnalysisCount,
            NetworkCaptureCount = counts.NetworkCaptureCount,
            ZeekNetworkArtifactCount = counts.ZeekNetworkArtifactCount,
            FilesystemArtifactCount = counts.FilesystemArtifactCount,
            SearchResultCount = _featureModules.TryGetActivated<SearchFeatureModule>(FeatureIds.SearchAndSigma, out var search)
                ? search.ViewModel.Results.Count : 0,
            SigmaFindingCount = _featureModules.TryGetActivated<SigmaViewModel>(FeatureIds.SearchAndSigma, out var sigma)
                ? sigma.Findings.Count : 0,
            UnresolvedEvidenceCount = counts.UnresolvedEvidenceCount,
            AmbiguousEvidenceCount = counts.AmbiguousEvidenceCount,
            SystemActivityCount = counts.SystemActivityCount,
            SystemActivityAccountCount = counts.SystemActivityAccountCount,
            SystemActivityCountsByScope = counts.SystemActivityCountsByScope,
            EventProcessesBySource = counts.EventProcessesBySource
        };
    }

    private async Task<IReadOnlyList<ExplorerNodeViewModel>> LoadExplorerChildrenAsync(ExplorerScope scope)
    {
        return scope.Kind switch
        {
            ExplorerScopeKind.ProcessExecutionRoot => await LoadProcessRootNodesAsync(scope),
            ExplorerScopeKind.ProcessBranch => await LoadProcessChildNodesAsync(scope),
            ExplorerScopeKind.ProcessOwners => await LoadProcessOwnerNodesAsync(scope),
            ExplorerScopeKind.UsersRoot => await LoadSystemActivityUserNodesAsync(scope),
            ExplorerScopeKind.FilesystemEvidenceRoots => await LoadFilesystemRootNodesAsync(),
            ExplorerScopeKind.FilesystemFolder => await LoadFilesystemFolderNodesAsync(scope),
            ExplorerScopeKind.NetworkCaptures => await Task.Run(BuildNetworkCaptureNodes),
            ExplorerScopeKind.UnresolvedEvidence or ExplorerScopeKind.AmbiguousEvidence =>
                await LoadCorrelationEvidenceGroupNodesAsync(scope),
            _ => []
        };
    }

    private async Task<IReadOnlyList<ExplorerNodeViewModel>> LoadProcessRootNodesAsync(ExplorerScope scope)
    {
        const int maxNodes = 100;
        if (_sqliteStagingQueryService != null)
        {
            var rows = await _sqliteStagingQueryService.GetExplorerProcessRootsAsync(scope, maxNodes);
            return rows.Select(CreateProcessExplorerNode).ToList();
        }

        var hierarchy = new ExplorerProcessHierarchy(_processViewModels.Values);
        return _processViewModels.Values
            .Where(row => MatchesIdentityScope(row, scope))
            .Where(row => !hierarchy.HasResolvableParent(row))
            .OrderBy(row => row.ProcessInfo.StartTime)
            .ThenBy(row => row.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Take(maxNodes)
            .Select(row => CreateProcessExplorerNode(CreateProcessNodeSummary(row, hierarchy)))
            .ToList();
    }

    private async Task<IReadOnlyList<ExplorerNodeViewModel>> LoadProcessChildNodesAsync(ExplorerScope parentScope)
    {
        const int maxNodes = 100;
        var parentProcessKey = parentScope.ProcessKey;
        if (string.IsNullOrWhiteSpace(parentProcessKey))
        {
            return [];
        }

        if (_sqliteStagingQueryService != null)
        {
            var rows = await _sqliteStagingQueryService.GetExplorerProcessChildrenAsync(parentScope, maxNodes);
            return rows.Select(CreateProcessExplorerNode).ToList();
        }

        var hierarchy = new ExplorerProcessHierarchy(_processViewModels.Values);
        return _processViewModels.Values
            .Where(row => MatchesIdentityScope(row, parentScope))
            .Where(row => hierarchy.IsImmediateChildOf(row, parentProcessKey))
            .OrderBy(row => row.ProcessInfo.StartTime)
            .ThenBy(row => row.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Take(maxNodes)
            .Select(row => CreateProcessExplorerNode(CreateProcessNodeSummary(row, hierarchy)))
            .ToList();
    }

    private async Task<IReadOnlyList<ExplorerNodeViewModel>> LoadProcessOwnerNodesAsync(ExplorerScope scope)
    {
        const int maxNodes = 100;
        if (_sqliteStagingQueryService != null)
        {
            var rows = await _sqliteStagingQueryService.GetExplorerProcessOwnersAsync(scope, maxNodes);
            return rows.Select(CreateProcessOwnerExplorerNode).ToList();
        }

        return BuildProcessOwnerNodesFromMemory(scope, maxNodes);
    }

    private IReadOnlyList<ExplorerNodeViewModel> BuildProcessOwnerNodesFromMemory(ExplorerScope scope, int maxNodes)
    {
        var summaries = new Dictionary<string, MutableOwnerSummary>(StringComparer.Ordinal);
        foreach (var row in _processViewModels.Values.Where(row => MatchesIdentityScope(row, scope)))
        {
            var ownerKey = NormalizeProcessOwnerKey(row.UserName);
            var key = string.Join(
                '\u001f',
                row.ProcessInfo.CaseId,
                row.ProcessInfo.EvidenceSessionId,
                row.ProcessInfo.CaptureId,
                row.ProcessInfo.SourceIdentityId,
                row.ProcessInfo.HostId,
                row.ProcessInfo.ExecutionRootId,
                ownerKey);
            if (!summaries.TryGetValue(key, out var summary))
            {
                var displayName = GetProcessOwnerDisplayName(row.UserName);
                summary = new MutableOwnerSummary
                {
                    OwnerKey = ownerKey,
                    DisplayName = displayName,
                    Domain = GetProcessOwnerDomain(displayName),
                    CaseId = row.ProcessInfo.CaseId,
                    EvidenceSessionId = row.ProcessInfo.EvidenceSessionId,
                    CaptureId = row.ProcessInfo.CaptureId,
                    SourceIdentityId = row.ProcessInfo.SourceIdentityId,
                    HostId = row.ProcessInfo.HostId,
                    ExecutionRootId = row.ProcessInfo.ExecutionRootId
                };
                summaries[key] = summary;
            }

            summary.ProcessCount++;
        }

        return summaries.Values
            .OrderBy(summary => string.Equals(summary.OwnerKey, UnknownProcessOwnerKey, StringComparison.Ordinal))
            .ThenBy(summary => summary.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(summary => summary.CaptureId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(summary => summary.ExecutionRootId, StringComparer.OrdinalIgnoreCase)
            .Take(maxNodes)
            .Select(summary => CreateProcessOwnerExplorerNode(summary.ToRecord()))
            .ToList();
    }

    private async Task<IReadOnlyList<ExplorerNodeViewModel>> LoadSystemActivityUserNodesAsync(ExplorerScope scope)
    {
        const int maxNodes = 100;
        var query = new SystemActivityQuery
        {
            CaseId = scope.CaseId,
            EvidenceSessionId = scope.EvidenceSessionId,
            CaptureId = scope.CaptureId,
            SourceIdentityId = scope.SourceIdentityId,
            HostId = scope.HostId,
            ExecutionRootId = scope.ExecutionRootId,
            MaxCount = 10000
        };

        var accounts = await Task.Run(() => _telemetryProjectionService.GetSystemActivityAccounts(query, maxNodes));
        return accounts.Select(CreateSystemActivityAccountExplorerNode).ToList();
    }

    private static ExplorerNodeViewModel CreateSystemActivityAccountExplorerNode(SystemActivityAccountSummary summary)
    {
        var title = string.IsNullOrWhiteSpace(summary.DisplayName)
            ? summary.AccountKey
            : summary.DisplayName;
        var scope = new ExplorerScope
        {
            Kind = ExplorerScopeKind.UserAccount,
            ScopeId = BuildSystemActivityAccountScopeId(summary),
            Title = title,
            Description =
                $"{summary.ActivityCount} account/system activit{(summary.ActivityCount == 1 ? "y" : "ies")}; " +
                $"{summary.LogonCount} logon event{(summary.LogonCount == 1 ? string.Empty : "s")}; " +
                $"{summary.GroupChangeCount} group change{(summary.GroupChangeCount == 1 ? string.Empty : "s")}",
            SystemActivityScope = SystemActivityScopeKind.All,
            AccountKey = summary.AccountKey,
            AccountDisplayName = title,
            AccountDomain = EmptyToNull(summary.Domain),
            AccountSid = EmptyToNull(summary.Sid),
            OwnerKey = summary.AccountKey,
            OwnerDisplayName = title,
            OwnerDomain = EmptyToNull(summary.Domain),
            OwnerSid = EmptyToNull(summary.Sid),
            CaseId = EmptyToNull(summary.CaseId),
            EvidenceSessionId = EmptyToNull(summary.EvidenceSessionId),
            CaptureId = EmptyToNull(summary.CaptureId),
            SourceIdentityId = EmptyToNull(summary.SourceIdentityId),
            HostId = EmptyToNull(summary.HostId),
            ExecutionRootId = EmptyToNull(summary.ExecutionRootId)
        };

        var node = new ExplorerNodeViewModel(scope, summary.ActivityCount);
        node.Children.Add(CreateAccountProcessOwnerNode(summary, title));
        node.Children.Add(CreateAccountActivityNode(summary, title, "Logons", SystemActivityScopeKind.Authentication, ExplorerScopeKind.ActivityAuthentication, summary.LogonCount));
        node.Children.Add(CreateAccountActivityNode(summary, title, "Group changes involving user", SystemActivityScopeKind.SecurityGroupMembershipChanges, ExplorerScopeKind.ActivitySecurityGroupMembershipChanges, summary.GroupChangeCount));
        node.Children.Add(CreateAccountActivityNode(summary, title, "Privileged activity", SystemActivityScopeKind.PrivilegedLogons, ExplorerScopeKind.ActivityPrivilegedLogons, summary.PrivilegedActivityCount));
        return node;
    }

    private static ExplorerNodeViewModel CreateAccountProcessOwnerNode(
        SystemActivityAccountSummary summary,
        string accountDisplayName)
    {
        return new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = ExplorerScopeKind.ProcessOwner,
            ScopeId = $"{BuildSystemActivityAccountScopeId(summary)}|processes-owned",
            Title = "Processes owned",
            Description = $"Processes whose normalized owner matches {accountDisplayName}.",
            OwnerKey = summary.AccountKey,
            OwnerDisplayName = accountDisplayName,
            OwnerDomain = EmptyToNull(summary.Domain),
            OwnerSid = EmptyToNull(summary.Sid),
            CaseId = EmptyToNull(summary.CaseId),
            EvidenceSessionId = EmptyToNull(summary.EvidenceSessionId),
            CaptureId = EmptyToNull(summary.CaptureId),
            SourceIdentityId = EmptyToNull(summary.SourceIdentityId),
            HostId = EmptyToNull(summary.HostId),
            ExecutionRootId = EmptyToNull(summary.ExecutionRootId)
        }, count: -1);
    }

    private static ExplorerNodeViewModel CreateAccountActivityNode(
        SystemActivityAccountSummary summary,
        string accountDisplayName,
        string title,
        SystemActivityScopeKind activityScope,
        ExplorerScopeKind explorerKind,
        int count)
    {
        return new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = explorerKind,
            ScopeId = $"{BuildSystemActivityAccountScopeId(summary)}|activity:{activityScope}",
            Title = title,
            Description = $"{title} for {accountDisplayName}.",
            SystemActivityScope = activityScope,
            AccountKey = summary.AccountKey,
            AccountDisplayName = accountDisplayName,
            AccountDomain = EmptyToNull(summary.Domain),
            AccountSid = EmptyToNull(summary.Sid),
            OwnerKey = summary.AccountKey,
            OwnerDisplayName = accountDisplayName,
            OwnerDomain = EmptyToNull(summary.Domain),
            OwnerSid = EmptyToNull(summary.Sid),
            CaseId = EmptyToNull(summary.CaseId),
            EvidenceSessionId = EmptyToNull(summary.EvidenceSessionId),
            CaptureId = EmptyToNull(summary.CaptureId),
            SourceIdentityId = EmptyToNull(summary.SourceIdentityId),
            HostId = EmptyToNull(summary.HostId),
            ExecutionRootId = EmptyToNull(summary.ExecutionRootId)
        }, count);
    }

    private static string BuildSystemActivityAccountScopeId(SystemActivityAccountSummary summary)
    {
        return string.Join(
            "|",
            "system-activity-account",
            summary.CaseId,
            summary.EvidenceSessionId,
            summary.CaptureId,
            summary.SourceIdentityId,
            summary.HostId,
            summary.ExecutionRootId,
            summary.AccountKey);
    }

    private static ExplorerNodeViewModel CreateProcessOwnerExplorerNode(ExplorerProcessOwnerSummary summary)
    {
        var descriptionParts = new List<string>
        {
            $"{summary.ProcessCount} owned process{(summary.ProcessCount == 1 ? string.Empty : "es")}"
        };
        if (!string.IsNullOrWhiteSpace(summary.Domain))
        {
            descriptionParts.Add($"Domain: {summary.Domain}");
        }

        if (!string.IsNullOrWhiteSpace(summary.Sid))
        {
            descriptionParts.Add($"SID: {summary.Sid}");
        }

        descriptionParts.Add(BuildEvidenceRootDescription(summary));

        return new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = ExplorerScopeKind.ProcessOwner,
            ScopeId = BuildProcessOwnerScopeId(summary),
            Title = string.IsNullOrWhiteSpace(summary.DisplayName) ? "Unknown / unresolved owner" : summary.DisplayName,
            Description = string.Join("; ", descriptionParts),
            OwnerKey = summary.OwnerKey,
            OwnerDisplayName = summary.DisplayName,
            OwnerDomain = EmptyToNull(summary.Domain),
            OwnerSid = EmptyToNull(summary.Sid),
            CaseId = EmptyToNull(summary.CaseId),
            EvidenceSessionId = EmptyToNull(summary.EvidenceSessionId),
            CaptureId = EmptyToNull(summary.CaptureId),
            SourceIdentityId = EmptyToNull(summary.SourceIdentityId),
            HostId = EmptyToNull(summary.HostId),
            ExecutionRootId = EmptyToNull(summary.ExecutionRootId)
        }, summary.ProcessCount);
    }

    private static string BuildProcessOwnerScopeId(ExplorerProcessOwnerSummary summary)
    {
        return string.Join(
            "|",
            "process-owner",
            summary.CaseId,
            summary.EvidenceSessionId,
            summary.CaptureId,
            summary.SourceIdentityId,
            summary.HostId,
            summary.ExecutionRootId,
            summary.OwnerKey);
    }

    private static ExplorerProcessNodeSummary CreateProcessNodeSummary(
        ProcessRowViewModel row,
        ExplorerProcessHierarchy hierarchy)
    {
        return new ExplorerProcessNodeSummary
        {
            ProcessKey = row.ProcessKey,
            ProcessId = row.ProcessId,
            ProcessName = row.ProcessName,
            ProcessPath = row.ProcessPath,
            Status = row.ProcessInfo.Status,
            ParentProcessKey = row.ProcessInfo.ParentProcessKey,
            DescendantProcessCount = hierarchy.CountDescendants(row),
            CaseId = row.ProcessInfo.CaseId,
            EvidenceSessionId = row.ProcessInfo.EvidenceSessionId,
            CaptureId = row.ProcessInfo.CaptureId,
            SourceIdentityId = row.ProcessInfo.SourceIdentityId,
            HostId = row.ProcessInfo.HostId,
            ExecutionRootId = row.ProcessInfo.ExecutionRootId
        };
    }

    private static ExplorerNodeViewModel CreateProcessExplorerNode(ExplorerProcessNodeSummary summary)
    {
        var title = string.IsNullOrWhiteSpace(summary.ProcessName)
            ? $"PID {summary.ProcessId}"
            : $"{summary.ProcessName} ({summary.ProcessId})";
        var node = new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = ExplorerScopeKind.ProcessBranch,
            ScopeId = BuildProcessBranchScopeId(summary),
            Title = title,
            Description = $"{summary.Status}; {summary.ProcessPath}",
            ProcessKey = summary.ProcessKey,
            CaseId = EmptyToNull(summary.CaseId),
            EvidenceSessionId = EmptyToNull(summary.EvidenceSessionId),
            CaptureId = EmptyToNull(summary.CaptureId),
            SourceIdentityId = EmptyToNull(summary.SourceIdentityId),
            HostId = EmptyToNull(summary.HostId),
            ExecutionRootId = EmptyToNull(summary.ExecutionRootId)
        }, summary.DescendantProcessCount);

        if (summary.DescendantProcessCount > 0)
        {
            node.MarkChildrenLazy();
        }

        return node;
    }

    private static string BuildProcessBranchScopeId(ExplorerProcessNodeSummary summary)
    {
        return string.Join(
            "|",
            "process",
            summary.CaseId,
            summary.EvidenceSessionId,
            summary.CaptureId,
            summary.SourceIdentityId,
            summary.HostId,
            summary.ExecutionRootId,
            summary.ProcessKey);
    }

    private ProcessRowViewModel? FindFallbackParent(ProcessRowViewModel child)
    {
        if (child.ProcessInfo.ParentProcessId <= 0)
        {
            return null;
        }

        return _processViewModels.Values
            .Where(parent => parent.ProcessId == child.ProcessInfo.ParentProcessId)
            .Where(parent => !string.Equals(parent.ProcessKey, child.ProcessKey, StringComparison.Ordinal))
            .Where(parent => HasSameEvidenceIdentity(child, parent))
            .Where(parent => IsPlausibleParentStart(child, parent))
            .OrderByDescending(parent => parent.ProcessInfo.StartTime ?? DateTime.MinValue)
            .FirstOrDefault();
    }

    private static bool HasSameEvidenceIdentity(ProcessRowViewModel child, ProcessRowViewModel parent)
    {
        return string.Equals(child.ProcessInfo.CaseId, parent.ProcessInfo.CaseId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.EvidenceSessionId, parent.ProcessInfo.EvidenceSessionId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.CaptureId, parent.ProcessInfo.CaptureId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.SourceIdentityId, parent.ProcessInfo.SourceIdentityId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.HostId, parent.ProcessInfo.HostId, StringComparison.Ordinal) &&
               string.Equals(child.ProcessInfo.ExecutionRootId, parent.ProcessInfo.ExecutionRootId, StringComparison.Ordinal);
    }

    private static bool IsPlausibleParentStart(ProcessRowViewModel child, ProcessRowViewModel parent)
    {
        return child.ProcessInfo.StartTime == null ||
               parent.ProcessInfo.StartTime == null ||
               child.ProcessInfo.StartTime >= parent.ProcessInfo.StartTime;
    }

    private async Task<IReadOnlyList<ExplorerNodeViewModel>> LoadFilesystemRootNodesAsync()
    {
        const int maxNodes = 100;
        if (_sqliteStagingQueryService == null)
        {
            return [];
        }

        var roots = await _sqliteStagingQueryService.GetExplorerFilesystemRootsAsync(maxNodes);
        return roots
            .Select(CreateFilesystemRootExplorerNode)
            .ToList();
    }

    private async Task<IReadOnlyList<ExplorerNodeViewModel>> LoadFilesystemFolderNodesAsync(ExplorerScope scope)
    {
        const int maxNodes = 100;
        if (_sqliteStagingQueryService != null)
        {
            var rows = await _sqliteStagingQueryService.GetExplorerFilesystemChildrenAsync(scope, maxNodes);
            return rows.Select(CreateFilesystemFolderNode).ToList();
        }

        return BuildFilesystemFolderNodesFromProjection(scope);
    }

    private IReadOnlyList<ExplorerNodeViewModel> BuildFilesystemFolderNodesFromProjection(ExplorerScope scope)
    {
        const int maxArtifacts = 5000;
        const int maxFolders = 100;
        var artifacts = _telemetryProjectionService.GetFilesystemArtifacts(maxArtifacts)
            .Where(artifact => !string.IsNullOrWhiteSpace(artifact.SourcePath))
            .Where(artifact => MatchesFilesystemIdentity(artifact, scope))
            .ToList();
        var folders = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var artifact in artifacts)
        {
            var childFolder = GetImmediateFilesystemChildFolder(artifact.SourcePath, scope.FilesystemPath);
            if (string.IsNullOrWhiteSpace(childFolder))
            {
                continue;
            }

            folders[childFolder] = folders.TryGetValue(childFolder, out var count) ? count + 1 : 1;
        }

        return folders
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(maxFolders)
            .Select(pair => CreateFilesystemFolderNode(new ExplorerFilesystemNodeSummary
            {
                FolderPath = pair.Key,
                ArtifactCount = pair.Value,
                ChildFolderCount = artifacts.Any(artifact => GetImmediateFilesystemChildFolder(artifact.SourcePath, pair.Key) != null) ? 1 : 0,
                CaseId = scope.CaseId ?? string.Empty,
                EvidenceSessionId = scope.EvidenceSessionId ?? string.Empty,
                CaptureId = scope.CaptureId ?? string.Empty,
                SourceIdentityId = scope.SourceIdentityId ?? string.Empty,
                HostId = scope.HostId ?? string.Empty,
                ExecutionRootId = scope.ExecutionRootId ?? string.Empty
            }))
            .ToList();
    }

    private static ExplorerNodeViewModel CreateFilesystemRootExplorerNode(EvidenceRootSummary root)
    {
        var scope = new ExplorerScope
        {
            Kind = ExplorerScopeKind.FilesystemFolder,
            ScopeId = BuildIdentityScopeId("filesystem-root", root),
            Title = BuildFilesystemRootTitle(root),
            Description = BuildEvidenceRootDescription(root),
            CaseId = EmptyToNull(root.CaseId),
            EvidenceSessionId = EmptyToNull(root.EvidenceSessionId),
            CaptureId = EmptyToNull(root.CaptureId),
            SourceIdentityId = EmptyToNull(root.SourceIdentityId),
            HostId = EmptyToNull(root.HostId),
            ExecutionRootId = EmptyToNull(root.ExecutionRootId)
        };

        var node = new ExplorerNodeViewModel(scope, root.FilesystemArtifactCount);
        node.MarkChildrenLazy();
        return node;
    }

    private static ExplorerNodeViewModel CreateFilesystemFolderNode(ExplorerFilesystemNodeSummary summary)
    {
        var folderPath = summary.FolderPath;
        var node = new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = ExplorerScopeKind.FilesystemFolder,
            ScopeId = BuildFilesystemScopeId(summary),
            Title = GetFolderDisplayName(folderPath),
            Description = folderPath,
            FilesystemPath = folderPath,
            CaseId = EmptyToNull(summary.CaseId),
            EvidenceSessionId = EmptyToNull(summary.EvidenceSessionId),
            CaptureId = EmptyToNull(summary.CaptureId),
            SourceIdentityId = EmptyToNull(summary.SourceIdentityId),
            HostId = EmptyToNull(summary.HostId),
            ExecutionRootId = EmptyToNull(summary.ExecutionRootId)
        }, summary.ArtifactCount);

        if (summary.ChildFolderCount > 0)
        {
            node.MarkChildrenLazy();
        }

        return node;
    }

    private static string BuildFilesystemScopeId(ExplorerFilesystemNodeSummary summary)
    {
        return string.Join(
            "|",
            "filesystem:folder",
            summary.CaseId,
            summary.EvidenceSessionId,
            summary.CaptureId,
            summary.SourceIdentityId,
            summary.HostId,
            summary.ExecutionRootId,
            summary.FolderPath);
    }

    private static string BuildFilesystemRootTitle(EvidenceRootSummary root)
    {
        if (!string.IsNullOrWhiteSpace(root.CaptureId))
        {
            return $"Capture {ShortId(root.CaptureId)}";
        }

        if (!string.IsNullOrWhiteSpace(root.SourceIdentityId))
        {
            return $"Source {ShortId(root.SourceIdentityId)}";
        }

        if (!string.IsNullOrWhiteSpace(root.EvidenceSessionId))
        {
            return $"Session {ShortId(root.EvidenceSessionId)}";
        }

        return "Default Filesystem Root";
    }

    private static string BuildIdentityScopeId(string prefix, EvidenceRootSummary root)
    {
        return string.Join(
            "|",
            prefix,
            root.CaseId,
            root.EvidenceSessionId,
            root.CaptureId,
            root.SourceIdentityId,
            root.HostId,
            root.ExecutionRootId);
    }

    private static string BuildEvidenceRootDescription(EvidenceRootSummary root)
    {
        return BuildEvidenceIdentityDescription(
            root.CaseId,
            root.EvidenceSessionId,
            root.CaptureId,
            root.SourceIdentityId,
            root.HostId,
            root.ExecutionRootId);
    }

    private static string BuildEvidenceRootDescription(ExplorerProcessOwnerSummary owner)
    {
        return BuildEvidenceIdentityDescription(
            owner.CaseId,
            owner.EvidenceSessionId,
            owner.CaptureId,
            owner.SourceIdentityId,
            owner.HostId,
            owner.ExecutionRootId);
    }

    private static string BuildEvidenceIdentityDescription(
        string caseId,
        string evidenceSessionId,
        string captureId,
        string sourceIdentityId,
        string hostId,
        string executionRootId)
    {
        var parts = new[]
        {
            $"Case: {FormatId(caseId)}",
            $"Session: {FormatId(evidenceSessionId)}",
            $"Capture: {FormatId(captureId)}",
            $"Source: {FormatId(sourceIdentityId)}",
            $"Host: {FormatId(hostId)}",
            $"Execution: {FormatId(executionRootId)}"
        };

        return string.Join("; ", parts);
    }

    private static string ShortId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "<default>";
        }

        return value.Length <= 18
            ? value
            : $"{value[..8]}...{value[^6..]}";
    }

    private static string FormatId(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "<default>" : value;
    }

    private static string NormalizeProcessOwnerKey(string? userName)
    {
        var trimmed = userName?.Trim();
        return IsUnknownProcessOwner(trimmed)
            ? UnknownProcessOwnerKey
            : trimmed!.ToLowerInvariant();
    }

    private static string GetProcessOwnerDisplayName(string? userName)
    {
        var trimmed = userName?.Trim();
        return IsUnknownProcessOwner(trimmed)
            ? UnknownProcessOwnerDisplayName
            : trimmed!;
    }

    private static bool IsUnknownProcessOwner(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ||
               string.Equals(value, "<not available>", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "<access denied>", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "<unknown>", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "unknown", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "n/a", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetProcessOwnerDomain(string displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName) ||
            string.Equals(displayName, UnknownProcessOwnerDisplayName, StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        var slashIndex = displayName.IndexOf('\\');
        if (slashIndex > 0)
        {
            return displayName[..slashIndex];
        }

        var atIndex = displayName.IndexOf('@');
        return atIndex > 0 && atIndex < displayName.Length - 1
            ? displayName[(atIndex + 1)..]
            : string.Empty;
    }

    private IReadOnlyList<ExplorerNodeViewModel> BuildNetworkCaptureNodes()
    {
        const int maxCaptures = 100;
        return GetMergedNetworkCaptures(maxCaptures)
            .Select(capture => new ExplorerNodeViewModel(new ExplorerScope
            {
                Kind = ExplorerScopeKind.NetworkCapture,
                ScopeId = $"network:capture:{capture.CaptureId}",
                Title = $"Segment {capture.SegmentIndex}: {capture.Status}",
                Description = string.IsNullOrWhiteSpace(capture.FilePath)
                    ? capture.OutputDirectory
                    : capture.FilePath
            }, count: -1))
            .ToList();
    }

    private IReadOnlyList<NetworkCaptureRecord> GetMergedNetworkCaptures(int maxCount)
    {
        return _telemetryProjectionService.GetNetworkCaptures(maxCount)
            .Select(row => global::ProcInsider.ViewModels.NetworkCapturesViewModel.NormalizeCaptureStatus(
                row,
                IsActiveNetworkCaptureRow(row),
                IsFinalizingNetworkCaptureRow(row)))
            .OrderByDescending(row => row.RequestedUtc)
            .Take(Math.Clamp(maxCount, 1, 10000))
            .ToList();
    }

    private bool IsActiveNetworkCaptureRow(NetworkCaptureRecord capture)
    {
        var networkState = _agentCaptureWorkflowCoordinator.Control
            .GetJobSource(JobKind.NetworkCapture)
            .State;
        if (capture.Status != NetworkCaptureStatus.Capturing ||
            networkState is not AgentCaptureRunState.Starting and not AgentCaptureRunState.Running)
        {
            return false;
        }

        if (_activeNetworkCaptureJobId.HasValue && capture.JobId.HasValue)
        {
            return _activeNetworkCaptureJobId.Value == capture.JobId.Value;
        }

        return !_activeNetworkCaptureJobId.HasValue;
    }

    private bool IsFinalizingNetworkCaptureRow(NetworkCaptureRecord capture)
    {
        var networkState = _agentCaptureWorkflowCoordinator.Control
            .GetJobSource(JobKind.NetworkCapture)
            .State;
        if (capture.Status != NetworkCaptureStatus.Capturing ||
            networkState is not AgentCaptureRunState.Stopping and not AgentCaptureRunState.Draining)
        {
            return false;
        }

        if (_activeNetworkCaptureJobId.HasValue && capture.JobId.HasValue)
        {
            return _activeNetworkCaptureJobId.Value == capture.JobId.Value;
        }

        return true;
    }

    private static string? GetImmediateFilesystemChildFolder(string artifactPath, string? parentPath)
    {
        var normalizedPath = NormalizeFilesystemPath(artifactPath);
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(parentPath))
        {
            var root = Path.GetPathRoot(normalizedPath);
            return string.IsNullOrWhiteSpace(root) ? null : root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        var normalizedParent = NormalizeFilesystemPath(parentPath);
        if (string.IsNullOrWhiteSpace(normalizedParent) ||
            !normalizedPath.StartsWith(normalizedParent, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var remainder = normalizedPath[normalizedParent.Length..].TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.IsNullOrWhiteSpace(remainder))
        {
            return null;
        }

        var separators = new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar };
        var firstSeparator = remainder.IndexOfAny(separators);
        if (firstSeparator <= 0)
        {
            return null;
        }

        var childSegment = remainder[..firstSeparator];
        return CombineFilesystemPath(normalizedParent, childSegment);
    }

    private static string NormalizeFilesystemPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var trimmed = path.Trim();
        if (trimmed.Length >= 2 &&
            char.IsLetter(trimmed[0]) &&
            trimmed[1] == ':' &&
            (trimmed.Length == 2 ||
             (trimmed.Length == 3 && (trimmed[2] == Path.DirectorySeparatorChar || trimmed[2] == Path.AltDirectorySeparatorChar))))
        {
            return trimmed[..2];
        }

        var separators = new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar };
        var root = Path.GetPathRoot(trimmed);
        if (!string.IsNullOrWhiteSpace(root) &&
            string.Equals(trimmed.TrimEnd(separators), root.TrimEnd(separators), StringComparison.OrdinalIgnoreCase))
        {
            return root.TrimEnd(separators);
        }

        try
        {
            return Path.GetFullPath(trimmed).TrimEnd(separators);
        }
        catch
        {
            return trimmed.TrimEnd(separators);
        }
    }

    private static string CombineFilesystemPath(string parent, string child)
    {
        if (parent.EndsWith(Path.DirectorySeparatorChar) || parent.EndsWith(Path.AltDirectorySeparatorChar))
        {
            return parent + child;
        }

        return parent + Path.DirectorySeparatorChar + child;
    }

    private static string GetFolderDisplayName(string folderPath)
    {
        var name = Path.GetFileName(folderPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return string.IsNullOrWhiteSpace(name) ? folderPath : name;
    }

    private static bool MatchesFilesystemIdentity(FilesystemArtifactRecord artifact, ExplorerScope scope)
    {
        return MatchesScopeValue(artifact.CaseId, scope.CaseId) &&
               MatchesScopeValue(artifact.EvidenceSessionId, scope.EvidenceSessionId) &&
               MatchesScopeValue(artifact.CaptureId, scope.CaptureId) &&
               MatchesScopeValue(artifact.SourceIdentityId, scope.SourceIdentityId) &&
               MatchesScopeValue(artifact.HostId, scope.HostId) &&
               MatchesScopeValue(artifact.ExecutionRootId, scope.ExecutionRootId);
    }

    private static bool MatchesScopeValue(string artifactValue, string? scopeValue)
    {
        return string.IsNullOrWhiteSpace(scopeValue) ||
               string.Equals(artifactValue, scopeValue, StringComparison.Ordinal);
    }

    private static string? EmptyToNull(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    [RelayCommand(CanExecute = nameof(CanToggleSelectedProcessBookmark))]
    private void ToggleSelectedProcessBookmark()
    {
        if (SelectedProcess == null || _annotationStore == null)
        {
            StatusMessage = "Select a staged process before changing bookmarks.";
            return;
        }

        var row = SelectedProcess;
        if (IsSelectedProcessBookmarked)
        {
            _annotationStore.DeleteBookmark(ProcessBookmarkKind, row.ProcessKey);
            IsSelectedProcessBookmarked = false;
            StatusMessage = $"Removed bookmark for {row.ProcessName} (PID {row.ProcessId}).";
        }
        else
        {
            var now = DateTime.UtcNow;
            var target = CreateProcessAnnotationTarget(row);
            var bookmark = new BookmarkRecord
            {
                BookmarkId = Guid.NewGuid().ToString("N"),
                TargetKind = target.TargetKind,
                TargetTable = target.TargetTable,
                TargetId = target.TargetId,
                ArtifactId = target.ArtifactId,
                CaseId = target.CaseId,
                EvidenceSessionId = target.EvidenceSessionId,
                CaptureId = target.CaptureId,
                SourceIdentityId = target.SourceIdentityId,
                HostId = target.HostId,
                ProcessKey = target.ProcessKey,
                ProcessId = target.ProcessId,
                ProcessName = target.ProcessName,
                Label = target.Label,
                DisplayPath = target.DisplayPath,
                CreatedUtc = now,
                UpdatedUtc = now
            };
            _annotationStore.UpsertBookmark(bookmark);
            IsSelectedProcessBookmarked = true;
            StatusMessage = $"Bookmarked {row.ProcessName} (PID {row.ProcessId}).";
        }

        _ = RefreshExplorerCountsForChangedInputsAsync(
            ExplorerCountRefreshTrigger.AnnotationMutation);
        if (_activeExplorerScope.Kind == ExplorerScopeKind.Bookmarked)
        {
            ScheduleDbRefresh();
        }
    }

    [RelayCommand(CanExecute = nameof(CanUseAiFeature))]
    private void OpenAiInvestigationTab()
    {
        if (!TryNavigateToExplorerTab(ExplorerTabKeys.Ai, "Open AI Investigation"))
        {
            return;
        }

        SelectedExplorerAiSection = ExplorerAiSection.Investigation;
        StatusMessage = "Explorer AI investigation tab selected.";
    }

    private bool CanToggleSelectedProcessBookmark()
    {
        return SelectedProcess != null &&
               _annotationStore != null &&
               !string.IsNullOrWhiteSpace(SelectedProcess.ProcessKey);
    }

    private void UpdateSelectedProcessBookmarkState()
    {
        IsSelectedProcessBookmarked = SelectedProcess != null && IsProcessBookmarked(SelectedProcess.ProcessKey);
        ToggleSelectedProcessBookmarkCommand.NotifyCanExecuteChanged();
    }

    private bool IsProcessBookmarked(string processKey)
    {
        if (_annotationStore == null || string.IsNullOrWhiteSpace(processKey))
        {
            return false;
        }

        try
        {
            return _annotationStore.IsBookmarked(ProcessBookmarkKind, processKey);
        }
        catch
        {
            return false;
        }
    }

    private static AnnotationTarget CreateProcessAnnotationTarget(ProcessRowViewModel row)
    {
        var process = row.ProcessInfo;
        return new AnnotationTarget
        {
            TargetKind = ProcessBookmarkKind,
            TargetTable = "Processes",
            TargetId = row.ProcessKey,
            ProcessKey = row.ProcessKey,
            ProcessId = row.ProcessId,
            ProcessName = row.ProcessName,
            Label = $"{row.ProcessName} (PID {row.ProcessId})",
            DisplayPath = row.ProcessPath,
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId
        };
    }

    private ProcessRowViewModel? FindVisibleProcessRow(TelemetrySearchResult result)
    {
        var candidates = _virtualizedProcessListing?.GetLoadedRows() ?? Processes;
        var target = !string.IsNullOrWhiteSpace(result.ProcessEntityId)
            ? candidates.FirstOrDefault(process =>
                string.Equals(process.ProcessInfo.ProcessEntityId, result.ProcessEntityId, StringComparison.Ordinal))
            : null;

        target ??= !string.IsNullOrWhiteSpace(result.ProcessKey)
            ? candidates.FirstOrDefault(process => process.ProcessKey == result.ProcessKey)
            : null;

        target ??= candidates
            .Where(process => process.ProcessId == result.ProcessId)
            .Where(process => string.IsNullOrWhiteSpace(result.ProcessName) ||
                string.Equals(process.ProcessName, result.ProcessName, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(process => process.ProcessInfo.StartTime ?? DateTime.MinValue)
            .FirstOrDefault();

        return target;
    }

    private ProcessRowViewModel? AddSearchResultProcessRow(TelemetrySearchResult result)
    {
        var process = _telemetryProjectionService.GetProcessForSearchResult(result);
        if (process == null)
        {
            return null;
        }

        var processKey = process.GetUniqueKey();
        if (!_processViewModels.TryGetValue(processKey, out var row))
        {
            row = new ProcessRowViewModel(process);
            UpdateProcessRowCounts(row, includeEventCounts: true);
            _processViewModels[processKey] = row;
        }

        if (!Processes.Contains(row))
        {
            Processes.Add(row);
            ProcessesView?.Refresh();
        }

        var stats = _telemetryProjectionService.GetStats();
        TotalProcessCount = stats.ProcessCount;
        RunningProcessCount = stats.RunningProcessCount;
        ExitedProcessCount = stats.ExitedProcessCount;
        return row;
    }

    private void UpdateProcessRowCounts(
        ProcessRowViewModel row,
        bool includeEventCounts,
        IReadOnlyDictionary<string, ProcessSourceEventCounts>? eventCountsByProcess = null,
        IReadOnlyDictionary<string, int>? moduleCountsByProcess = null,
        IReadOnlyDictionary<string, int>? handleCountsByProcess = null)
    {
        UpdateProcessRowArtifactCounts(row, moduleCountsByProcess, handleCountsByProcess);

        if (includeEventCounts)
        {
            var counts = eventCountsByProcess != null && eventCountsByProcess.TryGetValue(row.ProcessKey, out var groupedCounts)
                ? groupedCounts
                : _telemetryProjectionService.GetEventCounts(row.ProcessKey, row.ProcessInfo.ProcessEntityId);

            row.RuntimeEventCount = counts.RuntimeEventCount;
            row.EtwEventCount = counts.EtwEventCount;
            row.SecurityEventCount = counts.SecurityEventCount;
            row.PowerShellEventCount = counts.PowerShellEventCount;
            row.OtherWindowsEventCount = counts.OtherWindowsEventCount;
            row.SysmonEventCount = counts.SysmonEventCount;
        }
    }

    private void UpdateProcessRowArtifactCounts(
        ProcessRowViewModel row,
        IReadOnlyDictionary<string, int>? moduleCountsByProcess = null,
        IReadOnlyDictionary<string, int>? handleCountsByProcess = null)
    {
        var stagedModuleCount = moduleCountsByProcess != null && moduleCountsByProcess.TryGetValue(row.ProcessKey, out var moduleCount)
            ? moduleCount
            : _telemetryProjectionService.GetArtifactCounts(row.ProcessKey, row.ProcessInfo.ProcessEntityId).ModuleCount;
        var stagedHandleCount = handleCountsByProcess != null && handleCountsByProcess.TryGetValue(row.ProcessKey, out var handleCount)
            ? handleCount
            : _telemetryProjectionService.GetArtifactCounts(row.ProcessKey, row.ProcessInfo.ProcessEntityId).HandleCount;
        row.ModuleCount = stagedModuleCount > 0 ? stagedModuleCount : Math.Max(row.ProcessInfo.ModuleCount, row.ProcessInfo.CachedModules.Count);
        row.HandleCount = stagedHandleCount > 0 ? stagedHandleCount : Math.Max(row.ProcessInfo.HandleCount, row.ProcessInfo.CachedHandles.Count);
        row.ProcessInfo.ModuleCount = row.ModuleCount;
        row.ProcessInfo.HandleCount = row.HandleCount;
    }

    private void UpdateSelectedProcessArtifactCounts()
    {
        if (SelectedProcess == null)
        {
            return;
        }

        SelectedProcess.ModuleCount = ModulesViewModel.Modules.Count;
        SelectedProcess.HandleCount = HandlesViewModel.Handles.Count;
        SelectedProcess.ProcessInfo.ModuleCount = SelectedProcess.ModuleCount;
        SelectedProcess.ProcessInfo.HandleCount = SelectedProcess.HandleCount;
        SelectedProcess.RefreshDisplay();
    }

    private void RefreshSelectedProcessRow()
    {
        if (SelectedProcess == null)
        {
            return;
        }

        SelectedProcess.ModuleCount = Math.Max(SelectedProcess.ProcessInfo.ModuleCount, ModulesViewModel.Modules.Count);
        SelectedProcess.HandleCount = Math.Max(SelectedProcess.ProcessInfo.HandleCount, HandlesViewModel.Handles.Count);
        SelectedProcess.RefreshDisplay();
        ProcessPropertiesViewModel.LoadProcess(SelectedProcess);
    }

    private bool TryGetVisibleProcessRow(string processKey, out ProcessRowViewModel row)
    {
        if (_processViewModels.TryGetValue(processKey, out row!))
        {
            return true;
        }

        row = Processes.FirstOrDefault(process =>
            string.Equals(process.ProcessKey, processKey, StringComparison.Ordinal))!;
        return row != null;
    }

    /// <summary>
    /// Opens an existing PowerShell transcript folder without creating or widening it.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseSecurityMonitoringFeature))]
    public void OpenTranscriptFolder()
    {
        if (!RequireFeaturePublished(FeatureIds.SecurityMonitoringConfiguration, "Open PowerShell transcript folder")) return;
        try
        {
            _securityMonitoringService.OpenTranscriptFolder();
            StatusMessage = $"Opened transcript folder: {_securityMonitoringService.TranscriptPath}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open transcript folder: {ex.Message}";
        }
    }

    /// <summary>
    /// Opens Windows Event Viewer.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseEventTelemetryFeature))]
    public void OpenEventViewer()
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "Open Event Viewer")) return;
        try
        {
            _securityMonitoringService.OpenEventViewer();
            StatusMessage = "Opened Event Viewer.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open Event Viewer: {ex.Message}";
        }
    }

    /// <summary>
    /// Opens Windows Event Viewer focused on a specific event log channel.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseEventTelemetryFeature))]
    public void OpenEventViewerLog(string? logName)
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "Open Event Viewer log")) return;
        if (string.IsNullOrWhiteSpace(logName))
        {
            StatusMessage = "No Event Viewer log was selected.";
            return;
        }

        try
        {
            _securityMonitoringService.OpenEventViewerLog(logName);
            StatusMessage = $"Opened Event Viewer log: {logName}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open Event Viewer log '{logName}': {ex.Message}";
        }
    }

    /// <summary>
    /// Opens an existing legacy Security Monitoring install log without creating it.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseSecurityMonitoringFeature))]
    public void OpenMonitoringInstallLog()
    {
        if (!RequireFeaturePublished(FeatureIds.SecurityMonitoringConfiguration, "Open monitoring install log")) return;
        try
        {
            _securityMonitoringService.OpenInstallLog();
            StatusMessage = $"Opened monitoring install log: {_securityMonitoringService.InstallLogPath}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open monitoring install log: {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanUseSecurityMonitoringFeature))]
    public void OpenSecurityMonitoringPolicyProfile(ConfigProfileDefinition? profile)
    {
        if (!RequireFeaturePublished(FeatureIds.SecurityMonitoringConfiguration, "Open security monitoring profile")) return;
        if (profile == null)
        {
            StatusMessage = "No Security Monitoring profile was selected.";
            return;
        }

        var profileName = GetConfigProfileDisplayName(profile);
        try
        {
            _securityMonitoringService.OpenPolicyProfile(profile);
            RecordMonitoringProfileAction("open", profile, _securityMonitoringService.ResolvePolicyProfilePath(profile) ?? profile.FilePath);
            StatusMessage = $"Opened Security Monitoring profile: {profileName}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open Security Monitoring profile '{profileName}': {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanUseSecurityMonitoringFeature))]
    public void VerifyPowerShellAuditingProfile(ConfigProfileDefinition? profile)
    {
        if (!RequireFeaturePublished(FeatureIds.SecurityMonitoringConfiguration, "Verify PowerShell auditing profile")) return;
        if (profile == null)
        {
            StatusMessage = "No PowerShell Auditing profile was selected.";
            return;
        }

        var profileName = GetConfigProfileDisplayName(profile);
        if (!TryResolveMonitoringProfilePath(profile, _powerShellAuditingService.ResolveAuditingProfilePath, out var profilePath, out var pathError))
        {
            StatusMessage = $"Failed to resolve PowerShell Auditing profile '{profileName}': {pathError}";
            return;
        }

        try
        {
            var settings = _powerShellAuditingService.LoadSettings();
            if (!settings.IsAvailable)
            {
                StatusMessage =
                    $"PowerShell Auditing profile state is unavailable for '{profileName}': {settings.StatusDetail}";
                RecordMonitoringProfileAction("verify-powershell-unavailable", profile, profilePath);
                return;
            }

            var enabled = settings.ScriptBlockLoggingEnabled && settings.ModuleLoggingEnabled && settings.TranscriptionEnabled;
            StatusMessage = enabled
                ? $"PowerShell Auditing profile appears applied: {profileName}."
                : $"PowerShell Auditing profile is not fully applied: {profileName}.";
            RecordMonitoringProfileAction("verify-powershell", profile, profilePath);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to verify PowerShell Auditing profile '{profileName}': {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanUseSecurityMonitoringFeature))]
    public void OpenPowerShellAuditingProfile(ConfigProfileDefinition? profile)
    {
        if (!RequireFeaturePublished(FeatureIds.SecurityMonitoringConfiguration, "Open PowerShell auditing profile")) return;
        OpenConfigProfile(profile, "PowerShell Auditing");
    }

    [RelayCommand(CanExecute = nameof(CanUseSecurityMonitoringFeature))]
    public void OpenEventLogPolicyProfile(ConfigProfileDefinition? profile)
    {
        if (!RequireFeaturePublished(FeatureIds.SecurityMonitoringConfiguration, "Open Event Log policy profile")) return;
        OpenConfigProfile(profile, "Event Log Policy");
    }

    /// <summary>
    /// Restores tree-aware process ordering.
    /// </summary>
    public void ResetTreeSort()
    {
        _currentSortColumn = "Tree";
        _sortAscending = true;
        ProcessesView?.SortDescriptions.Clear();

        if (_processListingService != null)
        {
            ScheduleDbRefresh();
        }
        else
        {
            UpdateProcessList(GetProjectedProcesses());
        }
    }

    [RelayCommand]
    public void ClearCurrentViewerState()
    {
        const string warning =
            "Clear the current viewer rows and selections?\n\n" +
            "This does not modify the active SQLite evidence, agent capture, archived package, annotations, Windows logs, or monitoring policy. Refresh from db reloads the active snapshot.";

        if (MessageBox.Show(warning, "Clear Viewer State", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            StatusMessage = "Viewer-state clear canceled.";
            return;
        }

        var clearedVirtualListing = DetachVirtualizedProcessListing();
        clearedVirtualListing?.Dispose();
        _processViewModels.Clear();
        Processes.Clear();
        ProcessesView = CollectionViewSource.GetDefaultView(Processes);
        SelectedProcess = null;
        ProcessListingStatus = "Process listing was cleared; Refresh from db reloads it.";
        IsProcessListingLoading = false;
        if (_featureModules.TryGetActivated<DumpsAndPeFeatureModule>(FeatureIds.DumpsAndPeAnalysis, out var dumpsAndPe))
        {
            dumpsAndPe.MemoryDumpsViewModel.Clear();
            dumpsAndPe.PeAnalysisViewModel.Clear();
        }

        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory))
        {
            memory.Clear();
        }

        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            filesystem.Clear();
        }

        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events))
        {
            events.SystemActivityViewModel.Clear();
        }
        InspectorPaneViewModel.Clear();
        ExplorerViewModel.ResetCounts();
        ResetExplorerTabCounts();
        TotalProcessCount = 0;
        RunningProcessCount = 0;
        ExitedProcessCount = 0;
        StatusMessage = $"Cleared viewer rows only. {_telemetryProjectionService.PathDiagnostics.StatusMessage}";
    }

    private async Task BeginStagingLoadOperationAsync(string message)
    {
        IsRefreshing = true;
        IsStagingLoadInProgress = true;
        UpdateStagingLoadProgress(0, 1, message, isIndeterminate: true);
        await Dispatcher.Yield(DispatcherPriority.Background);
    }

    private async Task ReportStagingLoadProgressAsync(
        int current,
        int total,
        string message,
        bool isIndeterminate = true)
    {
        UpdateStagingLoadProgress(current, total, message, isIndeterminate);
        await Dispatcher.Yield(DispatcherPriority.Background);
    }

    private void UpdateStagingLoadProgress(
        int current,
        int total,
        string message,
        bool isIndeterminate = false)
    {
        StagingLoadProgressTotal = Math.Max(total, 1);
        StagingLoadProgressCurrent = Math.Clamp(current, 0, StagingLoadProgressTotal);
        StagingLoadProgressMessage = message;
        IsStagingLoadProgressIndeterminate = isIndeterminate;
        StatusMessage = message;
    }

    private void EndStagingLoadOperation()
    {
        IsStagingLoadInProgress = false;
        IsStagingLoadProgressIndeterminate = false;
        IsRefreshing = false;
    }

    private void OnWorkspaceLifecycleStateChanged(
        object? sender,
        ViewerWorkspaceLifecycleStateChangedEventArgs e)
    {
        _snapshotFollowCoordinator.BindWorkspace(CreateSnapshotFollowWorkspace(e.State));

        void ApplyState()
        {
            OnPropertyChanged(nameof(CaptureWorkspaceMode));
            OnPropertyChanged(nameof(CaptureWorkspaceModeDisplay));
            OnPropertyChanged(nameof(ActiveCaptureIdentityDisplay));
            if (e.State.Identity.Mode == CaptureWorkspaceMode.None)
            {
                ActiveSessionFolder = "Capture: none";
                ActiveSessionDetail = "No capture workspace is active.";
                SnapshotTimestampDisplay = "Snapshot: not loaded";
            }
            else if (e.State.Identity.Mode != CaptureWorkspaceMode.Switching)
            {
                UpdateActiveSessionDetail();
            }

            NotifyAgentCommandCanExecuteChanged();
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            ApplyState();
        }
        else
        {
            _ = dispatcher.BeginInvoke(ApplyState, DispatcherPriority.Background);
        }
    }

    private void OnLiveSnapshotRefreshStateChanged(
        object? sender,
        LiveSnapshotRefreshCoordinatorStateChangedEventArgs e)
    {
        _snapshotFollowCoordinator.SetAnalysisPreparationState(
            e.State.AnalysisState == SnapshotAnalysisPreparationState.Preparing);

        void ApplyState()
        {
            var state = e.State;
            IsSnapshotAnalysisPreparationInProgress =
                state.AnalysisState == SnapshotAnalysisPreparationState.Preparing;
            SnapshotAnalysisPreparationText = state.AnalysisText;
            if (_featureModules.TryGetActivated<SearchFeatureModule>(FeatureIds.SearchAndSigma, out var search))
            {
                ApplySearchAvailability(search, state);
            }

            if (!IsCurrentAnalysisDatabase(state.AnalysisDatabasePath))
            {
                return;
            }

            if (state.AnalysisState == SnapshotAnalysisPreparationState.Ready)
            {
                StatusMessage = state.IsDirectArchivedDatabase
                    ? $"Archived capture: {_sessionPaths.SessionId} (direct database); analysis indexes are ready."
                    : "Snapshot analysis indexes are ready.";
                _ = RefreshViewsAfterAnalysisAsync(state.AnalysisDatabasePath);
            }
            else if (state.AnalysisState == SnapshotAnalysisPreparationState.Failed)
            {
                StatusMessage = state.AnalysisText;
            }
            else if (state.AnalysisState == SnapshotAnalysisPreparationState.Canceled)
            {
                StatusMessage = state.AnalysisText;
            }
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            ApplyState();
        }
        else
        {
            _ = dispatcher.BeginInvoke(ApplyState, DispatcherPriority.Background);
        }
    }

    private void ApplySearchAvailability(
        SearchFeatureModule search,
        LiveSnapshotRefreshCoordinatorState state)
    {
        search.ApplyAvailability(
            state.AnalysisState,
            _hasActiveQueryDatabase,
            state.IsDirectArchivedDatabase,
            state.AnalysisText);
    }

    private bool IsCurrentAnalysisDatabase(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath) || string.IsNullOrWhiteSpace(SnapshotDatabasePath))
        {
            return false;
        }

        return string.Equals(
            Path.GetFullPath(databasePath),
            Path.GetFullPath(SnapshotDatabasePath),
            StringComparison.OrdinalIgnoreCase);
    }

    private async Task RefreshViewsAfterAnalysisAsync(string databasePath)
    {
        try
        {
            if (_featureAccess.IsPublished(FeatureIds.ProcessListing))
            {
                await ExecuteDbRefreshAsync();
            }

            if (!IsCurrentAnalysisDatabase(databasePath))
            {
                return;
            }

            await RefreshExplorerCountsForChangedInputsAsync(
                ExplorerCountRefreshTrigger.DerivedAnalysisReady);
        }
        catch (Exception ex) when (IsCurrentAnalysisDatabase(databasePath))
        {
            StatusMessage = $"Analysis indexes are ready, but the Listing risk summaries or Explorer counts could not refresh: {ex.Message}";
        }
    }

    private IProgress<ProcessListingLoadProgress> CreateStagingListingProgressReporter()
    {
        return new Progress<ProcessListingLoadProgress>(progress =>
        {
            var windowItems = Math.Max(progress.WindowItems, 1);
            var message = !string.IsNullOrWhiteSpace(progress.StageMessage)
                ? progress.StageMessage
                : progress.TotalMatchingItems > progress.WindowItems
                    ? $"Loading process rows {progress.LoadedItems:N0} of {progress.WindowItems:N0} in the current window ({progress.TotalMatchingItems:N0} matching records)."
                    : $"Loading process rows {progress.LoadedItems:N0} of {progress.WindowItems:N0}.";
            UpdateStagingLoadProgress(progress.LoadedItems, windowItems, message);
        });
    }

    private bool CanOpenCapture() => !IsRefreshing;

    [RelayCommand(CanExecute = nameof(CanOpenCapture))]
    public async Task OpenCaptureAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = $"Open {ProductIdentity.DisplayName} Capture",
            Filter = $"{ProductIdentity.DisplayName} capture manifest (session.json)|session.json|JSON files (*.json)|*.json|All files (*.*)|*.*",
            FileName = SessionPathService.CapturePackageManifestFileName,
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Open capture canceled.";
            return;
        }

        await OpenCaptureAsync(dialog.FileName);
    }

    [RelayCommand(CanExecute = nameof(CanOpenCapture))]
    public Task LoadSavedSessionAsync()
    {
        return OpenCaptureAsync();
    }

    private async Task OpenCaptureAsync(string captureManifestPath)
    {
        if (IsRefreshing)
        {
            StatusMessage = $"Another {ProductIdentity.DisplayName} operation is already in progress.";
            return;
        }

        await BeginStagingLoadOperationAsync($"Validating selected {ProductIdentity.DisplayName} capture package...");
        var committed = false;
        string? directDatabasePathToPrepare = null;
        string? directSessionIdToPrepare = null;
        TelemetryStoreStats? stats = null;

        try
        {
            var transition = await _captureWorkspaceCoordinator.OpenArchivedCaptureAsync(
                captureManifestPath,
                CreateWorkspaceTransitionCallbacks(),
                new Progress<ViewerWorkspaceLifecycleProgress>(progress =>
                    UpdateStagingLoadProgress(
                        1,
                        9,
                        progress.Message,
                        progress.IsIndeterminate)));
            if (!transition.Succeeded)
            {
                StatusMessage = transition.PreviousWorkspaceReleased
                    ? $"Open capture failed after the previous workspace was released; no capture is active: {transition.Error}"
                    : $"Open capture failed; current viewer state was kept: {transition.Error}";
                return;
            }

            committed = true;
            directDatabasePathToPrepare = transition.ActiveWorkspace?.SessionPaths.LiveDatabasePath;
            directSessionIdToPrepare = transition.ActiveWorkspace?.SessionPaths.SessionId;

            await WaitForWorkspaceQueriesToDrainAsync();
            await ReportStagingLoadProgressAsync(2, 9, "Loading process listing from archived database...", isIndeterminate: false);
            await ExecuteDbRefreshAsync(CreateStagingListingProgressReporter());
            await ReportStagingLoadProgressAsync(4, 9, "Refreshing Explorer scope counts...", isIndeterminate: false);
            await RefreshExplorerCountsForChangedInputsAsync(
                ExplorerCountRefreshTrigger.WorkspaceActivation);
            await ReportStagingLoadProgressAsync(5, 9, "Refreshing Explorer evidence summaries...", isIndeterminate: false);
            await RefreshSnapshotBackedOverviewViewsAsync();

            await ReportStagingLoadProgressAsync(7, 9, "Calculating archived capture statistics...", isIndeterminate: true);
            stats = await Task.Run(() => _telemetryProjectionService.GetStats());
            if (_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
            {
                agentFeature.AgentsViewModel.ApplyTelemetryStats(stats);
            }
            UpdateAgentCaptureRuntimeRows();
            await ReportStagingLoadProgressAsync(
                9,
                9,
                "Open capture complete.",
                isIndeterminate: false);
            StatusMessage =
                $"Archived capture: {_sessionPaths.SessionId} (direct database) " +
                $"({stats.ProcessCount} processes, {stats.EventCount} events). " +
                "Analysis indexes and search are preparing in the background. " +
                stats.StatusMessage;
        }
        catch (Exception ex)
        {
            StatusMessage = committed
                ? $"Capture was opened, but viewer refresh failed: {ex.Message}"
                : _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.None
                    ? $"Open capture failed after the previous workspace was released; no capture is active: {ex.Message}"
                    : $"Open capture failed; current viewer state was kept: {ex.Message}";
        }
        finally
        {
            EndStagingLoadOperation();
            if (committed && !string.IsNullOrWhiteSpace(directDatabasePathToPrepare))
            {
                await _liveSnapshotRefreshCoordinator.StartAnalysisPreparationAsync(
                    directDatabasePathToPrepare,
                    directSessionIdToPrepare
                        ?? throw new InvalidOperationException("The archived session identity is unavailable."),
                    isDirectArchivedDatabase: true);
            }
        }
    }

    [RelayCommand(CanExecute = nameof(CanOpenSessionFolder))]
    public void OpenSessionFolder()
    {
        try
        {
            if (!HasAvailableCaptureFolder())
            {
                StatusMessage = "Open Capture Location is unavailable because the active capture/session root does not exist.";
                return;
            }

            var result = _externalProcessService.OpenShellTarget(_sessionPaths.SessionRoot);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException(result.Detail);
            }

            StatusMessage = $"Opened capture location: {_sessionPaths.SessionRoot}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open capture location: {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanRefreshViewFromStaging))]
    public async Task RefreshViewFromStagingAsync()
    {
        if (IsRefreshing)
        {
            StatusMessage = $"Another {ProductIdentity.DisplayName} operation is already in progress.";
            return;
        }

        _snapshotFollowCoordinator.BindWorkspace(CreateSnapshotFollowWorkspace(
            _captureWorkspaceCoordinator.State));
        StatusMessage = "Validating the active live workspace before creating a coherent viewer snapshot...";
        var result = await _snapshotFollowCoordinator.RefreshManualAsync();
        if (result.Succeeded)
        {
            return;
        }

        UpdateActiveSessionDetail();
        StatusMessage = result.Outcome switch
        {
            ViewerSnapshotFollowOutcome.Canceled =>
                "Snapshot refresh was canceled; the current viewer state was kept.",
            ViewerSnapshotFollowOutcome.Superseded =>
                "Snapshot refresh was superseded; the current viewer state was kept.",
            ViewerSnapshotFollowOutcome.Disposed =>
                "Snapshot refresh is unavailable because the viewer is shutting down.",
            ViewerSnapshotFollowOutcome.Unavailable =>
                $"Snapshot refresh is unavailable: {result.Error}",
            _ => $"Snapshot refresh failed; the current viewer state was kept: {result.Error}"
        };
    }

    [RelayCommand]
    private void SelectManualSnapshotMode()
    {
        _snapshotFollowCoordinator.SetFollowEnabled(false);
    }

    [RelayCommand(CanExecute = nameof(CanSelectFollowCaptureMode))]
    private void SelectFollowCaptureMode()
    {
        _snapshotFollowCoordinator.SetFollowEnabled(true);
    }

    private bool CanSelectFollowCaptureMode() => CanEnableFollowCapture;

    [RelayCommand(CanExecute = nameof(CanSelectSnapshotFollowInterval))]
    private void SelectSnapshotFollowInterval(string? minutesText)
    {
        if (!int.TryParse(minutesText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var minutes) ||
            minutes is not (1 or 2 or 5 or 10))
        {
            return;
        }

        _snapshotFollowCoordinator.SetFollowInterval(TimeSpan.FromMinutes(minutes));
    }

    private bool CanSelectSnapshotFollowInterval(string? minutesText) =>
        IsSnapshotFollowIntervalEnabled &&
        int.TryParse(minutesText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var minutes) &&
        minutes is 1 or 2 or 5 or 10;

    private sealed record SnapshotPresentationRequest(
        long WorkspaceGeneration,
        string SessionId,
        ProcessListingQuery ListingQuery,
        long ListingQueryGeneration,
        long ExplorerInputGeneration,
        long InteractionGeneration,
        string SelectedProcessEntityId,
        string SelectedProcessKey,
        ViewerProcessViewportAnchor? ViewportAnchor,
        ExplorerScope ActiveScope,
        FeatureTabKey? ExplorerTabKey,
        FeatureTabKey? DataTabKey,
        ViewerDetailsTabKey DetailsTabKey,
        bool IncludeNetwork,
        bool IncludeMemory,
        bool IncludeFilesystem,
        bool IncludeSystemActivity);

    private sealed record PreparedSnapshotPresentation(
        SnapshotPresentationRequest Request,
        int ProcessCount,
        ProcessListingWindow FirstProcessPage,
        int SelectedProcessIndex,
        ProcessListingWindow? SelectedProcessPage,
        int ViewportProcessIndex,
        ProcessListingWindow? ViewportProcessPage,
        ExplorerCountRefreshPayload Explorer,
        long ExplorerInputGeneration,
        TelemetryStoreStats Statistics,
        IReadOnlyList<ProcessStatisticsRowViewModel> ProcessStatistics,
        IReadOnlyList<NetworkCaptureRecord> NetworkCaptures,
        IReadOnlyList<ZeekNetworkRecord> ZeekArtifacts,
        IReadOnlyList<MemoryImageRecord> MemoryImages,
        IReadOnlyList<VolatilityPluginRunRecord> VolatilityRuns,
        IReadOnlyList<MemoryProcessRecord> MemoryProcesses,
        IReadOnlyList<FilesystemArtifactRecord> FilesystemArtifacts,
        IReadOnlyList<SystemActivityRowViewModel> SystemActivities);

    private sealed class InlineViewerProgress<T>(Action<T> report) : IProgress<T>
    {
        private readonly Action<T> _report = report ?? throw new ArgumentNullException(nameof(report));

        public void Report(T value) => _report(value);
    }

    private async Task<ViewerSnapshotRefreshRuntimeResult> RunViewerSnapshotRefreshAsync(
        ViewerSnapshotRefreshRuntimeRequest request,
        IProgress<ViewerSnapshotRefreshRuntimeProgress>? progress,
        CancellationToken cancellationToken)
    {
        var presentationRequest = await InvokeOnViewerDispatcherAsync(
            () => CaptureSnapshotPresentationRequest(request),
            cancellationToken);
        var isManual = request.Trigger == ViewerSnapshotFollowTrigger.Manual;
        async Task ReportProgressAsync(
            ViewerSnapshotRefreshRuntimePhase phase,
            int step,
            string message,
            bool isIndeterminate = false)
        {
            progress?.Report(new ViewerSnapshotRefreshRuntimeProgress(phase, message));
            if (isManual)
            {
                await InvokeOnViewerDispatcherAsync(
                    () => UpdateStagingLoadProgress(
                        step,
                        6,
                        message,
                        isIndeterminate),
                    cancellationToken);
            }
        }

        if (isManual)
        {
            await InvokeOnViewerDispatcherAsync(() =>
            {
                IsRefreshing = true;
                IsStagingLoadInProgress = true;
                UpdateStagingLoadProgress(
                    0,
                    6,
                    "Creating viewer snapshot from the live SQLite database...",
                    isIndeterminate: true);
            }, cancellationToken);
        }

        PreparedSnapshotPresentation? prepared = null;
        var viewPublished = false;
        var publicationElapsedMilliseconds = 0d;
        var totalTimer = Stopwatch.StartNew();
        try
        {
            await ReportProgressAsync(
                ViewerSnapshotRefreshRuntimePhase.PreparingCandidate,
                1,
                "Creating a read-only WAL-safe snapshot candidate in the background.",
                isIndeterminate: true);
            var liveRefreshProgress = new InlineViewerProgress<LiveSnapshotRefreshProgress>(update =>
            {
                progress?.Report(new ViewerSnapshotRefreshRuntimeProgress(
                    ViewerSnapshotRefreshRuntimePhase.PreparingCandidate,
                    update.Message));
                if (!isManual)
                {
                    return;
                }

                var dispatcher = Application.Current?.Dispatcher;
                void ApplyRetryProgress()
                {
                    if (IsRefreshing)
                    {
                        UpdateStagingLoadProgress(
                            1,
                            6,
                            update.Message,
                            isIndeterminate: true);
                    }
                }

                if (dispatcher == null || dispatcher.CheckAccess())
                {
                    ApplyRetryProgress();
                }
                else
                {
                    _ = dispatcher.BeginInvoke(ApplyRetryProgress, DispatcherPriority.Background);
                }
            });
            var refreshResult = await _liveSnapshotRefreshCoordinator.RefreshAsync(
                new LiveSnapshotRefreshRequest(
                    _sessionPaths.LiveDatabasePath,
                    _sessionPaths.SnapshotDatabasePath,
                    _annotationStore?.DatabasePath ?? string.Empty,
                    _sessionPaths.SessionId,
                    _activeCapturePackageInfo?.CompatibilityMetadata,
                    IncludeProcessRisk: _featureAccess.IsPublished(FeatureIds.ProcessRiskScore)),
                progress: liveRefreshProgress,
                beforeActivation: async token =>
                {
                    await ReportProgressAsync(
                        ViewerSnapshotRefreshRuntimePhase.ActivatingDatabase,
                        4,
                        "The prepared generation is waiting for current viewer queries to drain.",
                        isIndeterminate: true);
                    await WaitForWorkspaceQueriesToDrainAsync(token);
                },
                preparePresentation: async (candidate, token) =>
                {
                    await ReportProgressAsync(
                        ViewerSnapshotRefreshRuntimePhase.PreparingPresentation,
                        3,
                        "Loading the critical Listing, Explorer, statistics, and activated overview state off the UI thread.",
                        isIndeterminate: true);
                    prepared = await PrepareSnapshotPresentationAsync(
                        presentationRequest,
                        candidate.Binding,
                        token);
                },
                publishPresentation: async (activation, token) =>
                {
                    if (prepared == null)
                    {
                        throw new InvalidOperationException(
                            "The snapshot candidate reached publication without a prepared presentation payload.");
                    }

                    await ReportProgressAsync(
                        ViewerSnapshotRefreshRuntimePhase.PublishingPresentation,
                        5,
                        "Publishing the coherent snapshot generation through one bounded dispatcher callback.");
                    var publicationTimer = Stopwatch.StartNew();
                    await PublishSnapshotPresentationAsync(prepared, activation, token);
                    publicationTimer.Stop();
                    publicationElapsedMilliseconds = publicationTimer.Elapsed.TotalMilliseconds;
                    viewPublished = true;
                },
                cancellationToken: cancellationToken);
            totalTimer.Stop();

            if (!refreshResult.Succeeded)
            {
                return new ViewerSnapshotRefreshRuntimeResult(
                    refreshResult.Outcome switch
                    {
                        LiveSnapshotRefreshOutcome.Canceled => ViewerSnapshotFollowOutcome.Canceled,
                        LiveSnapshotRefreshOutcome.Superseded => ViewerSnapshotFollowOutcome.Superseded,
                        LiveSnapshotRefreshOutcome.Disposed => ViewerSnapshotFollowOutcome.Disposed,
                        _ => ViewerSnapshotFollowOutcome.Failed
                    },
                    request.WorkspaceGeneration,
                    request.TargetCursor,
                    CandidatePrepared: prepared != null,
                    DatabaseActivated: false,
                    ViewPublished: false,
                    SnapshotAnalysisPreparationState.NotStarted,
                    SnapshotUtc: null,
                    BackgroundElapsedMilliseconds: Math.Max(
                        0,
                        totalTimer.Elapsed.TotalMilliseconds - publicationElapsedMilliseconds),
                    PublicationElapsedMilliseconds: publicationElapsedMilliseconds,
                    refreshResult.Error);
            }

            await ReportProgressAsync(
                ViewerSnapshotRefreshRuntimePhase.StartingAnalysis,
                6,
                "The coherent snapshot is published; derived analysis is preparing in the background.");
            var snapshot = refreshResult.Snapshot
                ?? throw new InvalidOperationException(
                    "Snapshot refresh succeeded without snapshot metadata.");
            await InvokeOnViewerDispatcherAsync(() =>
            {
                StatusMessage =
                    $"Refreshed viewer snapshot at {snapshot.SnapshotUtc.ToLocalTime():HH:mm:ss} " +
                    $"({FormatSnapshotAge(snapshot.SnapshotUtc)} old, {prepared!.Statistics.ProcessCount} processes, " +
                    $"{prepared.Statistics.EventCount} events). Snapshot copy " +
                    $"{FormatMilliseconds(snapshot.TotalDurationMilliseconds)}; dispatcher publication " +
                    $"{FormatMilliseconds(publicationElapsedMilliseconds)}. " +
                    $"{snapshot.SourceAccess?.Summary ?? "Snapshot source access diagnostics unavailable."} " +
                    $"SQLite diagnostics log {snapshot.DiagnosticsLogPath}. " +
                    prepared.Statistics.StatusMessage;
            }, CancellationToken.None);
            return new ViewerSnapshotRefreshRuntimeResult(
                ViewerSnapshotFollowOutcome.Succeeded,
                request.WorkspaceGeneration,
                request.TargetCursor,
                CandidatePrepared: prepared != null,
                DatabaseActivated: true,
                ViewPublished: viewPublished,
                _liveSnapshotRefreshCoordinator.State.AnalysisState,
                snapshot.SnapshotUtc,
                Math.Max(0, totalTimer.Elapsed.TotalMilliseconds - publicationElapsedMilliseconds),
                publicationElapsedMilliseconds);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            totalTimer.Stop();
            return new ViewerSnapshotRefreshRuntimeResult(
                ViewerSnapshotFollowOutcome.Canceled,
                request.WorkspaceGeneration,
                request.TargetCursor,
                CandidatePrepared: prepared != null,
                DatabaseActivated: false,
                ViewPublished: false,
                SnapshotAnalysisPreparationState.NotStarted,
                SnapshotUtc: null,
                BackgroundElapsedMilliseconds: Math.Max(
                    0,
                    totalTimer.Elapsed.TotalMilliseconds - publicationElapsedMilliseconds),
                PublicationElapsedMilliseconds: publicationElapsedMilliseconds,
                "Snapshot refresh was canceled.");
        }
        catch (Exception ex)
        {
            totalTimer.Stop();
            return new ViewerSnapshotRefreshRuntimeResult(
                ViewerSnapshotFollowOutcome.Failed,
                request.WorkspaceGeneration,
                request.TargetCursor,
                CandidatePrepared: prepared != null,
                DatabaseActivated: false,
                ViewPublished: false,
                SnapshotAnalysisPreparationState.NotStarted,
                SnapshotUtc: null,
                BackgroundElapsedMilliseconds: Math.Max(
                    0,
                    totalTimer.Elapsed.TotalMilliseconds - publicationElapsedMilliseconds),
                PublicationElapsedMilliseconds: publicationElapsedMilliseconds,
                ex.Message);
        }
        finally
        {
            if (isManual)
            {
                await InvokeOnViewerDispatcherAsync(
                    EndStagingLoadOperation,
                    CancellationToken.None);
            }
        }
    }

    private SnapshotPresentationRequest CaptureSnapshotPresentationRequest(
        ViewerSnapshotRefreshRuntimeRequest request)
    {
        if (request.WorkspaceGeneration != _captureWorkspaceCoordinator.Generation ||
            !string.Equals(request.SessionId, _sessionPaths.SessionId, StringComparison.Ordinal) ||
            _captureWorkspaceCoordinator.Mode != CaptureWorkspaceMode.LiveCapture)
        {
            throw new InvalidOperationException(
                "The snapshot request does not match the active live workspace generation.");
        }

        return new SnapshotPresentationRequest(
            request.WorkspaceGeneration,
            request.SessionId,
            BuildCurrentListingQuery(),
            Volatile.Read(ref _processListingQueryGeneration),
            Volatile.Read(ref _explorerCountInputGeneration),
            Volatile.Read(ref _snapshotPresentationInteractionGeneration),
            SelectedProcess?.ProcessInfo.ProcessEntityId ?? string.Empty,
            SelectedProcess?.ProcessKey ?? string.Empty,
            CaptureProcessViewportAnchor(),
            _activeExplorerScope,
            SelectedExplorerTab?.Key,
            SelectedDataTab?.Key,
            SelectedDetailsTabKey,
            _featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(
                FeatureIds.NetworkAndZeek,
                out _),
            _featureModules.TryGetActivated<MemoryInvestigationViewModel>(
                FeatureIds.SystemMemoryAndVolatility,
                out _),
            _featureModules.TryGetActivated<FilesystemArtifactsViewModel>(
                FeatureIds.FilesystemArtifacts,
                out _),
            _featureModules.TryGetActivated<EventTelemetryFeatureModule>(
                FeatureIds.EventTelemetry,
                out _));
    }

    private async Task<PreparedSnapshotPresentation> PrepareSnapshotPresentationAsync(
        SnapshotPresentationRequest request,
        LiveSnapshotDatabaseBinding binding,
        CancellationToken cancellationToken)
    {
        var queryService = binding.QueryService
            ?? throw new InvalidOperationException(
                "The validated snapshot candidate has no query service.");
        var listingService = binding.ListingService
            ?? throw new InvalidOperationException(
                "The validated snapshot candidate has no process-listing service.");
        var nextExplorerInputGeneration = checked(request.ExplorerInputGeneration + 1);

        return await Task.Run(async () =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = await listingService.CountProcessesAsync(
                request.ListingQuery.Filters,
                cancellationToken);
            var firstPage = await listingService.GetPageAsync(
                request.ListingQuery,
                cancellationToken);
            var selected = await PrepareProcessAnchorPageAsync(
                listingService,
                request.ListingQuery,
                request.SelectedProcessEntityId,
                request.SelectedProcessKey,
                firstPage,
                cancellationToken);
            var viewport = await PrepareProcessAnchorPageAsync(
                listingService,
                request.ListingQuery,
                request.ViewportAnchor?.ProcessEntityId ?? string.Empty,
                request.ViewportAnchor?.ProcessKey ?? string.Empty,
                firstPage,
                cancellationToken);

            Interlocked.Increment(ref _activeExplorerRefreshCount);
            ExplorerCountRefreshPayload explorerPayload;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var counts = await queryService.GetExplorerScopeCountsAsync();
                cancellationToken.ThrowIfCancellationRequested();
                var roots = await queryService.GetEvidenceRootsAsync();
                cancellationToken.ThrowIfCancellationRequested();
                explorerPayload = new ExplorerCountRefreshPayload(counts, roots);
            }
            finally
            {
                Interlocked.Decrement(ref _activeExplorerRefreshCount);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var stats = queryService.GetStats();
            var processStatistics = ProcessStatisticsViewModel.PrepareSnapshotRows(
                queryService.GetLatestProcessStatistics(100000));
            var networkCaptures = request.IncludeNetwork
                ? queryService.GetNetworkCaptures(1000)
                : [];
            var zeekArtifacts = request.IncludeNetwork
                ? queryService.GetZeekNetworkArtifacts(1000)
                : [];
            var memoryImages = request.IncludeMemory
                ? queryService.GetMemoryImages(1000)
                : [];
            var volatilityRuns = request.IncludeMemory
                ? queryService.GetVolatilityPluginRuns(maxCount: 1000)
                : [];
            var memoryProcesses = request.IncludeMemory
                ? queryService.GetMemoryProcesses(maxCount: 5000)
                : [];
            var filesystemArtifacts = request.IncludeFilesystem
                ? request.ActiveScope.Kind is ExplorerScopeKind.FilesystemFolder or
                    ExplorerScopeKind.FilesystemEvidenceRoots
                    ? queryService.GetFilesystemArtifacts(
                        request.ActiveScope,
                        includeDescendants: false,
                        maxCount: 2000)
                    : queryService.GetFilesystemArtifacts(2000)
                : [];
            var systemActivities = request.IncludeSystemActivity
                ? SystemActivityViewModel.PrepareSnapshotRows(
                    queryService.GetSystemActivities(
                        SystemActivityViewModel.BuildQuery(
                            IsSystemActivityScope(request.ActiveScope)
                                ? request.ActiveScope
                                : null)))
                : [];
            cancellationToken.ThrowIfCancellationRequested();

            return new PreparedSnapshotPresentation(
                request,
                count,
                firstPage,
                selected.Index,
                selected.Page,
                viewport.Index,
                viewport.Page,
                explorerPayload,
                nextExplorerInputGeneration,
                stats,
                processStatistics,
                networkCaptures,
                zeekArtifacts,
                memoryImages,
                volatilityRuns,
                memoryProcesses,
                filesystemArtifacts,
                systemActivities);
        }, cancellationToken);
    }

    private async Task PublishSnapshotPresentationAsync(
        PreparedSnapshotPresentation prepared,
        LiveSnapshotActivationContext activation,
        CancellationToken cancellationToken)
    {
        await ViewerSnapshotPresentationPublicationCoordinator.PublishLatestAsync(
            prepared,
            async (candidate, token) => await InvokeOnViewerDispatcherAsync(() =>
            {
                token.ThrowIfCancellationRequested();
                var currentRequest = CaptureSnapshotPresentationRequest(
                    new ViewerSnapshotRefreshRuntimeRequest(
                        ViewerSnapshotFollowTrigger.Automatic,
                        candidate.Request.WorkspaceGeneration,
                        candidate.Request.SessionId,
                        null));
                if (!CanPublishPreparedPresentation(candidate.Request, currentRequest))
                {
                    return ViewerSnapshotPresentationPublishAttempt<SnapshotPresentationRequest>
                        .Superseded(currentRequest);
                }

                PublishSnapshotPresentationCore(candidate, activation, token);
                return ViewerSnapshotPresentationPublishAttempt<SnapshotPresentationRequest>
                    .Published();
            }, token),
            (request, token) => PrepareSnapshotPresentationAsync(
                request,
                activation.Binding,
                token),
            cancellationToken);
    }

    private void PublishSnapshotPresentationCore(
        PreparedSnapshotPresentation prepared,
        LiveSnapshotActivationContext activation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidatePreparedPresentationIsCurrent(prepared.Request);

        var queryService = activation.Binding.QueryService
            ?? throw new InvalidOperationException(
                "The activated snapshot has no query service.");
        var listingService = activation.Binding.ListingService
            ?? throw new InvalidOperationException(
                "The activated snapshot has no process-listing service.");
        var nextQueryGeneration = Interlocked.Increment(
            ref _processListingQueryGeneration);
        var collection = new VirtualizedProcessCollection(
            listingService,
            prepared.Request.ListingQuery,
            prepared.Request.WorkspaceGeneration,
            VirtualProcessPageSize,
            VirtualProcessCachePages,
            SynchronizationContext.Current,
            nextQueryGeneration);
        collection.InitializePrepared(
            prepared.ProcessCount,
            prepared.FirstProcessPage,
            prepared.SelectedProcessPage,
            prepared.ViewportProcessPage);
        var selectedRow = prepared.SelectedProcessIndex < 0
            ? null
            : collection.GetLoadedItem(prepared.SelectedProcessIndex);
        var viewportRow = prepared.ViewportProcessIndex < 0
            ? null
            : collection.GetLoadedItem(prepared.ViewportProcessIndex);

        _isPublishingSnapshotPresentation = true;
        try
        {
            _processListingRefreshCts?.Cancel();
            _sqliteStagingQueryService = queryService;
            _processListingService = listingService;
            _telemetryProjectionService.SetSqliteStagingQueryService(
                queryService,
                EvidenceReadPath.ViewerSnapshotSqlite,
                activation.Snapshot.SnapshotPath);
            _hasActiveQueryDatabase = true;
            SnapshotDatabasePath = activation.Snapshot.SnapshotPath;
            Interlocked.Exchange(
                ref _explorerCountInputGeneration,
                prepared.ExplorerInputGeneration);
            ApplyExplorerCounts(AddAnalysisCounts(prepared.Explorer.Counts));
            ExplorerViewModel.RefreshEvidenceRoots(prepared.Explorer.EvidenceRoots);
            ProcessStatisticsViewModel.ApplyPreparedSnapshot(prepared.ProcessStatistics);

            if (prepared.Request.IncludeNetwork &&
                _featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(
                    FeatureIds.NetworkAndZeek,
                    out var network))
            {
                network.ViewModel.ApplySnapshot(
                    prepared.NetworkCaptures,
                    prepared.ZeekArtifacts);
            }

            if (prepared.Request.IncludeMemory &&
                _featureModules.TryGetActivated<MemoryInvestigationViewModel>(
                    FeatureIds.SystemMemoryAndVolatility,
                    out var memory))
            {
                memory.ApplySnapshot(
                    prepared.MemoryImages,
                    prepared.VolatilityRuns,
                    prepared.MemoryProcesses);
            }

            if (prepared.Request.IncludeFilesystem &&
                _featureModules.TryGetActivated<FilesystemArtifactsViewModel>(
                    FeatureIds.FilesystemArtifacts,
                    out var filesystem))
            {
                filesystem.ApplySnapshot(
                    prepared.FilesystemArtifacts,
                    IsSameScope(prepared.Request.ActiveScope, _activeExplorerScope)
                        ? _activeExplorerScope
                        : null);
            }

            if (prepared.Request.IncludeSystemActivity &&
                _featureModules.TryGetActivated<EventTelemetryFeatureModule>(
                    FeatureIds.EventTelemetry,
                    out var events))
            {
                events.SystemActivityViewModel.ApplyPreparedSnapshot(
                    prepared.SystemActivities,
                    IsSystemActivityScope(_activeExplorerScope)
                        ? _activeExplorerScope
                        : null);
            }

            AttachVirtualizedProcessListing(collection, selectedRow, navigateToSelection: false);
            if (_featureModules.TryGetActivated<BaselineComparisonFeatureModule>(
                    FeatureIds.BaselineComparison,
                    out var baseline))
            {
                baseline.SetActiveSnapshotPath(activation.Snapshot.SnapshotPath);
            }

            if (_featureModules.TryGetActivated<AgentFeatureModule>(
                    FeatureIds.AgentsAndCapture,
                    out var agentFeature))
            {
                agentFeature.AgentsViewModel.ApplyTelemetryStats(prepared.Statistics);
            }

            UpdateAgentCaptureRuntimeRows();
            UpdateActiveSessionDetail();
            var notices = new List<string>();
            if ((!string.IsNullOrWhiteSpace(prepared.Request.SelectedProcessEntityId) ||
                 !string.IsNullOrWhiteSpace(prepared.Request.SelectedProcessKey)) &&
                selectedRow == null)
            {
                notices.Add("The previously selected process is absent in this generation; selection was cleared without PID substitution.");
            }

            if (prepared.Request.ViewportAnchor != null && viewportRow == null)
            {
                notices.Add("The previous process scroll anchor is absent in this generation; no replacement row was selected.");
            }

            _snapshotPresentationContextNotice = string.Join(" ", notices);
            if (viewportRow != null && prepared.Request.ViewportAnchor != null)
            {
                ProcessViewportAnchorRestoreRequested?.Invoke(
                    viewportRow,
                    prepared.Request.ViewportAnchor.RelativeOffset);
            }
            else if (selectedRow != null)
            {
                ProcessRowNavigationRequested?.Invoke(selectedRow);
            }
        }
        finally
        {
            _isPublishingSnapshotPresentation = false;
        }
    }

    private void ValidatePreparedPresentationIsCurrent(
        SnapshotPresentationRequest request)
    {
        if (request.WorkspaceGeneration != _captureWorkspaceCoordinator.Generation ||
            !string.Equals(request.SessionId, _sessionPaths.SessionId, StringComparison.Ordinal) ||
            _captureWorkspaceCoordinator.Mode != CaptureWorkspaceMode.LiveCapture)
        {
            throw new InvalidOperationException(
                "The prepared snapshot presentation belongs to an obsolete workspace.");
        }

        if (request.ListingQueryGeneration != Volatile.Read(ref _processListingQueryGeneration) ||
            request.ExplorerInputGeneration != Volatile.Read(ref _explorerCountInputGeneration) ||
            request.InteractionGeneration != Volatile.Read(ref _snapshotPresentationInteractionGeneration) ||
            !IsSameScope(request.ActiveScope, _activeExplorerScope))
        {
            throw new InvalidOperationException(
                "Viewer filters, scope, or annotation inputs changed while the snapshot was preparing; the previous coherent presentation was kept.");
        }

        if (request.IncludeNetwork != _featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(
                FeatureIds.NetworkAndZeek,
                out _) ||
            request.IncludeMemory != _featureModules.TryGetActivated<MemoryInvestigationViewModel>(
                FeatureIds.SystemMemoryAndVolatility,
                out _) ||
            request.IncludeFilesystem != _featureModules.TryGetActivated<FilesystemArtifactsViewModel>(
                FeatureIds.FilesystemArtifacts,
                out _) ||
            request.IncludeSystemActivity != _featureModules.TryGetActivated<EventTelemetryFeatureModule>(
                FeatureIds.EventTelemetry,
                out _))
        {
            throw new InvalidOperationException(
                "An optional feature activated while the snapshot was preparing; the previous coherent presentation was kept so the next attempt can include it.");
        }
    }

    private static bool IsSameScope(ExplorerScope left, ExplorerScope right) =>
        string.Equals(left.ScopeId, right.ScopeId, StringComparison.Ordinal);

    private static bool CanPublishPreparedPresentation(
        SnapshotPresentationRequest prepared,
        SnapshotPresentationRequest current) =>
        prepared.WorkspaceGeneration == current.WorkspaceGeneration &&
        string.Equals(prepared.SessionId, current.SessionId, StringComparison.Ordinal) &&
        prepared.ListingQueryGeneration == current.ListingQueryGeneration &&
        prepared.ExplorerInputGeneration == current.ExplorerInputGeneration &&
        prepared.InteractionGeneration == current.InteractionGeneration &&
        IsSameScope(prepared.ActiveScope, current.ActiveScope) &&
        prepared.IncludeNetwork == current.IncludeNetwork &&
        prepared.IncludeMemory == current.IncludeMemory &&
        prepared.IncludeFilesystem == current.IncludeFilesystem &&
        prepared.IncludeSystemActivity == current.IncludeSystemActivity;

    private ViewerProcessViewportAnchor? CaptureProcessViewportAnchor()
    {
        var handlers = ProcessViewportAnchorCaptureRequested;
        if (handlers == null)
        {
            return null;
        }

        foreach (Func<ViewerProcessViewportAnchor?> handler in handlers.GetInvocationList())
        {
            try
            {
                var anchor = handler();
                if (anchor != null)
                {
                    return anchor;
                }
            }
            catch
            {
                // WPF virtualization may be between container generations. Logical
                // selection still survives; visual anchoring degrades gracefully.
            }
        }

        return null;
    }

    private static async Task<(int Index, ProcessListingWindow? Page)> PrepareProcessAnchorPageAsync(
        ProcessListingService listingService,
        ProcessListingQuery query,
        string processEntityId,
        string processKey,
        ProcessListingWindow firstPage,
        CancellationToken cancellationToken)
    {
        var resolvedKey = processKey;
        if (!string.IsNullOrWhiteSpace(processEntityId))
        {
            var lookup = await listingService.FindProcessByEntityIdAsync(
                processEntityId,
                cancellationToken);
            resolvedKey = lookup.IsFound && !string.IsNullOrWhiteSpace(lookup.Process?.ProcessKey)
                ? lookup.Process.ProcessKey
                : processKey;
        }

        if (string.IsNullOrWhiteSpace(resolvedKey))
        {
            return (-1, null);
        }

        var index = await listingService.GetProcessRowIndexAsync(
            resolvedKey,
            query,
            cancellationToken);
        if (index < 0)
        {
            return (-1, null);
        }

        var offset = (index / query.PageSize) * query.PageSize;
        if (offset == 0)
        {
            return (index, firstPage);
        }

        var page = await listingService.GetPageAsync(
            new ProcessListingQuery
            {
                Filters = query.Filters,
                Sort = query.Sort,
                Offset = offset,
                PageSize = query.PageSize,
                Cursor = null,
                IncludeTotalCount = false
            },
            cancellationToken);
        return (index, page);
    }

    private ViewerSnapshotFollowWorkspace CreateSnapshotFollowWorkspace(
        ViewerWorkspaceLifecycleState state,
        bool isShuttingDown = false) =>
        ViewerSnapshotFollowWorkspace.FromLifecycleState(
            state,
            _activeCapturePackageInfo?.CompatibilityAssessment,
            isShuttingDown);

    private void OnSnapshotFollowStateChanged(
        object? sender,
        ViewerSnapshotFollowStateChangedEventArgs e)
    {
        void Apply()
        {
            ApplySnapshotFollowState(e.State);
            if (e.State.Mode == ViewerSnapshotFollowMode.Follow &&
                (!IsRefreshing || e.State.ActiveTrigger == ViewerSnapshotFollowTrigger.Automatic) &&
                e.State.Phase is ViewerSnapshotFollowPhase.Preparing or
                    ViewerSnapshotFollowPhase.Publishing or
                    ViewerSnapshotFollowPhase.Backoff or
                    ViewerSnapshotFollowPhase.Unavailable)
            {
                StatusMessage = SnapshotFollowStatusText;
            }
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            Apply();
        }
        else
        {
            _ = dispatcher.BeginInvoke(Apply, DispatcherPriority.Background);
        }
    }

    private void ApplySnapshotFollowState(ViewerSnapshotFollowState state)
    {
        var presentation = ViewerSnapshotFollowPresentationFormatter.Create(
            state,
            DateTime.UtcNow,
            _snapshotPresentationContextNotice);
        SnapshotFollowMode = state.Mode;
        SnapshotFollowIntervalMinutes = presentation.IntervalMinutes;
        CanEnableFollowCapture = presentation.CanEnableFollow;
        IsSnapshotFollowIntervalEnabled = presentation.IsFollowIntervalEnabled;
        SnapshotFollowStatusText = presentation.StatusText;
        SnapshotFollowStatusDetail = presentation.DetailText;
        SelectFollowCaptureModeCommand.NotifyCanExecuteChanged();
        SelectSnapshotFollowIntervalCommand.NotifyCanExecuteChanged();
    }

    public void NotifyProcessViewportChanged()
    {
        MarkSnapshotPresentationInteraction();
    }

    private void MarkSnapshotPresentationInteraction()
    {
        if (!_isPublishingSnapshotPresentation)
        {
            Interlocked.Increment(ref _snapshotPresentationInteractionGeneration);
        }
    }

    private static async Task InvokeOnViewerDispatcherAsync(
        Action action,
        CancellationToken cancellationToken)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return;
        }

        await dispatcher.InvokeAsync(
            action,
            DispatcherPriority.Background,
            cancellationToken).Task;
    }

    private static async Task<T> InvokeOnViewerDispatcherAsync<T>(
        Func<T> action,
        CancellationToken cancellationToken)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            cancellationToken.ThrowIfCancellationRequested();
            return action();
        }

        return await dispatcher.InvokeAsync(
            action,
            DispatcherPriority.Background,
            cancellationToken).Task;
    }

    private async Task RefreshSnapshotBackedOverviewViewsAsync()
    {
        await Dispatcher.Yield(DispatcherPriority.Background);
        await ProcessStatisticsViewModel.RefreshStatisticsAsync();
        await Dispatcher.Yield(DispatcherPriority.Background);
        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
        {
            network.ViewModel.RefreshNetworkCaptures();
        }
        await Dispatcher.Yield(DispatcherPriority.Background);
        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory))
        {
            memory.RefreshMemoryInvestigation();
        }
        await Dispatcher.Yield(DispatcherPriority.Background);
        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            filesystem.RefreshArtifacts();
        }
        await Dispatcher.Yield(DispatcherPriority.Background);
        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events))
        {
            events.SystemActivityViewModel.RefreshActivities(
                IsSystemActivityScope(_activeExplorerScope) ? _activeExplorerScope : null);
        }
    }

    private async Task<bool> SwitchToFreshLiveCaptureWorkspaceAsync(string reason)
    {
        if (IsRefreshing)
        {
            StatusMessage = $"Another {ProductIdentity.DisplayName} operation is already in progress.";
            return false;
        }

        await BeginStagingLoadOperationAsync("Creating a new live capture workspace...");
        try
        {
            var transition = await _captureWorkspaceCoordinator.CreateFreshLiveCaptureAsync(
                CreateWorkspaceTransitionCallbacks(),
                new Progress<ViewerWorkspaceLifecycleProgress>(progress =>
                    UpdateStagingLoadProgress(
                        progress.CurrentStep,
                        progress.TotalSteps,
                        progress.Message,
                        progress.IsIndeterminate)));
            if (!transition.Succeeded)
            {
                StatusMessage = transition.PreviousWorkspaceReleased
                    ? $"Live workspace creation failed after the previous workspace was released; no capture is active: {transition.Error}"
                    : $"Live workspace creation failed; the current workspace was kept: {transition.Error}";
                return false;
            }

            var sessionId = transition.ActiveWorkspace?.SessionPaths.SessionId
                ?? throw new InvalidOperationException("The fresh live session identity is unavailable.");

            StatusMessage =
                $"{reason} Created live session '{sessionId}'. The agent will initialize its evidence database.";
            return true;
        }
        catch (Exception ex)
        {
            StatusMessage = _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.None
                ? $"Live workspace creation failed after the previous workspace was released; no capture is active: {ex.Message}"
                : $"Live workspace creation failed; the current workspace was kept: {ex.Message}";
            return false;
        }
        finally
        {
            EndStagingLoadOperation();
        }
    }

    private ViewerWorkspaceTransitionCallbacks CreateWorkspaceTransitionCallbacks()
    {
        return new ViewerWorkspaceTransitionCallbacks(
            _ => StopCaptureForSessionSwitchAsync(),
            _ => DetachAndReleaseCurrentWorkspaceAsync(),
            MaterializeCaptureWorkspaceAsync);
    }

    private async Task MaterializeCaptureWorkspaceAsync(
        ViewerWorkspaceActivation activation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var paths = activation.SessionPaths;
        var packageInfo = activation.PackageInfo
            ?? throw new InvalidOperationException("The target capture metadata is unavailable.");
        var annotationStore = TryInitializeAnnotationDatabase(paths.AnnotationDatabasePath)
            ?? throw new InvalidOperationException(
                activation.IsDirectArchivedDatabase
                    ? "The selected capture annotation SQLite database could not be opened for session use."
                    : "The new live capture annotation database could not be initialized.");

        if (!activation.IsDirectArchivedDatabase)
        {
            BindCaptureWorkspace(
                paths,
                packageInfo,
                annotationStore,
                queryService: null,
                listingService: null);
            return;
        }

        annotationStore.ImportBookmarksFromEvidenceDatabase(
            paths.LiveDatabasePath,
            CaptureOpenContext.ViewerArchivedReadOnly,
            packageInfo.CompatibilityMetadata,
            packageInfo.SessionId);
        cancellationToken.ThrowIfCancellationRequested();
        await ReportStagingLoadProgressAsync(
            1,
            9,
            "Opening archived capture source database directly...",
            isIndeterminate: false);
        var queryService = new SqliteStagingQueryService(
            paths.LiveDatabasePath,
            annotationStore.DatabasePath,
            openContext: CaptureOpenContext.ViewerArchivedReadOnly,
            manifest: packageInfo.CompatibilityMetadata,
            expectedEvidenceSessionId: packageInfo.SessionId);
        var listingService = new ProcessListingService(
            queryService,
            _featureAccess.IsPublished(FeatureIds.ProcessRiskScore));
        cancellationToken.ThrowIfCancellationRequested();

        BindCaptureWorkspace(
            paths,
            packageInfo,
            annotationStore,
            queryService,
            listingService,
            directArchivedDatabasePath: paths.LiveDatabasePath);
    }

    private async Task StopCaptureForSessionSwitchAsync()
    {
        var stopped = true;
        var workflowState = _agentCaptureWorkflowCoordinator.State;
        if (_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature) &&
            workflowState.HasWorkspaceTrackedAgent)
        {
            var trackedAgentId = workflowState.WorkspaceTrackedAgentId;
            var trackedAgent = agentFeature.AgentsViewModel.Agents.FirstOrDefault(agent =>
                string.Equals(agent.AgentId, trackedAgentId, StringComparison.Ordinal));
            stopped = await StopConnectedAgentAsync(
                trackedAgent,
                "Capture workspace switch requested by the viewer.",
                requireViewerConnection: false,
                allowVerifiedProcessFallback: false);
        }

        if (!stopped)
        {
            throw new InvalidOperationException(
                $"The active agent could not be stopped or verified for session '{_sessionPaths.SessionId}'. The workspace switch was canceled.");
        }

        SetLiveCaptureRunState(CaptureRunState.Off);
    }

    private async Task DetachAndReleaseCurrentWorkspaceAsync()
    {
        _viewerNavigationCoordinator.InvalidateProcessNavigation();
        await _selectedProcessFanOutCoordinator.RebindWorkspaceAsync(
            _captureWorkspaceCoordinator.Generation);
        await _liveSnapshotRefreshCoordinator.ReleaseActiveBindingAsync();
        _dbRefreshDebounceTimer?.Stop();
        _processListingRefreshCts?.Cancel();
        _processListingRefreshCts?.Dispose();
        _processListingRefreshCts = null;
        var previousVirtualListing = DetachVirtualizedProcessListing();
        previousVirtualListing?.Dispose();

        if (_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
        {
            agentFeature.StatusTimer.Stop();
        }

        ResetAgentStateForSessionSwitch();

        _processListingService = null;
        _sqliteStagingQueryService = null;
        _annotationStore = null;
        _telemetryProjectionService.SetSqliteStagingQueryService(null);

        await WaitForWorkspaceQueriesToDrainAsync();
        while (previousVirtualListing?.IsLoading == true)
        {
            await Task.Delay(25);
        }

        ProcessDescriptionViewModel.SetAnnotationStore(null);
        ProcessDescriptionViewModel.SetWorkspace(null, _captureWorkspaceCoordinator.Generation);
        NotesViewModel.SetAnnotationStore(null);
        if (_featureModules.TryGetActivated<AiFeatureModule>(FeatureIds.AiAssistance, out var ai))
        {
            ai.DetachWorkspace();
        }

        _hasActiveQueryDatabase = false;
        _activeCapturePackageInfo = null;
        LiveDatabasePath = string.Empty;
        SnapshotDatabasePath = string.Empty;
        SnapshotTimestampDisplay = "Snapshot: not loaded";
        ActiveSessionFolder = "Capture: switching";

        ClearViewerStateForSessionSwitch();
        if (_featureModules.TryGetActivated<BaselineComparisonFeatureModule>(FeatureIds.BaselineComparison, out var baseline))
        {
            baseline.DetachWorkspace();
        }

        if (_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var activatedAgentFeature))
        {
            activatedAgentFeature.AgentsViewModel.ApplyTelemetryStats(new TelemetryStoreStats());
        }

        if (_featureModules.TryGetActivated<SearchFeatureModule>(FeatureIds.SearchAndSigma, out var search))
        {
            search.DetachWorkspace();
        }

        DetachCompiledPrivateFeatureWorkspace();
    }

    private async Task WaitForWorkspaceQueriesToDrainAsync(
        CancellationToken cancellationToken = default)
    {
        while (Volatile.Read(ref _activeDbRefreshCount) > 0 ||
               Volatile.Read(ref _activeExplorerRefreshCount) > 0 ||
               _agentCaptureWorkflowCoordinator.State.IsPollRunning)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(25, cancellationToken);
        }
    }

    private void BindCaptureWorkspace(
        InvestigationSessionPaths sessionPaths,
        CapturePackageInfo capturePackageInfo,
        AnnotationDatabaseService annotationStore,
        SqliteStagingQueryService? queryService,
        ProcessListingService? listingService,
        string? directArchivedDatabasePath = null)
    {
        _sessionPaths = sessionPaths;
        _activeCapturePackageInfo = capturePackageInfo;
        _annotationStore = annotationStore;
        _sqliteStagingQueryService = queryService;
        _processListingService = listingService;
        _telemetryProjectionService.SetSqliteStagingQueryService(
            queryService,
            queryService == null
                ? EvidenceReadPath.Unavailable
                : string.IsNullOrWhiteSpace(directArchivedDatabasePath)
                    ? EvidenceReadPath.ViewerSnapshotSqlite
                    : EvidenceReadPath.ArchivedCaptureSqlite,
            directArchivedDatabasePath ?? string.Empty);

        ProcessDescriptionViewModel.SetAnnotationStore(annotationStore);
        ProcessDescriptionViewModel.SetWorkspace(
            sessionPaths,
            _captureWorkspaceCoordinator.Generation);
        NotesViewModel.SetAnnotationStore(annotationStore);
        if (_featureModules.TryGetActivated<AiFeatureModule>(FeatureIds.AiAssistance, out var ai))
        {
            ai.SetWorkspace(sessionPaths, annotationStore);
        }

        if (_featureModules.TryGetActivated<BaselineComparisonFeatureModule>(FeatureIds.BaselineComparison, out var baseline))
        {
            baseline.SetWorkspace(sessionPaths, directArchivedDatabasePath);
        }

        if (_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
        {
            agentFeature.BindSession(sessionPaths);
            agentFeature.StatusTimer.Start();
        }

        BindCompiledPrivateFeatureWorkspace(
            sessionPaths,
            annotationStore,
            directArchivedDatabasePath);

        _hasActiveQueryDatabase = queryService != null;
        LiveDatabasePath = sessionPaths.LiveDatabasePath;
        SnapshotDatabasePath = directArchivedDatabasePath ?? string.Empty;
        ActiveSessionFolder = $"Capture: {sessionPaths.SessionRoot}";
        UpdateActiveSessionDetail();
    }

    private void ResetAgentStateForSessionSwitch()
    {
        ClearPendingAgentTermination();
        CancelLateAgentExitObservation();
        _agentCaptureWorkflowCoordinator.BindWorkspace(
            _captureWorkspaceCoordinator.Generation,
            "Agent status detached from previous session.");
        _artifactEnrichmentWorkflowCoordinator.BindWorkspace(
            _captureWorkspaceCoordinator.Generation,
            "Artifact enrichment detached from previous session.");
        _activeImportJobId = null;
        _activeProcessDumpJobId = null;
        _activeZeekAnalysisJobId = null;
        _activeArtifactImportJobId = null;
        _activeProcessMonitorImportJobId = null;
        _activeMemoryAcquisitionJobId = null;
        _activeMemoryImageImportJobId = null;
        _activeVolatilityAnalysisJobId = null;
        _activeSqliteBenchmarkJobId = null;
        IsNetworkCaptureActive = false;
        IsProcessMonitorCaptureActive = false;
        SetLiveCaptureRunState(CaptureRunState.Off);
        SetNetworkCaptureRunState(CaptureRunState.Off);
        SetProcessMonitorCaptureRunState(CaptureRunState.Off);
        if (_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
        {
            agentFeature.AgentsViewModel.ResetSessionState("Agent status detached from previous session.");
        }
        AgentStatusMessage = "Agent: detached from previous session";
        AgentJobStatusMessage = "Jobs: idle";
    }

    private void ClearViewerStateForSessionSwitch()
    {
        var previousVirtualListing = DetachVirtualizedProcessListing();
        previousVirtualListing?.Dispose();
        _processViewModels.Clear();
        Processes.Clear();
        ProcessesView = CollectionViewSource.GetDefaultView(Processes);
        SelectedProcess = null;
        ProcessListingStatus = "Process listing is not loaded.";
        IsProcessListingLoading = false;
        TotalProcessCount = 0;
        RunningProcessCount = 0;
        ExitedProcessCount = 0;
        LastRefreshTime = default;
        ClearFilters();
        _dbRefreshDebounceTimer?.Stop();
        ClearScopedSelectionState();
        _activeExplorerScope = CreateAllProcessesScope();
        ExplorerViewModel.ResetSelection();
        ExplorerViewModel.ResetCounts();
        ResetExplorerTabCounts();
        _viewerNavigationCoordinator.ResetWorkspaceContext();
        if (_featureModules.TryGetActivated<MemoryInvestigationViewModel>(FeatureIds.SystemMemoryAndVolatility, out var memory))
        {
            memory.Clear();
        }

        if (_featureModules.TryGetActivated<EventTelemetryFeatureModule>(FeatureIds.EventTelemetry, out var events))
        {
            events.SystemActivityViewModel.Clear();
        }

        if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
        {
            network.ViewModel.Clear();
        }

        if (_featureModules.TryGetActivated<FilesystemArtifactsViewModel>(FeatureIds.FilesystemArtifacts, out var filesystem))
        {
            filesystem.Clear();
        }

        if (_featureModules.TryGetActivated<SearchFeatureModule>(FeatureIds.SearchAndSigma, out var search))
        {
            search.ClearResults();
        }

        if (_featureModules.TryGetActivated<SigmaViewModel>(FeatureIds.SearchAndSigma, out var sigma))
        {
            sigma.ClearCommand.Execute(null);
        }
        InspectorPaneViewModel.Clear("Open a session or select a process to inspect details here.");
        UpdateSelectedProcessBookmarkState();
        IncludeSelectedProcessCommand.NotifyCanExecuteChanged();
        ExcludeSelectedProcessCommand.NotifyCanExecuteChanged();
        QueueSelectedProcessDumpCommand.NotifyCanExecuteChanged();
        AnalyzeSelectedProcessImageCommand.NotifyCanExecuteChanged();
        AnalyzeSelectedDumpPeCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanUseEventTelemetryFeature))]
    public void SelectEtwCaptureProfile(ConfigProfileDefinition? profile)
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "Select ETW capture profile"))
        {
            return;
        }

        if (profile == null)
        {
            StatusMessage = "No ETW capture profile was selected.";
            return;
        }

        SelectedEtwCaptureProfile = profile;
        StatusMessage = $"Selected ETW capture profile: {GetConfigProfileDisplayName(profile)}.";
    }

    private StartLiveCaptureCommand CreateStartLiveCaptureCommand()
    {
        var selectedProfile = SelectedEtwCaptureProfile;
        return new StartLiveCaptureCommand
        {
            CaptureId = BuildViewerCaptureId(),
            ProcessRefreshIntervalSeconds = Math.Clamp(RefreshIntervalSeconds, 1, 3600),
            EtwProfileId = selectedProfile?.Id ?? string.Empty,
            EtwProfileDisplayName = selectedProfile == null ? string.Empty : GetConfigProfileDisplayName(selectedProfile),
            EtwProfilePath = selectedProfile == null
                ? string.Empty
                : _configProfileService.ResolveProfileFilePath(selectedProfile) ?? string.Empty,
            CollectRuntimeEvents = true,
            CollectEtwEvents = IsEtwCollectionEnabled,
            CollectSecurityEvents = IsWindowsAuditLogCollectionEnabled,
            CollectPowerShellEvents = IsPowerShellLogCollectionEnabled,
            CollectOtherWindowsEvents = IsWindowsOtherLogCollectionEnabled,
            CollectSysmonEvents = IsSysmonIntegrationEnabled
        };
    }

    private HostMonitoringConfigurationViewModel CreateHostMonitoringConfigurationSettings(
        AgentHostMonitoringConfiguration? configuration = null)
    {
        var settings = new HostMonitoringConfigurationViewModel(
            EtwCaptureProfiles,
            SysmonConfigProfiles,
            SecurityMonitoringPolicyProfiles,
            PowerShellAuditingProfiles,
            EventLogPolicyProfiles);

        if (configuration != null)
        {
            settings.ApplyExistingConfiguration(configuration, SelectedEtwCaptureProfile);
        }
        else
        {
            settings.SelectedSysmonProfile = HostMonitoringConfigurationViewModel.SelectProfile(
                SysmonConfigProfiles,
                profileId: null);
            settings.SelectedSecurityMonitoringProfile = HostMonitoringConfigurationViewModel.SelectProfile(
                SecurityMonitoringPolicyProfiles,
                profileId: null);
            settings.SelectedPowerShellAuditingProfile = HostMonitoringConfigurationViewModel.SelectProfile(
                PowerShellAuditingProfiles,
                profileId: null);
            settings.SelectedEventLogProfile = HostMonitoringConfigurationViewModel.SelectProfile(
                EventLogPolicyProfiles,
                profileId: null);
            settings.SelectedEtwProfile = HostMonitoringConfigurationViewModel.SelectProfile(
                EtwCaptureProfiles,
                SelectedEtwCaptureProfile?.Id);
            settings.TranscriptDirectory = TranscriptPath;
        }

        return settings;
    }

    private AgentHostMonitoringConfiguration CreateHostMonitoringConfigurationDraft(
        AgentRegistryEntryViewModel agent,
        HostMonitoringConfigurationViewModel? settings = null)
    {
        settings ??= CreateHostMonitoringConfigurationSettings(agent.HostMonitoringConfiguration);
        var sysmonProfile = settings.SelectedSysmonProfile;
        var securityProfile = settings.SelectedSecurityMonitoringProfile;
        var powerShellProfile = settings.SelectedPowerShellAuditingProfile;
        var eventLogProfile = settings.SelectedEventLogProfile;
        var etwProfile = settings.SelectedEtwProfile;

        return new AgentHostMonitoringConfiguration
        {
            AgentId = agent.AgentId,
            HostId = FirstNonEmpty(agent.HostId, Environment.MachineName),
            ConfigurationVersion = "viewer-current-monitoring",
            Sysmon = new AgentSysmonMonitoringIntent
            {
                InstallOrUpdate = settings.InstallOrUpdateSysmon,
                VerifyService = settings.VerifySysmonService,
                ProfileId = sysmonProfile?.Id ?? string.Empty,
                ProfileDisplayName = GetProfileName(sysmonProfile),
                ConfigurationPath = ResolveConfigProfileFilePath(sysmonProfile)
            },
            SecurityAuditPolicy = new AgentSecurityAuditMonitoringIntent
            {
                ConfigureAuditPolicy = settings.ConfigureAuditPolicy,
                EnableProcessCommandLineLogging = settings.EnableProcessCommandLineLogging,
                PolicyProfileId = securityProfile?.Id ?? string.Empty,
                PolicyProfileDisplayName = GetProfileName(securityProfile),
                AuditPolicyPath = ResolveConfigProfileFilePath(securityProfile)
            },
            EventLogs = new AgentEventLogMonitoringIntent
            {
                ConfigureChannels = settings.ConfigureEventLogChannels,
                ConfigureRetention = settings.ConfigureEventLogRetention,
                ProfileId = eventLogProfile?.Id ?? string.Empty,
                ProfileDisplayName = GetProfileName(eventLogProfile),
                ChannelNames =
                [
                    "Security",
                    "System",
                    "Application",
                    "Windows PowerShell",
                    "Microsoft-Windows-PowerShell/Operational",
                    "Microsoft-Windows-Sysmon/Operational"
                ]
            },
            PowerShellAuditing = new AgentPowerShellMonitoringIntent
            {
                EnableScriptBlockLogging = settings.EnablePowerShellScriptBlockLogging,
                EnableModuleLogging = settings.EnablePowerShellModuleLogging,
                EnableTranscription = settings.EnablePowerShellTranscription,
                ProfileId = powerShellProfile?.Id ?? string.Empty,
                TranscriptDirectory = settings.TranscriptDirectory
            },
            Etw = new AgentEtwMonitoringIntent
            {
                ConfigureSession = settings.ConfigureEtwSession,
                ProfileId = etwProfile?.Id ?? string.Empty,
                ProfileDisplayName = GetProfileName(etwProfile),
                ProfilePath = ResolveConfigProfileFilePath(etwProfile)
            },
            ScheduledDumps = new AgentScheduledDumpPolicy
            {
                Enabled = false,
                OutputDirectory = _sessionPaths.DumpsDirectory
            }
        };
    }

    private AgentCaptureConfiguration CreateCaptureConfigurationDraft(
        AgentRegistryEntryViewModel agent,
        IReadOnlyList<AgentCaptureOptionViewModel>? captureOptions = null)
    {
        var etwProfile = SelectedEtwCaptureProfile;
        var captureRuntime = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.ProcessLiveEvents,
            true);
        var captureEtw = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.EtwEvents,
            IsEtwCollectionEnabled);
        var captureSecurity = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.SecurityEvents,
            IsWindowsAuditLogCollectionEnabled);
        var capturePowerShell = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.PowerShellEvents,
            IsPowerShellLogCollectionEnabled);
        var captureWindowsOther = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.WindowsOtherEvents,
            IsWindowsOtherLogCollectionEnabled);
        var captureSysmon = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.SysmonEvents,
            IsSysmonIntegrationEnabled);
        var captureModules = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.ModuleEnrichment,
            IsModuleCollectionEnabled);
        var captureHandles = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.HandleEnrichment,
            IsHandleCollectionEnabled);
        var capturePe = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.PeAnalysis,
            true);
        var captureNetwork = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.NetworkCapture,
            false);
        var captureZeek = AgentCaptureOptionViewModel.IsSelected(
            captureOptions,
            AgentCaptureOptionKind.ZeekAnalysis,
            false);

        return new AgentCaptureConfiguration
        {
            AgentId = agent.AgentId,
            HostId = FirstNonEmpty(agent.HostId, Environment.MachineName),
            ConfigurationVersion = "viewer-current-capture",
            RuntimeProcessSnapshots = new AgentRuntimeSnapshotCapturePolicy
            {
                Enabled = captureRuntime,
                RefreshIntervalSeconds = Math.Clamp(RefreshIntervalSeconds, 1, 3600)
            },
            SourceToggles = new AgentCaptureSourceToggles
            {
                Runtime = captureRuntime,
                Etw = captureEtw,
                Security = captureSecurity,
                PowerShell = capturePowerShell,
                WindowsOther = captureWindowsOther,
                Sysmon = captureSysmon
            },
            Etw = new AgentEtwMonitoringIntent
            {
                ConfigureSession = captureEtw,
                ProfileId = etwProfile?.Id ?? string.Empty,
                ProfileDisplayName = GetProfileName(etwProfile),
                ProfilePath = ResolveConfigProfileFilePath(etwProfile)
            },
            NetworkCapture = new AgentNetworkCaptureMetadataPolicy
            {
                Enabled = captureNetwork,
                OutputDirectory = _sessionPaths.NetworkCapturesDirectory
            },
            Zeek = new AgentZeekAnalysisImportPolicy
            {
                Enabled = captureZeek,
                RunAfterNetworkCapture = captureZeek && captureNetwork,
                ZeekPath = ZeekExecutablePath,
                WslDistributionName = ZeekWslDistributionName,
                WslZeekCommand = ZeekWslCommand,
                OutputDirectory = _sessionPaths.ZeekDirectory
            },
            ArtifactCapture = new AgentArtifactCapturePolicy
            {
                CaptureModules = captureModules,
                CaptureHandles = captureHandles,
                CapturePeMetadata = capturePe,
                CaptureDumpMetadata = false,
                RefreshIntervalSeconds = Math.Clamp(RefreshIntervalSeconds, 1, 3600),
                ScopePolicy = "Viewer current enrichment toggles"
            },
            SourceHealth = new AgentSourceHealthPolicy
            {
                TrackSourceHealth = true,
                PersistHealthSnapshots = true,
                WarningAfterDroppedEvents = 100,
                WarningAfterSourceSilenceSeconds = 300
            },
            Guardrails = new AgentVolumeRetentionGuardrailPolicy
            {
                Enabled = true,
                MaxEventsPerSecondWarning = 1000,
                MaxLiveDatabaseBytesWarning = 10L * 1024 * 1024 * 1024
            }
        };
    }

    private HostMonitoringConfigurationViewModel? ShowHostMonitoringConfigurationDialog(
        AgentRegistryEntryViewModel agent,
        string primaryButtonContent,
        string title,
        AgentHostMonitoringConfiguration? configuration)
    {
        var dialog = new ProcInsider.HostMonitoringConfigurationDialog(
            CreateHostMonitoringConfigurationSettings(configuration ?? agent.HostMonitoringConfiguration),
            primaryButtonContent)
        {
            Owner = GetDialogOwner(),
            Title = title
        };

        return dialog.ShowDialog() == true
            ? dialog.MonitoringConfiguration
            : null;
    }

    private IReadOnlyList<AgentCaptureOptionViewModel>? ShowCaptureConfigurationDialog(
        AgentRegistryEntryViewModel agent,
        string primaryButtonContent,
        string title)
    {
        var dialog = new ProcInsider.CaptureConfigurationDialog(agent.CaptureOptions, primaryButtonContent)
        {
            Owner = GetDialogOwner(),
            Title = title
        };

        return dialog.ShowDialog() == true
            ? dialog.GetCaptureOptions()
            : null;
    }

    private static Window? GetDialogOwner()
    {
        var current = Application.Current;
        if (current == null)
        {
            return null;
        }

        return current.Windows
            .OfType<Window>()
            .FirstOrDefault(window => window.IsActive)
            ?? current.MainWindow;
    }

    [RelayCommand(CanExecute = nameof(CanStartAgentCaptureOption))]
    private async Task StartAgentCaptureOptionAsync(AgentCaptureOptionViewModel? option)
    {
        var featureId = option == null ? null : AgentCaptureOptionViewModel.GetFeatureId(option.Kind);
        if (!featureId.HasValue || !RequireFeaturePublished(featureId.Value, option?.DisplayName ?? "Agent capture option"))
        {
            return;
        }

        var targetAgent = AgentsViewModel.SelectedAgent;
        if (option == null || targetAgent == null)
        {
            StatusMessage = "Select an agent capture row before starting capture.";
            return;
        }

        if (!RequireDeployedAgentCommand(targetAgent, $"{option.DisplayName} start"))
        {
            return;
        }

        switch (option.Kind)
        {
            case AgentCaptureOptionKind.ProcessLiveEvents:
            case AgentCaptureOptionKind.EtwEvents:
            case AgentCaptureOptionKind.SecurityEvents:
            case AgentCaptureOptionKind.PowerShellEvents:
            case AgentCaptureOptionKind.WindowsOtherEvents:
            case AgentCaptureOptionKind.SysmonEvents:
                await StartLiveCaptureSourceOrConfiguredCaptureAsync(targetAgent, option);
                return;
            case AgentCaptureOptionKind.ModuleEnrichment:
            case AgentCaptureOptionKind.HandleEnrichment:
            case AgentCaptureOptionKind.PeAnalysis:
                await StartAgentEnrichmentWorkloadAsync(option.Kind);
                return;
            case AgentCaptureOptionKind.NetworkCapture:
                if (!CanStartNetworkCapture())
                {
                    StatusMessage = "Network capture is already active or the local agent is not deployed.";
                    return;
                }

                await StartNetworkCaptureAsync();
                UpdateAgentCaptureRuntimeRows();
                return;
            case AgentCaptureOptionKind.ProcessMonitorCapture:
                if (!CanStartProcessMonitorCapture())
                {
                    StatusMessage = "Process Monitor capture is already active or the local agent is not deployed.";
                    return;
                }

                await StartProcessMonitorCaptureAsync();
                UpdateAgentCaptureRuntimeRows();
                return;
            default:
                StatusMessage = $"{option.DisplayName} requires a dedicated picker or prerequisite artifact before it can be queued.";
                option.StatusText = "Use the dedicated command or select the required artifact first.";
                return;
        }
    }

    [RelayCommand(CanExecute = nameof(CanStopAgentCaptureOption))]
    private async Task StopAgentCaptureOptionAsync(AgentCaptureOptionViewModel? option)
    {
        var featureId = option == null ? null : AgentCaptureOptionViewModel.GetFeatureId(option.Kind);
        if (!featureId.HasValue || !RequireFeaturePublished(featureId.Value, option?.DisplayName ?? "Agent capture option"))
        {
            return;
        }

        var targetAgent = AgentsViewModel.SelectedAgent;
        if (option == null || targetAgent == null)
        {
            StatusMessage = "Select an agent capture row before stopping capture.";
            return;
        }

        if (!RequireDeployedAgentCommand(targetAgent, $"{option.DisplayName} stop"))
        {
            return;
        }

        switch (option.Kind)
        {
            case AgentCaptureOptionKind.ProcessLiveEvents:
                await StopLiveCaptureSourceAsync(option, "Runtime");
                UpdateAgentCaptureRuntimeRows();
                return;
            case AgentCaptureOptionKind.EtwEvents:
                await StopLiveCaptureSourceAsync(option, "ETW");
                UpdateAgentCaptureRuntimeRows();
                return;
            case AgentCaptureOptionKind.SecurityEvents:
            case AgentCaptureOptionKind.PowerShellEvents:
            case AgentCaptureOptionKind.WindowsOtherEvents:
            case AgentCaptureOptionKind.SysmonEvents:
                await StopLiveCaptureSourceAsync(option, GetLiveCaptureSourceName(option.Kind));
                UpdateAgentCaptureRuntimeRows();
                return;
            case AgentCaptureOptionKind.ModuleEnrichment:
            case AgentCaptureOptionKind.HandleEnrichment:
                await StopAgentEnrichmentWorkloadAsync(
                    option.Kind == AgentCaptureOptionKind.ModuleEnrichment
                        ? JobKind.ModuleEnrichment
                        : JobKind.HandleEnrichment);
                UpdateAgentCaptureRuntimeRows();
                return;
            case AgentCaptureOptionKind.PeAnalysis:
                await StopAgentEnrichmentWorkloadAsync(JobKind.PeAnalysis);
                UpdateAgentCaptureRuntimeRows();
                return;
            case AgentCaptureOptionKind.NetworkCapture:
                await StopNetworkCaptureAsync();
                UpdateAgentCaptureRuntimeRows();
                return;
            case AgentCaptureOptionKind.ProcessMonitorCapture:
                await StopProcessMonitorCaptureAsync();
                UpdateAgentCaptureRuntimeRows();
                return;
            default:
                StatusMessage = $"{option.DisplayName} does not expose a long-running stop action.";
                option.StatusText = "No stop action is available for this capture type.";
                return;
        }
    }

    private async Task StopLiveCaptureSourceAsync(AgentCaptureOptionViewModel option, string source)
    {
        var targetAgent = AgentsViewModel.SelectedAgent;
        if (targetAgent == null)
        {
            StatusMessage = "Select the deployed local agent before stopping a capture source.";
            return;
        }

        var result = await _agentCaptureActionService.StopSourceAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: true),
            source);
        var response = result.Response;
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        if (response?.Success == true)
        {
            option.StatusText = $"{option.DisplayName} stopped; other live collectors remain active.";
            StatusMessage = option.StatusText;
            await RefreshAgentRegistryHealthAsync();
        }
    }

    private async Task StartLiveCaptureSourceOrConfiguredCaptureAsync(
        AgentRegistryEntryViewModel targetAgent,
        AgentCaptureOptionViewModel option)
    {
        if (!IsLiveCaptureActive(includeStopping: true))
        {
            await StartConfiguredCaptureForOptionAsync(targetAgent, option.Kind);
            return;
        }

        var result = await _agentCaptureActionService.StartSourceAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: true),
            GetLiveCaptureSourceName(option.Kind));
        var response = result.Response;
        if (!result.Succeeded)
        {
            StatusMessage = result.Diagnostic;
        }

        if (response?.Success == true)
        {
            option.StatusText = $"{option.DisplayName} started; other live collectors remain active.";
            StatusMessage = option.StatusText;
            await RefreshAgentRegistryHealthAsync();
        }
    }

    private static string GetLiveCaptureSourceName(AgentCaptureOptionKind kind)
    {
        return kind switch
        {
            AgentCaptureOptionKind.ProcessLiveEvents => "Runtime",
            AgentCaptureOptionKind.EtwEvents => "ETW",
            AgentCaptureOptionKind.SecurityEvents => "Security",
            AgentCaptureOptionKind.PowerShellEvents => "PowerShell",
            AgentCaptureOptionKind.WindowsOtherEvents => "WindowsOther",
            AgentCaptureOptionKind.SysmonEvents => "Sysmon",
            _ => string.Empty
        };
    }

    private async Task<IReadOnlyList<ExplorerNodeViewModel>> LoadCorrelationEvidenceGroupNodesAsync(ExplorerScope scope)
    {
        if (_sqliteStagingQueryService == null || !scope.CorrelationState.HasValue)
        {
            return [];
        }

        var groups = await Task.Run(() =>
            _sqliteStagingQueryService.GetEvidenceCorrelationGroups(scope.CorrelationState.Value));
        return groups.Select(group => new ExplorerNodeViewModel(new ExplorerScope
        {
            Kind = ExplorerScopeKind.CorrelationEvidenceGroup,
            ScopeId = $"analysis:correlation:{group.State}:{group.EvidenceKind}:{group.Source}",
            Title = string.IsNullOrWhiteSpace(group.Source)
                ? group.EvidenceKind.ToString()
                : $"{group.EvidenceKind} / {group.Source}",
            Description = $"{group.State} {group.EvidenceKind} evidence from {group.Source} with retained process-correlation diagnostics.",
            CorrelationState = group.State,
            CorrelationEvidenceKind = group.EvidenceKind,
            CorrelationSource = group.Source
        }, group.Count)).ToList();
    }

    private async Task LoadCorrelationEvidenceResultsAsync(ExplorerScope scope)
    {
        var queryService = _sqliteStagingQueryService;
        if (queryService == null || !scope.CorrelationState.HasValue)
        {
            return;
        }

        var workspaceGeneration = _captureWorkspaceCoordinator.Generation;
        var results = await Task.Run(() => queryService.GetEvidenceCorrelationResults(
            scope.CorrelationState.Value,
            scope.CorrelationEvidenceKind,
            scope.CorrelationSource ?? string.Empty,
            maxCount: 1000));
        if (workspaceGeneration != _captureWorkspaceCoordinator.Generation ||
            !ReferenceEquals(queryService, _sqliteStagingQueryService))
        {
            return;
        }

        void ApplyResults()
        {
            var search = SearchViewModel;
            search.SetExternalResults(
                results,
                $"Showing {results.Count} {scope.CorrelationState.Value.ToString().ToLowerInvariant()} correlation record(s) for {scope.Title}.");
            TryNavigateToExplorerTab(ExplorerTabKeys.Search, "Open evidence correlation results");
        }

        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.Invoke(ApplyResults);
        }
        else
        {
            ApplyResults();
        }
    }

    private bool CanStartAgentCaptureOption(AgentCaptureOptionViewModel? option)
    {
        if (option?.CanStart != true || !option.IsPublished)
        {
            return false;
        }

        var targetAgent = AgentsViewModel.SelectedAgent;
        if (!CanRunDeployedAgentCommand(targetAgent))
        {
            return false;
        }

        return option.Kind switch
        {
            AgentCaptureOptionKind.ProcessLiveEvents or
                AgentCaptureOptionKind.EtwEvents or
                AgentCaptureOptionKind.SecurityEvents or
            AgentCaptureOptionKind.PowerShellEvents or
            AgentCaptureOptionKind.WindowsOtherEvents or
                AgentCaptureOptionKind.SysmonEvents => !_activeSqliteBenchmarkJobId.HasValue,
            AgentCaptureOptionKind.ModuleEnrichment or
                AgentCaptureOptionKind.HandleEnrichment or
                AgentCaptureOptionKind.PeAnalysis => !_activeSqliteBenchmarkJobId.HasValue,
            AgentCaptureOptionKind.NetworkCapture => CanStartNetworkCapture(),
            AgentCaptureOptionKind.ProcessMonitorCapture => CanStartProcessMonitorCapture(),
            _ => true
        };
    }

    private bool CanStopAgentCaptureOption(AgentCaptureOptionViewModel? option)
    {
        if (option?.CanStop != true || !option.IsPublished || !CanRunDeployedAgentCommand(AgentsViewModel.SelectedAgent))
        {
            return false;
        }

        return option.Kind switch
        {
            AgentCaptureOptionKind.ProcessLiveEvents or
                AgentCaptureOptionKind.EtwEvents or
                AgentCaptureOptionKind.SecurityEvents or
            AgentCaptureOptionKind.PowerShellEvents or
            AgentCaptureOptionKind.WindowsOtherEvents or
                AgentCaptureOptionKind.SysmonEvents => option.CanStop,
            AgentCaptureOptionKind.ModuleEnrichment or
                AgentCaptureOptionKind.HandleEnrichment => option.CanStop,
            AgentCaptureOptionKind.PeAnalysis => option.CanStop,
            AgentCaptureOptionKind.NetworkCapture => IsNetworkCaptureActiveForCommands(includeStopping: false),
            AgentCaptureOptionKind.ProcessMonitorCapture => IsProcessMonitorCaptureActiveForCommands(includeStopping: false),
            _ => false
        };
    }

    private async Task StartConfiguredCaptureForOptionAsync(
        AgentRegistryEntryViewModel targetAgent,
        AgentCaptureOptionKind kind)
    {
        var options = AgentCaptureOptionViewModel.CreateDefaultOptions()
            .Select(option =>
            {
                option.IsIncluded = option.Kind == kind;
                return option;
            })
            .ToList();

        targetAgent.ApplyCaptureOptionSelections(options);
        if (!await SaveAgentCaptureConfigurationAsync(targetAgent, requireViewerConnection: false, options))
        {
            return;
        }

        await StartSavedAgentConfiguredCaptureAsync(targetAgent);
    }

    private async Task StartAgentEnrichmentWorkloadAsync(AgentCaptureOptionKind kind)
    {
        var jobKind = kind switch
        {
            AgentCaptureOptionKind.ModuleEnrichment => JobKind.ModuleEnrichment,
            AgentCaptureOptionKind.HandleEnrichment => JobKind.HandleEnrichment,
            AgentCaptureOptionKind.PeAnalysis => JobKind.PeAnalysis,
            _ => JobKind.Unknown
        };
        if (jobKind == JobKind.Unknown)
        {
            return;
        }

        var result = await QueueArtifactEnrichmentActionAsync(
            new ArtifactEnrichmentQueueRequest(
                ArtifactEnrichmentQueueScope.Independent,
                CaptureModules: jobKind == JobKind.ModuleEnrichment,
                CaptureHandles: jobKind == JobKind.HandleEnrichment,
                CapturePe: jobKind == JobKind.PeAnalysis,
                PeStringExtractionMode: PeStringExtractionMode.Deferred,
                Action: $"queue {kind.ToString().ToLowerInvariant()} workload"));
        if (PreserveArtifactEnrichmentWorkflowTerminalProjection(result))
        {
            return;
        }

        if (!result.Succeeded)
        {
            if (PreserveUnknownAgentCommandOutcome(result.Response, result.Detail))
            {
                return;
            }

            StatusMessage = result.Response == null
                ? "Deploy the local agent before queueing enrichment."
                : $"Agent enrichment did not start: {FirstNonEmpty(result.Response.ErrorMessage, result.Response.ErrorCode, result.Detail, "agent command failed")}";
            return;
        }

        StatusMessage = $"Queued independent {kind.ToString().ToLowerInvariant()} workload; saved capture policy was not changed.";
    }

    private string ResolveConfigProfileFilePath(ConfigProfileDefinition? profile)
    {
        return profile == null ? string.Empty : _configProfileService.ResolveProfileFilePath(profile) ?? string.Empty;
    }

    private static string GetProfileName(ConfigProfileDefinition? profile)
    {
        return profile == null ? string.Empty : GetConfigProfileDisplayName(profile);
    }

    private static string BuildViewerCaptureId()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        return $"viewer-capture-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{suffix}";
    }

    [RelayCommand(CanExecute = nameof(CanStartLiveCapture))]
    public async Task StartLiveCaptureAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.AgentsAndCapture, "Start Live Capture"))
        {
            return;
        }

        if (!RequireConnectedAgent("live capture start"))
        {
            return;
        }

        if (_activeSqliteBenchmarkJobId.HasValue)
        {
            StatusMessage = "Cancel or wait for the SQLite benchmark before starting live capture.";
            return;
        }

        SetLiveCaptureRunState(CaptureRunState.Starting);
        var captureResult = await _agentCaptureWorkflowCoordinator.ExecuteCaptureCommandAsync(
            new AgentCaptureCommandRequest(
                JobKind.LiveCapture,
                AgentCapturePendingAction.Start,
                CreateStartLiveCaptureCommand(),
                "start live capture"));
        if (PreserveAgentCaptureWorkflowTerminalProjection(captureResult))
        {
            return;
        }

        var response = captureResult.Response;
        if (response?.Success == true)
        {
            UpdateAgentStatus(response, observeWorkflow: false);
            SetLiveCaptureRunState(CaptureRunStateFromJob(response.Job, CaptureRunState.Starting));
            StatusMessage = $"Submitted live capture to the agent. {EtwCaptureProfileStatus}";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        _activeLiveCaptureJobId = null;
        SetLiveCaptureRunState(CaptureRunState.Failed);
        StatusMessage =
            $"Agent live capture did not start: {FirstNonEmpty(response?.ErrorMessage, response?.ErrorCode, "agent unavailable")}. " +
            "No viewer capture fallback ran; the current snapshot was preserved.";
    }

    [RelayCommand(CanExecute = nameof(CanStopLiveCapture))]
    public async Task StopLiveCaptureAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.AgentsAndCapture, "Stop Live Capture"))
        {
            return;
        }

        if (!RequireConnectedAgent("live capture stop"))
        {
            return;
        }

        var captureResult = await _agentCaptureWorkflowCoordinator.ExecuteCaptureCommandAsync(
            new AgentCaptureCommandRequest(
                JobKind.LiveCapture,
                AgentCapturePendingAction.Stop,
                new StopLiveCaptureCommand(),
                "stop live capture",
                StartAgentIfNeeded: false));
        if (PreserveAgentCaptureWorkflowTerminalProjection(captureResult))
        {
            return;
        }

        var response = captureResult.Response;
        if (response?.Success == true)
        {
            UpdateAgentStatus(response, observeWorkflow: false);
            SetLiveCaptureRunState(CaptureRunStateFromJob(response.Job, CaptureRunState.Stopping));
            StatusMessage = "Requested agent live capture stop.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        StatusMessage =
            $"Agent live capture stop failed: {FirstNonEmpty(response?.ErrorMessage, response?.ErrorCode, "agent unavailable")}. " +
            "No viewer state was substituted; authoritative agent health remains unchanged.";
    }

    [RelayCommand(CanExecute = nameof(CanStartNetworkCapture))]
    public async Task StartNetworkCaptureAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.NetworkAndZeek, "Start network capture"))
        {
            return;
        }

        var targetAgent = GetLocalAgent();
        if (!RequireDeployedAgentCommand(targetAgent, "network capture start"))
        {
            return;
        }

        SetNetworkCaptureRunState(CaptureRunState.Starting);
        var action = await _agentToolActionService.StartNetworkCaptureAsync(
            CreateAgentCaptureActionTarget(targetAgent!, requireViewerConnection: false));
        var response = action.Response;
        if (response?.Success == true)
        {
            var acceptedJobId = response.AcceptedJobId;
            var pendingFinalization = acceptedJobId.HasValue &&
                                      HasPendingNetworkCaptureFinalization(acceptedJobId.Value, response.Job?.State);
            var jobIsActive = response.Job?.State is JobState.Queued or JobState.Running or JobState.Paused;
            _activeNetworkCaptureJobId = pendingFinalization ||
                                         jobIsActive ||
                                         response.Job == null && acceptedJobId.HasValue
                ? acceptedJobId
                : null;
            IsNetworkCaptureActive = pendingFinalization || jobIsActive;
            SetNetworkCaptureRunState(pendingFinalization
                ? CaptureRunState.Stopping
                : CaptureRunStateFromJob(response.Job, CaptureRunState.Starting));
            UpdateAgentStatus(response, observeWorkflow: false);
            TryNavigateToExplorerTab(ExplorerTabKeys.Network, "Open Network and Zeek");
            if (_featureModules.TryGetActivated<NetworkAndZeekFeatureModule>(FeatureIds.NetworkAndZeek, out var network))
            {
                network.ViewModel.RefreshNetworkCaptures();
            }
            StatusMessage = "Submitted network PCAP capture to the agent.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        IsNetworkCaptureActive = false;
        SetNetworkCaptureRunState(CaptureRunState.Failed);
        StatusMessage = response == null
            ? action.Diagnostic
            : $"Network PCAP capture did not start: {response.ErrorMessage}";
    }

    [RelayCommand(CanExecute = nameof(CanStopNetworkCapture))]
    public async Task StopNetworkCaptureAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.NetworkAndZeek, "Stop network capture"))
        {
            return;
        }

        var targetAgent = GetLocalAgent();
        if (!RequireDeployedAgentCommand(targetAgent, "network capture stop"))
        {
            return;
        }

        var action = await _agentToolActionService.StopNetworkCaptureAsync(
            CreateAgentCaptureActionTarget(targetAgent!, requireViewerConnection: false));
        var response = action.Response;
        if (response?.Success == true)
        {
            var acceptedJobId = response.AcceptedJobId ?? _activeNetworkCaptureJobId;
            var pendingFinalization = acceptedJobId.HasValue &&
                                      HasPendingNetworkCaptureFinalization(
                                          acceptedJobId.Value,
                                          response.Job?.State);
            var jobIsActive = response.Job?.State is JobState.Queued or JobState.Running or JobState.Paused;
            _activeNetworkCaptureJobId = pendingFinalization || jobIsActive
                ? acceptedJobId
                : null;
            IsNetworkCaptureActive = pendingFinalization || jobIsActive;
            SetNetworkCaptureRunState(pendingFinalization
                ? CaptureRunState.Stopping
                : CaptureRunStateFromJob(response.Job, CaptureRunState.Stopping));
            UpdateAgentStatus(response, observeWorkflow: false);
            NetworkCapturesViewModel.RefreshNetworkCaptures();
            StatusMessage = pendingFinalization
                ? "Requested agent network capture stop; finalizing the PCAP segment."
                : "Requested agent network capture stop and segment finalization.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        if (response?.Job?.JobKind == JobKind.NetworkCapture)
        {
            _activeNetworkCaptureJobId = response.AcceptedJobId ?? _activeNetworkCaptureJobId;
            IsNetworkCaptureActive = response.Job.State is JobState.Queued or JobState.Running or JobState.Paused;
            SetNetworkCaptureRunState(CaptureRunStateFromJob(response.Job, CaptureRunState.Failed));
            UpdateAgentStatus(response, observeWorkflow: false);
            NetworkCapturesViewModel.RefreshNetworkCaptures();
            StatusMessage = $"Network PCAP capture stop failed: {response.ErrorMessage}";
            return;
        }

        if (!_activeNetworkCaptureJobId.HasValue)
        {
            IsNetworkCaptureActive = false;
            SetNetworkCaptureRunState(CaptureRunState.Off);
        }

        NetworkCapturesViewModel.RefreshNetworkCaptures();
        StatusMessage = FirstNonEmpty(action.Diagnostic, "No agent network capture was stopped.");
    }

    [RelayCommand(CanExecute = nameof(CanUseEventTelemetryFeature))]
    public void SelectProcessMonitorExecutable()
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "Select Process Monitor executable"))
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Select Sysinternals Process Monitor",
            Filter = "Process Monitor (Procmon*.exe)|Procmon*.exe|Executable files (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Process Monitor executable selection canceled.";
            return;
        }

        ProcessMonitorExecutablePath = dialog.FileName;
        StatusMessage = $"Process Monitor executable selected: {ProcessMonitorExecutablePath}";
    }

    [RelayCommand(CanExecute = nameof(CanStartProcessMonitorCapture))]
    public async Task StartProcessMonitorCaptureAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "Start Process Monitor capture"))
        {
            return;
        }

        var targetAgent = GetLocalAgent();
        if (!RequireDeployedAgentCommand(targetAgent, "Process Monitor capture start"))
        {
            return;
        }

        SetProcessMonitorCaptureRunState(CaptureRunState.Starting);
        var action = await _agentToolActionService.StartProcessMonitorCaptureAsync(
            CreateAgentCaptureActionTarget(targetAgent!, requireViewerConnection: false),
            new ViewerProcessMonitorStartActionRequest(
                ProcessMonitorExecutablePath,
                AcceptEula: true));
        var response = action.Response;
        if (response?.Success == true)
        {
            IsProcessMonitorCaptureActive = response.Job?.State is JobState.Queued or JobState.Running or JobState.Paused ||
                                            response.Job == null && response.AcceptedJobId.HasValue;
            SetProcessMonitorCaptureRunState(CaptureRunStateFromJob(response.Job, CaptureRunState.Starting));
            UpdateAgentStatus(response, observeWorkflow: false);
            StatusMessage = "Submitted Process Monitor capture to the agent.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        _activeProcessMonitorCaptureJobId = null;
        IsProcessMonitorCaptureActive = false;
        SetProcessMonitorCaptureRunState(CaptureRunState.Failed);
        StatusMessage = response == null
            ? action.Diagnostic
            : $"Process Monitor capture did not start: {response.ErrorMessage}";
    }

    [RelayCommand(CanExecute = nameof(CanStopProcessMonitorCapture))]
    public async Task StopProcessMonitorCaptureAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "Stop Process Monitor capture"))
        {
            return;
        }

        var targetAgent = GetLocalAgent();
        if (!RequireDeployedAgentCommand(targetAgent, "Process Monitor capture stop"))
        {
            return;
        }

        var action = await _agentToolActionService.StopProcessMonitorCaptureAsync(
            CreateAgentCaptureActionTarget(targetAgent!, requireViewerConnection: false),
            new ViewerProcessMonitorStopActionRequest(ProcessMonitorExecutablePath));
        var response = action.Response;
        if (response?.Success == true)
        {
            IsProcessMonitorCaptureActive = response.Job?.State is JobState.Queued or JobState.Running or JobState.Paused;
            SetProcessMonitorCaptureRunState(CaptureRunStateFromJob(response.Job, CaptureRunState.Stopping));
            UpdateAgentStatus(response, observeWorkflow: false);
            StatusMessage = "Requested Process Monitor capture stop; CSV export/import will complete in the agent.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        _activeProcessMonitorCaptureJobId = null;
        IsProcessMonitorCaptureActive = false;
        SetProcessMonitorCaptureRunState(response == null ? CaptureRunState.Off : CaptureRunState.Failed);
        StatusMessage = response == null
            ? action.Diagnostic
            : $"Process Monitor capture stop failed: {response.ErrorMessage}";
    }

    [RelayCommand(CanExecute = nameof(CanRunProcessMonitorAgentCommand))]
    public async Task QueueProcessMonitorImportAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.EventTelemetry, "Import Process Monitor output"))
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Import Process Monitor Output",
            Filter = "Process Monitor output (*.csv;*.pml)|*.csv;*.pml|CSV files (*.csv)|*.csv|PML files (*.pml)|*.pml|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Process Monitor import canceled.";
            return;
        }

        var targetAgent = GetLocalAgent();
        if (!RequireDeployedAgentCommand(targetAgent, "Process Monitor import"))
        {
            return;
        }

        var action = await _agentToolActionService.QueueProcessMonitorImportAsync(
            CreateAgentCaptureActionTarget(targetAgent!, requireViewerConnection: false),
            new ViewerProcessMonitorImportActionRequest(
                dialog.FileName,
                ProcessMonitorExecutablePath));
        var response = action.Response;
        if (response?.Success == true)
        {
            _activeProcessMonitorImportJobId = response.AcceptedJobId;
            UpdateAgentStatus(response);
            StatusMessage = $"Queued Process Monitor import: {dialog.FileName}";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        StatusMessage = response == null
            ? action.Diagnostic
            : $"Process Monitor import was not queued: {response.ErrorMessage}";
    }

    private bool CanQueueSelectedZeekAnalysis()
        => _featureAccess.CanExecute(
            FeatureIds.NetworkAndZeek,
            CanRunDerivedAgentCommand() && NetworkCapturesViewModel.SelectedNetworkCapture?.CanRunZeek == true);

    [RelayCommand(CanExecute = nameof(CanQueueSelectedZeekAnalysis))]
    public async Task QueueSelectedZeekAnalysisAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.NetworkAndZeek, "Zeek analysis"))
        {
            return;
        }

        if (!RequireNetworkTabAgentCommand("Zeek analysis"))
        {
            return;
        }

        var capture = NetworkCapturesViewModel.SelectedNetworkCapture;
        if (capture == null)
        {
            StatusMessage = "Select a captured PCAP segment before running Zeek.";
            return;
        }

        var targetAgent = GetLocalAgent();
        if (!RequireDeployedAgentCommand(targetAgent, "Zeek analysis"))
        {
            return;
        }

        var action = await _agentToolActionService.QueueZeekAsync(
            CreateAgentCaptureActionTarget(targetAgent!, requireViewerConnection: false),
            new ViewerZeekActionRequest(
                CaptureId: capture.CaptureId,
                ZeekPath: ZeekExecutablePath,
                WslDistributionName: ZeekWslDistributionName,
                WslZeekCommand: ZeekWslCommand));
        var response = action.Response;
        if (response?.Success == true)
        {
            _activeZeekAnalysisJobId = response.AcceptedJobId;
            UpdateAgentStatus(response);
            TryNavigateToExplorerTab(ExplorerTabKeys.Network, "Open Network and Zeek");
            StatusMessage = "Queued Zeek analysis for the selected capture segment.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        StatusMessage = FirstNonEmpty(
            action.Diagnostic,
            "Zeek analysis requires the agent plus Zeek for Windows or the configured WSL Zeek command.");
    }

    private bool CanOpenSelectedZeekProcess()
        => _featureAccess.CanExecute(
            FeatureIds.NetworkAndZeek,
            NetworkCapturesViewModel.SelectedZeekArtifact?.HasProcessCorrelation == true);

    [RelayCommand(CanExecute = nameof(CanOpenSelectedZeekProcess))]
    public void OpenSelectedZeekProcess()
    {
        if (!RequireFeaturePublished(FeatureIds.NetworkAndZeek, "Open correlated Zeek process"))
        {
            return;
        }

        var artifact = NetworkCapturesViewModel.SelectedZeekArtifact;
        if (artifact?.HasProcessCorrelation != true)
        {
            StatusMessage = "The selected Zeek artifact is not correlated to a process.";
            return;
        }

        NavigateToSearchResult(artifact.ToNavigationResult());
    }

    private bool CanOpenSelectedZeekPcap()
    {
        var capture = FindSelectedZeekCapture();
        return _featureAccess.CanExecute(
            FeatureIds.NetworkAndZeek,
            !string.IsNullOrWhiteSpace(capture?.FilePath) && File.Exists(capture.FilePath));
    }

    [RelayCommand(CanExecute = nameof(CanOpenSelectedZeekPcap))]
    public void OpenSelectedZeekPcap()
    {
        if (!RequireFeaturePublished(FeatureIds.NetworkAndZeek, "Open Zeek PCAP"))
        {
            return;
        }

        var capture = FindSelectedZeekCapture();
        if (capture == null || string.IsNullOrWhiteSpace(capture.FilePath) || !File.Exists(capture.FilePath))
        {
            StatusMessage = "The selected Zeek artifact does not have an available PCAPNG capture file.";
            return;
        }

        try
        {
            var wireshark = FindExecutableOnPath("Wireshark.exe") ?? FindKnownWiresharkExecutable();
            if (!string.IsNullOrWhiteSpace(wireshark))
            {
                var result = _externalProcessService.OpenWireshark(wireshark, capture.FilePath);
                if (!result.Succeeded)
                {
                    throw new InvalidOperationException(result.Detail);
                }

                StatusMessage = $"Opened capture in Wireshark: {capture.FilePath}";
                return;
            }

            var shellResult = _externalProcessService.OpenShellTarget(capture.FilePath);
            if (!shellResult.Succeeded)
            {
                throw new InvalidOperationException(shellResult.Detail);
            }

            StatusMessage = $"Opened capture file: {capture.FilePath}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open PCAPNG capture: {ex.Message}";
        }
    }

    private bool CanCopySelectedZeekWiresharkFilter()
        => _featureAccess.CanExecute(
            FeatureIds.NetworkAndZeek,
            NetworkCapturesViewModel.SelectedZeekArtifact?.HasFlowTuple == true);

    [RelayCommand(CanExecute = nameof(CanCopySelectedZeekWiresharkFilter))]
    public void CopySelectedZeekWiresharkFilter()
    {
        if (!RequireFeaturePublished(FeatureIds.NetworkAndZeek, "Copy Zeek Wireshark filter"))
        {
            return;
        }

        var artifact = NetworkCapturesViewModel.SelectedZeekArtifact;
        if (artifact?.HasFlowTuple != true || string.IsNullOrWhiteSpace(artifact.WiresharkFilter))
        {
            StatusMessage = "The selected Zeek artifact does not have enough endpoint data for a Wireshark filter.";
            return;
        }

        try
        {
            Clipboard.SetText(artifact.WiresharkFilter);
            StatusMessage = "Copied Wireshark display filter for the selected Zeek connection.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to copy Wireshark filter: {ex.Message}";
        }
    }

    private bool CanExportSelectedZeekFlowPcap()
        => NetworkCapturesViewModel.SelectedZeekArtifact?.HasFlowTuple == true && CanOpenSelectedZeekPcap();

    [RelayCommand(CanExecute = nameof(CanExportSelectedZeekFlowPcap))]
    public async Task ExportSelectedZeekFlowPcapAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.NetworkAndZeek, "Export Zeek flow PCAP"))
        {
            return;
        }

        var artifact = NetworkCapturesViewModel.SelectedZeekArtifact;
        var capture = FindSelectedZeekCapture();
        if (artifact?.HasFlowTuple != true ||
            string.IsNullOrWhiteSpace(artifact.WiresharkFilter) ||
            capture == null ||
            string.IsNullOrWhiteSpace(capture.FilePath) ||
            !File.Exists(capture.FilePath))
        {
            StatusMessage = "Select a Zeek connection with endpoint data and an available PCAPNG capture before exporting.";
            return;
        }

        var tshark = FindExecutableOnPath("tshark.exe") ?? FindKnownTsharkExecutable();
        if (string.IsNullOrWhiteSpace(tshark))
        {
            StatusMessage = "TShark was not found. Install Wireshark or copy the filter and open the full PCAPNG manually.";
            return;
        }

        var exportDirectory = Path.Combine(_sessionPaths.NetworkCapturesDirectory, "Exports");
        Directory.CreateDirectory(exportDirectory);
        var exportName = $"{SanitizeFileName(capture.CaptureId)}-{SanitizeFileName(FirstNonEmpty(artifact.ZeekUid, artifact.ArtifactId))}.pcapng";
        var exportPath = Path.Combine(exportDirectory, exportName);

        try
        {
            StatusMessage = "Exporting selected Zeek flow with TShark...";
            var result = await _externalProcessService.ExportTsharkFlowAsync(
                tshark,
                capture.FilePath,
                artifact.WiresharkFilter,
                exportPath,
                TimeSpan.FromMinutes(2)).ConfigureAwait(true);
            if (result.Outcome is ViewerExternalProcessOutcome.MissingExecutable or
                ViewerExternalProcessOutcome.StartFailed or
                ViewerExternalProcessOutcome.ExecutionFailed)
            {
                throw new InvalidOperationException(result.Detail);
            }

            if (result.Outcome != ViewerExternalProcessOutcome.Completed &&
                result.Outcome != ViewerExternalProcessOutcome.MissingExpectedOutput)
            {
                StatusMessage = $"TShark flow export failed ({result.ExitCode ?? -1}): {FirstNonEmpty(result.StandardError, result.StandardOutput, result.Detail, "<no output>")}";
                return;
            }

            if (result.Outcome == ViewerExternalProcessOutcome.MissingExpectedOutput)
            {
                StatusMessage = $"TShark exported no packets for the selected Zeek flow. Filter: {artifact.WiresharkFilter}";
                return;
            }

            var shellResult = _externalProcessService.OpenShellTarget(exportPath);
            if (!shellResult.Succeeded)
            {
                throw new InvalidOperationException(shellResult.Detail);
            }

            StatusMessage = $"Exported selected Zeek flow: {exportPath}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to export selected Zeek flow: {ex.Message}";
        }
    }

    private NetworkCaptureRowViewModel? FindSelectedZeekCapture()
    {
        var artifact = NetworkCapturesViewModel.SelectedZeekArtifact;
        if (artifact == null || string.IsNullOrWhiteSpace(artifact.CaptureId))
        {
            return null;
        }

        return NetworkCapturesViewModel.NetworkCaptures
            .FirstOrDefault(capture => string.Equals(capture.CaptureId, artifact.CaptureId, StringComparison.Ordinal));
    }

    [RelayCommand(CanExecute = nameof(CanImportFilesystemArtifacts))]
    public async Task QueueArtifactFileImportAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.FilesystemArtifacts, "Filesystem artifact import"))
        {
            return;
        }

        if (!RequireConnectedAgent("filesystem artifact import"))
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Import NTFS or Prefetch Artifact",
            Filter = "Supported artifacts (*.pf;$MFT;$LogFile;*UsnJrnl*)|*.pf;$MFT;$LogFile;*UsnJrnl*|Prefetch (*.pf)|*.pf|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Artifact file import canceled.";
            return;
        }

        await QueueArtifactImportAsync(dialog.FileName, recurse: false);
    }

    [RelayCommand(CanExecute = nameof(CanImportFilesystemArtifacts))]
    public async Task QueueArtifactFolderImportAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.FilesystemArtifacts, "Filesystem artifact import"))
        {
            return;
        }

        if (!RequireConnectedAgent("filesystem artifact import"))
        {
            return;
        }

        var dialog = new OpenFolderDialog
        {
            Title = "Import NTFS and Prefetch Artifacts",
            Multiselect = false
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Artifact folder import canceled.";
            return;
        }

        await QueueArtifactImportAsync(dialog.FolderName, recurse: true);
    }

    private async Task QueueArtifactImportAsync(string path, bool recurse)
    {
        var targetAgent = GetLocalAgent();
        if (targetAgent == null)
        {
            StatusMessage = "Filesystem artifact import requires one exact connected local agent.";
            return;
        }

        var result = await _agentEvidenceActionService.QueueFilesystemImportAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: true),
            new ViewerFilesystemImportActionRequest(
                path,
                recurse,
                IncludeNtfs: true,
                IncludePrefetch: true));
        var response = result.Response;
        if (result.Succeeded && result.AcceptedJobId.HasValue)
        {
            _activeArtifactImportJobId = result.AcceptedJobId;
            if (response != null)
            {
                UpdateAgentStatus(response);
            }
            _viewerNavigationCoordinator.SetDataContext(
                _viewerNavigationCoordinator.State.IncludeNetworkData,
                includeFilesystemData: true);
            TryNavigateToDataTab(DataTabKeys.Filesystem, "Open Filesystem artifacts");
            FilesystemArtifactsViewModel.RefreshArtifacts();
            StatusMessage = $"Queued filesystem artifact import: {path}";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        StatusMessage = $"Filesystem artifact import did not start: {result.Diagnostic} No viewer fallback was run.";
    }

    [RelayCommand(CanExecute = nameof(CanUseSystemMemoryFeature))]
    public async Task DumpSystemMemoryAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.SystemMemoryAndVolatility, "System memory acquisition"))
        {
            return;
        }

        if (!RequireConnectedAgent("system memory acquisition"))
        {
            return;
        }

        TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open System Memory");
        var warning =
            "Start full system memory acquisition now?\n\n" +
            "The elevated agent will resolve the explicitly configured trusted tool, allocate a unique output " +
            "inside the active session Memory folder, validate the result, and publish its provenance.\n\n" +
            "This can create a very large file and may trigger security tooling. No bundled driver or tool is installed.";
        if (MessageBox.Show(warning, "Dump System Memory", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            StatusMessage = "System memory dump canceled.";
            return;
        }

        var targetAgent = GetLocalAgent();
        if (targetAgent == null)
        {
            return;
        }

        StatusMessage = "Queueing agent-owned system memory acquisition.";
        var action = await _agentMemoryActionService.Value.AcquireAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: true),
            new ViewerMemoryAcquisitionRequest(
                Confirmed: true,
                TimeoutSeconds: AgentMemoryActionPolicy.DefaultAcquisitionTimeoutSeconds));
        if (action.Succeeded)
        {
            _activeMemoryAcquisitionJobId = action.AcceptedJobId;
            if (action.Response != null)
            {
                UpdateAgentStatus(action.Response);
            }
            StatusMessage = "Agent-owned system memory acquisition queued. Progress and failures are reported by the agent; results appear after Refresh from db.";
            return;
        }

        StatusMessage = $"System memory acquisition was rejected before side effects: {action.Diagnostic}";
    }

    [RelayCommand(CanExecute = nameof(CanUseSystemMemoryFeature))]
    public async Task QueueMemoryImageImportAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.SystemMemoryAndVolatility, "System memory image import"))
        {
            return;
        }

        if (!RequireConnectedAgent("system memory image import"))
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Import System Memory Image",
            Filter = "Memory images (*.raw;*.mem;*.dmp;*.dump;*.vmem;*.lime;*.bin)|*.raw;*.mem;*.dmp;*.dump;*.vmem;*.lime;*.bin|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Memory image import canceled.";
            return;
        }

        var targetAgent = GetLocalAgent();
        if (targetAgent == null)
        {
            return;
        }

        var action = await _agentMemoryActionService.Value.ImportAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: true),
            new ViewerMemoryImageImportRequest(
                dialog.FileName,
                Path.GetFileName(dialog.FileName),
                Environment.MachineName,
                AcquisitionTool: "Analyst import",
                PrivilegeState: Environment.IsPrivilegedProcess ? "Elevated" : "Not elevated"));
        if (action.Succeeded)
        {
            _activeMemoryImageImportJobId = action.AcceptedJobId;
            if (action.Response != null)
            {
                UpdateAgentStatus(action.Response);
            }
            TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open System Memory");
            MemoryInvestigationViewModel.RefreshMemoryInvestigation();
            StatusMessage = "Queued system memory image import. Click Refresh from db after the agent reports a database change.";
            return;
        }

        StatusMessage = $"System memory image import was rejected: {action.Diagnostic} No viewer fallback was run.";
    }

    private bool CanQueueSelectedMemoryImageVolatilityAnalysis()
        => _featureAccess.CanExecute(
            FeatureIds.SystemMemoryAndVolatility,
            CanRunDerivedAgentCommand() && MemoryInvestigationViewModel.SelectedMemoryImage != null);

    [RelayCommand(CanExecute = nameof(CanQueueSelectedMemoryImageVolatilityAnalysis))]
    public async Task QueueSelectedMemoryImageVolatilityAnalysisAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.SystemMemoryAndVolatility, "Volatility analysis"))
        {
            return;
        }

        if (!CanRunDerivedAgentCommand())
        {
            StatusMessage = "Volatility analysis requires an active capture database and the local agent.";
            return;
        }

        var image = MemoryInvestigationViewModel.SelectedMemoryImage;
        if (image == null)
        {
            StatusMessage = "Select an imported memory image before running Volatility.";
            return;
        }

        var targetAgent = GetLocalAgent();
        if (targetAgent == null)
        {
            StatusMessage = "Volatility analysis requires a registered local agent.";
            return;
        }

        var action = await _agentMemoryActionService.Value.RunVolatilityAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: false),
            new ViewerVolatilityActionRequest(ImageId: image.ImageId));
        if (action.Succeeded)
        {
            _activeVolatilityAnalysisJobId = action.AcceptedJobId;
            if (action.Response != null)
            {
                UpdateAgentStatus(action.Response);
            }
            TryNavigateToExplorerTab(ExplorerTabKeys.Memory, "Open System Memory");
            StatusMessage = "Queued Volatility process plugin analysis. Results appear after Refresh from db.";
            return;
        }

        StatusMessage = $"Volatility analysis did not start: {action.Diagnostic}";
    }

    [RelayCommand(CanExecute = nameof(CanRunArtifactEnrichmentFeature))]
    public async Task StartArtifactEnrichmentAsync()
    {
        if (!FeaturePublication.ModulesAndHandles && !FeaturePublication.DumpsAndPeAnalysis)
        {
            RequireFeaturePublished(FeatureIds.ModulesAndHandles, "Artifact enrichment");
            return;
        }

        var result = await QueueArtifactEnrichmentActionAsync(
            new ArtifactEnrichmentQueueRequest(
                ArtifactEnrichmentQueueScope.Global,
                CaptureModules: FeaturePublication.ModulesAndHandles,
                CaptureHandles: FeaturePublication.ModulesAndHandles,
                CapturePe: FeaturePublication.DumpsAndPeAnalysis,
                PeStringExtractionMode: PeStringExtractionMode.Deferred,
                Action: "queue artifact enrichment"));
        if (PreserveArtifactEnrichmentWorkflowTerminalProjection(result))
        {
            return;
        }

        if (result.Succeeded)
        {
            StatusMessage = "Queued agent artifact enrichment for staged processes.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(result.Response, result.Detail))
        {
            return;
        }

        StatusMessage = result.Response == null
            ? "Deploy the local agent before queueing artifact enrichment."
            : $"Agent artifact enrichment did not start: {FirstNonEmpty(result.Response.ErrorMessage, result.Response.ErrorCode, result.Detail, "agent command failed")}";
    }

    private bool CanRefreshSelectedHandles()
    {
        return _featureAccess.CanExecute(
            FeatureIds.ModulesAndHandles,
            SelectedProcess != null && !IsAgentShutdownInProgress);
    }

    [RelayCommand(CanExecute = nameof(CanRefreshSelectedHandles))]
    public async Task RefreshSelectedModulesAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.ModulesAndHandles, "Refresh selected-process modules"))
        {
            return;
        }

        if (SelectedProcess == null)
        {
            StatusMessage = "Select a process before refreshing modules.";
            return;
        }

        TryNavigateToDataTab(DataTabKeys.Modules, "Open Modules");
        ModulesViewModel.LoadModulesForProcessCommand.Execute(SelectedProcess.ProcessInfo);
        if (!IsAgentViewerConnected)
        {
            StatusMessage = "Module refresh requires the agent; no viewer evidence fallback ran. The current snapshot was preserved.";
            return;
        }

        await QueueSelectedProcessEnrichmentIfNeededAsync(captureModules: true, captureHandles: false, force: true);
    }

    [RelayCommand(CanExecute = nameof(CanRefreshSelectedHandles))]
    public async Task RefreshSelectedHandlesAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.ModulesAndHandles, "Refresh selected-process handles"))
        {
            return;
        }

        if (SelectedProcess == null)
        {
            StatusMessage = "Select a process before refreshing handles.";
            return;
        }

        TryNavigateToDataTab(DataTabKeys.Handles, "Open Handles");
        HandlesViewModel.LoadHandlesForProcessCommand.Execute(SelectedProcess.ProcessInfo);
        if (IsAgentViewerConnected)
        {
            await QueueSelectedProcessEnrichmentIfNeededAsync(captureModules: false, captureHandles: true, force: true);
            return;
        }

        StatusMessage = "Handle refresh requires the agent; no viewer evidence fallback ran. The current snapshot was preserved.";
    }

    private async Task QueueSelectedProcessEnrichmentIfNeededAsync(bool captureModules, bool captureHandles, bool force)
    {
        if (!IsAgentViewerConnected)
        {
            return;
        }

        var selected = SelectedProcess;
        if (selected == null)
        {
            return;
        }

        var process = selected.ProcessInfo;
        var processKey = selected.ProcessKey;
        var selection = new ArtifactEnrichmentSelectionContext(
            process.ProcessEntityId,
            processKey,
            selected.ProcessName,
            selected.ProcessId,
            process.Status,
            process.ModuleCaptureStatus,
            process.ModuleLastCaptured,
            process.HandleCaptureStatus,
            process.HandleLastCaptured);
        var action = captureModules && captureHandles
            ? "queue selected-process module and handle enrichment"
            : captureModules
                ? "queue selected-process module enrichment"
                : "queue selected-process handle enrichment";
        var result = await QueueArtifactEnrichmentActionAsync(
            new ArtifactEnrichmentQueueRequest(
                ArtifactEnrichmentQueueScope.SelectedProcess,
                captureModules,
                captureHandles,
                CapturePe: false,
                PeStringExtractionMode: PeStringExtractionMode.Deferred,
                Action: action,
                Selection: selection,
                Force: force));
        if (SelectedProcess?.ProcessKey != processKey)
        {
            return;
        }

        if (PreserveArtifactEnrichmentWorkflowTerminalProjection(result))
        {
            return;
        }

        if (result.Succeeded)
        {
            MarkSelectedProcessEnrichmentCapturing(process, captureModules, captureHandles);
            StatusMessage = $"Queued agent enrichment for {selected.ProcessName} (PID {selected.ProcessId}).";
            return;
        }

        if (result.Outcome == ArtifactEnrichmentWorkflowOutcome.Duplicate)
        {
            UpdateSelectedArtifactTabStatus(process, captureModules, captureHandles, queued: true);
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(result.Response, result.Detail))
        {
            return;
        }

        if (result.Outcome == ArtifactEnrichmentWorkflowOutcome.Skipped &&
            string.IsNullOrWhiteSpace(processKey))
        {
            StatusMessage = result.Detail;
        }
        else if (result.Outcome == ArtifactEnrichmentWorkflowOutcome.Failed && result.Response == null)
        {
            StatusMessage = $"Selected-process enrichment failed before queueing: {result.Detail}";
        }

        UpdateSelectedArtifactTabStatus(process, captureModules, captureHandles, queued: false);
    }

    private void MarkSelectedProcessEnrichmentCapturing(ProcessInfo process, bool captureModules, bool captureHandles)
    {
        if (captureModules)
        {
            process.ModuleCaptureStatus = ArtifactCaptureStatus.Capturing;
            process.ModuleCaptureError = string.Empty;
            ModulesViewModel.IsLoading = true;
            ModulesViewModel.HasError = false;
            ModulesViewModel.StatusMessage = $"Queued agent module enrichment for {process.ProcessName} (PID {process.ProcessId}).";
        }

        if (captureHandles)
        {
            process.HandleCaptureStatus = ArtifactCaptureStatus.Capturing;
            process.HandleCaptureError = string.Empty;
            HandlesViewModel.IsLoading = true;
            HandlesViewModel.HasError = false;
            HandlesViewModel.StatusMessage = $"Queued agent handle enrichment for {process.ProcessName} (PID {process.ProcessId}).";
        }

        RefreshSelectedProcessRow();
    }

    private void UpdateSelectedArtifactTabStatus(ProcessInfo process, bool captureModules, bool captureHandles, bool queued)
    {
        if (captureModules)
        {
            ModulesViewModel.StatusMessage = queued
                ? $"Agent module enrichment is already queued for {process.ProcessName} (PID {process.ProcessId})."
                : ModulesViewModel.StatusMessage;
        }

        if (captureHandles)
        {
            HandlesViewModel.StatusMessage = queued
                ? $"Agent handle enrichment is already queued for {process.ProcessName} (PID {process.ProcessId})."
                : HandlesViewModel.StatusMessage;
        }
    }

    [RelayCommand(CanExecute = nameof(CanRunArtifactEnrichmentFeature))]
    public async Task StopArtifactEnrichmentAsync()
    {
        if (!FeaturePublication.ModulesAndHandles && !FeaturePublication.DumpsAndPeAnalysis)
        {
            RequireFeaturePublished(FeatureIds.ModulesAndHandles, "Stop artifact enrichment");
            return;
        }

        await StopAgentEnrichmentWorkloadAsync(
            JobKind.ModuleEnrichment,
            JobKind.HandleEnrichment,
            JobKind.PeAnalysis);
    }

    private async Task StopAgentEnrichmentWorkloadAsync(params JobKind[] requestedWorkloads)
    {
        var result = await _artifactEnrichmentWorkflowCoordinator.CancelAsync(requestedWorkloads);
        if (PreserveArtifactEnrichmentWorkflowTerminalProjection(result))
        {
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response: null, result.Detail))
        {
            return;
        }

        StatusMessage = result.Detail;
    }

    private async Task<ArtifactEnrichmentWorkflowResult> QueueArtifactEnrichmentActionAsync(
        ArtifactEnrichmentQueueRequest request,
        CancellationToken cancellationToken = default)
    {
        var action = await _agentEvidenceActionService.QueueEnrichmentAsync(
            new ViewerAgentCaptureActionTarget(
                AgentsViewModel.LocalAgentId,
                Environment.MachineName,
                _sessionPaths.SessionId,
                _sessionPaths.SessionRoot,
                _captureWorkspaceCoordinator.Generation,
                request.RequireViewerConnection,
                _sessionPaths.DumpsDirectory,
                _sessionPaths.NetworkCapturesDirectory,
                _sessionPaths.ZeekDirectory,
                _sessionPaths.ProcessMonitorDirectory,
                _sessionPaths.BenchmarkDirectory),
            _artifactEnrichmentWorkflowCoordinator,
            request,
            cancellationToken: cancellationToken);
        return action.EnrichmentResult ?? new ArtifactEnrichmentWorkflowResult(
            ArtifactEnrichmentWorkflowOutcome.Failed,
            _artifactEnrichmentWorkflowCoordinator.State,
            request,
            action.Response,
            Detail: action.Diagnostic);
    }

    [RelayCommand(CanExecute = nameof(CanQueueSelectedProcessDump))]
    public async Task QueueSelectedProcessDumpAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.DumpsAndPeAnalysis, "Process dump"))
        {
            return;
        }

        if (!RequireConnectedAgent("process dump"))
        {
            return;
        }

        if (SelectedProcess == null || string.IsNullOrWhiteSpace(SelectedProcess.ProcessKey))
        {
            StatusMessage = "Select a staged process before queueing a memory dump.";
            return;
        }

        var selected = SelectedProcess;
        var exactProcessKey = selected.ProcessKey;
        var processName = selected.ProcessName;
        var processId = selected.ProcessId;
        var targetAgent = GetLocalAgent();
        if (targetAgent == null)
        {
            StatusMessage = "Process dump capture requires one exact connected local agent.";
            return;
        }

        var warning =
            $"Capture a full process dump for {processName} (PID {processId})?\n\n" +
            "The exact PID + start-time identity is already captured. The elevated agent writes a new file only inside the active session Dumps directory and never overwrites an existing dump.";
        if (MessageBox.Show(
                warning,
                "Capture Process Dump",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            StatusMessage = "Process dump capture canceled.";
            return;
        }

        var result = await _agentEvidenceActionService.QueueProcessDumpAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: true),
            new ViewerProcessDumpActionRequest(
                exactProcessKey,
                MemoryDumpKind.Full,
                Confirmed: true));
        var response = result.Response;
        if (result.Succeeded && result.AcceptedJobId.HasValue)
        {
            _activeProcessDumpJobId = result.AcceptedJobId;
            if (response != null)
            {
                UpdateAgentStatus(response, observeWorkflow: false);
            }
            TryNavigateToDataTab(DataTabKeys.MemoryDumps, "Open Memory Dumps");
            MemoryDumpsViewModel.RefreshMemoryDumps();
            StatusMessage = $"Queued full memory dump for {processName} (PID {processId}). Results appear after Refresh from db.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(response))
        {
            return;
        }

        StatusMessage = $"Process dump capture did not start: {result.Diagnostic} No viewer fallback was run.";
    }

    private bool CanQueueSelectedProcessDump()
    {
        return _featureAccess.CanExecute(FeatureIds.DumpsAndPeAnalysis, IsAgentViewerConnected &&
               SelectedProcess != null &&
               !string.IsNullOrWhiteSpace(SelectedProcess.ProcessKey));
    }

    [RelayCommand(CanExecute = nameof(CanAnalyzeSelectedProcessImage))]
    public async Task AnalyzeSelectedProcessImageAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.DumpsAndPeAnalysis, "PE analysis"))
        {
            return;
        }

        if (SelectedProcess == null)
        {
            StatusMessage = "Select a process before running PE analysis.";
            return;
        }

        var selected = SelectedProcess;
        var process = selected.ProcessInfo;
        var result = await QueueArtifactEnrichmentActionAsync(
            new ArtifactEnrichmentQueueRequest(
                ArtifactEnrichmentQueueScope.SelectedProcessPe,
                CaptureModules: false,
                CaptureHandles: false,
                CapturePe: true,
                PeStringExtractionMode: PeStringExtractionMode.Immediate,
                Action: "queue selected-process PE analysis",
                Selection: new ArtifactEnrichmentSelectionContext(
                    process.ProcessEntityId,
                    selected.ProcessKey,
                    selected.ProcessName,
                    selected.ProcessId,
                    process.Status,
                    process.ModuleCaptureStatus,
                    process.ModuleLastCaptured,
                    process.HandleCaptureStatus,
                    process.HandleLastCaptured),
                Force: true));
        if (PreserveArtifactEnrichmentWorkflowTerminalProjection(result))
        {
            return;
        }

        if (result.Succeeded)
        {
            TryNavigateToDataTab(DataTabKeys.PeAnalysis, "Open PE Analysis");
            PeAnalysisViewModel.SelectedPeSourceTabIndex = 0;
            StatusMessage = $"Queued PE metadata and string analysis for {selected.ProcessName} (PID {selected.ProcessId}). Results appear after Refresh from db.";
            return;
        }

        if (PreserveUnknownAgentCommandOutcome(result.Response, result.Detail))
        {
            return;
        }

        StatusMessage =
            $"Agent PE analysis did not start: {FirstNonEmpty(result.Response?.ErrorMessage, result.Response?.ErrorCode, result.Detail, "agent unavailable")}. " +
            "No viewer evidence fallback ran; the current snapshot was preserved.";
    }

    private bool CanAnalyzeSelectedProcessImage()
    {
        return _featureAccess.CanExecute(FeatureIds.DumpsAndPeAnalysis, SelectedProcess != null &&
               !string.IsNullOrWhiteSpace(SelectedProcess.ProcessKey) &&
               !string.IsNullOrWhiteSpace(SelectedProcess.ProcessInfo.ProcessPath));
    }

    [RelayCommand(CanExecute = nameof(CanAnalyzeSelectedDumpPe))]
    public async Task AnalyzeSelectedDumpPeAsync()
    {
        if (!RequireFeaturePublished(FeatureIds.DumpsAndPeAnalysis, "Dump PE analysis"))
        {
            return;
        }

        if (SelectedProcess == null || MemoryDumpsViewModel.SelectedMemoryDump == null)
        {
            StatusMessage = "Select a process dump before running PE analysis.";
            return;
        }

        var dump = MemoryDumpsViewModel.SelectedMemoryDump.ToRecord();
        await Task.CompletedTask;
        StatusMessage =
            $"PE analysis for dump artifact {dump.DumpId} is unavailable until an agent-owned dump-analysis command is implemented. " +
            "No viewer evidence fallback ran; the current snapshot was preserved.";
    }

    private bool CanAnalyzeSelectedDumpPe()
    {
        return _featureAccess.CanExecute(FeatureIds.DumpsAndPeAnalysis, SelectedProcess != null &&
               MemoryDumpsViewModel.SelectedMemoryDump != null &&
               !string.IsNullOrWhiteSpace(MemoryDumpsViewModel.SelectedMemoryDump.FilePath));
    }

    private async Task<bool> StopConnectedAgentAsync(
        AgentRegistryEntryViewModel? agent,
        string reason,
        bool requireViewerConnection = true,
        bool allowVerifiedProcessFallback = true)
    {
        ClearPendingAgentTermination();
        if (IsAgentLateExitObservationActive)
        {
            StatusMessage =
                "The exact agent shutdown is already in late-exit observation; duplicate shutdown and process-stop requests are disabled until that observation completes or is superseded.";
            return false;
        }

        if (IsAgentShutdownInProgress)
        {
            StatusMessage = "Agent shutdown is already in progress.";
            return false;
        }

        if (requireViewerConnection && !IsAgentViewerConnected)
        {
            StatusMessage = "Connect to an agent before trying to stop it.";
            return false;
        }

        agent ??= GetConnectedAgent();
        if (agent != null && !IsSupportedLocalAgent(agent, "stop the agent"))
        {
            return false;
        }

        IsAgentShutdownInProgress = true;
        try
        {
            AgentStatusMessage = "Agent: validating shutdown target";
            AgentJobStatusMessage = "Jobs: waiting for agent shutdown and SQLite close";
            StatusMessage = $"Requesting graceful {ProductIdentity.AgentDisplayName} shutdown through the primary control path...";

            var control = await GetLocalAgentControlCoordinator().StopAsync(
                new LocalAgentStopRequest(
                    CreateLocalAgentControlTarget(),
                    AllowVerifiedProcessFallback: allowVerifiedProcessFallback,
                    LocalAgentControlCoordinator.DefaultGracefulShutdownTimeout,
                    reason,
                    CreateVerifiedShutdownTarget()));
            if (!control.Succeeded)
            {
                var processId = control.Binding?.Health.ProcessId ?? control.Process?.ProcessId ?? 0;
                var observingLateExit = TryStartLateAgentExitObservation(agent, control);
                var identitySuperseded =
                    control.Process?.Outcome == LocalAgentProcessOutcome.VerificationRejected;
                if (identitySuperseded)
                {
                    _lastVerifiedAgentShutdownTarget = null;
                    AgentsViewModel.MarkAgentViewerDisconnected(
                        agent,
                        "The prior exact shutdown identity was replaced or reused; the old close request was invalidated.");
                    RefreshDetectedLocalAgentPresence(projectNewDetection: true);
                }
                AgentStatusMessage = processId > 0
                    ? observingLateExit
                        ? $"Agent: awaiting late exit (PID {processId})"
                        : identitySuperseded
                            ? $"Agent: shutdown identity superseded (PID {processId})"
                            : $"Agent: shutdown failed (PID {processId})"
                    : "Agent: shutdown target rejected";
                AgentJobStatusMessage = observingLateExit
                    ? "Jobs: shutdown accepted; exact process exit observation continues"
                    : control.Diagnostic;
                StatusMessage = observingLateExit
                    ? $"{ProductIdentity.AgentDisplayName} PID {processId} remained alive after the bounded late-exit grace period. The viewer will stay open and continue observing only that exact verified process; shutdown controls remain disabled until it exits or the observation times out."
                    : $"{ProductIdentity.AgentDisplayName} is still running; {ProductIdentity.DisplayName} will not close until it stops or you choose to leave it running. {control.Diagnostic}";
                return false;
            }

            CancelLateAgentExitObservation();
            MarkAgentStoppedAfterShutdown(agent, control.Diagnostic, control.Forced);
            return true;
        }
        finally
        {
            IsAgentShutdownInProgress = false;
            NotifyAgentCommandCanExecuteChanged();
        }
    }

    private bool TryStartLateAgentExitObservation(
        AgentRegistryEntryViewModel? agent,
        LocalAgentControlResult control)
    {
        var binding = control.Binding;
        var verifiedTarget = control.VerifiedShutdownTarget ??
            (binding == null
                ? null
                : new LocalAgentVerifiedShutdownTarget(
                    binding.Health.ProcessId,
                    binding.Health.StartedAtUtc,
                    binding.SessionPaths.SessionId,
                    binding.SessionPaths.LiveDatabasePath));
        if (control.Outcome != LocalAgentControlOutcome.TimedOut ||
            control.Stage != LocalAgentControlStage.LateExitObservation ||
            verifiedTarget?.ProcessId is not > 0 ||
            verifiedTarget.StartedAtUtc == default ||
            !MatchesActiveLateExitWorkspace(verifiedTarget.SessionId, verifiedTarget.DatabasePath))
        {
            return false;
        }

        CancelLateAgentExitObservation();
        _lastVerifiedAgentShutdownTarget = new AgentShutdownTarget(
            verifiedTarget.ProcessId,
            verifiedTarget.StartedAtUtc,
            verifiedTarget.DatabasePath,
            verifiedTarget.SessionId);

        var observationGeneration = ++_agentLateExitObservationGeneration;
        var workspaceGeneration = _captureWorkspaceCoordinator.Generation;
        var sessionId = verifiedTarget.SessionId;
        var databasePath = verifiedTarget.DatabasePath;
        var identity = new LocalAgentProcessIdentity(
            verifiedTarget.ProcessId,
            verifiedTarget.StartedAtUtc,
            GetCompatibleAgentExecutableCandidates().ToArray());
        var cancellation = new CancellationTokenSource();
        _agentLateExitObservationCts = cancellation;
        _agentLateExitObservationTask = ObserveLateAgentExitAsync(
            agent,
            identity,
            workspaceGeneration,
            sessionId,
            databasePath,
            observationGeneration,
            cancellation);
        NotifyAgentCommandCanExecuteChanged();
        return true;
    }

    private async Task ObserveLateAgentExitAsync(
        AgentRegistryEntryViewModel? agent,
        LocalAgentProcessIdentity identity,
        long workspaceGeneration,
        string sessionId,
        string databasePath,
        long observationGeneration,
        CancellationTokenSource cancellation)
    {
        await Task.Yield();
        try
        {
            var result = await _localAgentProcessLifecycle.WaitForExitAsync(
                identity,
                AgentLateExitContinuationTimeout,
                cancellation.Token);
            if (!IsCurrentLateAgentExitObservation(
                    identity,
                    workspaceGeneration,
                    sessionId,
                    databasePath,
                    observationGeneration,
                    cancellation.Token))
            {
                return;
            }

            if (result.IsConfirmedExactExit)
            {
                MarkAgentStoppedAfterShutdown(
                    agent,
                    $"Local agent PID {identity.ProcessId} exited after the close-time grace period; the exact late exit was reconciled without another shutdown request.");
                return;
            }

            if (result.Outcome == LocalAgentProcessOutcome.VerificationRejected)
            {
                _lastVerifiedAgentShutdownTarget = null;
                AgentsViewModel.MarkAgentViewerDisconnected(
                    agent,
                    "The prior exact shutdown identity was replaced or reused during late-exit observation.");
                RefreshDetectedLocalAgentPresence(projectNewDetection: true);
                AgentStatusMessage = "Agent: shutdown identity superseded";
                AgentJobStatusMessage = "Jobs: prior shutdown target was replaced; no replacement process was stopped";
                StatusMessage =
                    $"The process identity for shutdown PID {identity.ProcessId} changed during late-exit observation. The old close request was invalidated and did not complete or stop the replacement process. {result.Detail}";
                return;
            }

            AgentStatusMessage = $"Agent: shutdown still unconfirmed (PID {identity.ProcessId})";
            AgentJobStatusMessage = "Jobs: exact late-exit observation reached its bounded timeout";
            StatusMessage =
                $"The exact verified local agent PID {identity.ProcessId} remained alive through the five-minute continuation observation. Refresh status or retry Terminate Agent; the viewer did not broaden process matching or issue another forced stop.";
        }
        finally
        {
            if (_agentLateExitObservationGeneration == observationGeneration)
            {
                _agentLateExitObservationTask = null;
                _agentLateExitObservationCts = null;
                cancellation.Dispose();
                NotifyAgentCommandCanExecuteChanged();
            }
        }
    }

    private bool IsCurrentLateAgentExitObservation(
        LocalAgentProcessIdentity identity,
        long workspaceGeneration,
        string sessionId,
        string databasePath,
        long observationGeneration,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested ||
            _agentLateExitObservationGeneration != observationGeneration ||
            _captureWorkspaceCoordinator.Generation != workspaceGeneration ||
            !string.Equals(_sessionPaths.SessionId, sessionId, StringComparison.Ordinal) ||
            !ViewerAgentCommandPathsEqual(_sessionPaths.LiveDatabasePath, databasePath))
        {
            return false;
        }

        var cached = _lastVerifiedAgentShutdownTarget;
        return cached != null &&
               cached.ProcessId == identity.ProcessId &&
               cached.StartedAtUtc == identity.StartedAtUtc &&
               string.Equals(cached.SessionId, sessionId, StringComparison.Ordinal) &&
               ViewerAgentCommandPathsEqual(cached.DatabasePath, databasePath);
    }

    private bool MatchesActiveLateExitWorkspace(string sessionId, string databasePath) =>
        _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.LiveCapture &&
        string.Equals(sessionId, _sessionPaths.SessionId, StringComparison.Ordinal) &&
        ViewerAgentCommandPathsEqual(databasePath, _sessionPaths.LiveDatabasePath);

    private void CancelLateAgentExitObservation()
    {
        _agentLateExitObservationGeneration++;
        var cancellation = _agentLateExitObservationCts;
        _agentLateExitObservationCts = null;
        _agentLateExitObservationTask = null;
        if (cancellation == null)
        {
            return;
        }

        cancellation.Cancel();
        cancellation.Dispose();
        NotifyAgentCommandCanExecuteChanged();
    }

    private LocalAgentProcessResult VerifyLocalAgentProcess(
        AgentHealthSnapshot? health)
    {
        if (health == null)
        {
            return new LocalAgentProcessResult(
                LocalAgentProcessOutcome.VerificationRejected,
                0,
                IsRunning: false,
                IsStopped: false,
                Forced: false,
                Detail: "The agent health response did not include a process identity.");
        }

        return _localAgentProcessLifecycle.VerifyRunning(
            new LocalAgentProcessIdentity(
                health.ProcessId,
                health.StartedAtUtc,
                GetCompatibleAgentExecutableCandidates().ToArray()));
    }

    private LocalAgentRecoveryCoordinator GetLocalAgentRecoveryCoordinator()
    {
        if (_localAgentRecoveryCoordinator != null)
        {
            return _localAgentRecoveryCoordinator;
        }

        var bindingExecutor = new ViewerAgentCommandExecutor(
            new DelegateViewerAgentCommandRuntime(
                context =>
                    (IsLocalAgentRecoveryInProgress || _isLocalAgentSetupInProgress) &&
                    !IsAgentViewerConnected &&
                    context.WorkspaceGeneration == _captureWorkspaceCoordinator.Generation,
                sessionPaths => _agentRecoveryClient.BindSession(sessionPaths),
                (commandKind, cancellationToken) =>
                    _agentRecoveryClient.GetHealthExchangeAsync(commandKind, cancellationToken),
                identity => _localAgentProcessLifecycle.VerifyRunning(identity),
                LocalAgentProcessLifecycleService.IsSupportedAgentExecutablePath,
                (command, expectedEndpoint, expectedPairingGeneration, cancellationToken) =>
                    _agentRecoveryClient.SubmitCommandExchangeAsync(
                        command,
                        expectedEndpoint,
                        expectedPairingGeneration,
                        cancellationToken)));
        _localAgentRecoveryCoordinator = new LocalAgentRecoveryCoordinator(
            new DelegateLocalAgentRecoveryRuntime(
                _discoverLocalAgentPairings,
                identity => _localAgentProcessLifecycle.VerifyRunning(identity),
                (discovery, sessionId, databaseIdentity, releaseId, nowUtc) =>
                    new AgentPairingStore(
                            discovery.DirectoryPath,
                            discovery.LeasePath,
                            discovery.SecretPath)
                        .Inspect(sessionId, databaseIdentity, releaseId, nowUtc),
                (manifestPath, cancellationToken) =>
                    _captureWorkspaceCoordinator.PrepareExistingLiveCaptureAsync(
                        manifestPath,
                        cancellationToken),
                (request, cancellationToken) =>
                    bindingExecutor.ValidateBindingAsync(request, cancellationToken)));
        return _localAgentRecoveryCoordinator;
    }

    private LocalAgentControlCoordinator GetLocalAgentControlCoordinator()
    {
        if (_localAgentControlCoordinator != null)
        {
            return _localAgentControlCoordinator;
        }

        _localAgentControlCoordinator = new LocalAgentControlCoordinator(
            new DelegateLocalAgentControlRuntime(
                target =>
                    target.WorkspaceGeneration == _captureWorkspaceCoordinator.Generation &&
                    target.WorkspaceMode == _captureWorkspaceCoordinator.Mode &&
                    string.Equals(
                        target.SessionPaths.SessionId,
                        _sessionPaths.SessionId,
                        StringComparison.Ordinal) &&
                    ViewerAgentCommandPathsEqual(
                        target.SessionPaths.LiveDatabasePath,
                        _sessionPaths.LiveDatabasePath),
                () => GetLocalAgentRecoveryCoordinator().Discover(),
                (request, cancellationToken) =>
                    GetLocalAgentRecoveryCoordinator().RecoverAsync(request, cancellationToken),
                sessionPaths => AgentFeature!.BindSession(sessionPaths),
                nowUtc => _agentClient.InspectPairing(nowUtc),
                nowUtc => _agentClient.PrepareNewPairing(nowUtc),
                LocalAgentProcessLifecycleService.IsSupportedAgentExecutablePath,
                request => _localAgentProcessLifecycle.Start(request),
                identity => _localAgentProcessLifecycle.VerifyRunning(identity),
                (command, cancellationToken) =>
                    _agentClient.SubmitCommandAsync(command, cancellationToken),
                (command, cancellationToken) =>
                    _agentShutdownControlClient.SubmitCommandAsync(command, cancellationToken),
                (identity, timeout, cancellationToken) =>
                    _localAgentProcessLifecycle.WaitForExitAsync(
                        identity,
                        timeout,
                        cancellationToken),
                (identity, timeout) =>
                    _localAgentProcessLifecycle.ForceStopAsync(identity, timeout),
                cancellationToken => _agentClient.RotatePairingAsync(cancellationToken),
                cancellationToken => _agentClient.RevokePairingAsync(cancellationToken)));
        return _localAgentControlCoordinator;
    }

    private LocalAgentControlTarget CreateLocalAgentControlTarget()
    {
        var candidates = GetCompatibleAgentExecutableCandidates().ToArray();
        return new LocalAgentControlTarget(
            _sessionPaths,
            _captureWorkspaceCoordinator.Mode,
            _captureWorkspaceCoordinator.Generation,
            _featureAccess.Catalog,
            FeaturePublication.ReleaseId,
            candidates,
            ResolveAgentExecutablePath() ?? string.Empty);
    }

    private bool ProjectLocalAgentRecoveryFailure(
        LocalAgentRecoveryResult recovery,
        LocalAgentRecoveryOrigin origin)
    {
        var discovery = recovery.Discovery;
        var representative = discovery.Candidates.FirstOrDefault()?.Discovery ??
            discovery.Conflicts.FirstOrDefault(conflict => conflict.Discovery != null)?.Discovery ??
            discovery.Discoveries.FirstOrDefault();
        if (representative != null &&
            (origin == LocalAgentRecoveryOrigin.Manual || recovery.BlocksAdd ||
             representative.Lease.State is AgentPairingState.Corrupt or
                 AgentPairingState.Revoked or
                 AgentPairingState.Expired))
        {
            var lease = representative.Lease;
            var local = AgentsViewModel.AddOrUpdateLocalAgent();
            var pairing = recovery.ProtectedPairing ?? new AgentPairingStoreResult(
                recovery.Outcome is
                    LocalAgentRecoveryOutcome.UnresolvedInspection or
                    LocalAgentRecoveryOutcome.MultipleCandidates or
                    LocalAgentRecoveryOutcome.AmbiguousCandidates
                    ? AgentPairingState.ProcessMismatch
                    : lease.State,
                lease.PairingGeneration,
                lease.ExpiresAtUtc,
                recovery.Diagnostic,
                lease);
            local.ApplyPairingStatus(pairing);
        }

        StatusMessage = recovery.Outcome switch
        {
            LocalAgentRecoveryOutcome.Absent when origin == LocalAgentRecoveryOrigin.Startup =>
                string.Empty,
            LocalAgentRecoveryOutcome.Absent when representative == null =>
                "No durable local-agent lease was discovered. Use Add Agent to start and pair a new agent explicitly.",
            LocalAgentRecoveryOutcome.Absent =>
                $"No verified running local agent was found. {FormatDiscoveredPairingState(representative!.Lease)} {recovery.Diagnostic}",
            LocalAgentRecoveryOutcome.DiscoveryUnavailable =>
                $"Local-agent discovery could not be completed safely; a second launch is blocked, while Connect / Add Agent remains available for secure recovery. {recovery.Diagnostic}",
            LocalAgentRecoveryOutcome.UnresolvedInspection =>
                $"A local-agent process identity could not be inspected exactly. A second launch is blocked to avoid another writer; Connect / Add Agent and Reconnect remain secure recovery actions. {recovery.Diagnostic}",
            LocalAgentRecoveryOutcome.MultipleCandidates =>
                "Multiple verified running local agents were discovered. No candidate was selected and a second launch is blocked; Connect / Add Agent remains available to report and retry secure recovery.",
            LocalAgentRecoveryOutcome.AmbiguousCandidates =>
                "Verified and unresolved running local-agent identities were discovered together. No candidate was selected and a second launch is blocked; Connect / Add Agent remains available to report and retry secure recovery.",
            LocalAgentRecoveryOutcome.CandidateRejected when representative != null =>
                $"A verified local agent is running, but its lease or exact process identity cannot authorize this viewer. A second launch is blocked; Connect / Add Agent remains a recovery action. {recovery.Diagnostic}",
            LocalAgentRecoveryOutcome.PairingRejected =>
                $"The discovered lease did not match a usable current-user protected pairing; no health was requested when pairing validation failed and no workspace was switched. {recovery.Diagnostic}",
            LocalAgentRecoveryOutcome.WorkspaceRejected =>
                $"The paired live workspace failed manifest-first validation; the current workspace was kept. {recovery.Diagnostic}",
            LocalAgentRecoveryOutcome.WorkspacePending =>
                $"The paired live workspace is waiting for the Agent to create its evidence database; the current workspace was kept. {recovery.Diagnostic}",
            LocalAgentRecoveryOutcome.AuthenticationRejected or
                LocalAgentRecoveryOutcome.FinalValidationRejected =>
                $"Fresh authenticated local-agent recovery failed closed; no workspace was switched and no command was submitted. {recovery.Diagnostic}",
            LocalAgentRecoveryOutcome.Canceled =>
                "Local-agent recovery was canceled before viewer attachment.",
            LocalAgentRecoveryOutcome.Busy =>
                "Another local-agent recovery operation is already in progress.",
            _ => $"Local-agent recovery failed closed without starting another process: {recovery.Diagnostic}"
        };

        return origin == LocalAgentRecoveryOrigin.Manual ||
            recovery.Outcome != LocalAgentRecoveryOutcome.Absent;
    }

    private void RefreshDetectedLocalAgentPresence(bool projectNewDetection)
    {
        var wasDetected = IsLocalAgentProcessDetected;
        var discovery = GetLocalAgentRecoveryCoordinator().Discover();
        ApplyLocalAgentDiscoveryState(discovery);
        if (projectNewDetection && !wasDetected && discovery.BlocksAdd)
        {
            StatusMessage = discovery.Outcome == LocalAgentDiscoveryOutcome.DiscoveryUnavailable
                ? $"Local-agent discovery could not be completed safely; a second launch is blocked, but Connect / Add Agent remains available for secure recovery. {discovery.Diagnostic}"
                : "A running, ambiguous, or unresolved local agent was detected. Connect / Add Agent will attempt secure recovery and will not start a second process while that identity remains present.";
        }
    }

    private void ApplyLocalAgentDiscoveryState(LocalAgentDiscoveryResult discovery)
    {
        var commandStateChanged =
            _localAgentStartBlockedByDiscoveryConflict != discovery.BlocksStart;
        _localAgentStartBlockedByDiscoveryConflict = discovery.BlocksStart;
        IsLocalAgentProcessDetected = discovery.BlocksAdd;
        if (commandStateChanged)
        {
            NotifyAgentCommandCanExecuteChanged();
        }
    }

    private void ClearLocalAgentStartDiscoveryConflict()
    {
        if (!_localAgentStartBlockedByDiscoveryConflict)
        {
            return;
        }

        _localAgentStartBlockedByDiscoveryConflict = false;
        NotifyAgentCommandCanExecuteChanged();
    }

    private string FormatDiscoveredPairingState(AgentPairingLeaseMetadata lease)
    {
        return lease.State switch
        {
            AgentPairingState.Revoked => "The discovered local-agent pairing was revoked; verified agent replacement is required before re-pairing.",
            AgentPairingState.AgentExited => "The discovered paired local-agent process has exited. Use Start Agent to create a new pairing generation.",
            AgentPairingState.Expired => "The discovered local-agent lease expired. Verify or replace the agent before re-pairing.",
            AgentPairingState.Corrupt => "The discovered local-agent lease is corrupt and cannot authorize discovery or reconnect.",
            _ when lease.ExpiresAtUtc <= DateTime.UtcNow =>
                "The discovered local-agent lease expired and cannot authorize reconnect.",
            _ when lease.PairingContractVersion != AgentContracts.PairingContractVersion ||
                   lease.IpcContractVersion != AgentContracts.ContractVersion =>
                "The discovered local-agent pairing protocol is incompatible and requires verified replacement.",
            _ when !string.Equals(
                lease.ReleaseId,
                _featureAccess.Catalog.ReleaseId,
                StringComparison.Ordinal) =>
                "The discovered local agent belongs to a different DFIRoscope release.",
            _ when lease.WorkspaceMode != CaptureWorkspaceMode.LiveCapture || lease.CaptureSealed =>
                "The discovered local-agent lease does not identify an unsealed live capture workspace.",
            _ when !HasExactAgentPairingEndpointInventory(lease) =>
                "The discovered local-agent endpoint inventory is incomplete or unexpected; reconnect is blocked.",
            _ => $"The discovered local-agent pairing state is {lease.State}."
        };
    }

    private static bool HasExactAgentPairingEndpointInventory(AgentPairingLeaseMetadata lease)
    {
        var expected = AgentContracts.CompatiblePipeNames
            .Concat(AgentContracts.CompatibleShutdownControlPipeNames)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return lease.Endpoints.Count == expected.Length &&
               !lease.Endpoints.Except(expected, StringComparer.Ordinal).Any();
    }

    private static string FormatLocalAgentIdentityFailure(
        LocalAgentProcessResult result) =>
        string.IsNullOrWhiteSpace(result.Detail)
            ? $"Local-agent process verification failed with {result.Outcome}."
            : $"{result.Detail} (Outcome: {result.Outcome}.)";

    private static AgentShutdownTarget CreateAgentShutdownTarget(
        AgentHealthSnapshot health,
        string activeDatabasePath) =>
        new(
            health.ProcessId,
            health.StartedAtUtc,
            activeDatabasePath,
            health.SessionId);

    private void RememberVerifiedAgentShutdownTarget(
        AgentHealthSnapshot health,
        string activeDatabasePath)
    {
        if (health.ProcessId <= 0 || string.IsNullOrWhiteSpace(activeDatabasePath))
        {
            return;
        }

        _lastVerifiedAgentShutdownTarget = CreateAgentShutdownTarget(health, activeDatabasePath);
    }

    private bool TryGetCachedAgentShutdownTarget(out AgentShutdownTarget target)
    {
        target = default!;
        var cached = _lastVerifiedAgentShutdownTarget;
        if (cached == null ||
            cached.ProcessId <= 0 ||
            string.IsNullOrWhiteSpace(cached.DatabasePath) ||
            !TryGetActiveLiveDatabasePath(out var activeDatabasePath))
        {
            return false;
        }

        if (!string.Equals(cached.DatabasePath, activeDatabasePath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(cached.SessionId, _captureWorkspaceCoordinator.Current.SessionId, StringComparison.Ordinal))
        {
            return false;
        }

        target = cached;
        return true;
    }

    private LocalAgentVerifiedShutdownTarget? CreateVerifiedShutdownTarget()
    {
        if (!TryGetCachedAgentShutdownTarget(out var cached))
        {
            return null;
        }

        return new LocalAgentVerifiedShutdownTarget(
            cached.ProcessId,
            cached.StartedAtUtc,
            cached.SessionId,
            cached.DatabasePath);
    }

    private void MarkAgentStoppedAfterShutdown(
        AgentRegistryEntryViewModel? agent,
        string message,
        bool forced = false)
    {
        ClearPendingAgentTermination();
        _lastVerifiedAgentShutdownTarget = null;
        ClearLocalAgentStartDiscoveryConflict();
        IsLocalAgentProcessDetected = false;
        ResetTrackedAgentJobsAfterStop();
        AgentsViewModel.RemoveLocalAgentAfterConfirmedStop(message);
        if (agent != null && !IsLocalAgentControlTarget(agent))
        {
            AgentsViewModel.MarkAgentViewerDisconnected(agent, message);
        }

        AgentStatusMessage = "Agent: stopped";
        AgentJobStatusMessage = forced
            ? "Jobs: agent stopped by verified local fallback"
            : "Jobs: agent stopped gracefully";
        StatusMessage = message;

        _localAgentProcessLifecycle.CleanupExited();
    }

    private void ResetTrackedAgentJobsAfterStop()
    {
        _agentCaptureWorkflowCoordinator.Reset("Agent process is stopped.");
        _artifactEnrichmentWorkflowCoordinator.Reset("Agent process is stopped.");
        _activeImportJobId = null;
        _activeProcessDumpJobId = null;
        _activeZeekAnalysisJobId = null;
        _activeArtifactImportJobId = null;
        _activeProcessMonitorImportJobId = null;
        _activeMemoryAcquisitionJobId = null;
        _activeMemoryImageImportJobId = null;
        _activeVolatilityAnalysisJobId = null;
        _activeSqliteBenchmarkJobId = null;
        IsNetworkCaptureActive = false;
        IsProcessMonitorCaptureActive = false;
        SetLiveCaptureRunState(CaptureRunState.Off);
        SetNetworkCaptureRunState(CaptureRunState.Off);
        SetProcessMonitorCaptureRunState(CaptureRunState.Off);
    }

    private async Task<AgentIpcResponse?> SubmitAgentCommandAsync(
        AgentCommand command,
        string action,
        bool startAgentIfNeeded = true,
        bool requireViewerConnection = true,
        bool observeWorkflow = true,
        CancellationToken cancellationToken = default)
    {
        var executionContext = CreateViewerAgentCommandExecutionContext(
            command,
            requireViewerConnection);
        if (executionContext == null)
        {
            StatusMessage = $"The active capture database could not be resolved before trying to {action}.";
            return null;
        }

        var preparedRequest = new ViewerAgentCommandExecutionRequest(command, executionContext);
        var result = await _viewerAgentCommandExecutor.ExecuteAsync(
            preparedRequest,
            cancellationToken);
        result = RejectViewerAgentCommandResultIfContextChanged(
            preparedRequest,
            result);
        ObserveViewerAgentCommandPreflight(result, preparedRequest.Context);

        var canStartAgent = startAgentIfNeeded ||
            (preparedRequest.Context.Target.WorkspaceMode == CaptureWorkspaceMode.ArchivedCapture &&
             preparedRequest.Context.WriteCategory == CaptureWriteCategory.DerivedEnrichment);
        if (IsViewerAgentAvailabilityFailure(result))
        {
            if (!canStartAgent || !TryGetActiveLiveDatabasePath(out _))
            {
                HandleViewerAgentAvailabilityFailure(result);
                StatusMessage = $"Agent unavailable; {action} requires the local agent.";
                return null;
            }

            var currentPreparation = _viewerAgentCommandExecutor.Prepare(preparedRequest);
            if (!currentPreparation.IsPrepared)
            {
                return ProjectViewerAgentCommandResult(
                    currentPreparation.Failure!,
                    action,
                    observeWorkflow);
            }

            preparedRequest = currentPreparation.Request!;
            var startupAuthorizedAccess = preparedRequest.Context.Access;

            if (cancellationToken.IsCancellationRequested)
            {
                return ProjectViewerAgentCommandResult(
                    ViewerAgentCommandResult.Reject(
                        command.CommandId,
                        ViewerAgentCommandOutcome.Canceled,
                        ViewerAgentCommandErrorCodes.Canceled,
                        "Agent command execution was canceled."),
                    action,
                    observeWorkflow);
            }

            var requestedMemoryMegabytes = GetLocalAgent()?.AgentMemoryLimitMegabytes ?? 500;
            var startControl = await GetLocalAgentControlCoordinator().StartAsync(
                new LocalAgentStartRequest(
                    CreateLocalAgentControlTarget(),
                    requestedMemoryMegabytes),
                cancellationToken);
            if (!startControl.Succeeded)
            {
                StatusMessage = $"Agent unavailable; {action} requires the local agent. {startControl.Diagnostic}";
                return null;
            }

            for (var attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    result = await _viewerAgentCommandExecutor.ExecuteAsync(
                        preparedRequest,
                        cancellationToken);
                    result = RejectViewerAgentCommandResultIfContextChanged(
                        preparedRequest,
                        result);
                    break;
                }

                _agentClient.InspectPairing();
                var retryContext = CreateViewerAgentCommandExecutionContext(
                    command,
                    requireViewerConnection);
                if (retryContext == null)
                {
                    result = ViewerAgentCommandResult.Reject(
                        command.CommandId,
                        ViewerAgentCommandOutcome.InvalidContext,
                        ViewerAgentCommandErrorCodes.InvalidContext,
                        "The active capture database changed while waiting for the local agent.");
                    break;
                }

                if (!ViewerAgentCommandContextsIdentifySameWorkspace(
                        executionContext,
                        retryContext))
                {
                    result = ViewerAgentCommandResult.Reject(
                        command.CommandId,
                        ViewerAgentCommandOutcome.Superseded,
                        ViewerAgentCommandErrorCodes.WorkspaceSuperseded,
                        "The capture workspace changed while waiting for the local agent; the original command was not retargeted.");
                    break;
                }

                retryContext = retryContext with { Access = startupAuthorizedAccess };
                preparedRequest = new ViewerAgentCommandExecutionRequest(command, retryContext);
                result = await _viewerAgentCommandExecutor.ExecuteAsync(
                    preparedRequest,
                    cancellationToken);
                result = RejectViewerAgentCommandResultIfContextChanged(
                    preparedRequest,
                    result);
                ObserveViewerAgentCommandPreflight(
                    result,
                    preparedRequest.Context,
                    observeFailure: attempt == 4);
                if (!IsViewerAgentAvailabilityFailure(result))
                {
                    break;
                }
            }

            if (IsViewerAgentAvailabilityFailure(result))
            {
                HandleViewerAgentAvailabilityFailure(result);
                AgentStatusMessage = $"Agent: start timed out ({result.ErrorCode})";
                StatusMessage = $"Agent unavailable; {action} requires the local agent.";
                return null;
            }
        }

        result = RejectViewerAgentCommandResultIfContextChanged(
            preparedRequest,
            result);
        return ProjectViewerAgentCommandResult(result, action, observeWorkflow);
    }

    private ViewerAgentCommandExecutionContext? CreateViewerAgentCommandExecutionContext(
        AgentCommand command,
        bool requireViewerConnection)
    {
        var workspaceState = _captureWorkspaceCoordinator.State;
        var activeWorkspace = workspaceState.ActiveWorkspace;
        if (activeWorkspace == null)
        {
            return null;
        }

        var package = activeWorkspace.PackageInfo;
        var packageIdentity = new ViewerAgentCommandPackageIdentity(
            package?.FormatName ?? string.Empty,
            package?.SessionId ?? activeWorkspace.SessionPaths.SessionId,
            package?.SessionRoot ?? activeWorkspace.SessionPaths.SessionRoot,
            package?.LiveDatabasePath ?? activeWorkspace.SessionPaths.LiveDatabasePath,
            package?.SchemaVersion ?? 0,
            package?.EvidenceFormatVersion);
        CaptureWriteCategory writeCategory;
        try
        {
            writeCategory = CaptureWritePolicy.GetCategory(command.Kind);
        }
        catch (ArgumentOutOfRangeException)
        {
            writeCategory = CaptureWriteCategory.Unspecified;
        }

        var expectedProcessId = 0;
        var expectedProcessStartedAtUtc = default(DateTime);
        if (TryGetExpectedViewerAgentCommandProcessIdentity(
                activeWorkspace.SessionPaths.SessionId,
                activeWorkspace.SessionPaths.LiveDatabasePath,
                activeWorkspace.Mode,
                activeWorkspace.Mode == CaptureWorkspaceMode.ArchivedCapture,
                out var exactProcessId,
                out var exactStartedAtUtc))
        {
            expectedProcessId = exactProcessId;
            expectedProcessStartedAtUtc = exactStartedAtUtc;
        }

        var accessKind = ResolveViewerAgentCommandAccessKind(
            IsAgentViewerConnected,
            requireViewerConnection);
        var target = new ViewerAgentCommandTarget(
            activeWorkspace.SessionPaths.SessionId,
            activeWorkspace.SessionPaths.LiveDatabasePath,
            activeWorkspace.Mode,
            activeWorkspace.Mode == CaptureWorkspaceMode.ArchivedCapture,
            packageIdentity,
            expectedProcessId,
            expectedProcessStartedAtUtc,
            GetCompatibleAgentExecutableCandidates().ToArray());
        return new ViewerAgentCommandExecutionContext(
            activeWorkspace.SessionPaths,
            target,
            _featureAccess.Catalog,
            _featureAccess.Catalog.ReleaseId,
            new ViewerAgentCommandAccessState(accessKind, requireViewerConnection),
            writeCategory,
            workspaceState.Generation);
    }

    private static ViewerAgentCommandAccessKind ResolveViewerAgentCommandAccessKind(
        bool isViewerConnected,
        bool requireViewerConnection) =>
        isViewerConnected
            ? ViewerAgentCommandAccessKind.ViewerConnected
            : requireViewerConnection
                ? ViewerAgentCommandAccessKind.Unknown
                : ViewerAgentCommandAccessKind.VerifiedDeployedAgent;

    private bool TryGetExpectedViewerAgentCommandProcessIdentity(
        string sessionId,
        string databasePath,
        CaptureWorkspaceMode workspaceMode,
        bool captureSealed,
        out int processId,
        out DateTime startedAtUtc)
    {
        processId = 0;
        startedAtUtc = default;
        AgentShutdownTarget? cachedTarget = null;
        if (TryGetCachedAgentShutdownTarget(out var cached) &&
            string.Equals(cached.SessionId, sessionId, StringComparison.Ordinal) &&
            ViewerAgentCommandPathsEqual(cached.DatabasePath, databasePath) &&
            cached.ProcessId > 0 &&
            cached.StartedAtUtc != default &&
            cached.StartedAtUtc.Kind == DateTimeKind.Utc)
        {
            cachedTarget = cached;
        }

        var pairing = _agentClient.LastPairingStatus;
        var lease = pairing.Lease;
        var validPairingIdentity =
            pairing.State is AgentPairingState.Ready or AgentPairingState.Connected &&
            pairing.PairingGeneration > 0 &&
            pairing.ExpiresAtUtc > DateTime.UtcNow &&
            lease != null &&
            lease.State is AgentPairingState.Ready or AgentPairingState.Connected &&
            lease.PairingGeneration == pairing.PairingGeneration &&
            lease.PairingContractVersion == AgentContracts.PairingContractVersion &&
            lease.IpcContractVersion == AgentContracts.ContractVersion &&
            lease.ExpiresAtUtc > DateTime.UtcNow &&
            lease.AgentProcessId > 0 &&
            lease.AgentStartedAtUtc != default &&
            lease.AgentStartedAtUtc.Kind == DateTimeKind.Utc &&
            lease.WorkspaceMode == workspaceMode &&
            lease.CaptureSealed == captureSealed &&
            string.Equals(lease.SessionId, sessionId, StringComparison.Ordinal) &&
            ViewerAgentCommandPathsEqual(lease.DatabaseIdentity, databasePath);
        if (validPairingIdentity)
        {
            if (cachedTarget != null &&
                (cachedTarget.ProcessId != lease!.AgentProcessId ||
                 cachedTarget.StartedAtUtc != lease.AgentStartedAtUtc))
            {
                LocalAgentProcessResult cachedVerification;
                try
                {
                    cachedVerification = _localAgentProcessLifecycle.VerifyRunning(
                        new LocalAgentProcessIdentity(
                            cachedTarget.ProcessId,
                            cachedTarget.StartedAtUtc,
                            GetCompatibleAgentExecutableCandidates().ToArray()));
                }
                catch
                {
                    cachedVerification = new LocalAgentProcessResult(
                        LocalAgentProcessOutcome.InspectionFailure,
                        cachedTarget.ProcessId,
                        IsRunning: false,
                        IsStopped: false,
                        Forced: false,
                        "The cached local-agent identity could not be inspected before pairing replacement.");
                }

                if (!CanPairingIdentitySupersedeCachedProcess(
                        cachedVerification,
                        cachedTarget.ProcessId))
                {
                    processId = cachedTarget.ProcessId;
                    startedAtUtc = cachedTarget.StartedAtUtc;
                    return true;
                }

                _lastVerifiedAgentShutdownTarget = null;
            }

            processId = lease!.AgentProcessId;
            startedAtUtc = lease.AgentStartedAtUtc;
            return true;
        }

        if (cachedTarget == null)
        {
            return false;
        }

        processId = cachedTarget.ProcessId;
        startedAtUtc = cachedTarget.StartedAtUtc;
        return true;
    }

    private static bool CanPairingIdentitySupersedeCachedProcess(
        LocalAgentProcessResult verification,
        int expectedProcessId) =>
        verification != null &&
        expectedProcessId > 0 &&
        verification.ProcessId == expectedProcessId &&
        !verification.IsRunning &&
        verification.IsStopped &&
        !verification.Forced &&
        verification.Outcome is
            (LocalAgentProcessOutcome.AlreadyExited or
             LocalAgentProcessOutcome.Exited);

    private bool IsViewerAgentCommandContextCurrent(
        ViewerAgentCommandExecutionContext context)
    {
        var state = _captureWorkspaceCoordinator.State;
        var active = state.ActiveWorkspace;
        return active != null &&
               state.Phase == ViewerWorkspaceLifecyclePhase.Active &&
               state.Generation == context.WorkspaceGeneration &&
               active.Mode == context.Target.WorkspaceMode &&
               string.Equals(
                   active.SessionPaths.SessionId,
                   context.Target.SessionId,
                   StringComparison.Ordinal) &&
               ViewerAgentCommandPathsEqual(
                   active.SessionPaths.SessionRoot,
                   context.SessionPaths.SessionRoot) &&
               ViewerAgentCommandPathsEqual(
                   active.SessionPaths.LiveDatabasePath,
                   context.Target.DatabasePath);
    }

    private static bool ViewerAgentCommandContextsIdentifySameWorkspace(
        ViewerAgentCommandExecutionContext origin,
        ViewerAgentCommandExecutionContext candidate) =>
        origin.WorkspaceGeneration == candidate.WorkspaceGeneration &&
        origin.Target.WorkspaceMode == candidate.Target.WorkspaceMode &&
        string.Equals(
            origin.Target.SessionId,
            candidate.Target.SessionId,
            StringComparison.Ordinal) &&
        ViewerAgentCommandPathsEqual(
            origin.SessionPaths.SessionRoot,
            candidate.SessionPaths.SessionRoot) &&
        ViewerAgentCommandPathsEqual(
            origin.Target.DatabasePath,
            candidate.Target.DatabasePath);

    private static bool ViewerAgentCommandPathsEqual(string left, string right)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(left),
                Path.GetFullPath(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private ViewerAgentCommandResult RejectViewerAgentCommandResultIfContextChanged(
        ViewerAgentCommandExecutionRequest preparedRequest,
        ViewerAgentCommandResult result)
    {
        if (PreserveViewerAgentCommandResultAcrossContextChange(result) ||
            IsViewerAgentCommandContextCurrent(preparedRequest.Context))
        {
            return result;
        }

        return ViewerAgentCommandResult.Reject(
            result.CommandId,
            ViewerAgentCommandOutcome.Superseded,
            ViewerAgentCommandErrorCodes.WorkspaceSuperseded,
            "The command result belongs to a superseded capture workspace and was not applied to the current workspace.",
            commandSubmissionAttempted: result.CommandSubmissionAttempted,
            authenticatedEndpoint: result.AuthenticatedEndpoint,
            pairingGeneration: result.PairingGeneration,
            verifiedPairingStatus: result.VerifiedPairingStatus);
    }

    private static bool PreserveViewerAgentCommandResultAcrossContextChange(
        ViewerAgentCommandResult result) =>
        result.Outcome == ViewerAgentCommandOutcome.Superseded ||
        string.Equals(
            result.ErrorCode,
            ViewerAgentCommandErrorCodes.CommandOutcomeUnknown,
            StringComparison.Ordinal);

    private void ObserveViewerAgentCommandPreflight(
        ViewerAgentCommandResult result,
        ViewerAgentCommandExecutionContext originatingContext,
        bool observeFailure = true)
    {
        if (result.Outcome == ViewerAgentCommandOutcome.Superseded ||
            !IsViewerAgentCommandContextCurrent(originatingContext))
        {
            return;
        }

        var preflight = result.PreflightResponse;
        if (preflight == null)
        {
            return;
        }

        if (!preflight.Success)
        {
            if (observeFailure)
            {
                _agentCaptureWorkflowCoordinator.ObserveResponse(
                    CreateUnverifiedAgentFailureObservation(result));
            }

            return;
        }

        if (!result.AuthenticatedHealthVerified || preflight.Health == null)
        {
            if (observeFailure)
            {
                _agentCaptureWorkflowCoordinator.ObserveResponse(
                    CreateUnverifiedAgentFailureObservation(result));
            }

            return;
        }

        if (ShouldObserveAuthenticatedPreflightAsFailure(result))
        {
            _agentCaptureWorkflowCoordinator.ObserveResponse(
                CreateUnverifiedAgentFailureObservation(result));
            return;
        }

        _agentCaptureWorkflowCoordinator.ObserveResponse(preflight);
        if (CanProjectAuthenticatedPreflightToAgentStatus(
                originatingContext.Target,
                preflight.Health))
        {
            UpdateAgentStatus(preflight, observeWorkflow: false);
        }
    }

    private static bool CanProjectAuthenticatedPreflightToAgentStatus(
        ViewerAgentCommandTarget target,
        AgentHealthSnapshot health) =>
        target.ExpectedProcessId <= 0 ||
        health.ProcessId == target.ExpectedProcessId &&
        health.StartedAtUtc.Kind == DateTimeKind.Utc &&
        target.ExpectedProcessStartedAtUtc.Kind == DateTimeKind.Utc &&
        health.StartedAtUtc == target.ExpectedProcessStartedAtUtc;

    private static bool ShouldObserveAuthenticatedPreflightAsFailure(
        ViewerAgentCommandResult result) =>
        result.Outcome == ViewerAgentCommandOutcome.ProcessRejected;

    private static AgentIpcResponse CreateUnverifiedAgentFailureObservation(
        ViewerAgentCommandResult result)
    {
        var response = result.ToAgentIpcResponse();
        return new AgentIpcResponse
        {
            ContractVersion = response.ContractVersion,
            RequestId = response.RequestId,
            Success = false,
            ErrorCode = response.ErrorCode,
            ErrorMessage = response.ErrorMessage,
            IsRetryable = response.IsRetryable
        };
    }

    private static bool IsViewerAgentAvailabilityFailure(ViewerAgentCommandResult result) =>
        !result.CommandSubmissionAttempted &&
        result.PreflightResponse is { Success: false } &&
        result.Outcome is
            (ViewerAgentCommandOutcome.HealthUnavailable or
             ViewerAgentCommandOutcome.PairingRejected);

    private void HandleViewerAgentAvailabilityFailure(ViewerAgentCommandResult result)
    {
        HandleTransientAgentUnavailable(
            result.PreflightResponse is { Success: false } preflight
                ? preflight
                : result.ToAgentIpcResponse());
    }

    private AgentIpcResponse? ProjectViewerAgentCommandResult(
        ViewerAgentCommandResult result,
        string action,
        bool observeWorkflow)
    {
        var response = result.ToAgentIpcResponse();
        if (result.Success)
        {
            UpdateAgentStatus(response, observeWorkflow);
            return response;
        }

        if (result.CommandSubmissionAttempted &&
            result.Response == null &&
            string.Equals(
                result.ErrorCode,
                ViewerAgentCommandErrorCodes.CommandOutcomeUnknown,
                StringComparison.Ordinal))
        {
            response = response with
            {
                ErrorCode = ViewerAgentCommandErrorCodes.CommandOutcomeUnknown,
                ErrorMessage = UnknownAgentCommandOutcomeDiagnostic,
                IsRetryable = false
            };
            StatusMessage =
                $"Could not confirm whether the agent completed {action}; refresh agent status before retrying.";
            return response;
        }

        switch (result.Outcome)
        {
            case ViewerAgentCommandOutcome.AccessRejected:
                StatusMessage = $"Connect to an agent before trying to {action}.";
                return null;
            case ViewerAgentCommandOutcome.WorkspaceRejected:
                StatusMessage = result.ErrorCode == ViewerAgentCommandErrorCodes.ArchivedCaptureSealed
                    ? $"{CaptureWritePolicy.ArchivedCaptureSealedMessage} {action} is an acquisition/import action."
                    : $"No active capture workspace is available to {action}.";
                return response;
            case ViewerAgentCommandOutcome.InvalidContext:
                StatusMessage = $"The active capture database could not be resolved before trying to {action}.";
                return null;
            case ViewerAgentCommandOutcome.ReleaseRejected:
                StatusMessage = result.VerifiedHealth == null
                    ? $"Agent unavailable; {action} requires the local agent."
                    : FormatAgentReleaseProfileMismatch(result.VerifiedHealth);
                return null;
            case ViewerAgentCommandOutcome.SessionRejected:
                var mismatch = FormatAgentSessionMismatch(result.VerifiedHealth);
                if (IsAgentSessionUnverified(result.VerifiedHealth))
                {
                    MarkAgentSessionUnverified(
                        result.VerifiedHealth,
                        "Agent health is not verified for the active SQLite database; active-session commands are unavailable.");
                }
                else
                {
                    AgentsViewModel.MarkAgentViewerDisconnected(
                        GetConnectedAgent(),
                        $"Viewer disconnected because the local agent is not verified for the active session database. {mismatch}");
                    AgentStatusMessage = string.IsNullOrWhiteSpace(result.VerifiedHealth?.DatabasePath)
                        ? "Agent: session unverified"
                        : "Agent: connected to another session";
                    AgentJobStatusMessage = mismatch;
                }

                StatusMessage = $"Agent unavailable; {action} requires the local agent.";
                return null;
            case ViewerAgentCommandOutcome.ProcessRejected:
                AgentStatusMessage = "Agent: process identity rejected";
                AgentJobStatusMessage = result.Diagnostic;
                StatusMessage = $"Agent unavailable; {action} requires the local agent.";
                return null;
            case ViewerAgentCommandOutcome.ContractRejected when result.PreflightResponse != null:
                StatusMessage = $"Agent unavailable; {action} requires the local agent.";
                return null;
            case ViewerAgentCommandOutcome.Canceled:
            case ViewerAgentCommandOutcome.Superseded:
            case ViewerAgentCommandOutcome.FeatureRejected:
                StatusMessage = result.Diagnostic;
                return response;
            case ViewerAgentCommandOutcome.OperationallyUnavailable:
                StatusMessage =
                    $"Could not {action} through agent: {FormatAgentIpcFailure(response, "agent returned an error")}";
                return response;
        }

        if (IsAgentHealthUnavailableResponse(response))
        {
            if (observeWorkflow)
            {
                _agentCaptureWorkflowCoordinator.ObserveResponse(response);
            }

            HandleTransientAgentUnavailable(response);
            StatusMessage = $"Agent connection was interrupted while trying to {action}; retrying health checks.";
            return response;
        }

        UpdateAgentStatus(response, observeWorkflow);
        StatusMessage =
            $"Could not {action} through agent: {FormatAgentIpcFailure(response, "agent returned an error")}";
        return response;
    }

    private bool PreserveUnknownAgentCommandOutcome(
        AgentIpcResponse? response,
        string? nestedDiagnostic = null)
    {
        var preservesStructuredOutcome = IsPreservedAgentCommandProjectionError(
            response?.ErrorCode);
        var preservesNestedOutcome = nestedDiagnostic?.Contains(
            UnknownAgentCommandOutcomeDiagnostic,
            StringComparison.Ordinal) == true;
        if (!preservesStructuredOutcome && !preservesNestedOutcome)
        {
            return false;
        }

        StatusMessage = FirstNonEmpty(
            StatusMessage,
            response?.ErrorMessage,
            nestedDiagnostic,
            UnknownAgentCommandOutcomeDiagnostic);
        return true;
    }

    private static bool IsPreservedAgentCommandProjectionError(string? errorCode) =>
        errorCode is
            ViewerAgentCommandErrorCodes.CommandOutcomeUnknown or
            ViewerAgentCommandErrorCodes.WorkspaceSuperseded or
            ViewerAgentCommandErrorCodes.Canceled;

    private static bool ShouldShowAgentMonitoringStatusDialog(
        AgentIpcResponse? response) =>
        response?.ConfigurationCheck != null;

    private bool PreserveAgentCaptureWorkflowTerminalProjection(
        AgentCaptureWorkflowResult result)
    {
        if (!IsAgentCaptureWorkflowTerminalProjection(result.Outcome))
        {
            return false;
        }

        StatusMessage = result.Outcome == AgentCaptureWorkflowOutcome.Superseded
            ? "The agent capture command completion belonged to a superseded workspace and was not applied."
            : FirstNonEmpty(StatusMessage, "The agent capture command operation was canceled.");
        return true;
    }

    private static bool IsAgentCaptureWorkflowTerminalProjection(
        AgentCaptureWorkflowOutcome outcome) =>
        outcome is
            AgentCaptureWorkflowOutcome.Superseded or
            AgentCaptureWorkflowOutcome.Canceled;

    private bool PreserveArtifactEnrichmentWorkflowTerminalProjection(
        ArtifactEnrichmentWorkflowResult result)
    {
        if (!IsArtifactEnrichmentWorkflowTerminalProjection(result.Outcome))
        {
            return false;
        }

        StatusMessage = FirstNonEmpty(
            result.Detail,
            result.Outcome == ArtifactEnrichmentWorkflowOutcome.Superseded
                ? "The artifact enrichment completion belonged to a superseded workspace and was not applied."
                : "The artifact enrichment operation was canceled.");
        return true;
    }

    private static bool IsArtifactEnrichmentWorkflowTerminalProjection(
        ArtifactEnrichmentWorkflowOutcome outcome) =>
        outcome is
            ArtifactEnrichmentWorkflowOutcome.Superseded or
            ArtifactEnrichmentWorkflowOutcome.Canceled;

    private async Task PollAgentStatusAsync()
    {
        if (IsLocalAgentRecoveryInProgress ||
            _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.Switching)
        {
            return;
        }

        var hasAdditionalActiveJobs = _artifactEnrichmentWorkflowCoordinator.HasTrackedJobs ||
                             _activeImportJobId.HasValue ||
                            _activeProcessDumpJobId.HasValue ||
                            _activeZeekAnalysisJobId.HasValue ||
                            _activeArtifactImportJobId.HasValue ||
                            _activeProcessMonitorImportJobId.HasValue ||
                            _activeMemoryAcquisitionJobId.HasValue ||
                            _activeMemoryImageImportJobId.HasValue ||
                            _activeVolatilityAnalysisJobId.HasValue ||
                            _activeSqliteBenchmarkJobId.HasValue;
        var pollResult = await _agentCaptureWorkflowCoordinator.PollAsync(
            hasAdditionalActiveJobs,
            DateTime.UtcNow);
        if (pollResult.Outcome is AgentCaptureWorkflowOutcome.Skipped or
            AgentCaptureWorkflowOutcome.Canceled or
            AgentCaptureWorkflowOutcome.Superseded or
            AgentCaptureWorkflowOutcome.Disposed)
        {
            return;
        }

        if (pollResult.Response != null)
        {
            UpdateAgentStatus(pollResult.Response, observeWorkflow: false);
        }

        foreach (var jobResponse in pollResult.JobResponses ?? [])
        {
            UpdateAgentStatus(jobResponse, observeWorkflow: false);
            ApplyCaptureJobProgress(jobResponse.Job);
            ApplySqliteBenchmarkProgress(jobResponse.Job);
        }

        if (pollResult.Response?.Success != true ||
            pollResult.Assessment?.Accepted != true)
        {
            return;
        }

        var enrichmentPoll = await _artifactEnrichmentWorkflowCoordinator.PollAsync();
        foreach (var response in enrichmentPoll.Responses)
        {
            UpdateAgentStatus(response, observeWorkflow: false);
            ApplyCaptureJobProgress(response.Job);
        }

        foreach (var completion in enrichmentPoll.Completions)
        {
            ReportArtifactEnrichmentCompletion(completion);
        }

        if (!enrichmentPoll.CanContinue)
        {
            return;
        }

        if (!await PollJobAsync(_activeImportJobId, isLive: false) ||
            !await PollJobAsync(_activeProcessDumpJobId, isLive: false) ||
            !await PollJobAsync(_activeZeekAnalysisJobId, isLive: false) ||
            !await PollJobAsync(_activeArtifactImportJobId, isLive: false) ||
            !await PollJobAsync(_activeProcessMonitorImportJobId, isLive: false) ||
            !await PollJobAsync(_activeMemoryAcquisitionJobId, isLive: false) ||
            !await PollJobAsync(_activeMemoryImageImportJobId, isLive: false) ||
            !await PollJobAsync(_activeVolatilityAnalysisJobId, isLive: false) ||
            !await PollJobAsync(_activeSqliteBenchmarkJobId, isLive: false))
        {
            return;
        }
    }

    private async Task<bool> PollJobAsync(Guid? jobId, bool isLive)
    {
        if (!jobId.HasValue)
        {
            return true;
        }

        var workspaceGeneration = _captureWorkspaceCoordinator.Generation;
        if (_captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.Switching)
        {
            return false;
        }

        var targetAgent = GetLocalAgent();
        if (targetAgent == null)
        {
            return false;
        }

        var jobResult = await _agentCaptureActionService.GetJobStatusAsync(
            CreateAgentCaptureActionTarget(targetAgent, requireViewerConnection: false),
            jobId.Value);
        if (workspaceGeneration != _captureWorkspaceCoordinator.Generation)
        {
            return false;
        }

        var response = jobResult.Response;
        if (response == null)
        {
            StatusMessage = jobResult.Diagnostic;
            return false;
        }

        UpdateAgentStatus(response);
        if (!response.Success && IsAgentHealthUnavailableResponse(response))
        {
            return false;
        }

        ApplyCaptureJobProgress(response.Job);
        ApplySqliteBenchmarkProgress(response.Job);
        if (response.Job?.State is JobState.Completed or JobState.Cancelled or JobState.Failed)
        {
            if (_activeLiveCaptureJobId == jobId)
            {
                _activeLiveCaptureJobId = null;
                SetLiveCaptureRunState(response.Job.State == JobState.Failed
                    ? CaptureRunState.Failed
                    : CaptureRunState.Off);
            }

            if (_activeImportJobId == jobId)
            {
                _activeImportJobId = null;
            }

            if (_activeProcessDumpJobId == jobId)
            {
                _activeProcessDumpJobId = null;
            }

            if (_activeNetworkCaptureJobId == jobId)
            {
                var pendingFinalization = response.Job.State != JobState.Failed &&
                                          HasPendingNetworkCaptureFinalization(jobId.Value, response.Job.State);
                if (pendingFinalization)
                {
                    IsNetworkCaptureActive = true;
                    SetNetworkCaptureRunState(CaptureRunState.Stopping);
                }
                else
                {
                    _activeNetworkCaptureJobId = null;
                    IsNetworkCaptureActive = false;
                    SetNetworkCaptureRunState(response.Job.State == JobState.Failed
                        ? CaptureRunState.Failed
                        : CaptureRunState.Off);
                }
            }

            if (_activeZeekAnalysisJobId == jobId)
            {
                _activeZeekAnalysisJobId = null;
                NetworkCapturesViewModel.RefreshZeekArtifacts();
            }

            if (_activeArtifactImportJobId == jobId)
            {
                _activeArtifactImportJobId = null;
            }

            if (_activeProcessMonitorCaptureJobId == jobId)
            {
                _activeProcessMonitorCaptureJobId = null;
                IsProcessMonitorCaptureActive = false;
                SetProcessMonitorCaptureRunState(response.Job.State == JobState.Failed
                    ? CaptureRunState.Failed
                    : CaptureRunState.Off);
            }

            if (_activeProcessMonitorImportJobId == jobId)
            {
                _activeProcessMonitorImportJobId = null;
            }

            if (_activeMemoryAcquisitionJobId == jobId)
            {
                _activeMemoryAcquisitionJobId = null;
                MemoryInvestigationViewModel.RefreshMemoryInvestigation();
            }

            if (_activeMemoryImageImportJobId == jobId)
            {
                _activeMemoryImageImportJobId = null;
            }

            if (_activeVolatilityAnalysisJobId == jobId)
            {
                _activeVolatilityAnalysisJobId = null;
            }

            if (_activeSqliteBenchmarkJobId == jobId)
            {
                _activeSqliteBenchmarkJobId = null;
                NotifySqliteBenchmarkStateChanged();
            }

            if (!isLive && response.Job.JobKind != JobKind.SqliteBenchmark)
            {
                StatusMessage = "Live database changed. Click Refresh from db to create a new viewer snapshot.";
            }

            UpdateAgentCaptureRuntimeRows();
        }

        return true;
    }

    private void ReportArtifactEnrichmentCompletion(ArtifactEnrichmentCompletion completion)
    {
        var selection = completion.Job.Selection;
        if (selection == null)
        {
            StatusMessage = "Live database changed. Click Refresh from db to create a new viewer snapshot.";
            return;
        }

        if (SelectedProcess?.ProcessKey == selection.ProcessKey)
        {
            UpdateSelectedArtifactTabStatus(
                SelectedProcess.ProcessInfo,
                completion.Job.CaptureModules,
                completion.Job.CaptureHandles,
                queued: false);
        }
        StatusMessage =
            $"Agent enrichment {completion.TerminalState} for {selection.ProcessName} (PID {selection.ProcessId}). " +
            "The current viewer snapshot was preserved; use Refresh from db to load the committed evidence.";
    }

    private void UpdateAgentStatus(
        AgentIpcResponse response,
        bool observeWorkflow = true)
    {
        if (observeWorkflow)
        {
            _agentCaptureWorkflowCoordinator.ObserveResponse(response);
        }

        if (response.Health != null || response.PairingStatus != null || IsPairingFailureResponse(response))
        {
            ApplyPairingStatusFromResponse(response);
        }

        var hasHealthSnapshot = response.Health != null;
        var isActiveSession = !hasHealthSnapshot || IsAgentConnectedToActiveSession(response);

        if (hasHealthSnapshot || (IsAgentHealthUnavailableResponse(response) && !IsAgentViewerConnected))
        {
            AgentsViewModel.ApplyLocalHealth(response, isActiveSession);
        }

        if (!response.Success)
        {
            if (IsAgentHealthUnavailableResponse(response))
            {
                HandleTransientAgentUnavailable(response);
                return;
            }

            AgentStatusMessage = $"Agent: IPC error ({response.ErrorCode})";
            AgentJobStatusMessage = FormatAgentIpcFailure(response, "Agent IPC request failed.");
            return;
        }

        if (response.Health != null)
        {
            var releaseProfileCompatible = IsAgentReleaseProfileCompatible(response.Health);
            if (!isActiveSession)
            {
                if (IsAgentSessionUnverified(response.Health))
                {
                    MarkAgentSessionUnverified(
                        response.Health,
                        "Agent health is not verified for the active SQLite database.");
                    return;
                }

                AgentsViewModel.MarkAgentViewerDisconnected(
                    GetConnectedAgent(),
                    $"Viewer disconnected because the local agent is not verified for the active session database. {FormatAgentSessionMismatch(response.Health)}");
                AgentStatusMessage = $"Agent: different session (PID {response.Health.ProcessId})";
                AgentJobStatusMessage = releaseProfileCompatible
                    ? FormatAgentSessionMismatch(response.Health)
                    : $"{FormatAgentSessionMismatch(response.Health)} {FormatAgentReleaseProfileMismatch(response.Health)}";
                return;
            }

            var processVerification = VerifyLocalAgentProcess(response.Health);
            if (processVerification.Outcome != LocalAgentProcessOutcome.VerifiedRunning)
            {
                var identityFailure = FormatLocalAgentIdentityFailure(processVerification);
                AgentsViewModel.MarkAgentViewerDisconnected(
                    GetConnectedAgent(),
                    $"Viewer disconnected because the local-agent process identity is no longer verified. {identityFailure}");
                AgentStatusMessage = $"Agent: process identity rejected (PID {response.Health.ProcessId})";
                AgentJobStatusMessage = identityFailure;
                StatusMessage = "The reachable local agent failed exact same-user elevated process verification; active-session commands are blocked.";
                return;
            }

            ClearLocalAgentStartDiscoveryConflict();
            IsLocalAgentProcessDetected = true;

            if (IsAgentHealthForActiveSession(response.Health, out _, out var activeDatabasePath))
            {
                RememberVerifiedAgentShutdownTarget(response.Health, activeDatabasePath);
            }

            var health = response.Health.CaptureHealth;
            var runtime = response.Health.Runtime;
            var connectionLabel = IsAgentViewerConnected ? "connected" : "reachable";
            AgentStatusMessage = releaseProfileCompatible
                ? $"Agent: {connectionLabel}, PID {response.Health.ProcessId}, {health.Health.ToString().ToLowerInvariant()}"
                : $"Agent: release mismatch, PID {response.Health.ProcessId}";
            UpdateAgentBenchmarkPreflight(AgentsViewModel.SelectedAgent);
            if (!releaseProfileCompatible)
            {
                AgentsViewModel.MarkAgentViewerDisconnected(
                    GetConnectedAgent(),
                    $"Viewer disconnected because the agent release profile does not match. {FormatAgentReleaseProfileMismatch(response.Health)}");
                AgentJobStatusMessage = FormatAgentReleaseProfileMismatch(response.Health);
            }
            else if (health.Sources.Count > 0 || health.TotalEventsReceived > 0 || health.TotalProcessRecordsWritten > 0)
            {
                AgentJobStatusMessage = FormatAgentWriteSummary(health, runtime);
            }
            else if (runtime.WorkerCount > 0)
            {
                AgentJobStatusMessage = FormatAgentRuntime(runtime);
            }

            UpdateAgentCaptureRuntimeRows();
        }

        if (response.Job != null)
        {
            ApplySqliteBenchmarkProgress(response.Job);
            AgentJobStatusMessage = FormatJobProgress(response.Job);
        }

        if (response.DatabaseChanged != null)
        {
            _snapshotFollowCoordinator.ObserveCursor(response.DatabaseChanged);
            if (_snapshotFollowCoordinator.State.Mode == ViewerSnapshotFollowMode.Manual)
            {
                StatusMessage = "Live database changed. Click Refresh from db to create a new viewer snapshot.";
            }
        }
    }

    private void HandleTransientAgentUnavailable(AgentIpcResponse response)
    {
        _snapshotFollowCoordinator.SetCursorSourceAvailable(false);
        var workflow = _agentCaptureWorkflowCoordinator.State;
        var detail = FormatAgentIpcFailure(response, "agent unavailable");
        const string retryDetail = "retry scheduled by the agent workflow coordinator";
        AgentStatusMessage = $"Agent: reconnecting ({response.ErrorCode})";
        var attachmentDetail = IsAgentViewerConnected
            ? "viewer remains attached"
            : "agent command polling remains active";
        AgentJobStatusMessage = $"Temporary agent IPC loss; {attachmentDetail} and is {retryDetail} at {workflow.NextPollUtc.ToLocalTime():HH:mm:ss}. {detail}";

        var agent = GetConnectedAgent();
        if (agent != null)
        {
            agent.LastCheckUtc = DateTime.UtcNow;
            agent.LastError = detail;
            agent.HealthSummary = $"Agent reconnecting, {response.ErrorCode}";
        }
    }

    private static bool IsAgentHealthUnavailableResponse(AgentIpcResponse response)
    {
        if (response.Success)
        {
            return false;
        }

        return response.ErrorCode is
            "Timeout" or
            "PipeIoError" or
            "PipeAccessDenied" or
            "InvalidResponse" or
            "InvalidJson" or
            "EmptyResponse";
    }

    private static string FormatAgentRuntime(AgentRuntimeSnapshot runtime)
    {
        if (runtime.WorkerCount <= 0)
        {
            return "Agent runtime: not reported.";
        }

        var limits = runtime.MaxParallelVolatilityJobs > 0
            ? $"limits enrichment/import/dump/zeek/artifact/volatility={runtime.MaxParallelEnrichmentJobs}/{runtime.MaxParallelImportJobs}/{runtime.MaxParallelProcessDumpJobs}/{runtime.MaxParallelZeekJobs}/{runtime.MaxParallelArtifactImportJobs}/{runtime.MaxParallelVolatilityJobs}"
            : $"limits enrichment/import/dump/zeek/artifact={runtime.MaxParallelEnrichmentJobs}/{runtime.MaxParallelImportJobs}/{runtime.MaxParallelProcessDumpJobs}/{runtime.MaxParallelZeekJobs}/{runtime.MaxParallelArtifactImportJobs}";
        var queueSummary = runtime.RejectedJobCount > 0
            ? $"queue {runtime.QueuedJobCount}/{runtime.QueueCapacity} (peak {runtime.PeakQueuedJobCount}, rejected {runtime.RejectedJobCount})"
            : $"queue {runtime.QueuedJobCount}/{runtime.QueueCapacity} (peak {runtime.PeakQueuedJobCount})";
        var writerPressure = runtime.WriterBackpressureActive ? ", backpressure" : string.Empty;
        var writerSummary = runtime.WriterQueueCapacity > 0
            ? $", writer {runtime.WriterPendingWorkItemCount}/{runtime.WriterQueueCapacity} (peak {runtime.WriterPeakPendingWorkItemCount}, rows {runtime.WriterCompletedRowCount:N0}, failed {runtime.WriterFailedWorkItemCount}, locked {runtime.WriterBusyOrLockedFailureCount}, batch <= {runtime.WriterMaxRowsPerTransaction:N0}{writerPressure})"
            : string.Empty;
        var sqliteSummary = FormatSqliteRuntimeSummary(runtime.LiveDatabaseDiagnostics);
        var timingSummary = runtime.WriterLastTransactionMilliseconds > 0
            ? $" Last writer op {runtime.WriterLastOperation}: {FormatMilliseconds(runtime.WriterLastTransactionMilliseconds)} tx, {FormatMilliseconds(runtime.WriterLastQueueDelayMilliseconds)} queue."
            : string.Empty;
        var peSummary = FormatPeRuntimeSummary(runtime.ArtifactEnrichment);
        var summary = $"Agent runtime: workers {runtime.RunningJobCount}/{runtime.WorkerCount}, {queueSummary}, completed {runtime.CompletedJobCount}{writerSummary}, {limits}.{peSummary}{sqliteSummary}{timingSummary}";
        return string.IsNullOrWhiteSpace(runtime.LastError)
            ? summary
            : $"{summary} Last error: {runtime.LastError}";
    }

    private static string FormatAgentWriteSummary(CaptureHealthReport health, AgentRuntimeSnapshot runtime)
    {
        var totalWritten = health.TotalEventsReceived + health.TotalProcessRecordsWritten;
        var totalDropped = health.TotalEventsDropped + health.TotalProcessRecordsDropped;
        var totalQueued = health.Sources.Sum(source => Math.Max(0, source.RecordsQueued));
        var recordsPerSecond = health.Sources.Sum(source => Math.Max(0, source.RecordsPerSecond));
        var writerPressure = runtime.WriterBackpressureActive ? ", backpressure" : string.Empty;
        var liveBufferSummary = health.LiveBufferMemoryLimitBytes > 0
            ? $"; live buffer pending {health.LiveBufferPendingRecords:N0} records/{health.LiveBufferPendingBatches:N0} batches, RAM {FormatBytes(health.LiveBufferMemoryBytes)}/{FormatBytes(health.LiveBufferMemoryLimitBytes)}, disk {FormatBytes(health.LiveBufferDiskBytes)}, retries {health.LiveBufferWriteRetries:N0}"
            : string.Empty;
        var drainSummary = health.LiveBufferDrainingAfterStop
            ? "; capture stopped, SQLite still loading accepted data"
            : string.Empty;
        var writerSummary = runtime.WriterQueueCapacity > 0
            ? $"; writer queue {runtime.WriterPendingWorkItemCount:N0}/{runtime.WriterQueueCapacity:N0}, rows {runtime.WriterCompletedRowCount:N0}, locked {runtime.WriterBusyOrLockedFailureCount:N0}{writerPressure}"
            : string.Empty;
        var peSummary = FormatPeRuntimeSummary(runtime.ArtifactEnrichment);
        var sqliteSummary = FormatSqliteRuntimeSummary(runtime.LiveDatabaseDiagnostics);
        return $"Live writes: {totalWritten:N0} records, {recordsPerSecond:N1}/s, queued {totalQueued:N0}, dropped {totalDropped:N0}{liveBufferSummary}{drainSummary}{writerSummary}.{peSummary}{sqliteSummary}";
    }

    private void ApplyPairingStatusFromResponse(AgentIpcResponse response)
    {
        AgentPairingStoreResult status;
        if (response.PairingStatus != null)
        {
            status = new AgentPairingStoreResult(
                response.PairingStatus.State,
                response.PairingStatus.PairingGeneration,
                response.PairingStatus.ExpiresAtUtc,
                response.PairingStatus.Status);
        }
        else
        {
            status = _agentClient.InspectPairing();
            if (!response.Success && IsPairingFailureResponse(response))
            {
                status = status with
                {
                    State = response.ErrorCode switch
                    {
                        "PairingRevoked" => AgentPairingState.Revoked,
                        "PairingExpired" => AgentPairingState.Expired,
                        "PairingCorrupt" => AgentPairingState.Corrupt,
                        "PairingWrongUser" => AgentPairingState.WrongUser,
                        "PairingSessionMismatch" => AgentPairingState.WrongSession,
                        "PairingReleaseMismatch" => AgentPairingState.WrongRelease,
                        "PairedAgentExited" => AgentPairingState.AgentExited,
                        "PairingProcessMismatch" => AgentPairingState.ProcessMismatch,
                        _ => AgentPairingState.RePairRequired
                    },
                    Status = FirstNonEmpty(response.ErrorMessage, status.Status)
                };
            }
        }

        AgentsViewModel.ApplyLocalPairing(
            status,
            authenticated: response.Success &&
                           (response.Health != null || response.PairingStatus != null));
    }

    private static bool IsPairingFailureResponse(AgentIpcResponse response) =>
        !response.Success &&
        (response.ErrorCode.StartsWith("Pairing", StringComparison.Ordinal) ||
         response.ErrorCode.StartsWith("PairedAgent", StringComparison.Ordinal));

    private static string FormatPeRuntimeSummary(AgentArtifactEnrichmentSnapshot enrichment)
    {
        if (enrichment.PeActiveCount > 0)
        {
            return $" PE active {enrichment.PeActiveCount:N0}, completed {enrichment.PeCompletedCount:N0}/{enrichment.PeAttemptCount:N0}, written {enrichment.PeRecordCount:N0}.";
        }

        if (enrichment.PeAttemptCount > 0 || enrichment.PeFreshnessSkipCount > 0)
        {
            return $" PE completed {enrichment.PeCompletedCount:N0}, written {enrichment.PeRecordCount:N0}, skipped {enrichment.PeFreshnessSkipCount:N0}, reused {enrichment.PeReuseCount:N0}, failed {enrichment.PeFailureCount:N0}.";
        }

        return string.Empty;
    }

    private static string FormatSqliteRuntimeSummary(AgentSqliteDatabaseDiagnostics? diagnostics)
    {
        if (diagnostics == null)
        {
            return string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(diagnostics.Error))
        {
            return $" SQLite diagnostics unavailable: {diagnostics.Error}.";
        }

        var checkpoint = diagnostics.LastCheckpoint == null
            ? string.Empty
            : diagnostics.LastCheckpoint.Succeeded
                ? $", checkpoint log {diagnostics.LastCheckpoint.LogFrameCount:N0}/{diagnostics.LastCheckpoint.CheckpointedFrameCount:N0}"
                : $", checkpoint error {diagnostics.LastCheckpoint.Error}";
        return $" SQLite {diagnostics.JournalMode}/{diagnostics.SynchronousMode}, wal_autocheckpoint {diagnostics.WalAutoCheckpointPages:N0}, WAL {FormatBytes(diagnostics.WalSizeBytes)}{checkpoint}, log {diagnostics.DiagnosticsLogPath}.";
    }

    private static string FormatMilliseconds(double milliseconds)
    {
        return milliseconds < 1
            ? "<1 ms"
            : $"{milliseconds:N1} ms";
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        var value = (double)Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:N1} {units[unit]}";
    }

    private AgentRegistryEntryViewModel? GetConnectedAgent()
    {
        if (!_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
        {
            return null;
        }

        return agentFeature.AgentsViewModel.Agents.FirstOrDefault(agent =>
            agent.IsViewerConnected ||
            (!string.IsNullOrWhiteSpace(_agentCaptureWorkflowCoordinator.State.ConnectedAgentId) &&
             string.Equals(
                 agent.AgentId,
                 _agentCaptureWorkflowCoordinator.State.ConnectedAgentId,
                 StringComparison.Ordinal)));
    }

    private AgentCaptureHealthAssessment AssessAgentCaptureHealth(AgentHealthSnapshot? health)
    {
        var expectedSession = IsAgentHealthForActiveSession(health, out _, out _);
        var releaseCompatible = IsAgentReleaseProfileCompatible(health);
        var processVerification = expectedSession && releaseCompatible
            ? VerifyLocalAgentProcess(health)
            : null;
        var processIdentityVerified =
            processVerification?.Outcome == LocalAgentProcessOutcome.VerifiedRunning;
        var error = !expectedSession
            ? FormatAgentSessionMismatch(health)
            : !releaseCompatible
                ? FormatAgentReleaseProfileMismatch(health)
                : !processIdentityVerified
                    ? FormatLocalAgentIdentityFailure(processVerification!)
                    : string.Empty;
        return new AgentCaptureHealthAssessment(
            expectedSession,
            releaseCompatible,
            error,
            processIdentityVerified);
    }

    private bool IsAgentConnectedToActiveSession(AgentIpcResponse response)
    {
        return IsAgentHealthForActiveSession(response.Health, out _, out _);
    }

    private bool IsAgentHealthForActiveSession(
        AgentHealthSnapshot? health,
        out string agentDatabasePath,
        out string activeDatabasePath)
    {
        agentDatabasePath = string.Empty;
        activeDatabasePath = string.Empty;
        if (health == null || string.IsNullOrWhiteSpace(health.DatabasePath))
        {
            return false;
        }

        if (!TryGetActiveLiveDatabasePath(out activeDatabasePath))
        {
            return false;
        }

        agentDatabasePath = health.DatabasePath;
        try
        {
            agentDatabasePath = Path.GetFullPath(health.DatabasePath);
            var expectedSealed = _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.ArchivedCapture;
            var requiredCompatibilityCapability = expectedSealed
                ? CaptureOpenCapability.MaintainAnalysisState
                : CaptureOpenCapability.WritePrimaryEvidence;
            var compatibility = health.CaptureCompatibility ??
                SqliteStagingStore.AssessExistingDatabase(
                    activeDatabasePath,
                    expectedSealed
                        ? CaptureOpenContext.ArchivedAnalysisMaintenance
                        : CaptureOpenContext.AgentWritableLive,
                    _activeCapturePackageInfo?.CompatibilityMetadata,
                    _captureWorkspaceCoordinator.Current.SessionId);
            return string.Equals(agentDatabasePath, activeDatabasePath, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(health.SessionId, _captureWorkspaceCoordinator.Current.SessionId, StringComparison.Ordinal) &&
                   health.CaptureSealed == expectedSealed &&
                   health.WorkspaceMode == _captureWorkspaceCoordinator.Mode &&
                   compatibility.Allows(requiredCompatibilityCapability);
        }
        catch
        {
            return false;
        }
    }

    private bool TryGetActiveLiveDatabasePath(out string databasePath)
    {
        databasePath = FirstNonEmpty(
            _sessionPaths.LiveDatabasePath,
            LiveDatabasePath);
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            return false;
        }

        try
        {
            databasePath = Path.GetFullPath(databasePath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void ApplyAgentCaptureControlProjection(
        AgentCaptureControlViewState projection,
        AgentRegistryEntryViewModel? agent = null)
    {
        if (agent == null &&
            _featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
        {
            agent = agentFeature.AgentsViewModel.Agents.FirstOrDefault(candidate =>
                IsLocalAgentControlTarget(candidate));
        }

        agent?.ApplyControlProjection(projection);
        OnPropertyChanged(nameof(LiveCaptureStateDisplay));
        OnPropertyChanged(nameof(NetworkCaptureStateDisplay));
        OnPropertyChanged(nameof(ProcessMonitorCaptureStateDisplay));
        NotifyAgentCommandCanExecuteChanged();
        UpdateAgentCaptureRuntimeRows();
    }

    private bool IsAgentReleaseProfileCompatible(AgentHealthSnapshot? health)
    {
        if (health == null ||
            string.IsNullOrWhiteSpace(health.ReleaseProfile.ReleaseId))
        {
            return false;
        }

        return health.ReleaseProfile.Match == AgentReleaseProfileMatch.Match &&
               string.Equals(
                   health.ReleaseProfile.ReleaseId,
                   _featureAccess.Catalog.ReleaseId,
                   StringComparison.Ordinal);
    }

    private string FormatAgentReleaseProfileMismatch(AgentHealthSnapshot? health)
    {
        var agentRelease = string.IsNullOrWhiteSpace(health?.ReleaseProfile.ReleaseId)
            ? "<not reported>"
            : health.ReleaseProfile.ReleaseId;
        return
            $"Viewer release '{_featureAccess.Catalog.ReleaseId}' does not match agent release '{agentRelease}'. " +
            "Feature-specific agent commands are unavailable until viewer and agent profiles match.";
    }

    private bool IsAgentSessionUnverified(AgentHealthSnapshot? health)
    {
        return health == null ||
               string.IsNullOrWhiteSpace(health.DatabasePath) ||
               !TryGetActiveLiveDatabasePath(out _);
    }

    private void MarkAgentSessionUnverified(AgentHealthSnapshot? health, string statusMessage)
    {
        var mismatch = FormatAgentSessionMismatch(health);
        AgentStatusMessage = health == null
            ? "Agent: session unverified"
            : $"Agent: session unverified (PID {health.ProcessId})";
        AgentJobStatusMessage = mismatch;
        StatusMessage = statusMessage;

        var agent = GetConnectedAgent();
        if (agent != null)
        {
            agent.LastCheckUtc = DateTime.UtcNow;
            agent.LastError = mismatch;
            agent.HealthSummary = health == null
                ? "Agent session unverified"
                : $"Agent session unverified, PID {health.ProcessId}";
        }
    }

    private string FormatAgentSessionMismatch(AgentHealthSnapshot? health)
    {
        var agentDatabasePath = string.IsNullOrWhiteSpace(health?.DatabasePath)
            ? "<not reported>"
            : health.DatabasePath;
        var activeDatabasePath = TryGetActiveLiveDatabasePath(out var activePath)
            ? activePath
            : "<active live DB unavailable>";
        var compatibility = health?.CaptureCompatibility == null
            ? "capture compatibility was not reported"
            : $"capture compatibility is {health.CaptureCompatibility.StatusCode}: {health.CaptureCompatibility.Message}";
        return $"Agent database or compatibility does not match the active session. Agent DB: {agentDatabasePath}; " +
               $"active live DB: {activeDatabasePath}; {compatibility}.";
    }

    private static string FormatAgentIpcFailure(AgentIpcResponse response, string fallback)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(response.ErrorCode))
        {
            parts.Add(response.ErrorCode);
        }

        if (!string.IsNullOrWhiteSpace(response.ErrorMessage))
        {
            parts.Add(response.ErrorMessage);
        }

        if (response.RequestId != Guid.Empty)
        {
            parts.Add($"request {response.RequestId}");
        }

        return parts.Count == 0 ? fallback : string.Join(": ", parts);
    }

    private static string FormatJobProgress(JobProgress job)
    {
        if (job.JobKind == JobKind.SqliteBenchmark && job.SqliteBenchmark != null)
        {
            var benchmark = job.SqliteBenchmark;
            var benchmarkDetail = FirstNonEmpty(job.ProgressMessage, benchmark.ThresholdReason);
            return
                $"Jobs: SQLite benchmark {job.State} ({benchmark.CommittedRecords:N0} records, " +
                $"{benchmark.CommittedRecordsPerSecond:N1}/s committed, queue {benchmark.WriterQueueDepth}/{benchmark.WriterQueueCapacity}) {benchmarkDetail}".TrimEnd();
        }

        var total = job.TotalCount >= 0 ? job.TotalCount.ToString() : "?";
        var detail = string.IsNullOrWhiteSpace(job.ErrorText)
            ? job.ProgressMessage
            : $"{job.ProgressMessage} {job.ErrorText}";
        return $"Jobs: {job.JobKind} {job.State} ({job.ProcessedCount}/{total}) {detail}".TrimEnd();
    }

    private List<string> GetTrackedActiveAgentJobs()
    {
        var jobs = new List<string>();
        Add(_activeLiveCaptureJobId, "live capture");
        jobs.AddRange(_artifactEnrichmentWorkflowCoordinator.DescribeTrackedJobs());

        Add(_activeImportJobId, "import");
        Add(_activeProcessDumpJobId, "process dump");
        Add(_activeNetworkCaptureJobId, "network capture");
        Add(_activeZeekAnalysisJobId, "Zeek analysis");
        Add(_activeArtifactImportJobId, "artifact import");
        Add(_activeProcessMonitorCaptureJobId, "Process Monitor capture");
        Add(_activeProcessMonitorImportJobId, "Process Monitor import");
        Add(_activeSqliteBenchmarkJobId, "SQLite benchmark");
        return jobs;

        void Add(Guid? jobId, string label)
        {
            if (jobId.HasValue)
            {
                jobs.Add($"{label} ({jobId.Value})");
            }
        }
    }

    private string? ResolveAgentExecutablePath()
    {
        foreach (var path in GetAgentLaunchExecutableCandidates())
        {
            if (File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }

    private static IEnumerable<string> GetAgentLaunchExecutableCandidates()
    {
        var configurationName = GetCurrentBuildConfigurationName();
        return ExecutableIdentity.BuildAgentLaunchExecutableCandidates(
            AppContext.BaseDirectory,
            Environment.CurrentDirectory,
            configurationName);
    }

    private static IEnumerable<string> GetCompatibleAgentExecutableCandidates()
    {
        var configurationName = GetCurrentBuildConfigurationName();
        return ExecutableIdentity.BuildCompatibleAgentExecutableCandidates(
            AppContext.BaseDirectory,
            Environment.CurrentDirectory,
            configurationName);
    }

    private static string GetCurrentBuildConfigurationName()
    {
        try
        {
            var targetFrameworkDirectory = Directory.GetParent(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            var configurationDirectory = targetFrameworkDirectory?.Parent;
            var configurationName = configurationDirectory?.Name;
            if (!string.IsNullOrWhiteSpace(configurationName) &&
                (string.Equals(configurationName, "Debug", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(configurationName, "Release", StringComparison.OrdinalIgnoreCase)))
            {
                return configurationName;
            }
        }
        catch
        {
        }

#if DEBUG
        return "Debug";
#else
        return "Release";
#endif
    }

    [RelayCommand]
    public async Task ExportLegacyStagedArchiveAsync()
    {
        await Task.CompletedTask;
        StatusMessage =
            "Legacy .pistage export is retired from the production viewer. Use the session capture folder as the preservation format.";
    }

    [RelayCommand]
    public async Task ImportLegacyStagedArchiveAsync()
    {
        if (IsRefreshing)
        {
            StatusMessage = $"Another {ProductIdentity.DisplayName} operation is already in progress.";
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Import Legacy Staged Archive",
            DefaultExt = ".pistage",
            Filter = "Legacy ProcInsider staged archive (*.pistage)|*.pistage|ZIP archive (*.zip)|*.zip|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog() != true)
        {
            StatusMessage = "Legacy staged archive import canceled.";
            return;
        }

        var archivePath = dialog.FileName;
        const string warning =
            "Import a legacy staged archive from the selected file?\n\n" +
            "Session folders are the normal preservation and reopen workflow. This compatibility path replaces ProcInsider's current staging data from a legacy archive. It does not clear Windows Event Logs, Sysmon, ETW providers, transcripts, or system audit policy.";

        if (MessageBox.Show(warning, "Import Legacy Staged Archive", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            StatusMessage = "Legacy staged archive import canceled.";
            return;
        }

        IsRefreshing = true;
        StatusMessage = "Importing legacy staged archive...";
        try
        {
            if (_captureWorkspaceCoordinator.Mode != CaptureWorkspaceMode.LiveCapture ||
                !File.Exists(_sessionPaths.LiveDatabasePath))
            {
                StatusMessage = "Legacy archive import requires an active live session and the agent; no viewer fallback ran.";
                return;
            }

            var agentResponse = await SubmitAgentCommandAsync(
                new QueueImportCommand { ArchivePath = archivePath },
                "queue staged telemetry import");
            if (agentResponse?.Success == true)
            {
                _activeImportJobId = agentResponse.AcceptedJobId;
                StatusMessage = $"Queued explicit legacy .pistage import in the agent: {archivePath}";
                return;
            }

            if (PreserveUnknownAgentCommandOutcome(agentResponse))
            {
                return;
            }

            StatusMessage =
                "Legacy live SQLite archive import requires the agent; no viewer fallback wrote evidence or replaced the current snapshot.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to import legacy staged archive: {ex.Message}";
        }
        finally
        {
            IsRefreshing = false;
        }
    }

    /// <summary>
    /// Sorts the currently visible process rows by a row view-model property.
    /// </summary>
    public void SortVisibleProcessRows(string columnName)
    {
        MarkSnapshotPresentationInteraction();
        if (_currentSortColumn == columnName)
        {
            _sortAscending = !_sortAscending;
        }
        else
        {
            _currentSortColumn = columnName;
            _sortAscending = true;
        }

        if (_processListingService != null)
        {
            // DB path: sort is pushed into the next SQLite query.
            ScheduleDbRefresh();
            return;
        }

        ProcessesView?.SortDescriptions.Clear();
        ProcessesView?.SortDescriptions.Add(new SortDescription(
            columnName,
            _sortAscending ? ListSortDirection.Ascending : ListSortDirection.Descending));
        ProcessesView?.Refresh();
    }

    /// <summary>
    /// Gets the current sort direction for a column (for UI indicators).
    /// </summary>
    public ListSortDirection? GetSortDirection(string columnName)
    {
        if (_currentSortColumn != columnName)
            return null;
        return _sortAscending ? ListSortDirection.Ascending : ListSortDirection.Descending;
    }

    // Partial methods for filter property changes
    // DB path: route through ScheduleDbRefresh (debounced, SQLite-backed).
    // Fallback path: ProcessesView.Refresh() applies the in-memory FilterProcess predicate.
    partial void OnFilterProcessNameChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterPidChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterParentPidChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterParentProcessNameChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterProcessPathChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterCommandLineChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterUserNameChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterSessionIdChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterArchitectureChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterStartTimeChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterEndTimeChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterStatusChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterCpuUsageChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterMemoryUsageChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterCompanyNameChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterFileDescriptionChanged(string value) => ScheduleDbRefresh();
    partial void OnFilterSha256HashChanged(string value) => ScheduleDbRefresh();

    partial void OnIsAgentViewerConnectedChanged(bool value)
    {
        NotifyAgentCommandCanExecuteChanged();
    }

    partial void OnIsAgentShutdownInProgressChanged(bool value) => NotifyAgentCommandCanExecuteChanged();

    partial void OnIsLocalAgentProcessDetectedChanged(bool value) => NotifyAgentCommandCanExecuteChanged();

    partial void OnIsLocalAgentRecoveryInProgressChanged(bool value) => NotifyAgentCommandCanExecuteChanged();

    partial void OnIsNetworkCaptureActiveChanged(bool value)
    {
        StartNetworkCaptureCommand.NotifyCanExecuteChanged();
        StopNetworkCaptureCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsProcessMonitorCaptureActiveChanged(bool value)
    {
        StartProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        StopProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        QueueProcessMonitorImportCommand.NotifyCanExecuteChanged();
    }

    private void NotifyCaptureAvailabilityCommandCanExecuteChanged()
    {
        RefreshViewFromStagingCommand.NotifyCanExecuteChanged();
        OpenSessionFolderCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsRefreshingChanged(bool value)
    {
        OpenCaptureCommand.NotifyCanExecuteChanged();
        LoadSavedSessionCommand.NotifyCanExecuteChanged();
        RefreshViewFromStagingCommand.NotifyCanExecuteChanged();
    }

    partial void OnRefreshIntervalSecondsChanged(int value)
    {
        var clamped = Math.Clamp(value, 1, 3600);
        if (clamped != value)
        {
            RefreshIntervalSeconds = clamped;
            return;
        }

    }

    /// <summary>
    /// Handles selection change - updates detail tabs.
    /// </summary>
    partial void OnSelectedProcessChanged(ProcessRowViewModel? oldValue, ProcessRowViewModel? newValue)
    {
        MarkSnapshotPresentationInteraction();
        _virtualizedProcessListing?.PreserveSelection(newValue);
        var fanOut = _selectedProcessFanOutCoordinator.SelectAsync(
            newValue,
            _captureWorkspaceCoordinator.Generation);
        if (!fanOut.IsCompletedSuccessfully)
        {
            _ = ObserveSelectedProcessFanOutAsync(fanOut);
        }

        UpdateSelectedProcessBookmarkState();
        IncludeSelectedProcessCommand.NotifyCanExecuteChanged();
        ExcludeSelectedProcessCommand.NotifyCanExecuteChanged();
        QueueSelectedProcessDumpCommand.NotifyCanExecuteChanged();
        AnalyzeSelectedProcessImageCommand.NotifyCanExecuteChanged();
        AnalyzeSelectedDumpPeCommand.NotifyCanExecuteChanged();
        if (newValue != null)
        {
            QueueSelectedDataTabEnrichmentIfNeeded();
        }

        RefreshDataTabCounts();
    }

    private async Task ObserveSelectedProcessFanOutAsync(
        Task<SelectedProcessFanOutResult> fanOut)
    {
        try
        {
            await fanOut;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Selected-process detail fan-out failed unexpectedly: {ex.Message}";
        }
    }

    private void OnSelectedProcessFanOutStateChanged(
        object? sender,
        SelectedProcessFanOutStateChangedEventArgs e)
    {
        if (e.State.LastOutcome == SelectedProcessFanOutOutcome.PartialFailure &&
            !string.IsNullOrWhiteSpace(e.State.LastError))
        {
            StatusMessage = $"Selected-process details loaded with partial failures: {e.State.LastError}";
        }

        if (e.State.Phase is SelectedProcessFanOutPhase.Active or SelectedProcessFanOutPhase.Empty)
        {
            RefreshDataTabCounts();
        }
    }

    private void OnFeatureModuleActivated(object? sender, FeatureActivatedEventArgs e)
    {
        var lateBinding = _selectedProcessFanOutCoordinator.BindActivatedConsumersAsync(e.FeatureId);
        if (!lateBinding.IsCompletedSuccessfully)
        {
            _ = ObserveSelectedProcessFanOutAsync(lateBinding);
        }
    }

    IReadOnlyList<ISelectedProcessFanOutConsumer>
        ISelectedProcessFanOutConsumerProvider.GetCoreConsumers()
    {
        var consumers = new List<ISelectedProcessFanOutConsumer>
        {
            CreateSelectedProcessConsumer(
                "process-properties",
                (context, cancellationToken) =>
                {
                    var provenance = context == null || _sqliteStagingQueryService == null
                        ? null
                        : _sqliteStagingQueryService.GetProcessProjectionProvenance(
                            context.ProcessEntityId);
                    cancellationToken.ThrowIfCancellationRequested();
                    ProcessPropertiesViewModel.LoadProcess(context?.Row, provenance);
                }),
            CreateSelectedProcessConsumer(
                "process-statistics",
                (context, _) => ProcessStatisticsViewModel.SetSelectedProcess(context?.Row)),
            CreateSelectedProcessConsumer(
                "application-info",
                (context, cancellationToken) =>
                    ProcessDescriptionViewModel.LoadForProcessSelectionAsync(
                        context?.Row,
                        cancellationToken)),
            CreateSelectedProcessConsumer(
                "process-notes",
                (context, cancellationToken) =>
                    NotesViewModel.LoadNotesForSelectionAsync(
                        context == null ? null : CreateProcessAnnotationTarget(context.Row),
                        cancellationToken)),
            CreateSelectedProcessConsumer(
                "details-object-inspector-clear",
                (_, _) => InspectorPaneViewModel.Clear(
                    "Select a row in Data to inspect its additional properties."))
        };

        var riskDetails = ProcessRiskDetailsViewModel;
        if (riskDetails != null)
        {
            consumers.Add(CreateSelectedProcessConsumer(
                "process-risk-details",
                (context, cancellationToken) =>
                    riskDetails.LoadAsync(
                        _sqliteStagingQueryService?.ProcessRiskProjectionQueries,
                        context?.ProcessEntityId ?? string.Empty,
                        context?.ProcessKey ?? string.Empty,
                        context == null
                            ? string.Empty
                            : $"{context.ProcessName} (PID {context.ProcessId})",
                        cancellationToken)));
        }

        return consumers;
    }

    IReadOnlyList<ISelectedProcessFanOutConsumer>
        ISelectedProcessFanOutConsumerProvider.GetActivatedOptionalConsumers() =>
        GetActivatedSelectedProcessConsumers(featureId: null);

    IReadOnlyList<ISelectedProcessFanOutConsumer>
        ISelectedProcessFanOutConsumerProvider.GetActivatedOptionalConsumers(
            FeatureId featureId) =>
        GetActivatedSelectedProcessConsumers(featureId);

    private IReadOnlyList<ISelectedProcessFanOutConsumer> GetActivatedSelectedProcessConsumers(
        FeatureId? featureId)
    {
        var consumers = new List<ISelectedProcessFanOutConsumer>();
        if ((!featureId.HasValue || featureId.Value == FeatureIds.ModulesAndHandles) &&
            _featureModules.TryGetActivated<ModulesAndHandlesFeatureModule>(
                FeatureIds.ModulesAndHandles,
                out var artifacts))
        {
            consumers.Add(CreateSelectedProcessConsumer(
                "modules",
                async (context, cancellationToken) =>
                {
                    if (context == null)
                    {
                        artifacts.ModulesViewModel.Clear();
                        return;
                    }

                    await artifacts.ModulesViewModel.LoadModulesForProcessAsync(context.Row.ProcessInfo);
                    cancellationToken.ThrowIfCancellationRequested();
                }));
            consumers.Add(CreateSelectedProcessConsumer(
                "handles",
                async (context, cancellationToken) =>
                {
                    if (context == null)
                    {
                        artifacts.HandlesViewModel.Clear();
                        return;
                    }

                    await artifacts.HandlesViewModel.LoadHandlesForProcessAsync(context.Row.ProcessInfo);
                    cancellationToken.ThrowIfCancellationRequested();
                }));
        }

        if ((!featureId.HasValue || featureId.Value == FeatureIds.DumpsAndPeAnalysis) &&
            _featureModules.TryGetActivated<DumpsAndPeFeatureModule>(
                FeatureIds.DumpsAndPeAnalysis,
                out var dumpsAndPe))
        {
            consumers.Add(CreateSelectedProcessConsumer(
                "memory-dumps",
                (context, _) =>
                {
                    if (context == null)
                    {
                        dumpsAndPe.MemoryDumpsViewModel.Clear();
                        return;
                    }

                    dumpsAndPe.MemoryDumpsViewModel.SetSelectedProcessEntityId(context.ProcessEntityId);
                    dumpsAndPe.MemoryDumpsViewModel.LoadMemoryDumpsForProcess(
                        (context.ProcessKey, context.ProcessId, context.ProcessName));
                }));
            consumers.Add(CreateSelectedProcessConsumer(
                "pe-analysis",
                (context, _) =>
                {
                    if (context == null)
                    {
                        dumpsAndPe.PeAnalysisViewModel.Clear();
                        return;
                    }

                    dumpsAndPe.PeAnalysisViewModel.SetSelectedProcessEntityId(context.ProcessEntityId);
                    dumpsAndPe.PeAnalysisViewModel.LoadPeAnalysesForProcess(
                        (context.ProcessKey, context.ProcessId, context.ProcessName));
                }));
        }

        if ((!featureId.HasValue || featureId.Value == FeatureIds.AiAssistance) &&
            _featureModules.TryGetActivated<AiFeatureModule>(
                FeatureIds.AiAssistance,
                out var ai))
        {
            consumers.Add(CreateSelectedProcessConsumer(
                "ai-details-context",
                (context, _) => ai.DetailsViewModel.SetSelectedProcessContext(context?.Row)));
            consumers.Add(CreateSelectedProcessConsumer(
                "ai-investigation",
                (context, cancellationToken) =>
                    ai.InvestigationViewModel.LoadForProcessSelectionAsync(
                        context?.Row,
                        cancellationToken)));
        }

        if ((!featureId.HasValue || featureId.Value == FeatureIds.EventTelemetry) &&
            _featureModules.TryGetActivated<EventTelemetryFeatureModule>(
                FeatureIds.EventTelemetry,
                out var events))
        {
            AddSelectedProcessEventConsumer(consumers, "runtime-events", events.RuntimeEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "etw-events", events.EtwEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "security-events", events.SecurityEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "powershell-events", events.PowerShellEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "windows-other-events", events.OtherWindowsEventsViewModel);
            AddSelectedProcessEventConsumer(consumers, "sysmon-events", events.SysmonEventsViewModel);
        }

        AddCompiledPrivateSelectedProcessConsumers(featureId, consumers);

        return consumers;
    }

    partial void AddCompiledPrivateViewerFeatureDefinitions(
        List<IViewerFeatureDefinition> definitions,
        List<FeatureId> requiredFeatureIds);

    partial void AddCompiledPrivateSelectedProcessConsumers(
        FeatureId? featureId,
        List<ISelectedProcessFanOutConsumer> consumers);

    partial void DetachCompiledPrivateFeatureWorkspace();

    partial void BindCompiledPrivateFeatureWorkspace(
        InvestigationSessionPaths sessionPaths,
        AnnotationDatabaseService annotationStore,
        string? directArchivedDatabasePath);

    private static void AddSelectedProcessEventConsumer(
        ICollection<ISelectedProcessFanOutConsumer> consumers,
        string key,
        EventsViewModel viewModel)
    {
        consumers.Add(CreateSelectedProcessConsumer(
            key,
            (context, _) =>
            {
                if (context == null)
                {
                    viewModel.Clear();
                    return;
                }

                viewModel.SetSelectedProcessEntityId(context.ProcessEntityId);
                viewModel.LoadEventsForProcess(
                    (context.ProcessKey, context.ProcessId, context.ProcessName));
            }));
    }

    private static ISelectedProcessFanOutConsumer CreateSelectedProcessConsumer(
        string key,
        Action<SelectedProcessContext?, CancellationToken> apply) =>
        new DelegateSelectedProcessFanOutConsumer(
            key,
            (context, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                apply(context, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                return Task.FromResult(SelectedProcessConsumerResult.Success);
            });

    private static ISelectedProcessFanOutConsumer CreateSelectedProcessConsumer(
        string key,
        Func<SelectedProcessContext?, CancellationToken, Task> apply) =>
        new DelegateSelectedProcessFanOutConsumer(
            key,
            async (context, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                await apply(context, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                return SelectedProcessConsumerResult.Success;
            });

    private void NotifyAgentCommandCanExecuteChanged()
    {
        AddAgentCommand.NotifyCanExecuteChanged();
        ReconnectRunningLocalAgentCommand.NotifyCanExecuteChanged();
        DeployAgentCommand.NotifyCanExecuteChanged();
        RefreshAgentRegistryHealthCommand.NotifyCanExecuteChanged();
        ShowAgentHealthCommand.NotifyCanExecuteChanged();
        ShowSqlitePerformanceCommand.NotifyCanExecuteChanged();
        RePairAgentCommand.NotifyCanExecuteChanged();
        RevokeAgentPairingCommand.NotifyCanExecuteChanged();
        StopAgentCommand.NotifyCanExecuteChanged();
        RefreshViewFromStagingCommand.NotifyCanExecuteChanged();
        OpenSessionFolderCommand.NotifyCanExecuteChanged();
        ReverseAgentMonitoringDeploymentCommand.NotifyCanExecuteChanged();
        StartLiveCaptureCommand.NotifyCanExecuteChanged();
        StopLiveCaptureCommand.NotifyCanExecuteChanged();
        StartAgentConfiguredCaptureCommand.NotifyCanExecuteChanged();
        PauseAgentConfiguredCaptureCommand.NotifyCanExecuteChanged();
        StopAgentConfiguredCaptureCommand.NotifyCanExecuteChanged();
        StartAgentSqliteBenchmarkCommand.NotifyCanExecuteChanged();
        CancelAgentSqliteBenchmarkCommand.NotifyCanExecuteChanged();
        StartAgentCaptureOptionCommand.NotifyCanExecuteChanged();
        StopAgentCaptureOptionCommand.NotifyCanExecuteChanged();
        StartNetworkCaptureCommand.NotifyCanExecuteChanged();
        StopNetworkCaptureCommand.NotifyCanExecuteChanged();
        StartProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        StopProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        QueueProcessMonitorImportCommand.NotifyCanExecuteChanged();
        QueueSelectedZeekAnalysisCommand.NotifyCanExecuteChanged();
        QueueArtifactFileImportCommand.NotifyCanExecuteChanged();
        QueueArtifactFolderImportCommand.NotifyCanExecuteChanged();
        DumpSystemMemoryCommand.NotifyCanExecuteChanged();
        QueueMemoryImageImportCommand.NotifyCanExecuteChanged();
        QueueSelectedMemoryImageVolatilityAnalysisCommand.NotifyCanExecuteChanged();
        StartArtifactEnrichmentCommand.NotifyCanExecuteChanged();
        RefreshSelectedHandlesCommand.NotifyCanExecuteChanged();
        RefreshSelectedModulesCommand.NotifyCanExecuteChanged();
        StopArtifactEnrichmentCommand.NotifyCanExecuteChanged();
        QueueSelectedProcessDumpCommand.NotifyCanExecuteChanged();
    }

    partial void OnSelectedDataTabChanged(FeatureTabDescriptor? value)
    {
        if (_isApplyingViewerNavigationState)
        {
            return;
        }

        MarkSnapshotPresentationInteraction();
        var result = _viewerNavigationCoordinator.AcceptDataSelection(value);
        if (result.Succeeded)
        {
            QueueSelectedDataTabEnrichmentIfNeeded();
        }
    }

    partial void OnSelectedExplorerTabChanged(FeatureTabDescriptor? value)
    {
        if (_isApplyingViewerNavigationState)
        {
            return;
        }

        MarkSnapshotPresentationInteraction();
        _viewerNavigationCoordinator.AcceptExplorerSelection(value);
    }

    partial void OnSelectedDetailsTabKeyChanged(ViewerDetailsTabKey value) =>
        MarkSnapshotPresentationInteraction();

    private void QueueSelectedDataTabEnrichmentIfNeeded()
    {
        if (!FeaturePublication.ModulesAndHandles)
        {
            return;
        }

        var task = SelectedDataTab?.Key switch
        {
            var key when key == DataTabKeys.Modules => QueueSelectedProcessEnrichmentIfNeededAsync(captureModules: true, captureHandles: false, force: false),
            var key when key == DataTabKeys.Handles => QueueSelectedProcessEnrichmentIfNeededAsync(captureModules: false, captureHandles: true, force: false),
            _ => Task.CompletedTask
        };
        if (!task.IsCompletedSuccessfully)
        {
            _ = ReportSelectedEnrichmentErrorAsync(task);
        }
    }

    private async Task ReportSelectedEnrichmentErrorAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Selected-process enrichment failed before queueing: {ex.Message}";
        }
    }

    partial void OnIsEtwCollectionEnabledChanged(bool value)
    {
        StatusMessage = value
            ? "Enabled the ETW capture preference. Acquisition starts only through the agent."
            : "Disabled the ETW capture preference.";
        NotifyLiveCaptureStateChanged();
    }

    partial void OnSelectedEtwCaptureProfileChanged(ConfigProfileDefinition? value)
    {
        if (value == null)
        {
            EtwCaptureProfileStatus = "ETW profile: none selected.";
            return;
        }

        var profileName = GetConfigProfileDisplayName(value);
        var profilePath = _configProfileService.ResolveProfileFilePath(value);
        if (string.IsNullOrWhiteSpace(profilePath) || !File.Exists(profilePath))
        {
            EtwCaptureProfileStatus = $"ETW profile: {profileName} (missing config file).";
        }
        else
        {
            EtwCaptureProfileStatus = $"ETW profile: {profileName}.";
        }
    }

    partial void OnIsWindowsAuditLogCollectionEnabledChanged(bool value)
    {
        StatusMessage = value
            ? "Enabled the Windows Security capture preference. Acquisition starts only through the agent."
            : "Disabled the Windows Security capture preference.";
        NotifyLiveCaptureStateChanged();
    }

    partial void OnIsPowerShellLogCollectionEnabledChanged(bool value)
    {
        StatusMessage = value
            ? "Enabled the PowerShell capture preference. Acquisition starts only through the agent."
            : "Disabled the PowerShell capture preference.";
        NotifyLiveCaptureStateChanged();
    }

    partial void OnIsWindowsOtherLogCollectionEnabledChanged(bool value)
    {
        StatusMessage = value
            ? "Enabled the Windows Other capture preference. Acquisition starts only through the agent."
            : "Disabled the Windows Other capture preference.";
        NotifyLiveCaptureStateChanged();
    }

    partial void OnIsModuleCollectionEnabledChanged(bool value)
    {
        StatusMessage = value
            ? "Enabled the module-enrichment preference. Acquisition starts only through the agent."
            : "Disabled the module-enrichment preference.";
        NotifyArtifactEnrichmentStateChanged();
    }

    partial void OnIsHandleCollectionEnabledChanged(bool value)
    {
        StatusMessage = value
            ? "Enabled the handle-enrichment preference. Acquisition starts only through the agent."
            : "Disabled the handle-enrichment preference.";
        NotifyArtifactEnrichmentStateChanged();
    }

    partial void OnIsSysmonIntegrationEnabledChanged(bool value)
    {
        if (_isLoadingSysmonSettings)
            return;

        try
        {
            _sysmonService.SetIntegrationEnabled(value);
            StatusMessage = value
                ? "Enabled the Sysmon capture preference. Acquisition starts only through the agent."
                : "Disabled the Sysmon capture preference.";
            LoadSysmonSettings();
            NotifyLiveCaptureStateChanged();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to update Sysmon integration: {ex.Message}";
            LoadSysmonSettings();
            NotifyLiveCaptureStateChanged();
        }
    }

    private void NotifyLiveCaptureStateChanged()
    {
        OnPropertyChanged(nameof(IsLiveCaptureEnabled));
        OnPropertyChanged(nameof(LiveCaptureStateDisplay));
    }

    private void ApplyCaptureJobProgress(JobProgress? job)
    {
        if (job == null)
        {
            return;
        }

        if (job.JobKind == JobKind.LiveCapture && _activeLiveCaptureJobId == job.JobId)
        {
            SetLiveCaptureRunState(CaptureRunStateFromJob(job, CaptureRunState.Off));
        }
        else if (job.JobKind == JobKind.NetworkCapture && _activeNetworkCaptureJobId == job.JobId)
        {
            var pendingFinalization = job.State != JobState.Failed &&
                                      HasPendingNetworkCaptureFinalization(job.JobId, job.State);
            IsNetworkCaptureActive = pendingFinalization || job.State is JobState.Queued or JobState.Running or JobState.Paused;
            SetNetworkCaptureRunState(pendingFinalization
                ? CaptureRunState.Stopping
                : CaptureRunStateFromJob(job, CaptureRunState.Off));
            NetworkCapturesViewModel.RefreshNetworkCaptures();
        }
        else if (job.JobKind == JobKind.ProcessMonitorCapture && _activeProcessMonitorCaptureJobId == job.JobId)
        {
            IsProcessMonitorCaptureActive = job.State is JobState.Queued or JobState.Running or JobState.Paused;
            SetProcessMonitorCaptureRunState(CaptureRunStateFromJob(job, CaptureRunState.Off));
        }
    }

    private void ApplySqliteBenchmarkProgress(JobProgress? job)
    {
        if (job?.JobKind != JobKind.SqliteBenchmark)
        {
            return;
        }

        var agent = AgentsViewModel.SelectedAgent ?? GetLocalAgent();
        agent?.ApplyBenchmarkProgress(job);
        if (job.State is JobState.Completed or JobState.Cancelled or JobState.Failed)
        {
            _activeSqliteBenchmarkJobId = null;
            var detail = FirstNonEmpty(job.SqliteBenchmark?.ThresholdReason, job.ErrorText, job.ProgressMessage);
            StatusMessage = string.IsNullOrWhiteSpace(detail)
                ? $"SQLite benchmark {job.State}."
                : $"SQLite benchmark {job.State}. {detail}";
        }

        NotifySqliteBenchmarkStateChanged();
    }

    private bool HasPendingNetworkCaptureFinalization(Guid jobId, JobState? jobState = null)
    {
        _ = jobId;
        var state = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.NetworkCapture).State;
        return jobState == JobState.Cancelled &&
               state is AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining;
    }

    private void ReconcileNetworkCaptureStateFromRows()
    {
        if (!_activeNetworkCaptureJobId.HasValue)
        {
            var hasActiveCaptureRow = NetworkCapturesViewModel.NetworkCaptures.Any(capture =>
                capture.StatusKind is NetworkCaptureStatus.Requested or NetworkCaptureStatus.Capturing or NetworkCaptureStatus.Stopping);
            if (!hasActiveCaptureRow && IsNetworkCaptureActive)
            {
                IsNetworkCaptureActive = false;
                SetNetworkCaptureRunState(CaptureRunState.Off);
            }

            QueueSelectedZeekAnalysisCommand.NotifyCanExecuteChanged();
            return;
        }

        var activeJobId = _activeNetworkCaptureJobId.Value.ToString("D");
        var matchingRows = NetworkCapturesViewModel.NetworkCaptures
            .Where(capture => string.Equals(capture.JobId, activeJobId, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (matchingRows.Count == 0)
        {
            QueueSelectedZeekAnalysisCommand.NotifyCanExecuteChanged();
            return;
        }

        if (matchingRows.Any(capture => capture.StatusKind == NetworkCaptureStatus.Captured))
        {
            _activeNetworkCaptureJobId = null;
            IsNetworkCaptureActive = false;
            SetNetworkCaptureRunState(CaptureRunState.Off);
            StatusMessage = "Network PCAP capture finalized.";
        }
        else if (matchingRows.Any(capture => capture.StatusKind is NetworkCaptureStatus.Failed or NetworkCaptureStatus.Unsupported))
        {
            _activeNetworkCaptureJobId = null;
            IsNetworkCaptureActive = false;
            SetNetworkCaptureRunState(CaptureRunState.Failed);
        }
        else if (matchingRows.Any(capture => capture.StatusKind == NetworkCaptureStatus.Stopping))
        {
            IsNetworkCaptureActive = true;
            SetNetworkCaptureRunState(CaptureRunState.Stopping);
        }
        else if (matchingRows.Any(capture => capture.StatusKind == NetworkCaptureStatus.Capturing))
        {
            IsNetworkCaptureActive = true;
            SetNetworkCaptureRunState(CaptureRunState.Running);
        }
        else if (matchingRows.Any(capture => capture.StatusKind == NetworkCaptureStatus.Requested))
        {
            IsNetworkCaptureActive = true;
            SetNetworkCaptureRunState(CaptureRunState.Starting);
        }

        QueueSelectedZeekAnalysisCommand.NotifyCanExecuteChanged();
    }

    private void SetLiveCaptureRunState(CaptureRunState _)
    {
        OnPropertyChanged(nameof(LiveCaptureStateDisplay));
        NotifyAgentCommandCanExecuteChanged();
        UpdateAgentCaptureRuntimeRows();
    }

    private void SetNetworkCaptureRunState(CaptureRunState _)
    {
        OnPropertyChanged(nameof(NetworkCaptureStateDisplay));
        StartNetworkCaptureCommand.NotifyCanExecuteChanged();
        StopNetworkCaptureCommand.NotifyCanExecuteChanged();
        UpdateAgentCaptureRuntimeRows();
    }

    private void SetProcessMonitorCaptureRunState(CaptureRunState _)
    {
        OnPropertyChanged(nameof(ProcessMonitorCaptureStateDisplay));
        StartProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        StopProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        QueueProcessMonitorImportCommand.NotifyCanExecuteChanged();
        UpdateAgentCaptureRuntimeRows();
    }

    private void UpdateAgentCaptureRuntimeRows()
    {
        if (!_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
        {
            return;
        }

        foreach (var agent in agentFeature.AgentsViewModel.Agents)
        {
            UpdateLiveSourceStatus(agent, AgentCaptureOptionKind.ProcessLiveEvents);
            UpdateLiveSourceStatus(agent, AgentCaptureOptionKind.EtwEvents);
            UpdateLiveSourceStatus(agent, AgentCaptureOptionKind.SecurityEvents);
            UpdateLiveSourceStatus(agent, AgentCaptureOptionKind.PowerShellEvents);
            UpdateLiveSourceStatus(agent, AgentCaptureOptionKind.WindowsOtherEvents);
            UpdateLiveSourceStatus(agent, AgentCaptureOptionKind.SysmonEvents);
            UpdateConfiguredOneShotStatus(agent, AgentCaptureOptionKind.ModuleEnrichment);
            UpdateConfiguredOneShotStatus(agent, AgentCaptureOptionKind.HandleEnrichment);
            UpdateConfiguredOneShotStatus(agent, AgentCaptureOptionKind.PeAnalysis);
            var networkControl = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.NetworkCapture);
            ApplyCaptureOptionControl(agent, AgentCaptureOptionKind.NetworkCapture, networkControl);
            agent.SetCaptureOptionStatus(AgentCaptureOptionKind.NetworkCapture, networkControl.StatusText);
            var processMonitorControl = _agentCaptureWorkflowCoordinator.Control.GetJobSource(JobKind.ProcessMonitorCapture);
            ApplyCaptureOptionControl(agent, AgentCaptureOptionKind.ProcessMonitorCapture, processMonitorControl);
            agent.SetCaptureOptionStatus(AgentCaptureOptionKind.ProcessMonitorCapture, processMonitorControl.StatusText);
            agent.SetCaptureOptionStatus(
                AgentCaptureOptionKind.ZeekAnalysis,
                "Run after network capture or from a selected PCAP segment.");
            agent.SetCaptureOptionStatus(
                AgentCaptureOptionKind.FilesystemArtifactImport,
                "Use file/folder import; requires analyst-selected input.");
            agent.SetCaptureOptionStatus(
                AgentCaptureOptionKind.MemoryImageImport,
                "Use memory import/acquisition; requires an image or configured tool.");
            agent.SetCaptureOptionStatus(
                AgentCaptureOptionKind.VolatilityAnalysis,
                "Use Volatility on a selected staged memory image.");
        }

        StartAgentCaptureOptionCommand.NotifyCanExecuteChanged();
        StopAgentCaptureOptionCommand.NotifyCanExecuteChanged();
        StartAgentSqliteBenchmarkCommand.NotifyCanExecuteChanged();
        CancelAgentSqliteBenchmarkCommand.NotifyCanExecuteChanged();
        UpdateAgentBenchmarkPreflight(agentFeature.AgentsViewModel.SelectedAgent);
    }

    private static void ApplyCaptureOptionControl(
        AgentRegistryEntryViewModel agent,
        AgentCaptureOptionKind kind,
        AgentCaptureSourceControlState control)
    {
        var option = agent.CaptureOptions.FirstOrDefault(candidate => candidate.Kind == kind);
        if (option == null)
        {
            return;
        }

        option.CanStart = control.CanStart;
        option.CanStop = control.CanStop;
    }

    private void UpdateAgentBenchmarkPreflight(AgentRegistryEntryViewModel? agent)
    {
        if (!_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
        {
            return;
        }

        agent ??= agentFeature.AgentsViewModel.SelectedAgent;
        if (agent == null)
        {
            return;
        }

        var captureIsActive = IsAnyTrackedCaptureActive(includeStopping: true);
        agent.UpdateBenchmarkPreflight(captureIsActive, _sessionPaths.BenchmarkDirectory);
    }

    private void NotifySqliteBenchmarkStateChanged()
    {
        StartAgentSqliteBenchmarkCommand.NotifyCanExecuteChanged();
        CancelAgentSqliteBenchmarkCommand.NotifyCanExecuteChanged();
        StartAgentConfiguredCaptureCommand.NotifyCanExecuteChanged();
        StartAgentCaptureOptionCommand.NotifyCanExecuteChanged();
        StartNetworkCaptureCommand.NotifyCanExecuteChanged();
        StartProcessMonitorCaptureCommand.NotifyCanExecuteChanged();
        if (_featureModules.TryGetActivated<AgentFeatureModule>(FeatureIds.AgentsAndCapture, out var agentFeature))
        {
            UpdateAgentBenchmarkPreflight(agentFeature.AgentsViewModel.SelectedAgent);
        }
    }

    private void UpdateLiveSourceStatus(AgentRegistryEntryViewModel agent, AgentCaptureOptionKind kind)
    {
        var option = agent.CaptureOptions.FirstOrDefault(candidate => candidate.Kind == kind);
        if (option == null)
        {
            return;
        }

        var source = _agentCaptureWorkflowCoordinator.Control.GetLiveSource(GetLiveCaptureSourceName(kind));
        option.CanStart = source.CanStart;
        option.CanStop = source.CanStop;
        option.StatusText = source.StatusText;
    }

    private void UpdateConfiguredOneShotStatus(AgentRegistryEntryViewModel agent, AgentCaptureOptionKind kind)
    {
        var option = agent.CaptureOptions.FirstOrDefault(candidate => candidate.Kind == kind);
        if (option == null)
        {
            return;
        }

        var jobKind = kind switch
        {
            AgentCaptureOptionKind.ModuleEnrichment => JobKind.ModuleEnrichment,
            AgentCaptureOptionKind.HandleEnrichment => JobKind.HandleEnrichment,
            AgentCaptureOptionKind.PeAnalysis => JobKind.PeAnalysis,
            _ => JobKind.Unknown
        };
        var control = _agentCaptureWorkflowCoordinator.Control.GetJobSource(jobKind);
        option.CanStart = control.CanStart;
        option.CanStop = control.CanStop;
        option.StatusText = control.StatusText;
    }

    private static CaptureRunState CaptureRunStateFromJob(JobProgress? job, CaptureRunState fallback)
    {
        return job?.State switch
        {
            JobState.Queued => CaptureRunState.Starting,
            JobState.Running or JobState.Paused when fallback == CaptureRunState.Stopping => CaptureRunState.Stopping,
            JobState.Running or JobState.Paused => CaptureRunState.Running,
            JobState.Failed => CaptureRunState.Failed,
            JobState.Completed or JobState.Cancelled => CaptureRunState.Off,
            _ => fallback
        };
    }

    private static CaptureRunState CaptureRunStateFromJobState(JobState state, CaptureRunState fallback)
    {
        return state switch
        {
            JobState.Queued => CaptureRunState.Starting,
            JobState.Running or JobState.Paused => CaptureRunState.Running,
            JobState.Completed or JobState.Cancelled => CaptureRunState.Off,
            JobState.Failed => CaptureRunState.Failed,
            _ => fallback
        };
    }

    private void NotifyArtifactEnrichmentStateChanged()
    {
        OnPropertyChanged(nameof(IsArtifactEnrichmentEnabled));
        OnPropertyChanged(nameof(ArtifactEnrichmentStateDisplay));
    }

    private void UpdateActiveSessionDetail()
    {
        var fallbackPrefix = _sessionPaths.UsedFallbackRoot
            ? $"{_sessionPaths.FallbackReason} "
            : string.Empty;
        var packageSummary = BuildCapturePackageSummary(_activeCapturePackageInfo);
        var artifactSummary = BuildCaptureArtifactSummary(_activeCapturePackageInfo);
        SnapshotTimestampDisplay = GetSnapshotTimestampDisplay();
        var viewerDatabaseDescription = _captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.ArchivedCapture
            ? $"Direct archived DB: {SnapshotDatabasePath} | Query connections: read-only; analysis index/FTS maintenance: background write"
            : $"Snapshot DB: {SnapshotDatabasePath} | Live DB writer: agent only";
        ActiveSessionDetail =
            $"{fallbackPrefix}Workspace mode: {CaptureWorkspaceModeDisplay} | {packageSummary} | " +
            $"Live DB: {_sessionPaths.LiveDatabasePath} | " +
            $"Annotation DB: {_sessionPaths.AnnotationDatabasePath} | " +
            $"Capture settings: {FormatPresence(_activeCapturePackageInfo?.HasCaptureConfiguration == true)} | " +
            $"Host monitoring config: {FormatPresence(_activeCapturePackageInfo?.HasHostMonitoringConfiguration == true)} | " +
            $"Original monitoring baseline: {FormatPresence(_activeCapturePackageInfo?.HasHostMonitoringOriginalState == true)} | " +
            $"Artifact folders: {artifactSummary} | " +
            $"AI settings: {_sessionPaths.AiSettingsPath} | " +
            $"{viewerDatabaseDescription} | " +
            $"Evidence path: {_telemetryProjectionService.PathDiagnostics.StatusCode}; writes: {EvidencePathDiagnostics.AgentWritePath} | " +
            SnapshotTimestampDisplay;
    }

    private static CapturePackageInfo? TryInspectCapturePackage(string sessionRoot)
    {
        try
        {
            return SessionPathService.InspectCapturePackage(
                sessionRoot,
                CaptureOpenContext.InspectionOnly,
                SqliteStagingStore.AssessExistingDatabase);
        }
        catch
        {
            return null;
        }
    }

    private static string BuildCapturePackageSummary(CapturePackageInfo? packageInfo)
    {
        if (packageInfo == null)
        {
            return $"Capture package: {SessionPathService.CapturePackageFormatName} | Manifest: {SessionPathService.CapturePackageManifestFileName}";
        }

        var created = packageInfo.CreatedUtc == default
            ? "unknown"
            : packageInfo.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        var appVersion = string.IsNullOrWhiteSpace(packageInfo.AppVersion)
            ? "unknown"
            : packageInfo.AppVersion;
        var machine = string.IsNullOrWhiteSpace(packageInfo.MachineName)
            ? "unknown"
            : packageInfo.MachineName;
        var productIdentity = packageInfo.HasDeclaredProductDisplayName
            ? packageInfo.ProductDisplayName
            : $"{packageInfo.ProductDisplayName} (legacy manifest)";
        var evidenceFormat = packageInfo.EvidenceFormatVersion?.ToString() ?? "legacy-unspecified";
        return $"Capture package: {packageInfo.FormatName} | Product metadata: {productIdentity} | " +
               $"Manifest schema: v{packageInfo.SchemaVersion} | " +
               $"Declared evidence format: {evidenceFormat} | " +
               $"Session: {packageInfo.SessionId} | Created: {created} | App: {appVersion} | Machine: {machine}";
    }

    private static string BuildCaptureArtifactSummary(CapturePackageInfo? packageInfo)
    {
        if (packageInfo == null || packageInfo.ArtifactFolders.Count == 0)
        {
            return "unknown";
        }

        return string.Join(", ", packageInfo.ArtifactFolders.Select(folder => $"{folder.Name} {FormatPresence(folder.Exists)}"));
    }

    private static string FormatPresence(bool isPresent)
    {
        return isPresent ? "present" : "missing";
    }

    private string GetSnapshotTimestampDisplay()
    {
        if (_captureWorkspaceCoordinator.Mode == CaptureWorkspaceMode.ArchivedCapture &&
            !string.IsNullOrWhiteSpace(SnapshotDatabasePath))
        {
            return "Viewer DB: archived source database (direct)";
        }

        var activeSnapshotUtc = _liveSnapshotRefreshCoordinator.ActiveSnapshotUtc;
        return activeSnapshotUtc.HasValue
            ? $"Snapshot: {activeSnapshotUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss} ({FormatSnapshotAge(activeSnapshotUtc.Value)} old)"
            : "Snapshot: not loaded";
    }

    private static string FormatSnapshotAge(DateTime snapshotUtc)
    {
        var age = DateTime.UtcNow - snapshotUtc;
        if (age < TimeSpan.Zero)
        {
            age = TimeSpan.Zero;
        }

        if (age.TotalMinutes < 1)
        {
            return "<1 min";
        }

        if (age.TotalHours < 1)
        {
            return $"{(int)age.TotalMinutes} min";
        }

        if (age.TotalDays < 1)
        {
            return $"{(int)age.TotalHours} hr {age.Minutes} min";
        }

        return $"{(int)age.TotalDays} d {age.Hours} hr";
    }

    private static AnnotationDatabaseService? TryInitializeAnnotationDatabase(string databasePath)
    {
        try
        {
            var annotationStore = new AnnotationDatabaseService(databasePath);
            annotationStore.Initialize();
            return annotationStore;
        }
        catch
        {
            return null;
        }
    }

    private PowerShellAuditingSettings LoadPowerShellAuditingSettings()
    {
        var settings = _powerShellAuditingService.LoadSettings();
        if (settings.IsAvailable)
        {
            IsScriptBlockLoggingEnabled = settings.ScriptBlockLoggingEnabled;
            IsModuleLoggingEnabled = settings.ModuleLoggingEnabled;
            IsTranscriptionEnabled = settings.TranscriptionEnabled;
            TranscriptPath = settings.TranscriptPath;
        }

        return settings;
    }

    private static ApplicationCatalogService? TryOpenApplicationCatalog()
    {
        try
        {
            var catalogPath = Path.Combine(
                AppContext.BaseDirectory,
                "Config",
                "ApplicationCatalog",
                "application-catalog.sqlite");
            return ApplicationCatalogService.OpenReadOnly(catalogPath);
        }
        catch
        {
            return null;
        }
    }

    private SysmonSettings LoadSysmonSettings()
    {
        _isLoadingSysmonSettings = true;
        try
        {
            UpdateSysmonConfigProfiles(_sysmonService.GetBundledConfigProfiles());
            var settings = _sysmonService.LoadSettings();
            IsSysmonIntegrationEnabled = settings.IntegrationEnabled;
            if (settings.IsServiceStateAvailable)
            {
                IsSysmonInstalled = settings.IsInstalled;
                IsSysmonRunning = settings.IsRunning;
            }

            IsSysmonChannelAvailable = settings.IsChannelAvailable;
            SysmonConfigPath = _sysmonService.GetBundledConfigPath();
            return settings;
        }
        finally
        {
            _isLoadingSysmonSettings = false;
        }
    }

    private void LoadEtwCaptureProfiles()
    {
        UpdateEtwCaptureProfiles(_configProfileService.GetProfiles(ConfigProfileKind.Etw));
    }

    private void UpdateEtwCaptureProfiles(IEnumerable<ConfigProfileDefinition> profiles)
    {
        EtwCaptureProfiles.Clear();
        foreach (var profile in SortProfilesForMenu(profiles))
        {
            EtwCaptureProfiles.Add(profile);
        }

        HasEtwCaptureProfiles = EtwCaptureProfiles.Count > 0;
        SelectedEtwCaptureProfile = EtwCaptureProfiles.FirstOrDefault(profile => profile.IsDefault)
            ?? EtwCaptureProfiles.FirstOrDefault();

        if (SelectedEtwCaptureProfile == null)
        {
            EtwCaptureProfileStatus = "ETW profile: no bundled profiles discovered.";
        }
    }

    private void UpdateSysmonConfigProfiles(IEnumerable<ConfigProfileDefinition> profiles)
    {
        SysmonConfigProfiles.Clear();
        foreach (var profile in SortProfilesForMenu(profiles))
        {
            SysmonConfigProfiles.Add(profile);
        }

        HasSysmonConfigProfiles = SysmonConfigProfiles.Count > 0;
    }

    private void LoadSecurityMonitoringProfileManifests()
    {
        UpdateSecurityMonitoringPolicyProfiles(_securityMonitoringService.GetPolicyProfiles());
        UpdatePowerShellAuditingProfiles(_powerShellAuditingService.GetAuditingProfiles());
        UpdateEventLogPolicyProfiles(_configProfileService.GetProfiles(ConfigProfileKind.EventLogs));
    }

    private void UpdateSecurityMonitoringPolicyProfiles(IEnumerable<ConfigProfileDefinition> profiles)
    {
        SecurityMonitoringPolicyProfiles.Clear();
        foreach (var profile in SortProfilesForMenu(profiles))
        {
            SecurityMonitoringPolicyProfiles.Add(profile);
        }

        HasSecurityMonitoringPolicyProfiles = SecurityMonitoringPolicyProfiles.Count > 0;
    }

    private void UpdatePowerShellAuditingProfiles(IEnumerable<ConfigProfileDefinition> profiles)
    {
        PowerShellAuditingProfiles.Clear();
        foreach (var profile in SortProfilesForMenu(profiles))
        {
            PowerShellAuditingProfiles.Add(profile);
        }

        HasPowerShellAuditingProfiles = PowerShellAuditingProfiles.Count > 0;
    }

    private void UpdateEventLogPolicyProfiles(IEnumerable<ConfigProfileDefinition> profiles)
    {
        EventLogPolicyProfiles.Clear();
        foreach (var profile in SortProfilesForMenu(profiles))
        {
            EventLogPolicyProfiles.Add(profile);
        }

        HasEventLogPolicyProfiles = EventLogPolicyProfiles.Count > 0;
    }

    private static IEnumerable<ConfigProfileDefinition> SortProfilesForMenu(IEnumerable<ConfigProfileDefinition> profiles)
    {
        return profiles.OrderByDescending(profile => profile.IsDefault)
            .ThenBy(profile => GetConfigProfileDisplayName(profile), StringComparer.OrdinalIgnoreCase);
    }

    private static string GetConfigProfileDisplayName(ConfigProfileDefinition profile)
    {
        return string.IsNullOrWhiteSpace(profile.DisplayName)
            ? profile.Id
            : profile.DisplayName;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var source = string.IsNullOrWhiteSpace(value) ? "artifact" : value;
        var builder = new System.Text.StringBuilder(source.Length);
        foreach (var ch in source)
        {
            builder.Append(invalid.Contains(ch) ? '_' : ch);
        }

        return builder.ToString();
    }

    private static string? FindExecutableOnPath(string fileName)
    {
        foreach (var entry in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                var candidate = Path.Combine(entry, fileName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            catch
            {
                // Ignore malformed PATH entries.
            }
        }

        return null;
    }

    private static string? FindKnownWiresharkExecutable()
        => FindKnownWiresharkTool("Wireshark.exe");

    private static string? FindKnownTsharkExecutable()
        => FindKnownWiresharkTool("tshark.exe");

    private static string? FindKnownWiresharkTool(string fileName)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs")
        };

        foreach (var root in roots.Where(root => !string.IsNullOrWhiteSpace(root)))
        {
            var candidate = Path.Combine(root, "Wireshark", fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private void OpenConfigProfile(ConfigProfileDefinition? profile, string profileKindDisplay)
    {
        if (profile == null)
        {
            StatusMessage = $"No {profileKindDisplay} profile was selected.";
            return;
        }

        var profileName = GetConfigProfileDisplayName(profile);
        try
        {
            var path = _configProfileService.ResolveProfileFilePath(profile);
            if (string.IsNullOrWhiteSpace(path))
            {
                path = profile.ManifestDirectory;
            }

            if (string.IsNullOrWhiteSpace(path) || (!File.Exists(path) && !Directory.Exists(path)))
            {
                throw new FileNotFoundException($"{profileKindDisplay} profile file was not found.", path);
            }

            var result = _externalProcessService.OpenShellTarget(path);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException(result.Detail);
            }

            RecordMonitoringProfileAction($"open-{profileKindDisplay}", profile, path);
            StatusMessage = $"Opened {profileKindDisplay} profile: {profileName}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to open {profileKindDisplay} profile '{profileName}': {ex.Message}";
        }
    }

    private static bool TryResolveMonitoringProfilePath(
        ConfigProfileDefinition profile,
        Func<ConfigProfileDefinition, string?> resolvePath,
        out string profilePath,
        out string error)
    {
        try
        {
            profilePath = resolvePath(profile) ?? profile.FilePath;
            error = string.Empty;
            return true;
        }
        catch (Exception ex)
        {
            profilePath = profile.FilePath;
            error = ex.Message;
            return false;
        }
    }

    private void RecordMonitoringProfileAction(string action, ConfigProfileDefinition profile, string? path)
    {
        try
        {
            Directory.CreateDirectory(_sessionPaths.LogsDirectory);
            var logPath = Path.Combine(_sessionPaths.LogsDirectory, "SecurityMonitoringProfiles.log");
            var line = string.Join(
                "\t",
                DateTimeOffset.Now.ToString("O"),
                action,
                profile.Kind,
                profile.Id,
                GetConfigProfileDisplayName(profile),
                string.IsNullOrWhiteSpace(path) ? string.Empty : path);
            File.AppendAllText(logPath, line + Environment.NewLine);
        }
        catch
        {
            // Profile logging is best-effort and must not block monitoring actions.
        }
    }

    private void BackfillSysmonEventsForProcess((string ProcessKey, int ProcessId, string ProcessName) processInfo)
    {
        ReportViewerBackfillUnavailable("Sysmon", processInfo);
    }

    private void BackfillSecurityEventsForProcess((string ProcessKey, int ProcessId, string ProcessName) processInfo)
    {
        ReportViewerBackfillUnavailable("Security", processInfo);
    }

    private void BackfillPowerShellEventsForProcess((string ProcessKey, int ProcessId, string ProcessName) processInfo)
    {
        ReportViewerBackfillUnavailable("PowerShell", processInfo);
    }

    private void BackfillOtherWindowsEventsForProcess((string ProcessKey, int ProcessId, string ProcessName) processInfo)
    {
        ReportViewerBackfillUnavailable("WindowsOther", processInfo);
    }

    private void ReportViewerBackfillUnavailable(
        string source,
        (string ProcessKey, int ProcessId, string ProcessName) processInfo)
    {
        StatusMessage =
            $"{source} backfill is unavailable for {processInfo.ProcessName} (PID {processInfo.ProcessId}). " +
            "Viewer-owned evidence backfill is retired; the current snapshot was preserved.";
    }

    // ── DB-backed process grid helpers (Phase 3F / 3G) ────────────────────────

    private const int VirtualProcessPageSize = 128;
    private const int VirtualProcessCachePages = 6;

    /// <summary>
    /// Schedules a DB-backed grid refresh, debounced to 300 ms so rapid filter
    /// keystrokes do not trigger a SQLite query on every character.
    /// Invalidates the active virtual collection so filter changes return to the
    /// first page of a new query generation.
    /// Leaves the viewer unchanged when no SQLite projection is active.
    /// </summary>
    private void ScheduleDbRefresh()
    {
        MarkSnapshotPresentationInteraction();
        if (_processListingService == null)
        {
            return;
        }

        Interlocked.Increment(ref _processListingQueryGeneration);
        _processListingRefreshCts?.Cancel();

        if (_dbRefreshDebounceTimer == null)
        {
            _dbRefreshDebounceTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _dbRefreshDebounceTimer.Tick += async (_, _) =>
            {
                _dbRefreshDebounceTimer.Stop();
                await ExecuteDbRefreshAsync();
            };
        }

        _dbRefreshDebounceTimer.Stop();
        _dbRefreshDebounceTimer.Start();
    }

    /// <summary>
    /// Executes a DB-backed process-grid refresh immediately.
    /// Builds the current query from UI filter/sort state, fetches a bounded
    /// window via <see cref="ProcessListingService"/>, and replaces the grid rows.
    /// </summary>
    private async Task ExecuteDbRefreshAsync(IProgress<ProcessListingLoadProgress>? progress = null)
    {
        var listingService = _processListingService;
        if (listingService == null)
        {
            return;
        }

        var requestGeneration = Interlocked.Increment(ref _processListingQueryGeneration);
        var workspaceGeneration = _captureWorkspaceCoordinator.Generation;
        var refreshCts = new CancellationTokenSource();
        var previousCts = Interlocked.Exchange(ref _processListingRefreshCts, refreshCts);
        previousCts?.Cancel();
        Interlocked.Increment(ref _activeDbRefreshCount);
        VirtualizedProcessCollection? pendingCollection = null;

        try
        {
            var query = BuildCurrentListingQuery();
            progress?.Report(new ProcessListingLoadProgress(
                0,
                query.PageSize,
                0,
                "Counting matching processes for the virtualized listing..."));
            pendingCollection = new VirtualizedProcessCollection(
                listingService,
                query,
                workspaceGeneration,
                VirtualProcessPageSize,
                VirtualProcessCachePages,
                SynchronizationContext.Current,
                requestGeneration);
            await pendingCollection.InitializeAsync(progress, refreshCts.Token);

            if (requestGeneration != Volatile.Read(ref _processListingQueryGeneration) ||
                workspaceGeneration != _captureWorkspaceCoordinator.Generation ||
                !ReferenceEquals(listingService, _processListingService))
            {
                return;
            }

            var selectedKey = SelectedProcess?.ProcessKey;
            ProcessRowViewModel? selectedRow = null;
            if (!string.IsNullOrWhiteSpace(selectedKey))
            {
                var rowIndex = await listingService.GetProcessRowIndexAsync(
                    selectedKey,
                    query,
                    refreshCts.Token);
                if (rowIndex >= 0)
                {
                    await pendingCollection.EnsureRangeAsync(rowIndex, 1, refreshCts.Token);
                    selectedRow = pendingCollection.GetLoadedItem(rowIndex);
                }
            }

            if (requestGeneration != Volatile.Read(ref _processListingQueryGeneration) ||
                workspaceGeneration != _captureWorkspaceCoordinator.Generation ||
                !ReferenceEquals(listingService, _processListingService))
            {
                return;
            }

            AttachVirtualizedProcessListing(pendingCollection, selectedRow);
            pendingCollection = null;

        }
        catch (OperationCanceledException) when (refreshCts.IsCancellationRequested)
        {
            // A newer sort/filter/scope/workspace generation superseded this request.
        }
        catch (Exception ex)
        {
            if (requestGeneration == Volatile.Read(ref _processListingQueryGeneration) &&
                workspaceGeneration == _captureWorkspaceCoordinator.Generation &&
                ReferenceEquals(listingService, _processListingService))
            {
                ProcessListingStatus = $"Listing error: {ex.Message}";
                StatusMessage = $"Process grid refresh error: {ex.Message}";
            }
        }
        finally
        {
            pendingCollection?.Dispose();
            Interlocked.CompareExchange(ref _processListingRefreshCts, null, refreshCts);
            refreshCts.Dispose();
            Interlocked.Decrement(ref _activeDbRefreshCount);
        }
    }

    private ProcessListingQuery BuildCurrentListingQuery()
    {
        var filters = BuildFilterSet();
        ApplyExplorerScope(filters);

        if (!HasGreenIncludedSelection() &&
            HasExplorerSelectionWithoutProcessListingScope(filters.SelectedScopes))
        {
            filters.IncludedProcessKeys = [NoProcessScopedSelectionKey];
        }

        return new ProcessListingQuery
        {
            Filters = filters,
            Sort = new ProcessListingSortDescriptor
            {
                Column = MapSortColumn(_currentSortColumn),
                Direction = _sortAscending
                    ? ProcessListingSortDirection.Ascending
                    : ProcessListingSortDirection.Descending
            },
            Offset = 0,
            PageSize = VirtualProcessPageSize,
            IncludeTotalCount = false
        };
    }

    private void ApplyExplorerScope(ProcessListingFilterSet filters)
    {
        if (!HasGreenIncludedSelection())
        {
            filters.SelectedScopes = GetProcessListingSelectedScopes();
            filters.SelectedDirectChildScopes = GetSelectedDirectChildScopes();
        }
    }

    private bool HasExplorerSelectionWithoutProcessListingScope(IReadOnlyCollection<ExplorerScope> selectedScopes)
    {
        return ExplorerViewModel.SelectedNode is { IsPlaceholder: false } &&
               selectedScopes.Count == 0 &&
               ExplorerViewModel.SelectedNode.Scope.ProcessKey is null or "";
    }

    private static bool UsesProcessListingScope(ExplorerScope scope)
    {
        return scope.Kind switch
        {
            ExplorerScopeKind.FilesystemRoot or
            ExplorerScopeKind.FilesystemEvidenceRoots or
            ExplorerScopeKind.FilesystemArtifacts or
            ExplorerScopeKind.FilesystemFolder or
            ExplorerScopeKind.NetworkRoot or
            ExplorerScopeKind.NetworkCaptures or
            ExplorerScopeKind.NetworkCapture or
            ExplorerScopeKind.ZeekArtifacts or
            ExplorerScopeKind.AnalysisRoot or
            ExplorerScopeKind.SearchResults or
            ExplorerScopeKind.SigmaFindings or
            ExplorerScopeKind.CorrelationEvidence or
            ExplorerScopeKind.UnresolvedEvidence or
            ExplorerScopeKind.AmbiguousEvidence or
            ExplorerScopeKind.CorrelationEvidenceGroup or
            ExplorerScopeKind.ArtifactRoot or
            ExplorerScopeKind.MemoryDumps or
            ExplorerScopeKind.SystemActivityRoot or
            ExplorerScopeKind.ActivityAuthentication or
            ExplorerScopeKind.ActivitySuccessfulLogons or
            ExplorerScopeKind.ActivityFailedLogons or
            ExplorerScopeKind.ActivityRemoteInteractive or
            ExplorerScopeKind.ActivityExplicitCredentialUse or
            ExplorerScopeKind.ActivityPrivilegedLogons or
            ExplorerScopeKind.ActivityAccounts or
            ExplorerScopeKind.ActivityCreatedUsers or
            ExplorerScopeKind.ActivityDisabledDeletedUsers or
            ExplorerScopeKind.ActivityPasswordChanges or
            ExplorerScopeKind.ActivityGroups or
            ExplorerScopeKind.ActivityLocalAdministratorsChanges or
            ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or
            ExplorerScopeKind.ActivityPolicyAudit or
            ExplorerScopeKind.ActivityAuditPolicyChanged or
            ExplorerScopeKind.ActivityLogIntegrity or
            ExplorerScopeKind.ActivitySecurityLogCleared or
            ExplorerScopeKind.ActivityServicesTasks or
            ExplorerScopeKind.ActivityServicesInstalled or
            ExplorerScopeKind.ActivityScheduledTasksChanged or
            ExplorerScopeKind.UsersRoot or
            ExplorerScopeKind.UserAccount => false,
            _ => true
        };
    }

    private static bool CanScopeFilterProcessListing(ExplorerScope scope)
    {
        return IsSelectableExplorerScope(scope) &&
               (UsesProcessListingScope(scope) || CanAccountScopeFilterProcessListing(scope));
    }

    private static bool CanAccountScopeFilterProcessListing(ExplorerScope scope)
    {
        return !string.IsNullOrWhiteSpace(scope.OwnerKey) &&
               scope.Kind is ExplorerScopeKind.UserAccount or
                   ExplorerScopeKind.ActivityAuthentication or
                   ExplorerScopeKind.ActivitySuccessfulLogons or
                   ExplorerScopeKind.ActivityFailedLogons or
                   ExplorerScopeKind.ActivityRemoteInteractive or
                   ExplorerScopeKind.ActivityExplicitCredentialUse or
                   ExplorerScopeKind.ActivityPrivilegedLogons or
                   ExplorerScopeKind.ActivityAccounts or
                   ExplorerScopeKind.ActivityCreatedUsers or
                   ExplorerScopeKind.ActivityDisabledDeletedUsers or
                   ExplorerScopeKind.ActivityPasswordChanges or
                   ExplorerScopeKind.ActivityGroups or
                   ExplorerScopeKind.ActivityLocalAdministratorsChanges or
                   ExplorerScopeKind.ActivitySecurityGroupMembershipChanges or
                   ExplorerScopeKind.ActivityPolicyAudit or
                   ExplorerScopeKind.ActivityAuditPolicyChanged or
                   ExplorerScopeKind.ActivityLogIntegrity or
                   ExplorerScopeKind.ActivitySecurityLogCleared or
                   ExplorerScopeKind.ActivityServicesTasks or
                   ExplorerScopeKind.ActivityServicesInstalled or
                   ExplorerScopeKind.ActivityScheduledTasksChanged;
    }

    private bool MatchesIdentityScope(ProcessRowViewModel process, ExplorerScope scope)
    {
        return MatchesIdentityValue(process.ProcessInfo.CaseId, scope.CaseId) &&
               MatchesIdentityValue(process.ProcessInfo.EvidenceSessionId, scope.EvidenceSessionId) &&
               MatchesIdentityValue(process.ProcessInfo.CaptureId, scope.CaptureId) &&
               MatchesIdentityValue(process.ProcessInfo.SourceIdentityId, scope.SourceIdentityId) &&
               MatchesIdentityValue(process.ProcessInfo.HostId, scope.HostId) &&
               MatchesIdentityValue(process.ProcessInfo.ExecutionRootId, scope.ExecutionRootId);
    }

    private static bool MatchesIdentityValue(string actual, string? expected)
    {
        return string.IsNullOrWhiteSpace(expected) ||
               string.Equals(actual, expected, StringComparison.Ordinal);
    }

    private bool IsProcessInSubtree(string processKey, string rootProcessKey)
    {
        if (string.IsNullOrWhiteSpace(processKey) || string.IsNullOrWhiteSpace(rootProcessKey))
        {
            return false;
        }

        var currentKey = processKey;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        while (!string.IsNullOrWhiteSpace(currentKey) && visited.Add(currentKey))
        {
            if (string.Equals(currentKey, rootProcessKey, StringComparison.Ordinal))
            {
                return true;
            }

            if (!_processViewModels.TryGetValue(currentKey, out var row))
            {
                return false;
            }

            currentKey = !string.IsNullOrWhiteSpace(row.ProcessInfo.ParentProcessKey)
                ? row.ProcessInfo.ParentProcessKey
                : FindFallbackParent(row)?.ProcessKey ?? string.Empty;
        }

        return false;
    }

    private ProcessListingFilterSet BuildFilterSet()
    {
        var includedScopes = GetProcessListingIncludedScopes();
        var excludedScopes = GetProcessListingExcludedScopes();
        var includedProcessKeys = _includedProcessKeys.ToList();
        if ((_includedScopes.Count > 0 || _includedProcessKeys.Count > 0) &&
            includedScopes.Count == 0 &&
            includedProcessKeys.Count == 0)
        {
            includedProcessKeys.Add(NoProcessScopedSelectionKey);
        }

        var f = new ProcessListingFilterSet
        {
            ProcessNameContains    = NullIfEmpty(FilterProcessName),
            ProcessIdContains      = NullIfEmpty(FilterPid),
            ParentProcessIdContains = NullIfEmpty(FilterParentPid),
            ParentProcessNameContains = NullIfEmpty(FilterParentProcessName),
            ProcessPathContains    = NullIfEmpty(FilterProcessPath),
            CommandLineContains    = NullIfEmpty(FilterCommandLine),
            UserNameContains       = NullIfEmpty(FilterUserName),
            ArchitectureContains   = NullIfEmpty(FilterArchitecture),
            CompanyNameContains    = NullIfEmpty(FilterCompanyName),
            FileDescriptionContains = NullIfEmpty(FilterFileDescription),
            Sha256HashContains     = NullIfEmpty(FilterSha256Hash),
            StatusContains         = NullIfEmpty(FilterStatus),
            IncludedScopes         = includedScopes,
            ExcludedScopes         = excludedScopes,
            IncludedProcessKeys    = includedProcessKeys,
            ExcludedProcessKeys    = _excludedProcessKeys.ToList(),
            SelectedScopes         = GetProcessListingSelectedScopes()
        };

        if (int.TryParse(FilterSessionId, out var sid))
            f.SessionIdEquals = sid;

        return f;

        static string? NullIfEmpty(string s) =>
            string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    }

    private List<ExplorerScope> GetProcessListingIncludedScopes()
    {
        return _includedScopes.Values
            .Concat(ExplorerViewModel.VisibleIncludedScopes)
            .GroupBy(scope => scope.StableId, StringComparer.Ordinal)
            .Select(group => group.First())
            .Where(CanScopeFilterProcessListing)
            .ToList();
    }

    private List<ExplorerScope> GetProcessListingSelectedScopes()
    {
        return HasGreenIncludedSelection()
            ? []
            : ExplorerViewModel.SelectedNodeAndLoadedDescendantScopes
                .Where(scope => string.IsNullOrWhiteSpace(scope.ProcessKey))
                .Where(CanScopeFilterProcessListing)
                .ToList();
    }

    private List<ExplorerScope> GetSelectedDirectChildScopes()
    {
        return HasGreenIncludedSelection()
            ? []
            : ExplorerViewModel.SelectedScopes
                .Where(scope => !string.IsNullOrWhiteSpace(scope.ProcessKey))
                .ToList();
    }

    private bool HasGreenIncludedSelection()
    {
        return _includedProcessKeys.Count > 0 ||
               _includedScopes.Count > 0 ||
               ExplorerViewModel.VisibleIncludedScopes.Count > 0;
    }

    private static string GetScopedSelectionGroupKey(ExplorerScope scope)
    {
        if (scope.Status.HasValue)
        {
            return "status";
        }

        if (!string.IsNullOrWhiteSpace(scope.OwnerKey))
        {
            return "owner";
        }

        if (!string.IsNullOrWhiteSpace(scope.ProcessKey))
        {
            return "process-tree";
        }

        if (scope.ArtifactScope != ExplorerArtifactScope.None)
        {
            return "artifact";
        }

        if (!string.IsNullOrWhiteSpace(scope.EventSource))
        {
            return "event-source";
        }

        if (scope.Kind == ExplorerScopeKind.Bookmarked)
        {
            return "annotation";
        }

        if (!string.IsNullOrWhiteSpace(scope.CaseId) ||
            !string.IsNullOrWhiteSpace(scope.EvidenceSessionId) ||
            !string.IsNullOrWhiteSpace(scope.CaptureId) ||
            !string.IsNullOrWhiteSpace(scope.SourceIdentityId) ||
            !string.IsNullOrWhiteSpace(scope.HostId) ||
            !string.IsNullOrWhiteSpace(scope.ExecutionRootId))
        {
            return "identity";
        }

        return scope.Kind.ToString();
    }

    private List<ExplorerScope> GetProcessListingExcludedScopes()
    {
        return _excludedScopes.Values
            .Concat(ExplorerViewModel.VisibleExcludedScopes)
            .GroupBy(scope => scope.StableId, StringComparer.Ordinal)
            .Select(group => group.First())
            .Where(CanScopeFilterProcessListing)
            .ToList();
    }

    private static ProcessListingSortColumn MapSortColumn(string column) => column switch
    {
        "Tree"              => ProcessListingSortColumn.Tree,
        "ProcessName"       => ProcessListingSortColumn.ProcessName,
        "ProcessId"         => ProcessListingSortColumn.ProcessId,
        "ParentProcessId"   => ProcessListingSortColumn.ParentProcessId,
        "ParentProcessName" => ProcessListingSortColumn.ParentProcessName,
        "ProcessPath"       => ProcessListingSortColumn.ProcessPath,
        "CommandLine"       => ProcessListingSortColumn.CommandLine,
        "UserName"          => ProcessListingSortColumn.UserName,
        "SessionId"         => ProcessListingSortColumn.SessionId,
        "Architecture"      => ProcessListingSortColumn.Architecture,
        "StartTimeDisplay"  => ProcessListingSortColumn.StartTime,
        "EndTimeDisplay"    => ProcessListingSortColumn.EndTime,
        "StatusDisplay"     => ProcessListingSortColumn.Status,
        "CpuUsage"          => ProcessListingSortColumn.CpuUsage,
        "MemoryUsage"       => ProcessListingSortColumn.MemoryUsage,
        "CompanyName"       => ProcessListingSortColumn.CompanyName,
        "FileDescription"   => ProcessListingSortColumn.FileDescription,
        "Sha256Hash"        => ProcessListingSortColumn.Sha256Hash,
        "RiskScore"         => ProcessListingSortColumn.ProcessRisk,
        _                   => ProcessListingSortColumn.Unknown
    };

    public void RequestProcessListingRange(int firstIndex, int itemCount = 1)
        => _virtualizedProcessListing?.RequestRange(firstIndex, itemCount);

    private void AttachVirtualizedProcessListing(
        VirtualizedProcessCollection collection,
        ProcessRowViewModel? selectedRow,
        bool navigateToSelection = true)
    {
        var previous = DetachVirtualizedProcessListing();
        _virtualizedProcessListing = collection;
        collection.CacheChanged += OnVirtualizedProcessListingChanged;
        Processes = new ObservableCollection<ProcessRowViewModel>();
        ProcessesView = CollectionViewSource.GetDefaultView(collection);
        TotalProcessCount = collection.Count;
        SelectedProcess = selectedRow;
        collection.PreserveSelection(selectedRow);
        OnVirtualizedProcessListingChanged(collection, EventArgs.Empty);
        if (selectedRow != null && navigateToSelection)
        {
            ProcessesView?.MoveCurrentTo(selectedRow);
            ProcessRowNavigationRequested?.Invoke(selectedRow);
        }

        previous?.Dispose();
    }

    private VirtualizedProcessCollection? DetachVirtualizedProcessListing()
    {
        var previous = _virtualizedProcessListing;
        if (previous != null)
        {
            previous.CacheChanged -= OnVirtualizedProcessListingChanged;
            _virtualizedProcessListing = null;
        }

        return previous;
    }

    private void OnVirtualizedProcessListingChanged(object? sender, EventArgs e)
    {
        if (sender is not VirtualizedProcessCollection collection ||
            !ReferenceEquals(collection, _virtualizedProcessListing))
        {
            return;
        }

        var loadedRows = collection.GetLoadedRows();
        _processViewModels.Clear();
        foreach (var row in loadedRows)
        {
            _processViewModels[row.ProcessKey] = row;
        }

        TotalProcessCount = collection.Count;
        RunningProcessCount = loadedRows.Count(row => !row.IsExited);
        ExitedProcessCount = loadedRows.Count(row => row.IsExited);
        IsProcessListingLoading = collection.IsLoading;
        ProcessListingStatus = collection.StatusMessage;
    }
}
