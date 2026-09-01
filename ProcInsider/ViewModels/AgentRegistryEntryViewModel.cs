using System;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.AgentIpc;

namespace ProcInsider.ViewModels;

public partial class AgentRegistryEntryViewModel : ViewModelBase
{
    [ObservableProperty]
    private string agentId = string.Empty;

    [ObservableProperty]
    private string hostId = string.Empty;

    [ObservableProperty]
    private string displayName = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TransportKindDisplay))]
    private AgentTransportKind transportKind;

    [ObservableProperty]
    private string endpoint = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CapabilitiesDisplay))]
    private AgentCapabilityFlags capabilities = AgentCapabilityFlags.Unknown;

    [ObservableProperty]
    private string configurationVersion = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConfigurationHashDisplay))]
    private string configurationHash = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CaptureConfigurationDisplay))]
    private string captureConfigurationVersion = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CaptureConfigurationHashDisplay))]
    [NotifyPropertyChangedFor(nameof(CaptureConfigurationDisplay))]
    private string captureConfigurationHash = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ActiveCaptureDisplay))]
    private string activeCaptureId = string.Empty;

    [ObservableProperty]
    private string captureSourceSummary = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastCaptureActivityDisplay))]
    private DateTime? lastCaptureStartedUtc;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastCaptureActivityDisplay))]
    private DateTime? lastCaptureStoppedUtc;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastCaptureActivityDisplay))]
    private DateTime? lastCaptureCheckedUtc;

    [ObservableProperty]
    private string captureStatusSummary = "No capture configuration saved.";

    [ObservableProperty]
    private string captureStatusDetails = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ViewerConnectionDisplay))]
    private bool isViewerConnected;

    [ObservableProperty]
    private bool isTerminationConfirmationPending;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ViewerConnectionDisplay))]
    [NotifyPropertyChangedFor(nameof(PairingStateDisplay))]
    private bool isInfrastructureProjection;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ViewerConnectionDisplay))]
    [NotifyPropertyChangedFor(nameof(InfrastructureStateDisplay))]
    private InfrastructureAgentProjectionState infrastructureState;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PairingStateDisplay))]
    private InfrastructureAgentEnrollmentState infrastructureEnrollmentState;

    [ObservableProperty]
    private string infrastructureCaseId = string.Empty;

    [ObservableProperty]
    private long infrastructureCredentialEpoch;

    [ObservableProperty]
    private Guid infrastructureConnectionGeneration;

    [ObservableProperty]
    private long infrastructureServerSessionGeneration;

    [ObservableProperty]
    private int infrastructureProtocolGeneration;

    [ObservableProperty]
    private string infrastructureReleaseId = string.Empty;

    [ObservableProperty]
    private DateTime? infrastructureFreshUntilUtc;

    [ObservableProperty]
    private bool isInfrastructureCommandEligible;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PairingStateDisplay))]
    private AgentPairingState pairingState = AgentPairingState.Unknown;

    [ObservableProperty]
    private string pairingStatus = "Pairing status has not been checked.";

    [ObservableProperty]
    private long pairingGeneration;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PairingExpiryDisplay))]
    private DateTime? pairingExpiresAtUtc;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DeploymentStateDisplay))]
    private AgentDeploymentState deploymentState = AgentDeploymentState.Unknown;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CaptureStateDisplay))]
    private AgentCaptureState captureState = AgentCaptureState.Unknown;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(OperationalCaptureStateDisplay))]
    [NotifyPropertyChangedFor(nameof(ConfiguredCapturePrimaryActionLabel))]
    private AgentCaptureRunState operationalCaptureState = AgentCaptureRunState.Unknown;

    [ObservableProperty]
    private AgentControlSnapshotStatus captureSnapshotStatus = AgentControlSnapshotStatus.Unknown;

    [ObservableProperty]
    private bool canStartCapture;

    [ObservableProperty]
    private bool canStopCapture;

    [ObservableProperty]
    private bool canPauseCapture;

    [ObservableProperty]
    private bool canResumeCapture;

    [ObservableProperty]
    private bool canEndCapture;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CaptureSnapshotDisplay))]
    private DateTime? captureSnapshotUtc;

    [ObservableProperty]
    private string operationalCaptureStatus = "Capture runtime: Unknown.";

    [ObservableProperty]
    private string operationalCaptureDetail = "Waiting for an authoritative agent control snapshot.";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastCheckDisplay))]
    private DateTime? lastCheckUtc;

    [ObservableProperty]
    private string lastError = string.Empty;

    [ObservableProperty]
    private string healthSummary = "Status has not been checked.";

    [ObservableProperty]
    private string lastConfigurationCheckSummary = "No configuration check has run.";

    [ObservableProperty]
    private string lastConfigurationCheckDetails = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasMonitoringOriginalState))]
    [NotifyPropertyChangedFor(nameof(MonitoringOriginalStateDisplay))]
    private DateTime? monitoringOriginalStateCapturedUtc;

    [ObservableProperty]
    private string monitoringOriginalStateSummary = "No original monitoring baseline captured.";

    [ObservableProperty]
    private string monitoringOriginalStateDetails = string.Empty;

    [ObservableProperty]
    private string benchmarkPreflightSummary = "Benchmark preflight has not run.";

    [ObservableProperty]
    private string benchmarkStatusSummary = "No benchmark has run.";

    [ObservableProperty]
    private string benchmarkStatusDetails = string.Empty;

    [ObservableProperty]
    private string benchmarkDatabasePath = string.Empty;

    [ObservableProperty]
    private string benchmarkReportPath = string.Empty;

    [ObservableProperty]
    private string benchmarkJsonReportPath = string.Empty;

    [ObservableProperty]
    private string benchmarkPerformanceProfile = "Conservative";

    [ObservableProperty]
    private bool isBenchmarkRunning;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AgentMemoryLimitDisplay))]
    private int agentMemoryLimitMegabytes = 500;

    public AgentRegistryEntryViewModel(AgentRegistryEntry entry)
    {
        foreach (var option in AgentCaptureOptionViewModel.CreateDefaultOptions())
        {
            CaptureOptions.Add(option);
        }

        ApplyRegistryEntry(entry);
    }

    public ObservableCollection<AgentCaptureOptionViewModel> CaptureOptions { get; } = new();

    public ObservableCollection<AgentBenchmarkResultRowViewModel> BenchmarkResultRows { get; } = new();

    public AgentHostMonitoringConfiguration? HostMonitoringConfiguration { get; private set; }

    public string TransportKindDisplay => FormatEnum(TransportKind);

    public string DeploymentStateDisplay => FormatEnum(DeploymentState);

    public string CaptureStateDisplay => FormatEnum(CaptureState);

    public string OperationalCaptureStateDisplay => FormatEnum(OperationalCaptureState);

    public string ConfiguredCapturePrimaryActionLabel =>
        OperationalCaptureState == AgentCaptureRunState.Paused ? "Resume Capture" : "Start Capture";

    public string CaptureConfigurationDisplay => string.IsNullOrWhiteSpace(CaptureConfigurationHash) ||
                                                 string.Equals(CaptureConfigurationHash, "pending", StringComparison.OrdinalIgnoreCase)
        ? "Not saved"
        : string.IsNullOrWhiteSpace(CaptureConfigurationVersion)
            ? CaptureConfigurationHashDisplay
            : $"{CaptureConfigurationVersion} / {CaptureConfigurationHashDisplay}";

    public string CaptureSnapshotDisplay => CaptureSnapshotUtc.HasValue
        ? CaptureSnapshotUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        : "No authoritative snapshot";

    public string ViewerConnectionDisplay => IsInfrastructureProjection
        ? InfrastructureState == InfrastructureAgentProjectionState.Authenticated
            ? "Via Server"
            : "Server projected"
        : IsViewerConnected ? "Connected" : "Not connected";

    public string PairingStateDisplay => IsInfrastructureProjection
        ? $"Enrollment {FormatEnum(InfrastructureEnrollmentState)}"
        : FormatEnum(PairingState);

    public string InfrastructureStateDisplay => FormatEnum(InfrastructureState);

    public string PairingExpiryDisplay => PairingExpiresAtUtc.HasValue
        ? PairingExpiresAtUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        : "Not available";

    public string CapabilitiesDisplay => Capabilities == AgentCapabilityFlags.Unknown
        ? "Unknown"
        : string.Join(", ", Enum.GetValues<AgentCapabilityFlags>()
            .Where(flag => flag != AgentCapabilityFlags.Unknown && Capabilities.HasFlag(flag))
            .Select(FormatEnum));

    public string ConfigurationHashDisplay => string.IsNullOrWhiteSpace(ConfigurationHash)
        ? string.Empty
        : ConfigurationHash.Length <= 16 ? ConfigurationHash : ConfigurationHash[..16];

    public string CaptureConfigurationHashDisplay => string.IsNullOrWhiteSpace(CaptureConfigurationHash)
        ? string.Empty
        : CaptureConfigurationHash.Length <= 16 ? CaptureConfigurationHash : CaptureConfigurationHash[..16];

    public string ActiveCaptureDisplay => string.IsNullOrWhiteSpace(ActiveCaptureId)
        ? "<none>"
        : ActiveCaptureId;

    public string AgentMemoryLimitDisplay => AgentMemoryLimitMegabytes >= 1024 && AgentMemoryLimitMegabytes % 1024 == 0
        ? $"{AgentMemoryLimitMegabytes / 1024:N0} GB"
        : $"{AgentMemoryLimitMegabytes:N0} MB";

    public string LastCheckDisplay => LastCheckUtc.HasValue
        ? LastCheckUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        : "Never";

    public bool HasMonitoringOriginalState => MonitoringOriginalStateCapturedUtc.HasValue;

    public string MonitoringOriginalStateDisplay => MonitoringOriginalStateCapturedUtc.HasValue
        ? $"Original config captured {MonitoringOriginalStateCapturedUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}"
        : "Original config baseline: none";

    public string LastCaptureActivityDisplay
    {
        get
        {
            var latest = new[] { LastCaptureStartedUtc, LastCaptureStoppedUtc, LastCaptureCheckedUtc }
                .Where(value => value.HasValue)
                .Select(value => value!.Value)
                .DefaultIfEmpty()
                .Max();
            return latest == default
                ? "Never"
                : latest.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        }
    }

    public void ApplyRegistryEntry(AgentRegistryEntry entry)
    {
        AgentId = entry.AgentId;
        HostId = entry.HostId;
        DisplayName = entry.DisplayName;
        TransportKind = entry.TransportKind;
        Endpoint = entry.Endpoint;
        Capabilities = entry.Capabilities;
        ConfigurationVersion = entry.ConfigurationVersion;
        ConfigurationHash = entry.ConfigurationHash;
        DeploymentState = entry.DeploymentState;
        CaptureState = entry.CaptureState;
        LastCheckUtc = entry.LastCheckUtc;
        LastError = entry.LastError;
    }

    public void ApplyInfrastructureProjection(InfrastructureAgentProjectionRow projection)
    {
        ArgumentNullException.ThrowIfNull(projection);
        IsInfrastructureProjection = true;
        AgentId = projection.AgentId;
        HostId = projection.HostId;
        DisplayName = projection.DisplayName;
        TransportKind = AgentTransportKind.RemoteHttp;
        Endpoint = "DFIRoscope Server";
        Capabilities = projection.Capabilities.Contains(
            InfrastructureSessionCapabilities.HealthProjectionV1,
            StringComparer.Ordinal)
            ? AgentCapabilityFlags.Health
            : AgentCapabilityFlags.Unknown;
        ConfigurationVersion = $"revision-{projection.ConfigurationRevision}";
        ConfigurationHash = string.Empty;
        DeploymentState = projection.State switch
        {
            InfrastructureAgentProjectionState.Authenticated => AgentDeploymentState.Available,
            InfrastructureAgentProjectionState.Configured => AgentDeploymentState.Deployed,
            InfrastructureAgentProjectionState.Connecting => AgentDeploymentState.Deployed,
            InfrastructureAgentProjectionState.Error => AgentDeploymentState.Failed,
            _ => AgentDeploymentState.Unavailable
        };
        CaptureState = AgentCaptureState.Unknown;
        LastCheckUtc = projection.HealthObservedAtUtc;
        LastError = projection.ErrorMessage;
        HealthSummary = $"Infrastructure {FormatEnum(projection.State)} via Server for case " +
                        $"{projection.CaseId}; release {projection.ReleaseId}, protocol " +
                        $"{projection.ProtocolGeneration}" +
                        (string.IsNullOrWhiteSpace(projection.AvailabilityCode)
                            ? string.Empty
                            : $"; {projection.AvailabilityCode}") +
                        (string.IsNullOrWhiteSpace(projection.ErrorMessage)
                            ? "."
                            : $"; {projection.ErrorMessage}");
        IsViewerConnected = false;
        PairingState = AgentPairingState.Unknown;
        PairingGeneration = projection.CredentialEpoch;
        PairingExpiresAtUtc = projection.FreshUntilUtc == DateTime.MinValue
            ? null
            : projection.FreshUntilUtc;
        PairingStatus = $"Infrastructure enrollment {FormatEnum(projection.EnrollmentState)}; " +
                        "credential and connection generations are Server-authoritative.";
        InfrastructureState = projection.State;
        InfrastructureEnrollmentState = projection.EnrollmentState;
        InfrastructureCaseId = projection.CaseId;
        InfrastructureCredentialEpoch = projection.CredentialEpoch;
        InfrastructureConnectionGeneration = projection.ConnectionGeneration;
        InfrastructureServerSessionGeneration = projection.ServerSessionGeneration;
        InfrastructureProtocolGeneration = projection.ProtocolGeneration;
        InfrastructureReleaseId = projection.ReleaseId;
        InfrastructureFreshUntilUtc = projection.FreshUntilUtc == DateTime.MinValue
            ? null
            : projection.FreshUntilUtc;
        IsInfrastructureCommandEligible = false;
        CanStartCapture = false;
        CanStopCapture = false;
        CanPauseCapture = false;
        CanResumeCapture = false;
        CanEndCapture = false;
    }

    public void ApplyHealth(AgentIpcResponse response, bool isActiveSession)
    {
        LastCheckUtc = DateTime.UtcNow;

        if (!response.Success)
        {
            var failure = FormatIpcFailure(response, "Agent health check failed.");
            DeploymentState = AgentDeploymentState.Unavailable;
            CaptureState = AgentCaptureState.Unknown;
            LastError = failure;
            HealthSummary = $"Unavailable: {failure}";
            return;
        }

        if (response.Health == null)
        {
            LastError = string.Empty;
            HealthSummary = "Agent responded without a health snapshot.";
            return;
        }

        HostId = FirstNonEmpty(response.Health.MachineName, HostId);

        if (!isActiveSession)
        {
            DeploymentState = AgentDeploymentState.Unavailable;
            CaptureState = AgentCaptureState.Unknown;
            LastError = string.IsNullOrWhiteSpace(response.Health.DatabasePath)
                ? "Agent health did not report a database path, so the viewer cannot verify the active session."
                : $"Agent is attached to another session database: {response.Health.DatabasePath}";
            HealthSummary = string.IsNullOrWhiteSpace(response.Health.DatabasePath)
                ? $"Unverified session (PID {response.Health.ProcessId})"
                : $"Different session (PID {response.Health.ProcessId})";
            return;
        }

        DeploymentState = AgentDeploymentState.Available;
        CaptureState = MapCaptureState(response.Health.CaptureHealth.Health);
        var releaseProfileError = response.Health.ReleaseProfile.Match == AgentReleaseProfileMatch.Match
            ? string.Empty
            : FirstNonEmpty(
                response.Health.ReleaseProfile.Status,
                "Agent release profile was not reported.");
        LastError = FirstNonEmpty(
            releaseProfileError,
            response.Health.Runtime.LastError,
            response.Health.Runtime.LiveDatabaseDiagnostics?.Error,
            response.Health.Runtime.WriterLastSqliteError,
            string.Empty);
        var connection = IsViewerConnected ? "connected" : "reachable";
        HealthSummary =
            $"Agent {connection}, PID {response.Health.ProcessId}, {response.Health.CaptureHealth.Health.ToString().ToLowerInvariant()}" +
            FormatReleaseProfileSummary(response.Health.ReleaseProfile) +
            FormatLiveBufferSummary(response.Health.CaptureHealth) +
            FormatPeAnalysisSummary(response.Health.Runtime.ArtifactEnrichment) +
            FormatSqliteSummary(response.Health.Runtime.LiveDatabaseDiagnostics);
        if (response.Health.CaptureHealth.LiveBufferDrainingAfterStop ||
            response.Health.CaptureHealth.LiveBufferPendingRecords > 0)
        {
            CaptureStatusSummary = FormatLiveBufferStatus(response.Health.CaptureHealth);
        }
    }

    public void ApplyPairingStatus(
        AgentPairingStoreResult status,
        bool authenticated = false)
    {
        ArgumentNullException.ThrowIfNull(status);
        PairingState = authenticated && status.State == AgentPairingState.Ready
            ? AgentPairingState.Connected
            : status.State;
        PairingGeneration = status.PairingGeneration;
        PairingExpiresAtUtc = status.ExpiresAtUtc;
        PairingStatus = status.Status;
        if (PairingState is AgentPairingState.RePairRequired or
            AgentPairingState.Revoked or
            AgentPairingState.Expired or
            AgentPairingState.Corrupt or
            AgentPairingState.WrongUser or
            AgentPairingState.WrongSession or
            AgentPairingState.WrongRelease or
            AgentPairingState.AgentExited or
            AgentPairingState.ProcessMismatch)
        {
            IsViewerConnected = false;
        }
    }

    public void ApplyControlProjection(AgentCaptureControlViewState projection)
    {
        ArgumentNullException.ThrowIfNull(projection);

        OperationalCaptureState = projection.State;
        CaptureSnapshotStatus = projection.SnapshotStatus;
        CanStartCapture = projection.CanStart;
        CanStopCapture = projection.CanStop;
        CanPauseCapture = projection.CanPause;
        CanResumeCapture = projection.CanResume;
        CanEndCapture = projection.CanEnd;
        CaptureSnapshotUtc = projection.SnapshotEmittedAtUtc;
        OperationalCaptureStatus = projection.StatusText;
        OperationalCaptureDetail = projection.StatusDetail;
        CaptureStatusSummary = projection.StatusText;
        CaptureStatusDetails = projection.StatusDetail;

        if (!string.IsNullOrWhiteSpace(projection.ActiveCaptureId))
        {
            ActiveCaptureId = projection.ActiveCaptureId;
        }
        else if (projection.SnapshotStatus == AgentControlSnapshotStatus.Current &&
                 projection.PendingAction == AgentCapturePendingAction.None &&
                 projection.State is AgentCaptureRunState.Off or AgentCaptureRunState.Failed)
        {
            ActiveCaptureId = string.Empty;
        }

        CaptureState = projection.State switch
        {
            AgentCaptureRunState.Off => AgentCaptureState.Idle,
            AgentCaptureRunState.Starting or AgentCaptureRunState.Running or AgentCaptureRunState.Paused => AgentCaptureState.Healthy,
            AgentCaptureRunState.Pausing or AgentCaptureRunState.Resuming or AgentCaptureRunState.Stopping or AgentCaptureRunState.Draining => AgentCaptureState.Degraded,
            AgentCaptureRunState.Failed => AgentCaptureState.Error,
            _ => AgentCaptureState.Unknown
        };
    }

    private static string FormatReleaseProfileSummary(AgentReleaseProfileSnapshot profile)
    {
        return profile.Match switch
        {
            AgentReleaseProfileMatch.Match => string.IsNullOrWhiteSpace(profile.ReleaseId)
                ? ", release profile matched"
                : $", release {profile.ReleaseId}",
            AgentReleaseProfileMatch.Mismatch =>
                $", release mismatch (viewer {FirstNonEmpty(profile.ViewerReleaseId, "<not supplied>")}; agent {FirstNonEmpty(profile.ReleaseId, "<not reported>")})",
            _ => ", release profile not verified"
        };
    }

    public void ApplyConfigurationCheck(AgentConfigurationCheckResult result)
    {
        LastCheckUtc = result.CheckedAtUtc;
        HostId = FirstNonEmpty(result.HostId, HostId);
        LastError = result.LastError;
        LastConfigurationCheckSummary = BuildConfigurationCheckSummary(result);
        LastConfigurationCheckDetails = BuildConfigurationCheckDetails(result);

        if (result.TargetKind == AgentConfigurationTargetKind.HostMonitoring)
        {
            ConfigurationVersion = FirstNonEmpty(result.ConfigurationVersion, ConfigurationVersion);
            ConfigurationHash = FirstNonEmpty(result.ConfigurationHash, ConfigurationHash);
            DeploymentState = result.OverallState == AgentConfigurationCheckState.Blocked
                ? AgentDeploymentState.Failed
                : AgentDeploymentState.Available;
        }
        else if (result.TargetKind == AgentConfigurationTargetKind.Capture)
        {
            LastCaptureCheckedUtc = result.CheckedAtUtc;
            CaptureStatusSummary = LastConfigurationCheckSummary;
            CaptureStatusDetails = LastConfigurationCheckDetails;
            CaptureState = result.OverallState switch
            {
                AgentConfigurationCheckState.Ready => AgentCaptureState.Idle,
                AgentConfigurationCheckState.Warning => AgentCaptureState.Degraded,
                AgentConfigurationCheckState.Blocked => AgentCaptureState.Error,
                _ => AgentCaptureState.Unknown
            };
        }
    }

    public void ApplyHostMonitoringConfiguration(AgentHostMonitoringConfiguration configuration)
    {
        HostMonitoringConfiguration = configuration;
        ApplyMonitoringOriginalState(configuration.OriginalState);
        LastCheckUtc = DateTime.UtcNow;
        HostId = FirstNonEmpty(configuration.HostId, HostId);
        ConfigurationVersion = FirstNonEmpty(configuration.ConfigurationVersion, ConfigurationVersion);
        ConfigurationHash = FirstNonEmpty(configuration.ConfigurationHash, ConfigurationHash);
        DeploymentState = AgentDeploymentState.Available;
        LastError = configuration.LastError;
        LastConfigurationCheckSummary = $"Monitoring configuration saved: {ConfigurationVersion} / {ConfigurationHashDisplay}.";
        LastConfigurationCheckDetails =
            $"Sysmon={configuration.Sysmon.ProfileDisplayName}; Security={configuration.SecurityAuditPolicy.PolicyProfileDisplayName}; " +
            $"cmdLineLogging={configuration.SecurityAuditPolicy.EnableProcessCommandLineLogging}; " +
            $"PowerShell={configuration.PowerShellAuditing.ProfileId}; ETW={configuration.Etw.ProfileDisplayName}; " +
            $"scheduledDumps={(configuration.ScheduledDumps.Enabled ? "enabled" : "disabled")}.";
    }

    public void ApplyMonitoringDeployment(AgentMonitoringDeploymentResult result)
    {
        ApplyMonitoringOriginalState(result.OriginalState);
        LastCheckUtc = result.CompletedAtUtc ?? DateTime.UtcNow;
        HostId = FirstNonEmpty(result.HostId, HostId);
        ConfigurationVersion = FirstNonEmpty(result.ConfigurationVersion, ConfigurationVersion);
        ConfigurationHash = FirstNonEmpty(result.ConfigurationHash, ConfigurationHash);
        LastError = result.LastError;
        LastConfigurationCheckSummary = BuildDeploymentSummary(result);
        LastConfigurationCheckDetails = BuildDeploymentDetails(result);

        DeploymentState = result.Status switch
        {
            AgentConfigurationOperationStatus.Failed => AgentDeploymentState.Failed,
            _ when result.Action == AgentMonitoringDeploymentAction.Deploy => AgentDeploymentState.Deployed,
            _ when result.Action == AgentMonitoringDeploymentAction.Reverse => AgentDeploymentState.Available,
            _ => DeploymentState
        };
    }

    public void ApplyCaptureConfiguration(AgentCaptureConfiguration configuration)
    {
        LastCaptureCheckedUtc = DateTime.UtcNow;
        HostId = FirstNonEmpty(configuration.HostId, HostId);
        CaptureConfigurationVersion = FirstNonEmpty(configuration.ConfigurationVersion, CaptureConfigurationVersion);
        CaptureConfigurationHash = FirstNonEmpty(configuration.ConfigurationHash, CaptureConfigurationHash);
        CaptureSourceSummary = BuildCaptureSourceSummary(configuration);
        CaptureState = AgentCaptureState.Idle;
        LastError = configuration.LastError;
        CaptureStatusSummary = $"Capture configuration saved: {CaptureConfigurationVersion} / {CaptureConfigurationHashDisplay}.";
        CaptureStatusDetails =
            $"Sources={CaptureSourceSummary}; " +
            $"network={(configuration.NetworkCapture.Enabled ? "enabled" : "disabled")}; " +
            $"Zeek={(configuration.Zeek.Enabled || configuration.Zeek.RunAfterNetworkCapture ? "enabled" : "disabled")}; " +
            $"artifacts=modules:{configuration.ArtifactCapture.CaptureModules}, handles:{configuration.ArtifactCapture.CaptureHandles}, pe:{configuration.ArtifactCapture.CapturePeMetadata}.";
        LastConfigurationCheckSummary = CaptureStatusSummary;
        LastConfigurationCheckDetails = CaptureStatusDetails;
        AgentCaptureOptionViewModel.ApplyConfiguration(CaptureOptions, configuration);
        UpdateCaptureOptionConfigurationStatuses();
    }

    public void ApplyCaptureLifecycle(AgentCaptureLifecycleResult result)
    {
        LastCheckUtc = result.CompletedAtUtc ?? DateTime.UtcNow;
        HostId = FirstNonEmpty(result.HostId, HostId);
        CaptureConfigurationVersion = FirstNonEmpty(result.ConfigurationVersion, CaptureConfigurationVersion);
        CaptureConfigurationHash = FirstNonEmpty(result.ConfigurationHash, CaptureConfigurationHash);
        ActiveCaptureId = FirstNonEmpty(result.CaptureId, ActiveCaptureId);
        LastError = result.LastError;
        CaptureStatusSummary = BuildCaptureLifecycleSummary(result);
        CaptureStatusDetails = FirstNonEmpty(result.Message, result.LastError, CaptureStatusDetails);
        LastConfigurationCheckSummary = CaptureStatusSummary;
        LastConfigurationCheckDetails = CaptureStatusDetails;

        if (result.Action == AgentCaptureLifecycleAction.Start)
        {
            LastCaptureStartedUtc = result.StartedAtUtc;
            CaptureState = result.Status == AgentConfigurationOperationStatus.Failed
                ? AgentCaptureState.Error
                : AgentCaptureState.Healthy;
        }
        else if (result.Action == AgentCaptureLifecycleAction.Stop)
        {
            LastCaptureStoppedUtc = result.CompletedAtUtc;
            CaptureState = result.Status == AgentConfigurationOperationStatus.Failed
                ? AgentCaptureState.Error
                : result.CompletedAtUtc.HasValue
                    ? AgentCaptureState.Idle
                    : AgentCaptureState.Degraded;
        }
        else if (result.Action == AgentCaptureLifecycleAction.Pause)
        {
            CaptureState = result.Status == AgentConfigurationOperationStatus.Failed
                ? AgentCaptureState.Error
                : AgentCaptureState.Healthy;
        }
        else if (result.Action == AgentCaptureLifecycleAction.Resume)
        {
            CaptureState = result.Status == AgentConfigurationOperationStatus.Failed
                ? AgentCaptureState.Error
                : AgentCaptureState.Healthy;
        }

        UpdateCaptureOptionLifecycleStatuses(result);
    }

    public void ApplyCaptureOptionSelections(IEnumerable<AgentCaptureOptionViewModel> options)
    {
        foreach (var source in options)
        {
            var target = CaptureOptions.FirstOrDefault(option => option.Kind == source.Kind);
            if (target?.CanConfigure == true)
            {
                target.IsIncluded = source.IsIncluded;
            }
        }

        CaptureSourceSummary = BuildCaptureSourceSummary(CaptureOptions);
        CaptureStatusSummary = "Capture configuration draft selected.";
        CaptureStatusDetails = $"Sources={CaptureSourceSummary}.";
        UpdateCaptureOptionConfigurationStatuses();
    }

    public void ApplyTelemetryStats(TelemetryStoreStats stats)
    {
        AgentCaptureOptionViewModel.ApplyTelemetryStats(CaptureOptions, stats);
    }

    public void ResetSessionState(string message)
    {
        ConfigurationVersion = string.Empty;
        ConfigurationHash = string.Empty;
        CaptureConfigurationVersion = string.Empty;
        CaptureConfigurationHash = string.Empty;
        ActiveCaptureId = string.Empty;
        CaptureSourceSummary = string.Empty;
        LastCaptureStartedUtc = null;
        LastCaptureStoppedUtc = null;
        LastCaptureCheckedUtc = null;
        CaptureStatusSummary = "No capture workspace is attached.";
        CaptureStatusDetails = string.Empty;
        OperationalCaptureState = AgentCaptureRunState.Unknown;
        CaptureSnapshotStatus = AgentControlSnapshotStatus.Unknown;
        CanStartCapture = false;
        CanStopCapture = false;
        CanPauseCapture = false;
        CanResumeCapture = false;
        CanEndCapture = false;
        CaptureSnapshotUtc = null;
        OperationalCaptureStatus = "Capture runtime: Unknown.";
        OperationalCaptureDetail = message;
        IsViewerConnected = false;
        PairingState = AgentPairingState.Unknown;
        PairingStatus = "Pairing status is detached from the previous session.";
        PairingGeneration = 0;
        PairingExpiresAtUtc = null;
        DeploymentState = AgentDeploymentState.Unavailable;
        CaptureState = AgentCaptureState.Unknown;
        LastCheckUtc = DateTime.UtcNow;
        LastError = string.Empty;
        HealthSummary = message;
        LastConfigurationCheckSummary = "No configuration check has run for this workspace.";
        LastConfigurationCheckDetails = string.Empty;
        HostMonitoringConfiguration = null;
        MonitoringOriginalStateCapturedUtc = null;
        MonitoringOriginalStateSummary = "No original monitoring baseline loaded for this workspace.";
        MonitoringOriginalStateDetails = string.Empty;
        BenchmarkPreflightSummary = "Benchmark preflight has not run for this workspace.";
        BenchmarkStatusSummary = "No benchmark has run for this workspace.";
        BenchmarkStatusDetails = string.Empty;
        BenchmarkDatabasePath = string.Empty;
        BenchmarkReportPath = string.Empty;
        BenchmarkJsonReportPath = string.Empty;
        IsBenchmarkRunning = false;
        BenchmarkResultRows.Clear();
        ApplyTelemetryStats(new TelemetryStoreStats());
    }

    public void SetCaptureOptionStatus(AgentCaptureOptionKind kind, string status)
    {
        var option = CaptureOptions.FirstOrDefault(candidate => candidate.Kind == kind);
        if (option != null)
        {
            option.StatusText = status;
        }
    }

    public void ApplyConfigurationCheckUnavailable(AgentConfigurationTargetKind targetKind, string message)
    {
        LastCheckUtc = DateTime.UtcNow;
        LastError = message;
        LastConfigurationCheckSummary = $"{FormatTargetKind(targetKind)} check unavailable.";
        LastConfigurationCheckDetails = message;

        if (targetKind == AgentConfigurationTargetKind.HostMonitoring)
        {
            DeploymentState = AgentDeploymentState.Unavailable;
        }
        else if (targetKind == AgentConfigurationTargetKind.Capture)
        {
            CaptureState = AgentCaptureState.Unknown;
            CaptureStatusSummary = "Capture check unavailable.";
            CaptureStatusDetails = message;
        }
    }

    public void UpdateBenchmarkPreflight(bool captureIsActive, string benchmarkDirectory)
    {
        var output = !string.IsNullOrWhiteSpace(BenchmarkDatabasePath)
            ? BenchmarkDatabasePath
            : string.IsNullOrWhiteSpace(benchmarkDirectory)
                ? "Benchmark DB path is created when the job starts."
                : $"New DB under {benchmarkDirectory}.";
        var captureState = captureIsActive
            ? "Active capture may affect benchmark results."
            : "Capture is idle for benchmark start.";

        BenchmarkPreflightSummary =
            $"Selected {DisplayName}; capture {CaptureStateDisplay}; profile {BenchmarkPerformanceProfile}; output {output} {captureState}";
    }

    public void ApplyBenchmarkProgress(JobProgress job)
    {
        if (job.JobKind != JobKind.SqliteBenchmark)
        {
            return;
        }

        LastCheckUtc = DateTime.UtcNow;
        LastError = job.ErrorText;
        IsBenchmarkRunning = job.State is JobState.Queued or JobState.Running or JobState.Paused;

        if (job.SqliteBenchmark == null)
        {
            BenchmarkStatusSummary = $"SQLite benchmark {FormatEnum(job.State)}.";
            BenchmarkStatusDetails = FirstNonEmpty(job.ProgressMessage, job.ErrorText, "Waiting for benchmark details.");
            return;
        }

        var result = job.SqliteBenchmark;
        BenchmarkDatabasePath = FirstNonEmpty(result.DatabasePath, BenchmarkDatabasePath);
        BenchmarkReportPath = FirstNonEmpty(result.ReportPath, BenchmarkReportPath);
        BenchmarkJsonReportPath = FirstNonEmpty(result.JsonReportPath, BenchmarkJsonReportPath);
        BenchmarkPerformanceProfile = FirstNonEmpty(result.PerformanceProfile, BenchmarkPerformanceProfile);
        BenchmarkStatusSummary = BuildBenchmarkSummary(job, result);
        BenchmarkStatusDetails = BuildBenchmarkDetails(job, result);
        ReplaceBenchmarkRows(job, result);
    }

    public void ApplyBenchmarkUnavailable(string message)
    {
        LastCheckUtc = DateTime.UtcNow;
        LastError = message;
        IsBenchmarkRunning = false;
        BenchmarkStatusSummary = "SQLite benchmark unavailable.";
        BenchmarkStatusDetails = message;
    }

    private static AgentCaptureState MapCaptureState(CaptureHealth health)
    {
        return health switch
        {
            CaptureHealth.Idle => AgentCaptureState.Idle,
            CaptureHealth.Healthy => AgentCaptureState.Healthy,
            CaptureHealth.Degraded => AgentCaptureState.Degraded,
            CaptureHealth.Error => AgentCaptureState.Error,
            _ => AgentCaptureState.Unknown
        };
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
    }

    private static string FormatIpcFailure(AgentIpcResponse response, string fallback)
    {
        var parts = new[]
            {
                response.ErrorCode,
                response.ErrorMessage,
                response.RequestId == Guid.Empty ? string.Empty : $"request {response.RequestId}"
            }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();

        return parts.Length == 0 ? fallback : string.Join(": ", parts);
    }

    private static string BuildConfigurationCheckSummary(AgentConfigurationCheckResult result)
    {
        var blocked = result.Findings.Count(finding => finding.Severity == AgentConfigurationFindingSeverity.Blocked);
        var errors = result.Findings.Count(finding => finding.Severity == AgentConfigurationFindingSeverity.Error);
        var warnings = result.Findings.Count(finding => finding.Severity == AgentConfigurationFindingSeverity.Warning);
        return $"{FormatTargetKind(result.TargetKind)} check: {FormatEnum(result.OverallState)} ({blocked} blocked, {errors} errors, {warnings} warnings).";
    }

    private static string BuildConfigurationCheckDetails(AgentConfigurationCheckResult result)
    {
        if (result.Findings.Length == 0)
        {
            return "No findings were returned.";
        }

        return string.Join(Environment.NewLine, result.Findings.Select(finding =>
        {
            var detail = FirstNonEmpty(finding.TechnicalDetail, finding.SuggestedRemediation);
            return string.IsNullOrWhiteSpace(detail)
                ? $"[{FormatEnum(finding.Severity)}] {FormatEnum(finding.Area)}: {finding.Message}"
                : $"[{FormatEnum(finding.Severity)}] {FormatEnum(finding.Area)}: {finding.Message} {detail}";
        }));
    }

    private static string BuildDeploymentSummary(AgentMonitoringDeploymentResult result)
    {
        var failed = result.AreaResults.Count(area => area.Status == AgentConfigurationOperationStatus.Failed);
        var warnings = result.AreaResults.Count(area =>
            area.Status is AgentConfigurationOperationStatus.Warning or AgentConfigurationOperationStatus.Unsupported);
        return $"Monitoring {FormatEnum(result.Action).ToLowerInvariant()}: {FormatEnum(result.Status)} ({failed} failed, {warnings} warnings).";
    }

    private static string BuildDeploymentDetails(AgentMonitoringDeploymentResult result)
    {
        if (result.AreaResults.Length == 0)
        {
            return FirstNonEmpty(result.LastError, "No deployment area results were returned.");
        }

        var lines = result.AreaResults.Select(area =>
        {
            var detail = FirstNonEmpty(area.TechnicalDetail, area.ReverseSupported ? "Reverse supported." : "Reverse not supported.");
            return $"[{FormatEnum(area.Status)}] {FormatEnum(area.Area)}: {area.Message} {detail}";
        });

        return string.Join(Environment.NewLine, lines);
    }

    private static string BuildCaptureLifecycleSummary(AgentCaptureLifecycleResult result)
    {
        var action = FormatEnum(result.Action).ToLowerInvariant();
        var status = FormatEnum(result.Status);
        return string.IsNullOrWhiteSpace(result.CaptureId)
            ? $"Capture {action}: {status}."
            : $"Capture {action}: {status} ({result.CaptureId}).";
    }

    private void ApplyMonitoringOriginalState(AgentMonitoringOriginalStateSnapshot snapshot)
    {
        if (!snapshot.BaselineExists || !snapshot.CapturedAtUtc.HasValue)
        {
            MonitoringOriginalStateCapturedUtc = null;
            MonitoringOriginalStateSummary = "No original monitoring baseline captured.";
            MonitoringOriginalStateDetails = string.Empty;
            return;
        }

        MonitoringOriginalStateCapturedUtc = snapshot.CapturedAtUtc;
        var revertText = snapshot.LastRevertedUtc.HasValue
            ? $" Last revert {snapshot.LastRevertedUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}: {FormatEnum(snapshot.LastRevertStatus)}."
            : string.Empty;
        MonitoringOriginalStateSummary = FirstNonEmpty(snapshot.Summary, "Original host monitoring state captured.") + revertText;
        MonitoringOriginalStateDetails = snapshot.Areas.Length == 0
            ? "No baseline area details were returned."
            : string.Join(Environment.NewLine, snapshot.Areas.Select(area =>
            {
                var detail = FirstNonEmpty(area.Detail, area.RestoreGuidance);
                return string.IsNullOrWhiteSpace(detail)
                    ? $"[{FormatEnum(area.Status)}] {FormatEnum(area.Area)}: {area.Summary}"
                    : $"[{FormatEnum(area.Status)}] {FormatEnum(area.Area)}: {area.Summary} {detail}";
            }));
    }

    private static string BuildCaptureSourceSummary(AgentCaptureConfiguration configuration)
    {
        var sources = new[]
            {
                configuration.SourceToggles.Runtime && configuration.RuntimeProcessSnapshots.Enabled ? "Runtime" : string.Empty,
                configuration.SourceToggles.Etw ? FirstNonEmpty(configuration.Etw.ProfileDisplayName, configuration.Etw.ProfileId, "ETW") : string.Empty,
                configuration.SourceToggles.Security ? "Security" : string.Empty,
                configuration.SourceToggles.PowerShell ? "PowerShell" : string.Empty,
                configuration.SourceToggles.WindowsOther ? "WindowsOther" : string.Empty,
                configuration.SourceToggles.Sysmon ? "Sysmon" : string.Empty,
                configuration.NetworkCapture.Enabled ? "Network" : string.Empty,
                configuration.Zeek.Enabled || configuration.Zeek.RunAfterNetworkCapture ? "Zeek" : string.Empty
            }
            .Where(value => !string.IsNullOrWhiteSpace(value));
        return string.Join(", ", sources.DefaultIfEmpty("none"));
    }

    private static string BuildCaptureSourceSummary(IEnumerable<AgentCaptureOptionViewModel> options)
    {
        var sources = options
            .Where(option => option.CanConfigure && option.IsIncluded)
            .Select(option => option.DisplayName);
        return string.Join(", ", sources.DefaultIfEmpty("none"));
    }

    private void UpdateCaptureOptionConfigurationStatuses()
    {
        foreach (var option in CaptureOptions)
        {
            option.StatusText = option.CanConfigure
                ? option.IsIncluded ? "Enabled in saved configuration." : "Disabled in saved configuration."
                : "Available through a dedicated command or picker.";
        }
    }

    private void UpdateCaptureOptionLifecycleStatuses(AgentCaptureLifecycleResult result)
    {
        var status = result.Action == AgentCaptureLifecycleAction.Start
            ? result.Status == AgentConfigurationOperationStatus.Failed ? "Start failed." : "Start requested."
            : result.Status == AgentConfigurationOperationStatus.Failed ? "Stop failed." : "Stopped.";
        foreach (var option in CaptureOptions.Where(option => option.CanConfigure && option.IsIncluded))
        {
            option.StatusText = status;
        }
    }

    private static string BuildBenchmarkSummary(JobProgress job, AgentSqliteBenchmarkResult result)
    {
        var state = FormatEnum(job.State);
        var committedRate = FormatRate(result.CommittedRecordsPerSecond);
        var sustainedRate = FormatRate(result.MaxSustainedCommittedRecordsPerSecond);
        return $"SQLite benchmark {state}: {committedRate} committed rec/s, max sustained {sustainedRate} rec/s.";
    }

    private static string BuildBenchmarkDetails(JobProgress job, AgentSqliteBenchmarkResult result)
    {
        var lines = new[]
        {
            FirstNonEmpty(job.ProgressMessage, result.Status),
            string.IsNullOrWhiteSpace(result.ThresholdReason) ? string.Empty : result.ThresholdReason,
            string.IsNullOrWhiteSpace(result.DatabasePath) ? string.Empty : $"DB: {result.DatabasePath}",
            string.IsNullOrWhiteSpace(result.ReportPath) ? string.Empty : $"Report: {result.ReportPath}",
            string.IsNullOrWhiteSpace(result.JsonReportPath) ? string.Empty : $"JSON: {result.JsonReportPath}",
            string.IsNullOrWhiteSpace(job.ErrorText) ? string.Empty : $"Error: {job.ErrorText}"
        };

        return string.Join(Environment.NewLine, lines.Where(line => !string.IsNullOrWhiteSpace(line)));
    }

    private void ReplaceBenchmarkRows(JobProgress job, AgentSqliteBenchmarkResult result)
    {
        BenchmarkResultRows.Clear();
        AddBenchmarkRow("State", FormatEnum(job.State));
        AddBenchmarkRow("Status", FirstNonEmpty(result.Status, job.ProgressMessage));
        AddBenchmarkRow("Started", FormatTimestamp(result.StartedAtUtc));
        AddBenchmarkRow("Completed", result.CompletedAtUtc.HasValue ? FormatTimestamp(result.CompletedAtUtc.Value) : string.Empty);
        AddBenchmarkRow("Duration", FormatSeconds(result.DurationSeconds));
        AddBenchmarkRow("Performance profile", result.PerformanceProfile);
        AddBenchmarkRow("Source mix", result.SourceMix);
        AddBenchmarkRow("Max sustained committed rec/s", FormatRate(result.MaxSustainedCommittedRecordsPerSecond));
        AddBenchmarkRow("Attempted rec/s", FormatRate(result.AttemptedRecordsPerSecond));
        AddBenchmarkRow("Committed rec/s", FormatRate(result.CommittedRecordsPerSecond));
        AddBenchmarkRow("Attempted records", FormatCount(result.AttemptedRecords));
        AddBenchmarkRow("Committed records", FormatCount(result.CommittedRecords));
        AddBenchmarkRow("Writer queue depth", result.WriterQueueDepth.ToString("N0", CultureInfo.CurrentCulture));
        AddBenchmarkRow("Writer peak queue depth", result.WriterPeakQueueDepth.ToString("N0", CultureInfo.CurrentCulture));
        AddBenchmarkRow("Writer queue capacity", result.WriterQueueCapacity.ToString("N0", CultureInfo.CurrentCulture));
        AddBenchmarkRow("Dropped records", FormatCount(result.DroppedRecords));
        AddBenchmarkRow("Failed batches", FormatCount(result.FailedBatches));
        AddBenchmarkRow("Failed records", FormatCount(result.FailedRecords));
        AddBenchmarkRow("Threshold reason", result.ThresholdReason);

        foreach (var phase in result.Phases)
        {
            AddBenchmarkRow(
                $"Phase {phase.PhaseNumber}",
                $"{phase.SourceMix}; committed {FormatRate(phase.CommittedRecordsPerSecond)} rec/s; " +
                $"attempted {FormatRate(phase.AttemptedRecordsPerSecond)} rec/s; " +
                $"queue {phase.WriterQueueDepth}/{phase.WriterPeakQueueDepth}; dropped {FormatCount(phase.DroppedRecords)}.");
        }
    }

    private void AddBenchmarkRow(string metric, string value)
    {
        BenchmarkResultRows.Add(new AgentBenchmarkResultRowViewModel(metric, value));
    }

    private static string FormatTimestamp(DateTime timestamp)
    {
        return timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);
    }

    private static string FormatSeconds(double value)
    {
        return value <= 0
            ? string.Empty
            : $"{value:N1}s";
    }

    private static string FormatRate(double value)
    {
        return value <= 0
            ? "0.0"
            : value.ToString("N1", CultureInfo.CurrentCulture);
    }

    private static string FormatCount(long value)
    {
        return value.ToString("N0", CultureInfo.CurrentCulture);
    }

    private static string FormatSqliteSummary(AgentSqliteDatabaseDiagnostics? diagnostics)
    {
        if (diagnostics == null)
        {
            return string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(diagnostics.Error))
        {
            return "; SQLite diagnostics unavailable";
        }

        var checkpoint = diagnostics.LastCheckpoint == null
            ? string.Empty
            : diagnostics.LastCheckpoint.Succeeded
                ? $", checkpoint {diagnostics.LastCheckpoint.CheckpointedFrameCount:N0}/{diagnostics.LastCheckpoint.LogFrameCount:N0}"
                : ", checkpoint warning";
        return $"; SQLite {diagnostics.JournalMode}/{diagnostics.SynchronousMode}, auto-checkpoint {diagnostics.WalAutoCheckpointPages:N0}, WAL {FormatBytes(diagnostics.WalSizeBytes)}{checkpoint}";
    }

    private static string FormatPeAnalysisSummary(AgentArtifactEnrichmentSnapshot enrichment)
    {
        if (enrichment.PeActiveCount > 0)
        {
            return $"; PE active {enrichment.PeActiveCount:N0}, completed {enrichment.PeCompletedCount:N0}/{enrichment.PeAttemptCount:N0}";
        }

        if (enrichment.PeAttemptCount > 0 || enrichment.PeFreshnessSkipCount > 0)
        {
            return $"; PE completed {enrichment.PeCompletedCount:N0}, written {enrichment.PeRecordCount:N0}, skipped {enrichment.PeFreshnessSkipCount:N0}, failed {enrichment.PeFailureCount:N0}";
        }

        return string.Empty;
    }

    private static string FormatLiveBufferSummary(CaptureHealthReport capture)
    {
        if (capture.LiveBufferMemoryLimitBytes <= 0)
        {
            return string.Empty;
        }

        if (capture.LiveBufferDrainingAfterStop)
        {
            return $"; SQLite loading {capture.LiveBufferPendingRecords:N0} accepted event(s)";
        }

        if (capture.LiveBufferPendingRecords > 0 || capture.LiveBufferDiskBytes > 0)
        {
            return $"; buffer {capture.LiveBufferPendingRecords:N0} event(s), RAM {FormatBytes(capture.LiveBufferMemoryBytes)}, disk {FormatBytes(capture.LiveBufferDiskBytes)}";
        }

        if (capture.LiveBufferSpilledBatches > 0)
        {
            return $"; buffer drained, spilled {capture.LiveBufferSpilledRecords:N0} event(s)";
        }

        return $"; buffer RAM {FormatBytes(capture.LiveBufferMemoryLimitBytes)}";
    }

    private static string FormatLiveBufferStatus(CaptureHealthReport capture)
    {
        var prefix = capture.LiveBufferDrainingAfterStop
            ? "Capture stopped; SQLite is still loading accepted live event data."
            : "SQLite is loading accepted live event data.";
        return $"{prefix} Pending {capture.LiveBufferPendingRecords:N0} event(s) in {capture.LiveBufferPendingBatches:N0} batch(es); RAM {FormatBytes(capture.LiveBufferMemoryBytes)}/{FormatBytes(capture.LiveBufferMemoryLimitBytes)}; disk {FormatBytes(capture.LiveBufferDiskBytes)}.";
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

    private static string FormatTargetKind(AgentConfigurationTargetKind targetKind)
    {
        return targetKind switch
        {
            AgentConfigurationTargetKind.HostMonitoring => "Monitoring",
            AgentConfigurationTargetKind.Capture => "Capture",
            _ => "Configuration"
        };
    }

    private static string FormatEnum<T>(T value) where T : Enum
    {
        var text = value.ToString();
        return string.Concat(text.Select((character, index) =>
            index > 0 && char.IsUpper(character) ? " " + character : character.ToString()));
    }
}

public sealed class AgentBenchmarkResultRowViewModel
{
    public AgentBenchmarkResultRowViewModel(string metric, string value)
    {
        Metric = metric;
        Value = value;
    }

    public string Metric { get; }

    public string Value { get; }
}
