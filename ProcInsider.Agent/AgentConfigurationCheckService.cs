using System.Diagnostics.Eventing.Reader;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Diagnostics.Tracing;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentConfigurationCheckService
{
    private const string AuditPolicyRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
    private const string ProcessCommandLineLoggingValueName = "ProcessCreationIncludeCmdLine_Enabled";

    private static readonly string[] MonitoringEventLogs =
    {
        "Security",
        "System",
        "Application",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational"
    };

    private readonly AgentOptions _options;
    private readonly InvestigationSessionPaths _sessionPaths;
    private readonly ConfigProfileService _configProfiles = new();
    private readonly SysmonService _sysmonService;
    private readonly PowerShellAuditingService _powerShellAuditingService;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public AgentConfigurationCheckService(AgentOptions options, InvestigationSessionPaths sessionPaths)
    {
        _options = options;
        _sessionPaths = sessionPaths;
        _sysmonService = new SysmonService(_configProfiles);
        _powerShellAuditingService = new PowerShellAuditingService(_configProfiles);
    }

    public AgentConfigurationCheckResult CheckHostMonitoringConfiguration(CheckHostMonitoringConfigurationCommand command)
    {
        var configuration = command.DraftConfiguration ?? CreateDefaultHostMonitoringConfiguration(command);
        var findings = new List<AgentConfigurationFinding>();

        CheckHostPrivileges(findings, requiresElevation: true);
        CheckSysmon(findings, configuration.Sysmon);
        CheckSecurityAuditPolicy(findings, configuration.SecurityAuditPolicy);
        CheckProcessCommandLineLogging(findings, configuration.SecurityAuditPolicy);
        CheckEventLogs(findings, configuration.EventLogs.ChannelNames.Length == 0 ? MonitoringEventLogs : configuration.EventLogs.ChannelNames);
        CheckPowerShellAuditing(findings, configuration.PowerShellAuditing);
        CheckEtw(findings, configuration.Etw, required: configuration.Etw.ConfigureSession);
        CheckScheduledDumps(findings, configuration.ScheduledDumps);
        CheckReverseDeploymentSupport(findings);

        return CreateResult(
            AgentConfigurationTargetKind.HostMonitoring,
            command.AgentId,
            command.HostId,
            command.ConfigurationVersion,
            command.ConfigurationHash,
            configuration,
            findings);
    }

    public AgentConfigurationCheckResult CheckCaptureConfiguration(CheckCaptureConfigurationCommand command)
    {
        var configuration = command.DraftConfiguration ?? CreateDefaultCaptureConfiguration(command);
        var findings = new List<AgentConfigurationFinding>();

        CheckLiveDatabase(findings);
        CheckRuntimeSnapshots(findings, configuration.RuntimeProcessSnapshots);
        CheckCaptureSources(findings, configuration);
        CheckNetworkCapture(findings, configuration.NetworkCapture);
        CheckZeek(findings, configuration.Zeek, configuration.NetworkCapture.Enabled);
        CheckArtifactCapture(findings, configuration.ArtifactCapture);
        CheckGuardrails(findings, configuration);

        return CreateResult(
            AgentConfigurationTargetKind.Capture,
            command.AgentId,
            command.HostId,
            command.ConfigurationVersion,
            command.ConfigurationHash,
            configuration,
            findings);
    }

    public AgentHostMonitoringConfiguration CreateDefaultHostMonitoringConfiguration(AgentConfigurationCommand command)
    {
        var sysmonProfile = _configProfiles.GetDefaultProfile(ConfigProfileKind.Sysmon);
        var securityProfile = _configProfiles.GetDefaultProfile(ConfigProfileKind.SecurityMonitoring);
        var powershellProfile = _configProfiles.GetDefaultProfile(ConfigProfileKind.PowerShellAuditing);
        var eventLogProfile = _configProfiles.GetDefaultProfile(ConfigProfileKind.EventLogs);
        var etwProfile = _configProfiles.GetDefaultProfile(ConfigProfileKind.Etw);

        return new AgentHostMonitoringConfiguration
        {
            AgentId = command.AgentId,
            HostId = FirstNonEmpty(command.HostId, Environment.MachineName),
            ConfigurationVersion = FirstNonEmpty(command.ConfigurationVersion, "monitoring-default-v1"),
            Sysmon = new AgentSysmonMonitoringIntent
            {
                InstallOrUpdate = true,
                VerifyService = true,
                ProfileId = sysmonProfile?.Id ?? string.Empty,
                ProfileDisplayName = GetProfileName(sysmonProfile),
                ConfigurationPath = ResolveProfilePath(sysmonProfile)
            },
            SecurityAuditPolicy = new AgentSecurityAuditMonitoringIntent
            {
                ConfigureAuditPolicy = true,
                EnableProcessCommandLineLogging = true,
                PolicyProfileId = securityProfile?.Id ?? string.Empty,
                PolicyProfileDisplayName = GetProfileName(securityProfile),
                AuditPolicyPath = ResolveProfilePath(securityProfile)
            },
            EventLogs = new AgentEventLogMonitoringIntent
            {
                ConfigureChannels = true,
                ConfigureRetention = true,
                ProfileId = eventLogProfile?.Id ?? string.Empty,
                ProfileDisplayName = GetProfileName(eventLogProfile),
                ChannelNames = MonitoringEventLogs
            },
            PowerShellAuditing = new AgentPowerShellMonitoringIntent
            {
                EnableScriptBlockLogging = true,
                EnableModuleLogging = true,
                EnableTranscription = true,
                ProfileId = powershellProfile?.Id ?? string.Empty,
                TranscriptDirectory = @"C:\PS_transcripts"
            },
            Etw = new AgentEtwMonitoringIntent
            {
                ProfileId = etwProfile?.Id ?? string.Empty,
                ProfileDisplayName = GetProfileName(etwProfile),
                ProfilePath = ResolveProfilePath(etwProfile)
            },
            ScheduledDumps = new AgentScheduledDumpPolicy
            {
                Enabled = false,
                OutputDirectory = _sessionPaths.DumpsDirectory
            }
        };
    }

    public AgentCaptureConfiguration CreateDefaultCaptureConfiguration(AgentConfigurationCommand command)
    {
        var etwProfile = _configProfiles.GetDefaultProfile(ConfigProfileKind.Etw);
        return new AgentCaptureConfiguration
        {
            AgentId = command.AgentId,
            HostId = FirstNonEmpty(command.HostId, Environment.MachineName),
            ConfigurationVersion = FirstNonEmpty(command.ConfigurationVersion, "capture-default-v1"),
            RuntimeProcessSnapshots = new AgentRuntimeSnapshotCapturePolicy
            {
                Enabled = true,
                RefreshIntervalSeconds = 10
            },
            SourceToggles = new AgentCaptureSourceToggles(),
            Etw = new AgentEtwMonitoringIntent
            {
                ConfigureSession = true,
                ProfileId = etwProfile?.Id ?? string.Empty,
                ProfileDisplayName = GetProfileName(etwProfile),
                ProfilePath = ResolveProfilePath(etwProfile)
            },
            NetworkCapture = new AgentNetworkCaptureMetadataPolicy
            {
                Enabled = false,
                OutputDirectory = _sessionPaths.NetworkCapturesDirectory
            },
            Zeek = new AgentZeekAnalysisImportPolicy
            {
                Enabled = false,
                OutputDirectory = _sessionPaths.ZeekDirectory
            },
            ArtifactCapture = new AgentArtifactCapturePolicy
            {
                CaptureModules = true,
                CaptureHandles = true,
                CapturePeMetadata = true,
                ScopePolicy = "Selected and recently observed processes"
            },
            SourceHealth = new AgentSourceHealthPolicy(),
            Guardrails = new AgentVolumeRetentionGuardrailPolicy
            {
                MaxEventsPerSecondWarning = 1000,
                MaxLiveDatabaseBytesWarning = 10L * 1024 * 1024 * 1024
            }
        } with
        {
            LastError = etwProfile == null ? "No default ETW profile was discovered." : string.Empty
        };
    }

    private static void CheckHostPrivileges(List<AgentConfigurationFinding> findings, bool requiresElevation)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            var isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
            if (isElevated)
            {
                Add(findings, AgentConfigurationAreaKind.HostPrivileges, AgentConfigurationFindingSeverity.Info,
                    "Agent is running with administrator privileges.",
                    "Host monitoring deployment checks can inspect privileged prerequisites.");
                return;
            }

            Add(findings, AgentConfigurationAreaKind.HostPrivileges,
                requiresElevation ? AgentConfigurationFindingSeverity.Warning : AgentConfigurationFindingSeverity.Info,
                "Agent is not running elevated.",
                "Read-only checks can continue, but deployment, audit policy changes, Sysmon changes, packet capture, and protected-process inspection may require elevation.",
                $"Run {ProductIdentity.DisplayName} and the local agent as administrator before deploying host monitoring or starting privileged capture.");
        }
        catch (Exception ex)
        {
            Add(findings, AgentConfigurationAreaKind.HostPrivileges, AgentConfigurationFindingSeverity.Warning,
                "Could not determine the agent privilege state.",
                ex.Message,
                "Verify the agent process elevation before deploying monitoring changes.");
        }
    }

    private void CheckSysmon(List<AgentConfigurationFinding> findings, AgentSysmonMonitoringIntent intent)
    {
        TryCheck(findings, AgentConfigurationAreaKind.Sysmon, () =>
        {
            var settings = _sysmonService.LoadSettings();
            var profilePath = FirstNonEmpty(intent.ConfigurationPath, ResolveProfilePath(_configProfiles.GetDefaultProfile(ConfigProfileKind.Sysmon)));
            if (!settings.IsServiceStateAvailable)
            {
                Add(findings, AgentConfigurationAreaKind.Sysmon, AgentConfigurationFindingSeverity.Warning,
                    "Sysmon service state could not be read.",
                    $"{settings.ServiceStatusDetail} {settings.ServiceError}".Trim(),
                    "Resolve service/registry access before deploying or relying on Sysmon; an inaccessible state is not treated as not installed.");
                return;
            }

            var executablePath = _sysmonService.FindSysmonExecutablePath();
            Add(findings, AgentConfigurationAreaKind.Sysmon,
                settings.IsInstalled ? AgentConfigurationFindingSeverity.Info : AgentConfigurationFindingSeverity.Warning,
                settings.IsInstalled ? "Sysmon service registration was detected." : "Sysmon service registration was not detected.",
                $"Running={settings.IsRunning}; channelEnabled={settings.IsChannelEnabled}; watcherAccessible={settings.IsWatcherAccessible}; channelAvailable={settings.IsChannelAvailable}; executable={(string.IsNullOrWhiteSpace(executablePath) ? "<not found>" : executablePath)}. {settings.ChannelStatusDetail}",
                settings.IsInstalled ? string.Empty : "Install Sysmon or choose a monitoring profile that does not require Sysmon.");

            if (settings.IsInstalled && !settings.IsRunning)
            {
                Add(findings, AgentConfigurationAreaKind.Sysmon, AgentConfigurationFindingSeverity.Warning,
                    "Sysmon is installed but not currently running.",
                    "The service exists, but no running Sysmon process was detected.",
                    "Start or reinstall Sysmon before relying on Sysmon events.");
            }

            if (!settings.IsChannelAvailable)
            {
                Add(findings, AgentConfigurationAreaKind.Sysmon, AgentConfigurationFindingSeverity.Warning,
                    settings.IsChannelEnabled
                        ? "Sysmon operational event log is enabled but not readable by the agent."
                        : "Sysmon operational event log is unavailable or disabled.",
                    string.IsNullOrWhiteSpace(settings.ChannelStatusDetail)
                        ? "Channel Microsoft-Windows-Sysmon/Operational could not be opened as enabled."
                        : settings.ChannelStatusDetail,
                    settings.IsChannelEnabled
                        ? "Run the agent with permission to subscribe to the Sysmon operational log."
                        : "Enable the Sysmon operational log after installing Sysmon.");
            }

            if (string.IsNullOrWhiteSpace(profilePath) || !File.Exists(profilePath))
            {
                Add(findings, AgentConfigurationAreaKind.Sysmon, AgentConfigurationFindingSeverity.Warning,
                    "Bundled Sysmon profile file was not found.",
                    $"Requested profile '{FirstNonEmpty(intent.ProfileDisplayName, intent.ProfileId, "<default>")}' resolved to '{profilePath}'.",
                    "Verify the bundled Config/Sysmon profile assets are present in the agent output folder.");
            }
            else
            {
                Add(findings, AgentConfigurationAreaKind.Sysmon, AgentConfigurationFindingSeverity.Info,
                    "Bundled Sysmon profile is present.",
                    $"Profile '{FirstNonEmpty(intent.ProfileDisplayName, intent.ProfileId, Path.GetFileName(profilePath))}' at {profilePath}. Current applied Sysmon profile identity is not read by this check.");
            }
        });
    }

    private void CheckSecurityAuditPolicy(List<AgentConfigurationFinding> findings, AgentSecurityAuditMonitoringIntent intent)
    {
        var auditPol = FindSystemExecutable("auditpol.exe");
        var profiles = _configProfiles.GetProfiles(ConfigProfileKind.SecurityMonitoring);
        var profilePath = FirstNonEmpty(intent.AuditPolicyPath, ResolveProfilePath(profiles.FirstOrDefault(profile => profile.IsDefault) ?? profiles.FirstOrDefault()));

        if (string.IsNullOrWhiteSpace(auditPol))
        {
            Add(findings, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, AgentConfigurationFindingSeverity.Warning,
                "auditpol.exe was not found.",
                "Security audit policy readiness cannot be inspected on this host.",
                "Run the check on Windows with auditpol.exe available under System32.");
        }
        else
        {
            Add(findings, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, AgentConfigurationFindingSeverity.Info,
                "Windows audit policy tool is available.",
                $"auditpol path: {auditPol}.");
        }

        if (profiles.Count == 0)
        {
            Add(findings, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, AgentConfigurationFindingSeverity.Warning,
                "No bundled Security Monitoring policy profiles were discovered.",
                "Config/SecurityMonitoring/profiles.json did not produce any profiles.",
                "Verify Config/SecurityMonitoring is copied to the agent output.");
        }
        else if (string.IsNullOrWhiteSpace(profilePath) || (!File.Exists(profilePath) && !Directory.Exists(profilePath)))
        {
            Add(findings, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, AgentConfigurationFindingSeverity.Warning,
                "Security Monitoring policy profile path was not found.",
                $"Profile '{FirstNonEmpty(intent.PolicyProfileDisplayName, intent.PolicyProfileId, "<default>")}' resolved to '{profilePath}'.",
                "Verify the selected profile manifest and action paths.");
        }
        else
        {
            Add(findings, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, AgentConfigurationFindingSeverity.Info,
                "Security Monitoring policy profile assets are present.",
                $"Profile path: {profilePath}. Detailed audit subcategory drift is left to explicit verify/deploy workflows.");
        }
    }

    private static void CheckProcessCommandLineLogging(
        List<AgentConfigurationFinding> findings,
        AgentSecurityAuditMonitoringIntent intent)
    {
        TryCheck(findings, AgentConfigurationAreaKind.ProcessCommandLineAuditing, () =>
        {
            var state = ReadProcessCommandLineLoggingEnabled();
            if (state == true)
            {
                Add(findings, AgentConfigurationAreaKind.ProcessCommandLineAuditing, AgentConfigurationFindingSeverity.Info,
                    "Process command-line logging is enabled.",
                    $@"HKLM\{AuditPolicyRegistryPath}\{ProcessCommandLineLoggingValueName}=1.");
                return;
            }

            var severity = intent.EnableProcessCommandLineLogging
                ? AgentConfigurationFindingSeverity.Warning
                : AgentConfigurationFindingSeverity.Info;
            Add(findings, AgentConfigurationAreaKind.ProcessCommandLineAuditing, severity,
                "Process command-line logging is not enabled.",
                state.HasValue
                    ? $@"HKLM\{AuditPolicyRegistryPath}\{ProcessCommandLineLoggingValueName}=0."
                    : $@"HKLM\{AuditPolicyRegistryPath}\{ProcessCommandLineLoggingValueName} is not configured.",
                intent.EnableProcessCommandLineLogging
                    ? "Deploy host monitoring configuration to include command lines in Security 4688 process creation events."
                    : string.Empty);
        }, "Process command-line logging policy could not be inspected.");
    }

    private static void CheckEventLogs(List<AgentConfigurationFinding> findings, IEnumerable<string> channels)
    {
        foreach (var channel in channels.Where(channel => !string.IsNullOrWhiteSpace(channel)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            TryCheck(findings, AgentConfigurationAreaKind.WindowsEventLogs, () =>
            {
                using var configuration = new EventLogConfiguration(channel);
                var sizeMb = configuration.MaximumSizeInBytes <= 0
                    ? "unknown"
                    : $"{configuration.MaximumSizeInBytes / 1024 / 1024:N0} MB";
                var severity = configuration.IsEnabled ? AgentConfigurationFindingSeverity.Info : AgentConfigurationFindingSeverity.Warning;
                Add(findings, AgentConfigurationAreaKind.WindowsEventLogs, severity,
                    configuration.IsEnabled ? $"Event log '{channel}' is available." : $"Event log '{channel}' is disabled.",
                    $"Retention/log mode: {configuration.LogMode}; maximum size: {sizeMb}.",
                    configuration.IsEnabled ? string.Empty : "Enable the channel before relying on this source.");
            }, $"Event log '{channel}' could not be inspected.");
        }
    }

    private void CheckPowerShellAuditing(List<AgentConfigurationFinding> findings, AgentPowerShellMonitoringIntent intent)
    {
        TryCheck(findings, AgentConfigurationAreaKind.PowerShellAuditing, () =>
        {
            var settings = _powerShellAuditingService.LoadSettings();
            if (!settings.IsAvailable)
            {
                Add(findings, AgentConfigurationAreaKind.PowerShellAuditing, AgentConfigurationFindingSeverity.Warning,
                    "PowerShell auditing policy could not be read.",
                    $"{settings.StatusDetail} {settings.Error}".Trim(),
                    "Resolve policy-registry access before deployment; inaccessible values are not treated as disabled.");
                return;
            }

            Add(findings, AgentConfigurationAreaKind.PowerShellAuditing, AgentConfigurationFindingSeverity.Info,
                "Current PowerShell auditing policy was read.",
                $"ScriptBlock={settings.ScriptBlockLoggingEnabled}; Module={settings.ModuleLoggingEnabled}; Transcription={settings.TranscriptionEnabled}; transcriptPath={settings.TranscriptPath}.");

            if (intent.EnableScriptBlockLogging && !settings.ScriptBlockLoggingEnabled)
            {
                Add(findings, AgentConfigurationAreaKind.PowerShellAuditing, AgentConfigurationFindingSeverity.Warning,
                    "Script block logging is requested but not currently enabled.",
                    "PowerShell script content evidence may be missing until the policy is deployed.",
                    "Deploy the selected PowerShell auditing profile before capture.");
            }

            if (intent.EnableModuleLogging && !settings.ModuleLoggingEnabled)
            {
                Add(findings, AgentConfigurationAreaKind.PowerShellAuditing, AgentConfigurationFindingSeverity.Warning,
                    "Module logging is requested but not currently enabled.",
                    "PowerShell module invocation evidence may be missing until the policy is deployed.",
                    "Deploy the selected PowerShell auditing profile before capture.");
            }

            if (intent.EnableTranscription && !settings.TranscriptionEnabled)
            {
                Add(findings, AgentConfigurationAreaKind.PowerShellAuditing, AgentConfigurationFindingSeverity.Warning,
                    "PowerShell transcription is requested but not currently enabled.",
                    "Transcript files will not be created until transcription policy is deployed.",
                    "Deploy the selected PowerShell auditing profile before capture.");
            }
        });

        CheckEventLogs(findings, ["Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]);
    }

    private void CheckEtw(List<AgentConfigurationFinding> findings, AgentEtwMonitoringIntent intent, bool required)
    {
        var profilePath = FirstNonEmpty(intent.ProfilePath, ResolveProfilePath(_configProfiles.GetDefaultProfile(ConfigProfileKind.Etw)));
        if (string.IsNullOrWhiteSpace(profilePath))
        {
            Add(findings, AgentConfigurationAreaKind.Etw,
                required ? AgentConfigurationFindingSeverity.Blocked : AgentConfigurationFindingSeverity.Warning,
                "No ETW profile path was resolved.",
                "The selected or default Config/Etw profile could not be found.",
                "Select a valid ETW profile or restore the bundled Config/Etw assets.");
            return;
        }

        if (!File.Exists(profilePath))
        {
            Add(findings, AgentConfigurationAreaKind.Etw,
                required ? AgentConfigurationFindingSeverity.Blocked : AgentConfigurationFindingSeverity.Warning,
                "ETW profile file is missing.",
                profilePath,
                "Select a valid ETW profile or restore the bundled Config/Etw assets.");
            return;
        }

        TryCheck(findings, AgentConfigurationAreaKind.Etw, () =>
        {
            var json = File.ReadAllText(profilePath);
            var configuration = JsonSerializer.Deserialize<EtwProviderConfiguration>(json, _jsonOptions) ?? new EtwProviderConfiguration();
            var errors = ValidateEtwConfiguration(configuration);
            if (errors.Count > 0)
            {
                Add(findings, AgentConfigurationAreaKind.Etw,
                    required ? AgentConfigurationFindingSeverity.Blocked : AgentConfigurationFindingSeverity.Warning,
                    "ETW profile is invalid.",
                    string.Join("; ", errors),
                    "Fix the profile JSON before enabling ETW capture.");
                return;
            }

            var enabledProviders = configuration.Providers.Count(provider => provider.Enabled);
            Add(findings, AgentConfigurationAreaKind.Etw, AgentConfigurationFindingSeverity.Info,
                "ETW profile is syntactically valid.",
                $"Profile '{FirstNonEmpty(configuration.Profile.DisplayName, configuration.Profile.Id, Path.GetFileNameWithoutExtension(profilePath))}', session '{configuration.Session.Name}', enabled providers {enabledProviders}/{configuration.Providers.Count}.");

            if (string.Equals(configuration.Profile.ExpectedVolume, "high", StringComparison.OrdinalIgnoreCase) ||
                configuration.Profile.ExpectedVolume.Contains("high", StringComparison.OrdinalIgnoreCase))
            {
                Add(findings, AgentConfigurationAreaKind.VolumeRetentionGuardrails, AgentConfigurationFindingSeverity.Warning,
                    "Selected ETW profile declares high expected volume.",
                    FirstNonEmpty(configuration.Profile.RiskNote, "High-volume ETW providers can grow the live database quickly."),
                    "Use a lower-volume profile unless this diagnostic capture is intentional.");
            }
        }, "ETW profile could not be inspected.");
    }

    private void CheckScheduledDumps(List<AgentConfigurationFinding> findings, AgentScheduledDumpPolicy policy)
    {
        if (!policy.Enabled)
        {
            Add(findings, AgentConfigurationAreaKind.ScheduledDumps, AgentConfigurationFindingSeverity.Info,
                "Scheduled dump policy is disabled.",
                "No scheduled dump capture will run from this monitoring configuration.");
            return;
        }

        if (policy.IntervalSeconds <= 0 && string.IsNullOrWhiteSpace(policy.OffsetsFromCaptureStart))
        {
            Add(findings, AgentConfigurationAreaKind.ScheduledDumps, AgentConfigurationFindingSeverity.Blocked,
                "Scheduled dump policy has no valid schedule.",
                "Neither a positive interval nor comma-delimited offsets were provided.",
                "Set an interval or explicit offsets before deploying scheduled dumps.");
        }

        var outputDirectory = FirstNonEmpty(policy.OutputDirectory, _sessionPaths.DumpsDirectory);
        AddPathReadiness(findings, AgentConfigurationAreaKind.ScheduledDumps, outputDirectory, "dump output directory");
    }

    private static void CheckReverseDeploymentSupport(List<AgentConfigurationFinding> findings)
    {
        Add(findings, AgentConfigurationAreaKind.ReverseDeployment, AgentConfigurationFindingSeverity.Info,
            "Reverse deployment support is conservative.",
            $"The check is read-only and does not inspect or change machine settings. Future reverse deployment should only undo {ProductIdentity.DisplayName}-owned settings and report manual cleanup for everything else.",
            "Review per-area reverse support before deploying monitoring changes.");
    }

    private void CheckLiveDatabase(List<AgentConfigurationFinding> findings)
    {
        var databasePath = _options.DatabasePath;
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            Add(findings, AgentConfigurationAreaKind.LiveDatabase, AgentConfigurationFindingSeverity.Blocked,
                "Live SQLite database path is empty.",
                "The agent cannot stage capture evidence without a database path.",
                "Start the agent with --database pointing at the active session live database.");
            return;
        }

        var directory = Path.GetDirectoryName(databasePath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            Add(findings, AgentConfigurationAreaKind.LiveDatabase, AgentConfigurationFindingSeverity.Blocked,
                "Live SQLite database directory does not exist.",
                directory ?? databasePath,
                $"Create or reopen a valid {ProductIdentity.DisplayName} session before capture.");
            return;
        }

        try
        {
            if (File.Exists(databasePath))
            {
                using var stream = new FileStream(databasePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
                Add(findings, AgentConfigurationAreaKind.LiveDatabase, AgentConfigurationFindingSeverity.Info,
                    "Live SQLite database is reachable for read/write access.",
                    databasePath);
            }
            else
            {
                Add(findings, AgentConfigurationAreaKind.LiveDatabase, AgentConfigurationFindingSeverity.Warning,
                    "Live SQLite database file does not exist yet.",
                    $"Directory exists: {directory}. Write access was not proven because the check did not create files.",
                    "Initialize the live database before starting capture.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Add(findings, AgentConfigurationAreaKind.LiveDatabase, AgentConfigurationFindingSeverity.Blocked,
                "Live SQLite database could not be opened for read/write access.",
                ex.Message,
                "Close conflicting tools or fix permissions on the session live database.");
        }
    }

    private static void CheckRuntimeSnapshots(List<AgentConfigurationFinding> findings, AgentRuntimeSnapshotCapturePolicy policy)
    {
        if (!policy.Enabled)
        {
            Add(findings, AgentConfigurationAreaKind.RuntimeProcessSnapshots, AgentConfigurationFindingSeverity.Warning,
                "Runtime process snapshots are disabled.",
                "Capture can run without periodic process snapshots, but process context may be sparse.",
                "Enable runtime process snapshots for normal incident-response capture.");
            return;
        }

        if (policy.RefreshIntervalSeconds is < 1 or > 3600)
        {
            Add(findings, AgentConfigurationAreaKind.RuntimeProcessSnapshots, AgentConfigurationFindingSeverity.Blocked,
                "Runtime process refresh interval is outside supported bounds.",
                $"Configured interval: {policy.RefreshIntervalSeconds} seconds; supported range: 1-3600 seconds.",
                "Choose a refresh interval between 1 and 3600 seconds.");
            return;
        }

        Add(findings, AgentConfigurationAreaKind.RuntimeProcessSnapshots, AgentConfigurationFindingSeverity.Info,
            "Runtime process snapshots are configured.",
            $"Refresh interval: {policy.RefreshIntervalSeconds} seconds.");
    }

    private void CheckCaptureSources(List<AgentConfigurationFinding> findings, AgentCaptureConfiguration configuration)
    {
        var toggles = configuration.SourceToggles;
        if (!toggles.Runtime && !toggles.Etw && !toggles.Security && !toggles.PowerShell && !toggles.WindowsOther && !toggles.Sysmon)
        {
            Add(findings, AgentConfigurationAreaKind.SourceHealth, AgentConfigurationFindingSeverity.Blocked,
                "No capture sources are enabled.",
                "At least one Runtime, ETW, Security, PowerShell, WindowsOther, or Sysmon source must be selected.",
                "Enable the Runtime source or another evidence source before starting capture.");
            return;
        }

        if (toggles.Runtime)
        {
            Add(findings, AgentConfigurationAreaKind.RuntimeEvents, AgentConfigurationFindingSeverity.Info,
                "Runtime source is enabled.",
                "Process snapshot/delta evidence will be collected by the agent.");
        }

        if (toggles.Etw)
        {
            CheckEtw(findings, configuration.Etw, required: true);
        }

        if (toggles.Security)
        {
            CheckEventLogForCapture(findings, "Security", AgentConfigurationAreaKind.SecurityEvents);
        }

        if (toggles.PowerShell)
        {
            CheckEventLogForCapture(findings, "Microsoft-Windows-PowerShell/Operational", AgentConfigurationAreaKind.PowerShellEvents);
            TryCheck(findings, AgentConfigurationAreaKind.PowerShellEvents, () =>
            {
                var settings = _powerShellAuditingService.LoadSettings();
                if (!settings.IsAvailable)
                {
                    Add(findings, AgentConfigurationAreaKind.PowerShellEvents, AgentConfigurationFindingSeverity.Warning,
                        "PowerShell auditing policy could not be read for capture readiness.",
                        $"{settings.StatusDetail} {settings.Error}".Trim(),
                        "Resolve policy-registry access before deciding whether PowerShell auditing is disabled.");
                    return;
                }

                if (!settings.ScriptBlockLoggingEnabled && !settings.ModuleLoggingEnabled && !settings.TranscriptionEnabled)
                {
                    Add(findings, AgentConfigurationAreaKind.PowerShellEvents, AgentConfigurationFindingSeverity.Warning,
                        "PowerShell capture is enabled but PowerShell auditing policy is mostly inactive.",
                        "Script block logging, module logging, and transcription all appear disabled.",
                        "Deploy PowerShell auditing before capture if script content evidence is required.");
                }
            });
        }

        if (toggles.WindowsOther)
        {
            CheckEventLogForCapture(findings, "System", AgentConfigurationAreaKind.WindowsOtherEvents);
            CheckEventLogForCapture(findings, "Application", AgentConfigurationAreaKind.WindowsOtherEvents);
        }

        if (toggles.Sysmon)
        {
            TryCheck(findings, AgentConfigurationAreaKind.SysmonEvents, () =>
            {
                var settings = _sysmonService.LoadSettings();
                if (!settings.IsServiceStateAvailable)
                {
                    Add(findings, AgentConfigurationAreaKind.SysmonEvents, AgentConfigurationFindingSeverity.Warning,
                        "Sysmon service state could not be read for capture readiness.",
                        $"{settings.ServiceStatusDetail} {settings.ServiceError}".Trim(),
                        "Resolve service/registry access before deciding whether Sysmon is unavailable.");
                    return;
                }

                var severity = settings.IsInstalled && settings.IsRunning && settings.IsChannelAvailable
                    ? AgentConfigurationFindingSeverity.Info
                    : AgentConfigurationFindingSeverity.Warning;
                Add(findings, AgentConfigurationAreaKind.SysmonEvents, severity,
                    settings.IsInstalled && settings.IsRunning && settings.IsChannelAvailable
                        ? "Sysmon source appears capture-ready."
                        : "Sysmon source is enabled but Sysmon is not fully ready.",
                    $"Installed={settings.IsInstalled}; running={settings.IsRunning}; channelEnabled={settings.IsChannelEnabled}; watcherAccessible={settings.IsWatcherAccessible}; channelAvailable={settings.IsChannelAvailable}. {settings.ChannelStatusDetail}",
                    severity == AgentConfigurationFindingSeverity.Info ? string.Empty : "Install/start Sysmon and enable the operational channel before capture.");
            });
        }
    }

    private static void CheckEventLogForCapture(
        List<AgentConfigurationFinding> findings,
        string channel,
        AgentConfigurationAreaKind area)
    {
        TryCheck(findings, area, () =>
        {
            using var configuration = new EventLogConfiguration(channel);
            Add(findings, area,
                configuration.IsEnabled ? AgentConfigurationFindingSeverity.Info : AgentConfigurationFindingSeverity.Warning,
                configuration.IsEnabled ? $"Capture log '{channel}' is enabled." : $"Capture log '{channel}' is disabled.",
                $"Retention/log mode: {configuration.LogMode}; maximum size: {configuration.MaximumSizeInBytes / 1024 / 1024:N0} MB.",
                configuration.IsEnabled ? string.Empty : "Enable the channel before relying on this source.");
        }, $"Capture log '{channel}' could not be inspected.");
    }

    private void CheckNetworkCapture(List<AgentConfigurationFinding> findings, AgentNetworkCaptureMetadataPolicy policy)
    {
        if (!policy.Enabled)
        {
            Add(findings, AgentConfigurationAreaKind.NetworkCapture, AgentConfigurationFindingSeverity.Info,
                "Network packet capture metadata policy is disabled.",
                "No Packet Monitor capture will start from this capture configuration.");
            return;
        }

        var pktmon = FindSystemExecutable("pktmon.exe") ?? FindOnPath("pktmon.exe");
        if (string.IsNullOrWhiteSpace(pktmon))
        {
            Add(findings, AgentConfigurationAreaKind.NetworkCapture, AgentConfigurationFindingSeverity.Blocked,
                "Packet Monitor was not found.",
                "pktmon.exe is required for the current Windows packet capture path.",
                "Install/use a Windows version with pktmon.exe or disable network capture.");
        }
        else
        {
            Add(findings, AgentConfigurationAreaKind.NetworkCapture, AgentConfigurationFindingSeverity.Info,
                "Packet Monitor is available.",
                pktmon);
        }

        AddPathReadiness(findings, AgentConfigurationAreaKind.NetworkCapture, FirstNonEmpty(policy.OutputDirectory, _sessionPaths.NetworkCapturesDirectory), "network capture output directory");
    }

    private void CheckZeek(List<AgentConfigurationFinding> findings, AgentZeekAnalysisImportPolicy policy, bool networkCaptureEnabled)
    {
        if (!policy.Enabled && !policy.RunAfterNetworkCapture)
        {
            Add(findings, AgentConfigurationAreaKind.ZeekAnalysis, AgentConfigurationFindingSeverity.Info,
                "Zeek analysis policy is disabled.",
                "No Zeek analysis will run automatically after capture.");
            return;
        }

        if (policy.RunAfterNetworkCapture && !networkCaptureEnabled)
        {
            Add(findings, AgentConfigurationAreaKind.ZeekAnalysis, AgentConfigurationFindingSeverity.Warning,
                "Zeek is configured to run after network capture, but network capture is disabled.",
                "No PCAP segment will be produced by this capture configuration.",
                "Enable network capture or run Zeek manually against an existing PCAP.");
        }

        var zeekPath = !string.IsNullOrWhiteSpace(policy.ZeekPath) && File.Exists(policy.ZeekPath)
            ? policy.ZeekPath
            : FindOnPath("zeek.exe") ?? FindOnPath("zeek");
        if (string.IsNullOrWhiteSpace(zeekPath))
        {
            var wsl = FindOnPath("wsl.exe");
            Add(findings, AgentConfigurationAreaKind.ZeekAnalysis,
                string.IsNullOrWhiteSpace(wsl) ? AgentConfigurationFindingSeverity.Warning : AgentConfigurationFindingSeverity.Info,
                string.IsNullOrWhiteSpace(wsl) ? "Zeek was not found on PATH." : "Native Zeek was not found; WSL is present.",
                string.IsNullOrWhiteSpace(wsl)
                    ? "The read-only check did not find zeek.exe, zeek, or wsl.exe."
                    : $"Configured WSL distro: {FirstNonEmpty(policy.WslDistributionName, "<default>")}; Zeek command: {FirstNonEmpty(policy.WslZeekCommand, "zeek")}. The bounded read-only check did not execute WSL to verify Zeek inside Linux.",
                "Install Zeek for Windows or inside WSL, or set the Network tab WSL distro and Zeek command before relying on automatic Zeek analysis.");
        }
        else
        {
            Add(findings, AgentConfigurationAreaKind.ZeekAnalysis, AgentConfigurationFindingSeverity.Info,
                "Zeek executable is available.",
                zeekPath);
        }

        AddPathReadiness(findings, AgentConfigurationAreaKind.ZeekAnalysis, FirstNonEmpty(policy.OutputDirectory, _sessionPaths.ZeekDirectory), "Zeek output directory");
    }

    private static void CheckArtifactCapture(List<AgentConfigurationFinding> findings, AgentArtifactCapturePolicy policy)
    {
        if (!policy.CaptureModules && !policy.CaptureHandles && !policy.CapturePeMetadata && !policy.CaptureDumpMetadata)
        {
            Add(findings, AgentConfigurationAreaKind.ModuleCapture, AgentConfigurationFindingSeverity.Warning,
                "All artifact enrichment capture policies are disabled.",
                "Capture will not collect module, handle, PE metadata, or dump metadata enrichment.",
                "Enable at least module or handle capture for richer process triage.");
            return;
        }

        if (policy.CaptureModules)
        {
            Add(findings, AgentConfigurationAreaKind.ModuleCapture, AgentConfigurationFindingSeverity.Info,
                "Module enrichment policy is enabled.",
                FirstNonEmpty(policy.ScopePolicy, "Default scope policy."));
        }

        if (policy.CaptureHandles)
        {
            Add(findings, AgentConfigurationAreaKind.HandleCapture, AgentConfigurationFindingSeverity.Info,
                "Handle enrichment policy is enabled.",
                FirstNonEmpty(policy.ScopePolicy, "Default scope policy."));
        }

        if (policy.CapturePeMetadata)
        {
            Add(findings, AgentConfigurationAreaKind.PeMetadataCapture, AgentConfigurationFindingSeverity.Info,
                "PE metadata enrichment policy is enabled.",
                "Process image PE metadata can be captured by enrichment jobs.");
        }

        if (policy.CaptureDumpMetadata)
        {
            Add(findings, AgentConfigurationAreaKind.DumpMetadataCapture, AgentConfigurationFindingSeverity.Info,
                "Dump metadata capture policy is enabled.",
                "Dump binaries remain file references; SQLite stores metadata only.");
        }
    }

    private static void CheckGuardrails(List<AgentConfigurationFinding> findings, AgentCaptureConfiguration configuration)
    {
        var enabledSources = new[]
            {
                configuration.SourceToggles.Etw,
                configuration.SourceToggles.Security,
                configuration.SourceToggles.PowerShell,
                configuration.SourceToggles.WindowsOther,
                configuration.SourceToggles.Sysmon
            }
            .Count(enabled => enabled);

        if (configuration.Guardrails.Enabled &&
            configuration.Guardrails.MaxEventsPerSecondWarning <= 0 &&
            configuration.Guardrails.MaxLiveDatabaseBytesWarning <= 0)
        {
            Add(findings, AgentConfigurationAreaKind.VolumeRetentionGuardrails, AgentConfigurationFindingSeverity.Warning,
                "Volume guardrails are enabled but warning thresholds are not set.",
                "No event-rate or live database size warning threshold was provided.",
                "Set warning thresholds before high-volume capture.");
        }

        if (enabledSources >= 4)
        {
            Add(findings, AgentConfigurationAreaKind.VolumeRetentionGuardrails, AgentConfigurationFindingSeverity.Warning,
                "Multiple high-volume event sources are enabled.",
                $"Enabled event/log sources: {enabledSources}.",
                "Watch live database growth and use lower-volume profiles for long captures.");
        }
    }

    private static void AddPathReadiness(
        List<AgentConfigurationFinding> findings,
        AgentConfigurationAreaKind area,
        string path,
        string label)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            Add(findings, area, AgentConfigurationFindingSeverity.Warning,
                $"{label} is not configured.",
                "The agent will fall back to its session default where supported.");
            return;
        }

        if (!Directory.Exists(path))
        {
            Add(findings, area, AgentConfigurationFindingSeverity.Warning,
                $"{label} does not exist yet.",
                path,
                "The read-only check did not create directories. Ensure the path can be created before execution.");
            return;
        }

        Add(findings, area, AgentConfigurationFindingSeverity.Info,
            $"{label} exists.",
            path);
    }

    private static IReadOnlyList<string> ValidateEtwConfiguration(EtwProviderConfiguration configuration)
    {
        var errors = new List<string>();
        if (configuration.Session == null)
        {
            errors.Add("session settings are missing");
        }

        configuration.Providers ??= new List<EtwProviderDefinition>();
        if (configuration.Providers.Count == 0)
        {
            errors.Add("no providers are declared");
        }

        var enabledProviders = configuration.Providers.Where(provider => provider.Enabled).ToList();
        if (enabledProviders.Count == 0)
        {
            errors.Add("no providers are enabled");
        }

        foreach (var provider in enabledProviders)
        {
            if (string.IsNullOrWhiteSpace(provider.Name) && string.IsNullOrWhiteSpace(provider.Guid))
            {
                errors.Add("an enabled provider is missing both Name and Guid");
            }

            if (!string.IsNullOrWhiteSpace(provider.Guid) && !Guid.TryParse(provider.Guid, out _))
            {
                errors.Add($"provider '{GetProviderDisplayName(provider)}' has invalid Guid '{provider.Guid}'");
            }

            if (!Enum.TryParse<TraceEventLevel>(provider.Level, ignoreCase: true, out _))
            {
                errors.Add($"provider '{GetProviderDisplayName(provider)}' has invalid level '{provider.Level}'");
            }

            if (!TryParseKeywords(provider.KeywordsHex, out _))
            {
                errors.Add($"provider '{GetProviderDisplayName(provider)}' has invalid KeywordsHex '{provider.KeywordsHex}'");
            }
        }

        return errors;
    }

    private static bool TryParseKeywords(string? keywordsHex, out ulong keywords)
    {
        if (string.IsNullOrWhiteSpace(keywordsHex))
        {
            keywords = ulong.MaxValue;
            return true;
        }

        var normalized = keywordsHex.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        return ulong.TryParse(normalized, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out keywords);
    }

    private static AgentConfigurationCheckResult CreateResult<TConfiguration>(
        AgentConfigurationTargetKind targetKind,
        string agentId,
        string hostId,
        string commandVersion,
        string commandHash,
        TConfiguration configuration,
        List<AgentConfigurationFinding> findings)
    {
        if (findings.Count == 0)
        {
            Add(findings, AgentConfigurationAreaKind.Unknown, AgentConfigurationFindingSeverity.Info,
                "No findings were produced by the configuration check.");
        }

        var lastError = findings.FirstOrDefault(finding =>
            finding.Severity is AgentConfigurationFindingSeverity.Blocked or AgentConfigurationFindingSeverity.Error)?.Message ?? string.Empty;

        return new AgentConfigurationCheckResult
        {
            TargetKind = targetKind,
            AgentId = agentId,
            HostId = FirstNonEmpty(hostId, Environment.MachineName),
            ConfigurationVersion = FirstNonEmpty(commandVersion, GetConfigurationVersion(configuration)),
            ConfigurationHash = FirstNonEmpty(commandHash, ComputeHash(configuration)),
            CheckedAtUtc = DateTime.UtcNow,
            OverallState = ResolveOverallState(findings),
            Findings = findings.ToArray(),
            LastError = lastError
        };
    }

    private static AgentConfigurationCheckState ResolveOverallState(IEnumerable<AgentConfigurationFinding> findings)
    {
        var severities = findings.Select(finding => finding.Severity).ToArray();
        if (severities.Any(severity => severity is AgentConfigurationFindingSeverity.Blocked or AgentConfigurationFindingSeverity.Error))
        {
            return AgentConfigurationCheckState.Blocked;
        }

        if (severities.Any(severity => severity is AgentConfigurationFindingSeverity.Warning or AgentConfigurationFindingSeverity.Unknown))
        {
            return AgentConfigurationCheckState.Warning;
        }

        return AgentConfigurationCheckState.Ready;
    }

    private static string GetConfigurationVersion<TConfiguration>(TConfiguration configuration)
    {
        return configuration switch
        {
            AgentConfigurationDocument document when !string.IsNullOrWhiteSpace(document.ConfigurationVersion) => document.ConfigurationVersion,
            AgentHostMonitoringConfiguration => "monitoring-check-v1",
            AgentCaptureConfiguration => "capture-check-v1",
            _ => "configuration-check-v1"
        };
    }

    private static string ComputeHash<TConfiguration>(TConfiguration configuration)
    {
        var json = JsonSerializer.Serialize(configuration, AgentJson.JsonOptions);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private string ResolveProfilePath(ConfigProfileDefinition? profile)
    {
        return profile == null ? string.Empty : _configProfiles.ResolveProfileFilePath(profile) ?? string.Empty;
    }

    private static string GetProfileName(ConfigProfileDefinition? profile)
        => profile == null ? string.Empty : FirstNonEmpty(profile.DisplayName, profile.Id);

    private static string GetProviderDisplayName(EtwProviderDefinition provider)
        => FirstNonEmpty(provider.Name, provider.Guid, "<unnamed provider>");

    private static string? FindSystemExecutable(string fileName)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (string.IsNullOrWhiteSpace(system))
        {
            return null;
        }

        var candidate = Path.Combine(system, fileName);
        return File.Exists(candidate) ? candidate : null;
    }

    private static string? FindOnPath(string fileName)
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

    private static bool? ReadProcessCommandLineLoggingEnabled()
    {
        using var key = Registry.LocalMachine.OpenSubKey(AuditPolicyRegistryPath, writable: false);
        var value = key?.GetValue(ProcessCommandLineLoggingValueName);
        return value switch
        {
            int intValue => intValue != 0,
            string stringValue when int.TryParse(stringValue, out var parsed) => parsed != 0,
            null => null,
            _ => false
        };
    }

    private static void TryCheck(
        List<AgentConfigurationFinding> findings,
        AgentConfigurationAreaKind area,
        Action check,
        string? failureMessage = null)
    {
        try
        {
            check();
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or IOException or JsonException or InvalidOperationException)
        {
            Add(findings, area, AgentConfigurationFindingSeverity.Warning,
                failureMessage ?? $"{area} could not be inspected.",
                ex.Message,
                "Review permissions, installed components, and bundled configuration assets.");
        }
    }

    private static void Add(
        List<AgentConfigurationFinding> findings,
        AgentConfigurationAreaKind area,
        AgentConfigurationFindingSeverity severity,
        string message,
        string technicalDetail = "",
        string suggestedRemediation = "")
    {
        findings.Add(new AgentConfigurationFinding
        {
            Area = area,
            Severity = severity,
            Message = message,
            TechnicalDetail = technicalDetail,
            SuggestedRemediation = suggestedRemediation
        });
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}
