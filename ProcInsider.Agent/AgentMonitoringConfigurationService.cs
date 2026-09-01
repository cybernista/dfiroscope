using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentMonitoringConfigurationService
{
    private const string ConfigurationFileName = "agent-host-monitoring-configuration.json";
    private const string OriginalStateFileName = "agent-monitoring-original-state.json";
    private const string LegacyDeploymentStateFileName = "agent-monitoring-deployment-state.json";
    private const string DeploymentLogFileName = "AgentMonitoringDeployment.jsonl";
    private const string AuditPolicyRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
    private const string ProcessCommandLineLoggingValueName = "ProcessCreationIncludeCmdLine_Enabled";

    private readonly InvestigationSessionPaths _sessionPaths;
    private readonly AgentConfigurationCheckService _configurationChecks;
    private readonly ConfigProfileService _configProfiles = new();
    private readonly SysmonService _sysmonService;
    private readonly PowerShellAuditingService _powerShellAuditingService;
    private readonly TextWriter _log;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public AgentMonitoringConfigurationService(
        InvestigationSessionPaths sessionPaths,
        AgentConfigurationCheckService configurationChecks,
        TextWriter log)
    {
        _sessionPaths = sessionPaths;
        _configurationChecks = configurationChecks;
        _sysmonService = new SysmonService(_configProfiles);
        _powerShellAuditingService = new PowerShellAuditingService(_configProfiles);
        _log = log;
    }

    private string ConfigurationPath => Path.Combine(_sessionPaths.SessionRoot, ConfigurationFileName);

    private string OriginalStatePath => Path.Combine(_sessionPaths.SessionRoot, OriginalStateFileName);

    private string LegacyDeploymentStatePath => Path.Combine(_sessionPaths.SessionRoot, LegacyDeploymentStateFileName);

    private string DeploymentLogPath => Path.Combine(_sessionPaths.LogsDirectory, DeploymentLogFileName);

    public AgentHostMonitoringConfiguration GetHostMonitoringConfiguration(GetHostMonitoringConfigurationCommand command)
    {
        var saved = TryReadConfiguration();
        return AttachOriginalState(saved ?? StampConfiguration(_configurationChecks.CreateDefaultHostMonitoringConfiguration(command), command));
    }

    public AgentHostMonitoringConfiguration SaveHostMonitoringConfiguration(SaveHostMonitoringConfigurationCommand command)
    {
        var stamped = StampConfiguration(command.Configuration, command);
        Directory.CreateDirectory(_sessionPaths.SessionRoot);
        File.WriteAllText(ConfigurationPath, JsonSerializer.Serialize(stamped, _jsonOptions));
        AppendLog(new
        {
            action = "save",
            timestampUtc = DateTime.UtcNow,
            stamped.AgentId,
            stamped.HostId,
            stamped.ConfigurationVersion,
            stamped.ConfigurationHash
        });
        return AttachOriginalState(stamped);
    }

    public AgentMonitoringDeploymentResult DeployHostMonitoringConfiguration(DeployHostMonitoringConfigurationCommand command)
    {
        var startedAtUtc = DateTime.UtcNow;
        var configuration = TryReadConfiguration();
        if (configuration == null)
        {
            var missingConfigurationResult = CreateResult(
                command,
                AgentMonitoringDeploymentAction.Deploy,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                [],
                "No saved monitoring configuration was found. Save or configure monitoring before deploying.");
            AppendLog(missingConfigurationResult);
            return missingConfigurationResult;
        }

        if (command.RequireMatchingHash &&
            !string.IsNullOrWhiteSpace(command.ConfigurationHash) &&
            !string.Equals(command.ConfigurationHash, configuration.ConfigurationHash, StringComparison.OrdinalIgnoreCase))
        {
            var hashMismatchResult = CreateResult(
                command,
                AgentMonitoringDeploymentAction.Deploy,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                [],
                "Saved monitoring configuration hash does not match the deployment command.");
            AppendLog(hashMismatchResult);
            return hashMismatchResult;
        }

        var previousState = CaptureOriginalState(configuration, command);
        SaveOriginalState(previousState);
        var areaResults = new List<AgentMonitoringDeploymentAreaResult>
        {
            DeploySysmon(configuration.Sysmon),
            DeploySecurityAuditPolicy(configuration.SecurityAuditPolicy, previousState),
            DeployProcessCommandLineLogging(configuration.SecurityAuditPolicy),
            DeployEventLogs(configuration.EventLogs),
            DeployPowerShellAuditing(configuration.PowerShellAuditing, previousState),
            DeployEtw(configuration.Etw),
            DeployScheduledDumps(configuration.ScheduledDumps)
        };

        previousState.AreaResults = areaResults.ToArray();
        SaveOriginalState(previousState);

        var resultStatus = ResolveResultStatus(areaResults);
        var result = CreateResult(command, AgentMonitoringDeploymentAction.Deploy, startedAtUtc, resultStatus, areaResults, string.Empty, previousState);
        AppendLog(result);
        return result;
    }

    public AgentMonitoringDeploymentResult ReverseHostMonitoringDeployment(ReverseHostMonitoringDeploymentCommand command)
    {
        var startedAtUtc = DateTime.UtcNow;
        var configuration = TryReadConfiguration();
        var previousState = TryReadDeploymentState();
        if (configuration == null || previousState == null)
        {
            var missingStateResult = CreateResult(
                command,
                AgentMonitoringDeploymentAction.Reverse,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                [],
                "No prior monitoring deployment state was found. Manual cleanup guidance is required.");
            AppendLog(missingStateResult);
            return missingStateResult;
        }

        var areaResults = new List<AgentMonitoringDeploymentAreaResult>
        {
            ReverseSysmon(previousState),
            ReverseSecurityAuditPolicy(previousState),
            ReverseProcessCommandLineLogging(previousState),
            ReverseEventLogs(previousState),
            ReversePowerShellAuditing(previousState),
            ReverseEtw(configuration.Etw),
            ReverseScheduledDumps(configuration, previousState)
        };

        var resultStatus = ResolveResultStatus(areaResults);
        previousState.LastRevertedUtc = DateTime.UtcNow;
        previousState.LastRevertStatus = resultStatus;
        previousState.LastRevertAreaResults = areaResults.ToArray();
        SaveOriginalState(previousState);

        var result = CreateResult(command, AgentMonitoringDeploymentAction.Reverse, startedAtUtc, resultStatus, areaResults, string.Empty, previousState);
        AppendLog(result);
        return result;
    }

    private AgentHostMonitoringConfiguration AttachOriginalState(AgentHostMonitoringConfiguration configuration)
        => configuration with
        {
            OriginalState = BuildOriginalStateSnapshot(TryReadDeploymentState())
        };

    private AgentHostMonitoringConfiguration? TryReadConfiguration()
    {
        try
        {
            if (!File.Exists(ConfigurationPath))
            {
                return null;
            }

            return JsonSerializer.Deserialize<AgentHostMonitoringConfiguration>(
                File.ReadAllText(ConfigurationPath),
                _jsonOptions);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to read host monitoring configuration: {ex.Message}");
            return null;
        }
    }

    private AgentHostMonitoringConfiguration StampConfiguration(
        AgentHostMonitoringConfiguration configuration,
        AgentConfigurationCommand command)
    {
        var updatedUtc = DateTime.UtcNow;
        var stamped = configuration with
        {
            AgentId = FirstNonEmpty(command.AgentId, configuration.AgentId, AgentsViewModelLocalAgentId()),
            HostId = FirstNonEmpty(command.HostId, configuration.HostId, Environment.MachineName),
            ConfigurationVersion = FirstNonEmpty(command.ConfigurationVersion, configuration.ConfigurationVersion, "monitoring-v1"),
            ConfigurationHash = string.Empty,
            OriginalState = BuildOriginalStateSnapshot(TryReadDeploymentState()),
            UpdatedAtUtc = updatedUtc,
            Status = AgentConfigurationStatus.Saved,
            LastError = string.Empty
        };

        return stamped with
        {
            ConfigurationHash = ComputeHash(stamped)
        };
    }

    private AgentMonitoringDeploymentAreaResult DeploySysmon(AgentSysmonMonitoringIntent intent)
    {
        return TryArea(AgentConfigurationAreaKind.Sysmon, reverseSupported: false, () =>
        {
            var profile = ResolveProfile(ConfigProfileKind.Sysmon, intent.ProfileId);
            var settings = _sysmonService.LoadSettings();
            if (!settings.IsServiceStateAvailable)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.Sysmon,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = false,
                    Message = "Sysmon service state could not be read; no install or configuration command was started.",
                    TechnicalDetail = $"{settings.ServiceStatusDetail} {settings.ServiceError}".Trim()
                };
            }

            if (!intent.InstallOrUpdate)
            {
                var status = settings.IsInstalled && settings.IsRunning && settings.IsChannelAvailable
                    ? AgentConfigurationOperationStatus.Success
                    : AgentConfigurationOperationStatus.Warning;
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.Sysmon,
                    Status = status,
                    ReverseSupported = false,
                    Message = settings.IsInstalled
                        ? "Sysmon was verified; no install/update was requested."
                        : "Sysmon install/update is disabled and Sysmon is not fully available.",
                    TechnicalDetail = $"Installed={settings.IsInstalled}; running={settings.IsRunning}; channelEnabled={settings.IsChannelEnabled}; watcherAccessible={settings.IsWatcherAccessible}; channelAvailable={settings.IsChannelAvailable}. {settings.ChannelStatusDetail}"
                };
            }

            if (settings.IsInstalled)
            {
                if (profile != null)
                {
                    _sysmonService.ApplyBundledConfig(profile);
                }
                else
                {
                    _sysmonService.ApplyBundledConfig();
                }
            }
            else if (profile != null)
            {
                _sysmonService.InstallWithBundledConfig(profile);
            }
            else
            {
                _sysmonService.InstallWithBundledConfig();
            }

            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.Sysmon,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = false,
                Message = settings.IsInstalled
                    ? "Sysmon configuration profile was applied."
                    : "Sysmon install was requested with the selected bundled profile.",
                TechnicalDetail = FirstNonEmpty(intent.ProfileDisplayName, intent.ProfileId, profile?.DisplayName ?? string.Empty)
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult DeploySecurityAuditPolicy(
        AgentSecurityAuditMonitoringIntent intent,
        MonitoringDeploymentState previousState)
    {
        return TryArea(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, reverseSupported: true, () =>
        {
            if (!intent.ConfigureAuditPolicy)
            {
                return Skipped(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, "Security audit policy deployment is disabled.");
            }

            var auditPolicyPath = ResolveSecurityAuditPolicyPath(intent);
            if (string.IsNullOrWhiteSpace(auditPolicyPath) || !File.Exists(auditPolicyPath))
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = !string.IsNullOrWhiteSpace(previousState.AuditPolicyBackupPath),
                    Message = "Security audit policy profile was not found.",
                    TechnicalDetail = auditPolicyPath
                };
            }

            if (string.IsNullOrWhiteSpace(previousState.AuditPolicyBackupPath) ||
                !File.Exists(previousState.AuditPolicyBackupPath))
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = false,
                    Message = "Security audit policy original state could not be captured; no policy change was attempted.",
                    TechnicalDetail = "A readable session-owned audit policy backup is required before deployment."
                };
            }

            var output = ApplySecurityAuditPolicyProfile(auditPolicyPath);
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = !string.IsNullOrWhiteSpace(previousState.AuditPolicyBackupPath),
                Message = "Security audit policy was applied from the selected agent-owned profile.",
                TechnicalDetail = output
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult DeployProcessCommandLineLogging(
        AgentSecurityAuditMonitoringIntent intent)
    {
        return TryArea(AgentConfigurationAreaKind.ProcessCommandLineAuditing, reverseSupported: true, () =>
        {
            if (!intent.EnableProcessCommandLineLogging)
            {
                return Skipped(
                    AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                    "Process command-line logging deployment is disabled.");
            }

            using var key = Registry.LocalMachine.CreateSubKey(AuditPolicyRegistryPath);
            if (key == null)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = true,
                    Message = "Process command-line logging registry policy could not be opened.",
                    TechnicalDetail = $@"HKLM\{AuditPolicyRegistryPath}"
                };
            }

            key.SetValue(ProcessCommandLineLoggingValueName, 1, RegistryValueKind.DWord);
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = true,
                Message = "Process command-line logging policy was enabled.",
                TechnicalDetail = $@"HKLM\{AuditPolicyRegistryPath}\{ProcessCommandLineLoggingValueName}=1"
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult DeployEventLogs(AgentEventLogMonitoringIntent intent)
    {
        return TryArea(AgentConfigurationAreaKind.WindowsEventLogs, reverseSupported: true, () =>
        {
            if (!intent.ConfigureChannels && !intent.ConfigureRetention)
            {
                return Skipped(AgentConfigurationAreaKind.WindowsEventLogs, "Event-log configuration is disabled.");
            }

            var entries = LoadEventLogProfile(intent).ToArray();
            if (entries.Length == 0 && intent.ChannelNames.Length == 0)
            {
                return Skipped(AgentConfigurationAreaKind.WindowsEventLogs, "No event-log channels were configured.");
            }

            if (entries.Length == 0)
            {
                entries = intent.ChannelNames
                    .Where(channel => !string.IsNullOrWhiteSpace(channel))
                    .Select(channel => new EventLogProfileEntry { Name = channel, Enable = true })
                    .ToArray();
            }

            var messages = new List<string>();
            var failures = 0;
            foreach (var entry in entries)
            {
                if (string.IsNullOrWhiteSpace(entry.Name))
                {
                    continue;
                }

                try
                {
                    if (!EventLogExists(entry.Name))
                    {
                        messages.Add(entry.Optional ? $"Optional log missing, skipped: {entry.Name}" : $"Log missing: {entry.Name}");
                        if (!entry.Optional)
                        {
                            failures++;
                        }

                        continue;
                    }

                    if (intent.ConfigureChannels && entry.Enable && entry.Name.Contains('/'))
                    {
                        RunProcess("wevtutil.exe", $"sl \"{entry.Name}\" /e:true");
                    }

                    if (intent.ConfigureRetention && entry.SizeBytes > 0)
                    {
                        RunProcess("wevtutil.exe", $"sl \"{entry.Name}\" /ms:{entry.SizeBytes} /rt:false /ab:false");
                    }

                    messages.Add($"Configured {entry.Name}");
                }
                catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or
                                              TimeoutException or Win32Exception)
                {
                    failures++;
                    messages.Add($"{entry.Name}: {ex.Message}");
                }
            }

            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.WindowsEventLogs,
                Status = failures == 0 ? AgentConfigurationOperationStatus.Success : AgentConfigurationOperationStatus.Warning,
                ReverseSupported = true,
                Message = failures == 0
                    ? "Event-log channel and retention settings were applied."
                    : "Some event-log settings could not be applied.",
                TechnicalDetail = string.Join("; ", messages)
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult DeployPowerShellAuditing(
        AgentPowerShellMonitoringIntent intent,
        MonitoringDeploymentState previousState)
    {
        return TryArea(AgentConfigurationAreaKind.PowerShellAuditing, reverseSupported: true, () =>
        {
            if (!intent.EnableScriptBlockLogging && !intent.EnableModuleLogging && !intent.EnableTranscription)
            {
                return Skipped(AgentConfigurationAreaKind.PowerShellAuditing, "PowerShell auditing deployment is disabled.");
            }

            if (previousState.PowerShellStateAvailable == false)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.PowerShellAuditing,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = false,
                    Message = "PowerShell auditing state could not be captured; no policy write was attempted.",
                    TechnicalDetail = previousState.PowerShellStateError
                };
            }

            _powerShellAuditingService.SetScriptBlockLogging(intent.EnableScriptBlockLogging);
            _powerShellAuditingService.SetModuleLogging(intent.EnableModuleLogging);
            _powerShellAuditingService.SetTranscription(intent.EnableTranscription, intent.TranscriptDirectory);

            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.PowerShellAuditing,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = true,
                Message = "PowerShell auditing registry policy was applied.",
                TechnicalDetail = $"ScriptBlock={intent.EnableScriptBlockLogging}; module={intent.EnableModuleLogging}; transcription={intent.EnableTranscription}; transcriptPath={intent.TranscriptDirectory}."
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult DeployEtw(AgentEtwMonitoringIntent intent)
    {
        return TryArea(AgentConfigurationAreaKind.Etw, reverseSupported: true, () =>
        {
            if (!intent.ConfigureSession)
            {
                return Skipped(AgentConfigurationAreaKind.Etw, "ETW monitoring session deployment is disabled.");
            }

            var path = FirstNonEmpty(intent.ProfilePath, ResolveProfilePath(ConfigProfileKind.Etw, intent.ProfileId));
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.Etw,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = true,
                    Message = "ETW profile was not found.",
                    TechnicalDetail = path
                };
            }

            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.Etw,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = true,
                Message = "ETW profile was saved for capture configuration; no capture session was started.",
                TechnicalDetail = path
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult DeployScheduledDumps(AgentScheduledDumpPolicy policy)
    {
        return TryArea(AgentConfigurationAreaKind.ScheduledDumps, reverseSupported: true, () =>
        {
            if (!policy.Enabled)
            {
                return Skipped(AgentConfigurationAreaKind.ScheduledDumps, "Scheduled dump policy is disabled.");
            }

            if (policy.IntervalSeconds <= 0 && string.IsNullOrWhiteSpace(policy.OffsetsFromCaptureStart))
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.ScheduledDumps,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = true,
                    Message = "Scheduled dump policy has no valid schedule.",
                    TechnicalDetail = "Set a positive interval or comma-delimited offsets from capture start."
                };
            }

            Directory.CreateDirectory(FirstNonEmpty(policy.OutputDirectory, _sessionPaths.DumpsDirectory));
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.ScheduledDumps,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = true,
                Message = "Scheduled dump policy was saved for future capture execution.",
                TechnicalDetail = $"Interval={policy.IntervalSeconds}; offsets={policy.OffsetsFromCaptureStart}; max={policy.MaxDumpsPerCapture}."
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult ReverseSysmon(MonitoringDeploymentState previousState)
    {
        if (!WasDeploymentAreaApplied(previousState, AgentConfigurationAreaKind.Sysmon))
        {
            return Skipped(AgentConfigurationAreaKind.Sysmon, "Sysmon deployment was not applied; original state was retained for audit only.");
        }

        return new AgentMonitoringDeploymentAreaResult
        {
            Area = AgentConfigurationAreaKind.Sysmon,
            Status = AgentConfigurationOperationStatus.Unsupported,
            ReverseSupported = false,
            Message = "Sysmon removal is not automatic.",
            TechnicalDetail = previousState.SysmonWasInstalled
                ? $"Sysmon existed before deployment or ownership cannot be proven; {ProductIdentity.DisplayName} will not remove it automatically."
                : "A Sysmon install may have been requested, but automatic removal is withheld until ownership can be proven."
        };
    }

    private AgentMonitoringDeploymentAreaResult ReverseSecurityAuditPolicy(MonitoringDeploymentState previousState)
    {
        if (!WasDeploymentAreaApplied(previousState, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy))
        {
            return Skipped(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, "Security audit policy deployment was not applied; original state was retained for audit only.");
        }

        return TryArea(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, reverseSupported: true, () =>
        {
            if (string.IsNullOrWhiteSpace(previousState.AuditPolicyBackupPath) || !File.Exists(previousState.AuditPolicyBackupPath))
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                    Status = AgentConfigurationOperationStatus.Unsupported,
                    ReverseSupported = false,
                    Message = "No pre-deployment audit policy backup is available.",
                    TechnicalDetail = "Manual audit policy review is required."
                };
            }

            var output = RunProcess("auditpol.exe", $"/restore /file:\"{previousState.AuditPolicyBackupPath}\"");
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = true,
                Message = "Security audit policy was restored from the pre-deployment backup.",
                TechnicalDetail = output
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult ReverseProcessCommandLineLogging(
        MonitoringDeploymentState previousState)
    {
        if (!WasDeploymentAreaApplied(previousState, AgentConfigurationAreaKind.ProcessCommandLineAuditing))
        {
            return Skipped(AgentConfigurationAreaKind.ProcessCommandLineAuditing, "Process command-line logging deployment was not applied; original state was retained for audit only.");
        }

        return TryArea(AgentConfigurationAreaKind.ProcessCommandLineAuditing, reverseSupported: true, () =>
        {
            using var key = Registry.LocalMachine.OpenSubKey(AuditPolicyRegistryPath, writable: true);
            if (key == null)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                    Status = previousState.ProcessCommandLineLoggingValueExisted
                        ? AgentConfigurationOperationStatus.Failed
                        : AgentConfigurationOperationStatus.Success,
                    ReverseSupported = true,
                    Message = previousState.ProcessCommandLineLoggingValueExisted
                        ? "Process command-line logging registry policy could not be opened for restore."
                        : "Process command-line logging registry policy was already absent.",
                    TechnicalDetail = $@"HKLM\{AuditPolicyRegistryPath}"
                };
            }

            if (previousState.ProcessCommandLineLoggingValueExisted)
            {
                key.SetValue(
                    ProcessCommandLineLoggingValueName,
                    previousState.ProcessCommandLineLoggingEnabled ? 1 : 0,
                    RegistryValueKind.DWord);
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                    Status = AgentConfigurationOperationStatus.Success,
                    ReverseSupported = true,
                    Message = "Process command-line logging policy was restored from the pre-deployment snapshot.",
                    TechnicalDetail = $"{ProcessCommandLineLoggingValueName}={(previousState.ProcessCommandLineLoggingEnabled ? 1 : 0)}"
                };
            }

            key.DeleteValue(ProcessCommandLineLoggingValueName, throwOnMissingValue: false);
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = true,
                Message = "Process command-line logging policy was removed because it was absent before deployment.",
                TechnicalDetail = ProcessCommandLineLoggingValueName
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult ReverseEventLogs(MonitoringDeploymentState previousState)
    {
        if (!WasDeploymentAreaApplied(previousState, AgentConfigurationAreaKind.WindowsEventLogs))
        {
            return Skipped(AgentConfigurationAreaKind.WindowsEventLogs, "Event-log deployment was not applied; original state was retained for audit only.");
        }

        return TryArea(AgentConfigurationAreaKind.WindowsEventLogs, reverseSupported: true, () =>
        {
            if (previousState.EventLogs.Length == 0)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.WindowsEventLogs,
                    Status = AgentConfigurationOperationStatus.Unsupported,
                    ReverseSupported = false,
                    Message = "No pre-deployment event-log settings were recorded.",
                    TechnicalDetail = "Manual event-log size and retention review is required."
                };
            }

            var messages = new List<string>();
            var failures = 0;
            foreach (var entry in previousState.EventLogs)
            {
                if (string.IsNullOrWhiteSpace(entry.Name) || !entry.Exists)
                {
                    continue;
                }

                try
                {
                    if (entry.Name.Contains('/'))
                    {
                        RunProcess("wevtutil.exe", $"sl \"{entry.Name}\" /e:{entry.IsEnabled.ToString().ToLowerInvariant()}");
                    }

                    if (entry.MaximumSizeInBytes > 0)
                    {
                        RunProcess("wevtutil.exe", $"sl \"{entry.Name}\" /ms:{entry.MaximumSizeInBytes}{BuildRetentionArguments(entry.LogMode)}");
                    }

                    messages.Add($"Restored {entry.Name}");
                }
                catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or
                                              TimeoutException or Win32Exception)
                {
                    failures++;
                    messages.Add($"{entry.Name}: {ex.Message}");
                }
            }

            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.WindowsEventLogs,
                Status = failures == 0 ? AgentConfigurationOperationStatus.Success : AgentConfigurationOperationStatus.Warning,
                ReverseSupported = true,
                Message = failures == 0
                    ? "Event-log settings were restored from the pre-deployment snapshot."
                    : "Some event-log settings could not be restored.",
                TechnicalDetail = string.Join("; ", messages)
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult ReversePowerShellAuditing(MonitoringDeploymentState previousState)
    {
        if (previousState.PowerShellStateAvailable == false)
        {
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.PowerShellAuditing,
                Status = AgentConfigurationOperationStatus.Unsupported,
                ReverseSupported = false,
                Message = "PowerShell auditing original state was unavailable and cannot be restored safely.",
                TechnicalDetail = previousState.PowerShellStateError
            };
        }

        if (!WasDeploymentAreaApplied(previousState, AgentConfigurationAreaKind.PowerShellAuditing))
        {
            return Skipped(AgentConfigurationAreaKind.PowerShellAuditing, "PowerShell auditing deployment was not applied; original state was retained for audit only.");
        }

        return TryArea(AgentConfigurationAreaKind.PowerShellAuditing, reverseSupported: true, () =>
        {
            var previous = previousState.PowerShell;
            _powerShellAuditingService.SetScriptBlockLogging(previous.ScriptBlockLoggingEnabled);
            _powerShellAuditingService.SetModuleLogging(previous.ModuleLoggingEnabled);
            _powerShellAuditingService.SetTranscription(previous.TranscriptionEnabled, previous.TranscriptPath);
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.PowerShellAuditing,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = true,
                Message = "PowerShell auditing settings were restored from the pre-deployment snapshot.",
                TechnicalDetail = $"ScriptBlock={previous.ScriptBlockLoggingEnabled}; module={previous.ModuleLoggingEnabled}; transcription={previous.TranscriptionEnabled}; transcriptPath={previous.TranscriptPath}."
            };
        });
    }

    private static AgentMonitoringDeploymentAreaResult ReverseEtw(AgentEtwMonitoringIntent intent)
    {
        return new AgentMonitoringDeploymentAreaResult
        {
            Area = AgentConfigurationAreaKind.Etw,
            Status = AgentConfigurationOperationStatus.Success,
            ReverseSupported = true,
            Message = "No ETW session was started by monitoring deployment.",
            TechnicalDetail = string.IsNullOrWhiteSpace(intent.SessionName)
                ? "Capture owns ETW session start/stop."
                : $"Configured session name was {intent.SessionName}; capture owns ETW session start/stop."
        };
    }

    private AgentMonitoringDeploymentAreaResult ReverseScheduledDumps(
        AgentHostMonitoringConfiguration configuration,
        MonitoringDeploymentState previousState)
    {
        if (!WasDeploymentAreaApplied(previousState, AgentConfigurationAreaKind.ScheduledDumps))
        {
            return Skipped(AgentConfigurationAreaKind.ScheduledDumps, "Scheduled dump deployment was not applied; saved configuration was left unchanged.");
        }

        return TryArea(AgentConfigurationAreaKind.ScheduledDumps, reverseSupported: true, () =>
        {
            var disabledWithoutHash = configuration with
            {
                ScheduledDumps = configuration.ScheduledDumps with
                {
                    Enabled = false,
                    Status = AgentConfigurationStatus.Reversed,
                    LastError = string.Empty
                },
                ReverseDeployment = configuration.ReverseDeployment with
                {
                    SupportsReverseDeployment = true,
                    LastReversedUtc = DateTime.UtcNow,
                    Status = AgentConfigurationStatus.Reversed
                },
                ConfigurationHash = string.Empty,
                UpdatedAtUtc = DateTime.UtcNow
            };
            var disabled = disabledWithoutHash with
            {
                ConfigurationHash = ComputeHash(disabledWithoutHash)
            };
            File.WriteAllText(ConfigurationPath, JsonSerializer.Serialize(disabled, _jsonOptions));

            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.ScheduledDumps,
                Status = AgentConfigurationOperationStatus.Success,
                ReverseSupported = true,
                Message = "Scheduled dump policy was disabled in the saved monitoring configuration.",
                TechnicalDetail = "No capture lifecycle was started or stopped."
            };
        });
    }

    private static bool WasDeploymentAreaApplied(MonitoringDeploymentState state, AgentConfigurationAreaKind area)
    {
        return state.AreaResults.Length == 0 ||
               state.AreaResults.Any(result =>
                   result.Area == area &&
                   result.Status is AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning);
    }

    private MonitoringDeploymentState CaptureOriginalState(
        AgentHostMonitoringConfiguration configuration,
        AgentConfigurationCommand command)
    {
        var eventLogNames = LoadEventLogProfile(configuration.EventLogs)
            .Select(entry => entry.Name)
            .Concat(configuration.EventLogs.ChannelNames)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var sysmon = _sysmonService.LoadSettings();
        var sysmonExecutablePath = sysmon.IsServiceStateAvailable
            ? _sysmonService.FindSysmonExecutablePath() ?? string.Empty
            : string.Empty;
        var auditPolicyBackupPath = BackupAuditPolicy();
        var powerShell = _powerShellAuditingService.LoadSettings();
        var commandLineValueExisted = TryReadProcessCommandLineLoggingEnabled(out var commandLineEnabled);
        return new MonitoringDeploymentState
        {
            CapturedAtUtc = DateTime.UtcNow,
            AgentId = FirstNonEmpty(command.AgentId, configuration.AgentId, AgentsViewModelLocalAgentId()),
            HostId = FirstNonEmpty(command.HostId, configuration.HostId, Environment.MachineName),
            ConfigurationHash = configuration.ConfigurationHash,
            SysmonStateAvailable = sysmon.IsServiceStateAvailable,
            SysmonStateError = FirstNonEmpty(sysmon.ServiceError, sysmon.ServiceStatusDetail),
            SysmonWasInstalled = sysmon.IsInstalled,
            SysmonWasRunning = sysmon.IsRunning,
            SysmonChannelWasAvailable = sysmon.IsChannelAvailable,
            SysmonExecutablePath = sysmonExecutablePath,
            SysmonConfigurationSummary = CaptureSysmonConfigurationSummary(sysmon.IsInstalled, sysmonExecutablePath),
            ProcessCommandLineLoggingValueExisted = commandLineValueExisted,
            ProcessCommandLineLoggingEnabled = commandLineEnabled,
            AuditPolicyBackupPath = auditPolicyBackupPath,
            AuditPolicySummary = SummarizeAuditPolicyBackup(auditPolicyBackupPath),
            PowerShellStateAvailable = powerShell.IsAvailable,
            PowerShellStateError = FirstNonEmpty(powerShell.Error, powerShell.StatusDetail),
            PowerShell = new PowerShellAuditState
            {
                ScriptBlockLoggingEnabled = powerShell.ScriptBlockLoggingEnabled,
                ModuleLoggingEnabled = powerShell.ModuleLoggingEnabled,
                TranscriptionEnabled = powerShell.TranscriptionEnabled,
                TranscriptPath = powerShell.TranscriptPath
            },
            EventLogs = eventLogNames.Select(CaptureEventLogState).ToArray()
        };
    }

    private static string CaptureSysmonConfigurationSummary(bool isInstalled, string executablePath)
    {
        if (!isInstalled)
        {
            return "Sysmon was not installed before deployment.";
        }

        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            return "Sysmon was installed, but the executable path could not be resolved for a configuration query.";
        }

        try
        {
            return TrimForDisplay(RunProcess(executablePath, "-c", throwOnFailure: false), 1500);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or
                                      TimeoutException or Win32Exception)
        {
            return $"Sysmon configuration query failed: {ex.Message}";
        }
    }

    private static string SummarizeAuditPolicyBackup(string backupPath)
    {
        if (string.IsNullOrWhiteSpace(backupPath))
        {
            return "Audit policy backup was unavailable.";
        }

        try
        {
            if (!File.Exists(backupPath))
            {
                return $"Audit policy backup path was recorded but the file is missing: {backupPath}";
            }

            var rowCount = File.ReadLines(backupPath).Count(line => !string.IsNullOrWhiteSpace(line));
            return $"Audit policy backed up to {backupPath} ({rowCount:N0} non-empty rows).";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"Audit policy backup was recorded at {backupPath}, but summary failed: {ex.Message}";
        }
    }

    private static bool TryReadProcessCommandLineLoggingEnabled(out bool enabled)
    {
        enabled = false;
        using var key = Registry.LocalMachine.OpenSubKey(AuditPolicyRegistryPath, writable: false);
        var value = key?.GetValue(ProcessCommandLineLoggingValueName);
        switch (value)
        {
            case int intValue:
                enabled = intValue != 0;
                return true;
            case string stringValue when int.TryParse(stringValue, out var parsed):
                enabled = parsed != 0;
                return true;
            case null:
                return false;
            default:
                return false;
        }
    }

    private EventLogState CaptureEventLogState(string name)
    {
        try
        {
            using var configuration = new EventLogConfiguration(name);
            return new EventLogState
            {
                Name = name,
                Exists = true,
                IsEnabled = configuration.IsEnabled,
                MaximumSizeInBytes = configuration.MaximumSizeInBytes,
                LogMode = configuration.LogMode.ToString()
            };
        }
        catch
        {
            return new EventLogState
            {
                Name = name,
                Exists = false
            };
        }
    }

    private void SaveOriginalState(MonitoringDeploymentState state)
    {
        Directory.CreateDirectory(_sessionPaths.SessionRoot);
        var json = JsonSerializer.Serialize(state, _jsonOptions);
        File.WriteAllText(OriginalStatePath, json);

        try
        {
            File.WriteAllText(LegacyDeploymentStatePath, json);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to update legacy monitoring deployment state: {ex.Message}");
        }
    }

    private MonitoringDeploymentState? TryReadDeploymentState()
    {
        try
        {
            var path = File.Exists(OriginalStatePath)
                ? OriginalStatePath
                : File.Exists(LegacyDeploymentStatePath)
                    ? LegacyDeploymentStatePath
                    : string.Empty;
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            return JsonSerializer.Deserialize<MonitoringDeploymentState>(
                File.ReadAllText(path),
                _jsonOptions);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to read monitoring deployment state: {ex.Message}");
            return null;
        }
    }

    private static AgentMonitoringOriginalStateSnapshot BuildOriginalStateSnapshot(MonitoringDeploymentState? state)
    {
        if (state == null)
        {
            return new AgentMonitoringOriginalStateSnapshot();
        }

        var areas = BuildOriginalStateAreas(state).ToArray();
        var available = areas.Count(area => area.Status is AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning);
        var partial = areas.Any(area => area.Status is AgentConfigurationOperationStatus.Warning or AgentConfigurationOperationStatus.Unsupported);
        var summary = partial
            ? $"Original host monitoring state captured with partial restore coverage for {available}/{areas.Length} areas."
            : $"Original host monitoring state captured for {areas.Length} areas.";

        return new AgentMonitoringOriginalStateSnapshot
        {
            BaselineExists = true,
            AgentId = state.AgentId,
            HostId = state.HostId,
            ConfigurationHash = state.ConfigurationHash,
            CapturedAtUtc = state.CapturedAtUtc,
            LastRevertedUtc = state.LastRevertedUtc,
            LastRevertStatus = state.LastRevertStatus,
            Summary = summary,
            Areas = areas
        };
    }

    private static IEnumerable<AgentMonitoringOriginalStateArea> BuildOriginalStateAreas(MonitoringDeploymentState state)
    {
        yield return new AgentMonitoringOriginalStateArea
        {
            Area = AgentConfigurationAreaKind.Sysmon,
            Status = state.SysmonStateAvailable == false
                ? AgentConfigurationOperationStatus.Warning
                : state.SysmonWasInstalled
                ? AgentConfigurationOperationStatus.Success
                : AgentConfigurationOperationStatus.Unsupported,
            RestoreSupported = false,
            Summary = state.SysmonStateAvailable == false
                ? "Sysmon service state was inaccessible during baseline capture."
                : state.SysmonWasInstalled
                ? "Sysmon was present before deployment."
                : "Sysmon was not installed before deployment.",
            Detail = state.SysmonStateAvailable == false
                ? state.SysmonStateError
                : $"Installed={state.SysmonWasInstalled}; running={state.SysmonWasRunning}; channelAvailable={state.SysmonChannelWasAvailable}; executable={FirstNonEmpty(state.SysmonExecutablePath, "<unknown>")}. {state.SysmonConfigurationSummary}",
            RestoreGuidance = state.SysmonWasInstalled
                ? $"{ProductIdentity.DisplayName} will not replace or remove an existing Sysmon installation automatically."
                : $"{ProductIdentity.DisplayName} will not uninstall Sysmon automatically until ownership can be proven."
        };

        var auditBackupAvailable = !string.IsNullOrWhiteSpace(state.AuditPolicyBackupPath) && File.Exists(state.AuditPolicyBackupPath);
        yield return new AgentMonitoringOriginalStateArea
        {
            Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
            Status = auditBackupAvailable
                ? AgentConfigurationOperationStatus.Success
                : AgentConfigurationOperationStatus.Warning,
            RestoreSupported = auditBackupAvailable,
            Summary = auditBackupAvailable
                ? "Windows audit policy backup is available."
                : "Windows audit policy backup is missing or unavailable.",
            Detail = FirstNonEmpty(state.AuditPolicySummary, state.AuditPolicyBackupPath, "No audit policy backup path was recorded."),
            RestoreGuidance = auditBackupAvailable
                ? "Revert restores this auditpol backup."
                : "Manual audit policy review is required before rollback."
        };

        yield return new AgentMonitoringOriginalStateArea
        {
            Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
            Status = AgentConfigurationOperationStatus.Success,
            RestoreSupported = true,
            Summary = state.ProcessCommandLineLoggingValueExisted
                ? "Process command-line logging registry value existed before deployment."
                : "Process command-line logging registry value was absent before deployment.",
            Detail = state.ProcessCommandLineLoggingValueExisted
                ? $"{ProcessCommandLineLoggingValueName}={(state.ProcessCommandLineLoggingEnabled ? 1 : 0)}."
                : $@"HKLM\{AuditPolicyRegistryPath}\{ProcessCommandLineLoggingValueName} was not configured.",
            RestoreGuidance = state.ProcessCommandLineLoggingValueExisted
                ? "Revert restores the previous DWORD value."
                : $"Revert removes the value if {ProductIdentity.DisplayName} created it."
        };

        yield return new AgentMonitoringOriginalStateArea
        {
            Area = AgentConfigurationAreaKind.PowerShellAuditing,
            Status = state.PowerShellStateAvailable == false
                ? AgentConfigurationOperationStatus.Warning
                : AgentConfigurationOperationStatus.Success,
            RestoreSupported = state.PowerShellStateAvailable != false,
            Summary = state.PowerShellStateAvailable == false
                ? "PowerShell logging policy levels were inaccessible during baseline capture."
                : "PowerShell logging policy levels were captured.",
            Detail = state.PowerShellStateAvailable == false
                ? state.PowerShellStateError
                : $"ScriptBlock={state.PowerShell.ScriptBlockLoggingEnabled}; module={state.PowerShell.ModuleLoggingEnabled}; transcription={state.PowerShell.TranscriptionEnabled}; transcriptPath={state.PowerShell.TranscriptPath}.",
            RestoreGuidance = state.PowerShellStateAvailable == false
                ? "Resolve policy-registry access and review the host manually; no policy write is safe without a baseline."
                : "Revert restores script-block, module, transcription, and transcript path settings."
        };

        yield return new AgentMonitoringOriginalStateArea
        {
            Area = AgentConfigurationAreaKind.WindowsEventLogs,
            Status = state.EventLogs.Length > 0
                ? AgentConfigurationOperationStatus.Success
                : AgentConfigurationOperationStatus.Unsupported,
            RestoreSupported = state.EventLogs.Length > 0,
            Summary = state.EventLogs.Length > 0
                ? $"Event-log settings were captured for {state.EventLogs.Length} channels."
                : "No event-log settings were captured.",
            Detail = string.Join("; ", state.EventLogs.Select(log =>
                $"{log.Name}: exists={log.Exists}, enabled={log.IsEnabled}, maxBytes={log.MaximumSizeInBytes}, mode={log.LogMode}")),
            RestoreGuidance = state.EventLogs.Length > 0
                ? "Revert restores captured enablement, size, and retention settings where the log still exists."
                : "Manual event-log retention review is required."
        };
    }

    private string BackupAuditPolicy()
    {
        try
        {
            Directory.CreateDirectory(_sessionPaths.LogsDirectory);
            var backupPath = Path.Combine(_sessionPaths.LogsDirectory, $"audit-policy-before-monitoring-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csv");
            RunProcess("auditpol.exe", $"/backup /file:\"{backupPath}\"");
            return backupPath;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or
                                      TimeoutException or Win32Exception)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to back up audit policy before monitoring deploy: {ex.Message}");
            return string.Empty;
        }
    }

    private string ResolveSecurityAuditPolicyPath(AgentSecurityAuditMonitoringIntent intent)
    {
        var policyRoot = Path.GetFullPath(Path.Combine(_configProfiles.ConfigRoot, "SecurityMonitoring"));
        if (IsSupportedSecurityAuditPolicyPath(intent.AuditPolicyPath, policyRoot))
        {
            return Path.GetFullPath(intent.AuditPolicyPath);
        }

        var profile = ResolveProfile(ConfigProfileKind.SecurityMonitoring, intent.PolicyProfileId)
            ?? _configProfiles.GetDefaultProfile(ConfigProfileKind.SecurityMonitoring);
        if (profile == null)
        {
            return string.Empty;
        }

        var profilePath = _configProfiles.ResolveProfileFilePath(profile);
        if (IsSupportedSecurityAuditPolicyPath(profilePath, policyRoot))
        {
            return Path.GetFullPath(profilePath!);
        }

        foreach (var fileName in new[] { "monitoring-audit-policy.csv", "monitoring-audit-policy.json" })
        {
            var candidate = Path.Combine(profile.ManifestDirectory, "auditpol", fileName);
            if (IsSupportedSecurityAuditPolicyPath(candidate, policyRoot) && File.Exists(candidate))
            {
                return candidate;
            }
        }

        return string.Empty;
    }

    private string ApplySecurityAuditPolicyProfile(string auditPolicyPath)
    {
        if (string.Equals(Path.GetExtension(auditPolicyPath), ".csv", StringComparison.OrdinalIgnoreCase))
        {
            return RunProcess("auditpol.exe", $"/restore /file:\"{auditPolicyPath}\"");
        }

        var profileLength = new FileInfo(auditPolicyPath).Length;
        if (profileLength > 256 * 1024)
        {
            throw new InvalidOperationException(
                "The Security audit policy profile exceeds the 256 KB safety limit.");
        }

        var entries = JsonSerializer.Deserialize<SecurityAuditPolicyProfileEntry[]>(
            File.ReadAllText(auditPolicyPath),
            _jsonOptions) ?? [];
        if (entries.Length == 0 || entries.Length > 128)
        {
            throw new InvalidOperationException(
                "The Security audit policy profile must contain between 1 and 128 subcategories.");
        }

        var subcategories = entries
            .Select(entry => entry.Subcategory?.Trim() ?? string.Empty)
            .ToArray();
        if (subcategories.Any(subcategory =>
                subcategory.Length == 0 ||
                subcategory.Length > 128 ||
                subcategory.Contains('"')) ||
            subcategories.Distinct(StringComparer.OrdinalIgnoreCase).Count() != subcategories.Length)
        {
            throw new InvalidOperationException(
                "The Security audit policy profile contains an invalid or duplicate subcategory name.");
        }

        var results = new List<string>(entries.Length);
        for (var index = 0; index < entries.Length; index++)
        {
            var entry = entries[index];
            var subcategory = subcategories[index];
            var output = RunProcess(
                "auditpol.exe",
                $"/set /subcategory:\"{subcategory}\" " +
                $"/success:{(entry.Success ? "enable" : "disable")} " +
                $"/failure:{(entry.Failure ? "enable" : "disable")}");
            results.Add($"{subcategory}: {output}");
        }

        return TrimForDisplay(
            $"Applied {entries.Length} audit subcategories. {string.Join("; ", results)}",
            4000);
    }

    private static bool IsSupportedSecurityAuditPolicyPath(string? path, string policyRoot)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var extension = Path.GetExtension(path);
        if (!string.Equals(extension, ".csv", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(extension, ".json", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            var normalizedRoot = policyRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            var normalizedPath = Path.GetFullPath(path);
            return normalizedPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private IEnumerable<EventLogProfileEntry> LoadEventLogProfile(AgentEventLogMonitoringIntent intent)
    {
        var path = FirstNonEmpty(intent.ProfileId.Length == 0 ? string.Empty : ResolveProfilePath(ConfigProfileKind.EventLogs, intent.ProfileId), string.Empty);
        if (string.IsNullOrWhiteSpace(path))
        {
            path = ResolveProfilePath(ConfigProfileKind.EventLogs, string.Empty);
        }

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<EventLogProfileEntry[]>(File.ReadAllText(path), _jsonOptions) ?? [];
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to read event-log profile '{path}': {ex.Message}");
            return [];
        }
    }

    private ConfigProfileDefinition? ResolveProfile(ConfigProfileKind kind, string profileId)
    {
        var profiles = _configProfiles.GetProfiles(kind);
        return string.IsNullOrWhiteSpace(profileId)
            ? profiles.FirstOrDefault(profile => profile.IsDefault) ?? profiles.FirstOrDefault()
            : profiles.FirstOrDefault(profile => string.Equals(profile.Id, profileId, StringComparison.OrdinalIgnoreCase))
              ?? profiles.FirstOrDefault(profile => profile.IsDefault)
              ?? profiles.FirstOrDefault();
    }

    private string ResolveProfilePath(ConfigProfileKind kind, string profileId)
    {
        var profile = ResolveProfile(kind, profileId);
        return profile == null ? string.Empty : _configProfiles.ResolveProfileFilePath(profile) ?? string.Empty;
    }

    private AgentMonitoringDeploymentAreaResult TryArea(
        AgentConfigurationAreaKind area,
        bool reverseSupported,
        Func<AgentMonitoringDeploymentAreaResult> action)
    {
        try
        {
            return action();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or
                                      TimeoutException or EventLogException or JsonException or Win32Exception)
        {
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = area,
                Status = AgentConfigurationOperationStatus.Failed,
                ReverseSupported = reverseSupported,
                Message = $"{FormatEnum(area)} operation failed.",
                TechnicalDetail = ex.Message
            };
        }
    }

    private static AgentMonitoringDeploymentAreaResult Skipped(AgentConfigurationAreaKind area, string message)
    {
        return new AgentMonitoringDeploymentAreaResult
        {
            Area = area,
            Status = AgentConfigurationOperationStatus.Skipped,
            ReverseSupported = true,
            Message = message
        };
    }

    private static AgentConfigurationOperationStatus ResolveResultStatus(IEnumerable<AgentMonitoringDeploymentAreaResult> areaResults)
    {
        var results = areaResults.ToArray();
        if (results.Any(result => result.Status == AgentConfigurationOperationStatus.Failed))
        {
            return AgentConfigurationOperationStatus.Failed;
        }

        if (results.Any(result => result.Status is AgentConfigurationOperationStatus.Warning or AgentConfigurationOperationStatus.Unsupported or AgentConfigurationOperationStatus.Unknown))
        {
            return AgentConfigurationOperationStatus.Warning;
        }

        return AgentConfigurationOperationStatus.Success;
    }

    private AgentMonitoringDeploymentResult CreateResult(
        AgentConfigurationCommand command,
        AgentMonitoringDeploymentAction action,
        DateTime startedAtUtc,
        AgentConfigurationOperationStatus status,
        IEnumerable<AgentMonitoringDeploymentAreaResult> areaResults,
        string lastError,
        MonitoringDeploymentState? originalState = null)
    {
        var results = areaResults.ToArray();
        return new AgentMonitoringDeploymentResult
        {
            AgentId = FirstNonEmpty(command.AgentId, AgentsViewModelLocalAgentId()),
            HostId = FirstNonEmpty(command.HostId, Environment.MachineName),
            ConfigurationVersion = command.ConfigurationVersion,
            ConfigurationHash = command.ConfigurationHash,
            Action = action,
            StartedAtUtc = startedAtUtc,
            CompletedAtUtc = DateTime.UtcNow,
            Status = status,
            AreaResults = results,
            Warnings = results
                .Where(result => result.Status is AgentConfigurationOperationStatus.Warning or AgentConfigurationOperationStatus.Unsupported)
                .Select(result => $"{FormatEnum(result.Area)}: {result.Message}")
                .Concat(string.IsNullOrWhiteSpace(lastError) ? [] : [lastError])
                .ToArray(),
            LastError = status == AgentConfigurationOperationStatus.Failed
                ? FirstNonEmpty(lastError, results.FirstOrDefault(result => result.Status == AgentConfigurationOperationStatus.Failed)?.Message ?? string.Empty)
                : string.Empty,
            OriginalState = BuildOriginalStateSnapshot(originalState ?? TryReadDeploymentState())
        };
    }

    private void AppendLog(object entry)
    {
        try
        {
            Directory.CreateDirectory(_sessionPaths.LogsDirectory);
            File.AppendAllText(DeploymentLogPath, JsonSerializer.Serialize(entry, _jsonOptions) + Environment.NewLine);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to append monitoring deployment log: {ex.Message}");
        }
    }

    private static bool EventLogExists(string name)
    {
        var result = RunProcess("wevtutil.exe", $"gl \"{name}\"", throwOnFailure: false);
        return !result.StartsWith("exit=", StringComparison.OrdinalIgnoreCase);
    }

    private static string RunProcess(string fileName, string arguments, bool throwOnFailure = true)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        }) ?? throw new InvalidOperationException($"Failed to start {fileName}.");

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30_000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
            {
                // The timeout remains authoritative even when cleanup races process exit.
            }

            throw new TimeoutException($"{fileName} exceeded the 30 second monitoring-operation timeout.");
        }

        var output = outputTask.GetAwaiter().GetResult();
        var error = errorTask.GetAwaiter().GetResult();

        var combined = TrimForDisplay(
            FirstNonEmpty(error.Trim(), output.Trim(), $"exit={process.ExitCode}"),
            4000);
        if (throwOnFailure && process.ExitCode != 0)
        {
            throw new InvalidOperationException($"{fileName} exited with code {process.ExitCode}: {combined}");
        }

        return process.ExitCode == 0 ? combined : $"exit={process.ExitCode}: {combined}";
    }

    private static string BuildRetentionArguments(string logMode)
    {
        return logMode switch
        {
            nameof(EventLogMode.Circular) => " /rt:false /ab:false",
            nameof(EventLogMode.Retain) => " /rt:true /ab:false",
            nameof(EventLogMode.AutoBackup) => " /rt:true /ab:true",
            _ => string.Empty
        };
    }

    private static string ComputeHash(AgentHostMonitoringConfiguration configuration)
    {
        var hashSource = configuration with
        {
            ConfigurationHash = string.Empty,
            OriginalState = new AgentMonitoringOriginalStateSnapshot()
        };
        var json = JsonSerializer.Serialize(hashSource, AgentJson.JsonOptions);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string TrimForDisplay(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim();
        return trimmed.Length <= maxLength
            ? trimmed
            : trimmed[..maxLength] + "...";
    }

    private static string FormatEnum<T>(T value) where T : Enum
    {
        var text = value.ToString();
        return string.Concat(text.Select((character, index) =>
            index > 0 && char.IsUpper(character) ? " " + character : character.ToString()));
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static string AgentsViewModelLocalAgentId() => "local";

    private sealed class EventLogProfileEntry
    {
        public string Name { get; init; } = string.Empty;

        public long SizeBytes { get; init; }

        public bool Enable { get; init; }

        public bool Optional { get; init; }
    }

    private sealed class SecurityAuditPolicyProfileEntry
    {
        public string Subcategory { get; init; } = string.Empty;

        public bool Success { get; init; }

        public bool Failure { get; init; }
    }

    private sealed class MonitoringDeploymentState
    {
        public DateTime CapturedAtUtc { get; init; }

        public string AgentId { get; init; } = string.Empty;

        public string HostId { get; init; } = string.Empty;

        public string ConfigurationHash { get; init; } = string.Empty;

        public bool? SysmonStateAvailable { get; init; }

        public string SysmonStateError { get; init; } = string.Empty;

        public bool SysmonWasInstalled { get; init; }

        public bool SysmonWasRunning { get; init; }

        public bool SysmonChannelWasAvailable { get; init; }

        public string SysmonExecutablePath { get; init; } = string.Empty;

        public string SysmonConfigurationSummary { get; init; } = string.Empty;

        public bool ProcessCommandLineLoggingValueExisted { get; init; }

        public bool ProcessCommandLineLoggingEnabled { get; init; }

        public string AuditPolicyBackupPath { get; set; } = string.Empty;

        public string AuditPolicySummary { get; init; } = string.Empty;

        public bool? PowerShellStateAvailable { get; init; }

        public string PowerShellStateError { get; init; } = string.Empty;

        public PowerShellAuditState PowerShell { get; init; } = new();

        public EventLogState[] EventLogs { get; init; } = [];

        public AgentMonitoringDeploymentAreaResult[] AreaResults { get; set; } = [];

        public DateTime? LastRevertedUtc { get; set; }

        public AgentConfigurationOperationStatus LastRevertStatus { get; set; } = AgentConfigurationOperationStatus.Unknown;

        public AgentMonitoringDeploymentAreaResult[] LastRevertAreaResults { get; set; } = [];
    }

    private sealed class PowerShellAuditState
    {
        public bool ScriptBlockLoggingEnabled { get; init; }

        public bool ModuleLoggingEnabled { get; init; }

        public bool TranscriptionEnabled { get; init; }

        public string TranscriptPath { get; init; } = string.Empty;
    }

    private sealed class EventLogState
    {
        public string Name { get; init; } = string.Empty;

        public bool Exists { get; init; }

        public bool IsEnabled { get; init; }

        public long MaximumSizeInBytes { get; init; }

        public string LogMode { get; init; } = string.Empty;
    }
}
