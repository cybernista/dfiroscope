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

internal sealed partial class AgentMonitoringConfigurationService
{
    private const string ConfigurationFileName = "agent-host-monitoring-configuration.json";
    private const string OriginalStateFileName = "agent-monitoring-original-state.json";
    private const string WindowsSecurityConfigurationFileName = "agent-windows-security-configuration.json";
    private const string WindowsSecurityOriginalStateFileName = "agent-windows-security-original-state.json";
    private const string LegacyDeploymentStateFileName = "agent-monitoring-deployment-state.json";
    private const string DeploymentLogFileName = "AgentMonitoringDeployment.jsonl";
    private const string AuditPolicyRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
    private const string ProcessCommandLineLoggingValueName = "ProcessCreationIncludeCmdLine_Enabled";

    private readonly InvestigationSessionPaths _sessionPaths;
    private readonly AgentConfigurationCheckService _configurationChecks;
    private readonly ConfigProfileService _configProfiles;
    private readonly IAgentMonitoringHostStateAccessor _hostState;
    private readonly Func<string> _auditPolicyBackup;
    private readonly Func<string, string, bool, string> _processRunner;
    private readonly AgentHostMonitoringOperationGate _operationGate = new();
    private readonly AgentSecurityAuditPolicyProfileResolver _securityAuditPolicyProfiles;
    private readonly AgentObjectAccessAuditingService _objectAccessAuditing;
    private readonly SysmonService _sysmonService;
    private readonly PowerShellAuditingService _powerShellAuditingService;
    private readonly TextWriter _log;
    private readonly MonitoringConfigurationStore _portableStore;
    private readonly Func<AuditSubcategorySetting[]> _readSystemAuditPolicy;
    private readonly Func<Guid, string> _auditPolicyDisplayName;
    private readonly Func<string, WindowsSecuritySettingsSnapshot, string> _saveSettingsFolder;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };
    private static readonly JsonSerializerOptions SecurityProfileJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public AgentMonitoringConfigurationService(
        InvestigationSessionPaths sessionPaths,
        AgentConfigurationCheckService configurationChecks,
        TextWriter log,
        ConfigProfileService? configProfiles = null,
        IAgentMonitoringHostStateAccessor? hostState = null,
        Func<string>? auditPolicyBackup = null,
        Func<string, string, bool, string>? processRunner = null,
        AgentObjectAccessAuditingService? objectAccessAuditing = null,
        MonitoringConfigurationStore? portableStore = null,
        Func<AuditSubcategorySetting[]>? readSystemAuditPolicy = null,
        Func<string, WindowsSecuritySettingsSnapshot, string>? saveSettingsFolder = null,
        Func<Guid, string>? auditPolicyDisplayName = null)
    {
        _sessionPaths = sessionPaths;
        _configurationChecks = configurationChecks;
        _configProfiles = configProfiles ?? new ConfigProfileService();
        _securityAuditPolicyProfiles = new AgentSecurityAuditPolicyProfileResolver(_configProfiles);
        _objectAccessAuditing = objectAccessAuditing ?? new AgentObjectAccessAuditingService(sessionPaths);
        _hostState = hostState ?? new WindowsAgentMonitoringHostStateAccessor();
        _auditPolicyBackup = auditPolicyBackup ?? BackupAuditPolicy;
        _processRunner = processRunner ?? RunProcess;
        _sysmonService = new SysmonService(_configProfiles);
        _powerShellAuditingService = new PowerShellAuditingService(_configProfiles);
        _log = log;
        _portableStore = portableStore ?? new MonitoringConfigurationStore();
        _readSystemAuditPolicy = readSystemAuditPolicy ?? WindowsSystemAuditPolicyReader.Read;
        _auditPolicyDisplayName = auditPolicyDisplayName ?? WindowsSystemAuditPolicyReader.GetDisplayName;
        _saveSettingsFolder = saveSettingsFolder ?? new WindowsSettingsFolderStore().Save;
    }

    private string LegacyDeploymentStatePath => Path.Combine(_sessionPaths.SessionRoot, LegacyDeploymentStateFileName);

    private string DeploymentLogPath => Path.Combine(_sessionPaths.LogsDirectory, DeploymentLogFileName);

    internal T ExecuteSerialized<T>(Func<T> operation) => _operationGate.Execute(operation);

    internal AgentConfigurationCheckResult CheckHostMonitoringConfiguration(
        CheckHostMonitoringConfigurationCommand command, CaptureHealthReport? captureHealth)
    {
        var previousState = TryReadDeploymentState(command);
        var configuration = command.DraftConfiguration ?? TryReadConfiguration(command) ??
                            _configurationChecks.CreateDefaultHostMonitoringConfiguration(command);
        var requestedAreas = ResolveAreas(command, configuration);
        var recovery = GetObjectAuditParentRecoveryState(previousState, command, configuration, requestedAreas);
        if (configuration.SettingsSnapshot != null)
            return CheckSettingsSnapshot(command, configuration, recovery, previousState?.ObjectAuditJournalExpected == true, captureHealth);
        return _configurationChecks.CheckHostMonitoringConfiguration(command, captureHealth,
            previousState?.ObjectAuditJournalExpected == true, recovery.JournalEntryCount, recovery.Error);
    }

    public AgentHostMonitoringConfiguration GetHostMonitoringConfiguration(GetHostMonitoringConfigurationCommand command)
    {
        if (command.ExportSettingsAreas.Length > 0) return ExportSettings(command);
        var saved = TryReadConfiguration(command);
        return AttachOriginalState(
            saved ?? StampConfiguration(_configurationChecks.CreateDefaultHostMonitoringConfiguration(command), command),
            command);
    }

    public AgentHostMonitoringConfiguration SaveHostMonitoringConfiguration(SaveHostMonitoringConfigurationCommand command)
    {
        ValidateObjectAuditScope(command.Configuration, ResolveAreas(command, command.Configuration));
        var stamped = StampConfiguration(command.Configuration, command);
        Directory.CreateDirectory(_sessionPaths.SessionRoot);
        File.WriteAllText(GetConfigurationPath(command), JsonSerializer.Serialize(stamped, _jsonOptions));
        AppendLog(new
        {
            action = "save",
            timestampUtc = DateTime.UtcNow,
            stamped.AgentId,
            stamped.HostId,
            stamped.ConfigurationVersion,
            stamped.ConfigurationHash
        });
        return AttachOriginalState(stamped, command);
    }

    public AgentMonitoringDeploymentResult DeployHostMonitoringConfiguration(DeployHostMonitoringConfigurationCommand command)
        => RunWithRecoveryFailureResult(command, AgentMonitoringDeploymentAction.Deploy,
            () => DeployHostMonitoringConfigurationCore(command));

    private AgentMonitoringDeploymentResult DeployHostMonitoringConfigurationCore(DeployHostMonitoringConfigurationCommand command)
    {
        var startedAtUtc = DateTime.UtcNow;
        var configuration = TryReadConfiguration(command);
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

        var requestedAreas = ResolveAreas(command, configuration);
        ValidateObjectAuditScope(configuration, requestedAreas);
        RequireBackupCoverage(requestedAreas);
        var savedSettingsApply = PrepareSavedSettingsApply(command, configuration, requestedAreas);
        if (savedSettingsApply != null) configuration = savedSettingsApply.Configuration;
        var persistedState = TryReadDeploymentState(command);
        var objectRecovery = GetObjectAuditParentRecoveryState(persistedState, command, configuration, requestedAreas);
        var objectRecoveryError = objectRecovery.Error;
        if (!string.IsNullOrWhiteSpace(objectRecoveryError))
        {
            var recoveryFailure = CreateResult(
                command,
                AgentMonitoringDeploymentAction.Deploy,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                [],
                objectRecoveryError);
            AppendLog(recoveryFailure);
            return recoveryFailure;
        }
        WindowsSecurityDeploymentPlan? windowsSecurityPlan = null;
        if (AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(requestedAreas))
        {
            try
            {
                windowsSecurityPlan = CreateWindowsSecurityDeploymentPlan(configuration, requestedAreas);
                if (savedSettingsApply != null) windowsSecurityPlan = windowsSecurityPlan with { RootBackup = savedSettingsApply.Snapshot };
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or
                                          JsonException or ArgumentException or NotSupportedException or PathTooLongException)
            {
                var validationFailure = CreateResult(
                    command,
                    AgentMonitoringDeploymentAction.Deploy,
                    startedAtUtc,
                    AgentConfigurationOperationStatus.Failed,
                    [],
                    $"Windows Security configuration validation failed before original-state capture: {ex.Message}");
                AppendLog(validationFailure);
                return validationFailure;
            }
        }

        var previousState = TryReuseActiveOriginalState(configuration, command, requestedAreas, persistedState) ??
                            CaptureOriginalState(configuration, command, requestedAreas);
        if (objectRecovery.JournalExists)
        {
            // A validated empty journal still proves that object-audit recovery existed. Preserve
            // that relationship across a completed revert and fresh policy-only baseline.
            previousState.ObjectAuditJournalExpected = true;
        }
        var previouslyAppliedAreas = previousState.AreaResults.ToArray();
        var baselineError = ValidateWindowsSecurityOriginalState(
            configuration,
            requestedAreas,
            previousState);
        if (previousState.ObjectAuditJournalExpected)
        {
            try { _objectAccessAuditing.RequireRecoveryJournal(); }
            catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex) || ex is JsonException)
            { baselineError = ex.Message; }
        }
        if (!string.IsNullOrWhiteSpace(baselineError))
        {
            var withheldResults = requestedAreas
                .Select(area => Skipped(
                    area,
                    "Deployment was withheld because the complete Windows Security baseline was unavailable."))
                .ToArray();
            previousState.AreaResults = MergeAppliedAreaResults(previouslyAppliedAreas, withheldResults);
            SaveOriginalState(previousState, command);
            var baselineFailure = CreateResult(
                command,
                AgentMonitoringDeploymentAction.Deploy,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                [],
                baselineError,
                previousState);
            AppendLog(baselineFailure);
            return baselineFailure;
        }

        previousState.LatestSettingsBackupPath = savedSettingsApply?.Folder ?? SavePreApplySettings(configuration, command, requestedAreas);

        if (AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(requestedAreas) &&
            AgentObjectAccessAuditingService.Requested(configuration.SecurityAuditPolicy))
        {
            // Persist the parent/empty-journal relationship before any Windows mutation. The
            // object plan itself is captured after command-line policy deployment because that
            // authorized child-key change can advance the audited Policies\System root identity.
            previousState.ObjectAuditJournalExpected = true;
            SaveOriginalState(previousState, command);
            _objectAccessAuditing.InitializeRecoveryJournal();
        }
        SaveOriginalState(previousState, command);
        var areaResults = AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(requestedAreas)
            ? DeployWindowsSecurity(configuration, previousState, requestedAreas, windowsSecurityPlan!, command)
            : DeployLegacy(configuration, previousState, requestedAreas);

        if (savedSettingsApply != null)
        {
            VerifySavedSettingsApply(savedSettingsApply, windowsSecurityPlan!, areaResults);
            savedSettingsApply.AddCoverageResults(areaResults);
        }

        previousState.AreaResults = MergeAppliedAreaResults(previouslyAppliedAreas, areaResults);
        SaveOriginalState(previousState, command);

        var resultStatus = ResolveResultStatus(areaResults);
        if (savedSettingsApply?.Gaps.Count > 0 && resultStatus == AgentConfigurationOperationStatus.Success)
            resultStatus = AgentConfigurationOperationStatus.Warning;
        var result = CreateResult(command, AgentMonitoringDeploymentAction.Deploy, startedAtUtc, resultStatus, areaResults, string.Empty, previousState);
        AppendLog(result);
        return result;
    }

    public AgentMonitoringDeploymentResult ReverseHostMonitoringDeployment(ReverseHostMonitoringDeploymentCommand command)
        => RunWithRecoveryFailureResult(command, AgentMonitoringDeploymentAction.Reverse,
            () => ReverseHostMonitoringDeploymentCore(command));

    private AgentMonitoringDeploymentResult ReverseHostMonitoringDeploymentCore(ReverseHostMonitoringDeploymentCommand command)
    {
        var startedAtUtc = DateTime.UtcNow;
        var configuration = TryReadConfiguration(command);
        var previousState = TryReadDeploymentState(command);
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

        var requestedAreas = ResolveAreas(command, configuration);
        var areaResults = AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(requestedAreas)
            ? ReverseWindowsSecurity(previousState, requestedAreas)
            : ReverseLegacy(configuration, previousState, command, requestedAreas);

        if (areaResults.Any(result =>
                result.Area == AgentConfigurationAreaKind.ProcessCommandLineAuditing &&
                result.Status == AgentConfigurationOperationStatus.Success))
        {
            // Reversal is idempotent. Clear the uncertainty marker only after the host restore
            // returned successfully; a crash before the state save safely causes another restore.
            previousState.ProcessCommandLineMutationMayHaveOccurred = false;
        }

        var resultStatus = ResolveResultStatus(areaResults);
        previousState.LastRevertedUtc = DateTime.UtcNow;
        previousState.LastRevertStatus = resultStatus;
        previousState.LastRevertAreaResults = areaResults.ToArray();
        previousState.SnapshotMutationAreas = previousState.SnapshotMutationAreas.Where(area => !areaResults.Any(
            result => result.Area == area && IsRestorationComplete(result))).ToArray();
        SaveOriginalState(previousState, command);

        var result = CreateResult(command, AgentMonitoringDeploymentAction.Reverse, startedAtUtc, resultStatus, areaResults, string.Empty, previousState);
        AppendLog(result);
        return result;
    }

    private AgentHostMonitoringConfiguration AttachOriginalState(
        AgentHostMonitoringConfiguration configuration,
        AgentConfigurationCommand command)
        => configuration with
        {
            OriginalState = BuildOriginalStateSnapshot(TryReadDeploymentState(command))
        };

    private AgentHostMonitoringConfiguration? TryReadConfiguration(AgentConfigurationCommand command)
    {
        try
        {
            var path = GetConfigurationPath(command);
            if (!File.Exists(path))
            {
                return null;
            }

            return JsonSerializer.Deserialize<AgentHostMonitoringConfiguration>(
                File.ReadAllText(path),
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
            ConfigurationAreas = ResolveAreas(command, configuration),
            ConfigurationHash = string.Empty,
            OriginalState = BuildOriginalStateSnapshot(TryReadDeploymentState(command)),
            UpdatedAtUtc = updatedUtc,
            Status = AgentConfigurationStatus.Saved,
            LastError = string.Empty
        };

        return stamped with
        {
            ConfigurationHash = ComputeHash(stamped)
        };
    }

    private string GetConfigurationPath(AgentConfigurationCommand command) =>
        Path.Combine(
            _sessionPaths.SessionRoot,
            AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(ResolveCommandAreas(command))
                ? WindowsSecurityConfigurationFileName
                : ConfigurationFileName);

    private string GetOriginalStatePath(AgentConfigurationCommand command) =>
        Path.Combine(
            _sessionPaths.SessionRoot,
            AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(ResolveCommandAreas(command))
                ? WindowsSecurityOriginalStateFileName
                : OriginalStateFileName);

    private static AgentConfigurationAreaKind[] ResolveCommandAreas(AgentConfigurationCommand command)
    {
        var commandAreas = AgentHostMonitoringConfigurationAreas.Normalize(command.ConfigurationAreas);
        if (commandAreas.Length > 0)
        {
            return commandAreas;
        }

        return command switch
        {
            SaveHostMonitoringConfigurationCommand save =>
                AgentHostMonitoringConfigurationAreas.Normalize(save.Configuration.ConfigurationAreas),
            CheckHostMonitoringConfigurationCommand check =>
                AgentHostMonitoringConfigurationAreas.Normalize(check.DraftConfiguration?.ConfigurationAreas),
            _ => []
        };
    }

    private static AgentConfigurationAreaKind[] ResolveAreas(
        AgentConfigurationCommand command,
        AgentHostMonitoringConfiguration configuration)
    {
        var commandAreas = AgentHostMonitoringConfigurationAreas.Normalize(command.ConfigurationAreas);
        return commandAreas.Length > 0
            ? commandAreas
            : AgentHostMonitoringConfigurationAreas.Normalize(configuration.ConfigurationAreas);
    }

    private WindowsSecurityDeploymentPlan CreateWindowsSecurityDeploymentPlan(
        AgentHostMonitoringConfiguration configuration,
        IReadOnlyCollection<AgentConfigurationAreaKind> requestedAreas)
    {
        if (configuration.SettingsSnapshot is { } snapshot)
            return new WindowsSecurityDeploymentPlan(string.Empty, null, [])
            { SettingsPlan = ValidateSettingsForDeployment(snapshot, configuration.ConfigurationHash) };
        var auditPolicyPath = string.Empty;
        SecurityAuditPolicyProfileEntry[]? auditPolicyEntries = null;
        if (requestedAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy) &&
            (configuration.SecurityAuditPolicy.ConfigureAuditPolicy ||
             !string.IsNullOrWhiteSpace(configuration.SecurityAuditPolicy.PolicyProfileId) ||
             !string.IsNullOrWhiteSpace(configuration.SecurityAuditPolicy.AuditPolicyPath)))
        {
            var resolvedProfile = _securityAuditPolicyProfiles.Resolve(configuration.SecurityAuditPolicy);
            auditPolicyPath = resolvedProfile.Path;
            auditPolicyEntries = resolvedProfile.Entries;
        }

        EventLogProfileEntry[] eventLogEntries = [];
        if (requestedAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityEventLog) &&
            (configuration.EventLogs.ConfigureChannels ||
             configuration.EventLogs.ConfigureRetention ||
             !string.IsNullOrWhiteSpace(configuration.EventLogs.ProfileId)))
        {
            var eventLogProfilePath = ResolveWindowsSecurityEventLogProfilePath(
                configuration.EventLogs.ProfileId);
            if (string.IsNullOrWhiteSpace(eventLogProfilePath) || !File.Exists(eventLogProfilePath))
            {
                throw new InvalidOperationException(
                    "The selected Windows Security event-log profile is unknown, unowned, or missing.");
            }

            eventLogEntries = ValidateWindowsSecurityEventLogProfile(eventLogProfilePath);
        }

        return new WindowsSecurityDeploymentPlan(
            auditPolicyPath,
            auditPolicyEntries,
            eventLogEntries);
    }

    private static void ValidateObjectAuditScope(AgentHostMonitoringConfiguration configuration,
        IReadOnlyCollection<AgentConfigurationAreaKind> areas)
    {
        if (configuration.SettingsSnapshot is { } snapshot)
        {
            snapshot.ValidateIntent(configuration);
            if (!AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(areas) ||
                configuration.ConfigurationVersion != "monitoring-snapshot-v1" ||
                System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(snapshot).Length > 256 * 1024)
                throw new InvalidOperationException("Settings snapshots require the bounded Windows Security snapshot contract.");
        }
        AgentObjectAccessAuditingService.ValidateIntent(configuration.SecurityAuditPolicy);
        if (AgentObjectAccessAuditingService.Requested(configuration.SecurityAuditPolicy) &&
            !AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(areas))
            throw new InvalidOperationException("Object auditing belongs exclusively to the Windows Security configuration scope.");
    }

    private static string ValidateWindowsSecurityOriginalState(
        AgentHostMonitoringConfiguration configuration,
        IReadOnlyCollection<AgentConfigurationAreaKind> requestedAreas,
        MonitoringDeploymentState state)
    {
        if (!AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(requestedAreas))
        {
            return string.Empty;
        }

        if (requestedAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy) &&
            !IsReadableNonEmptyFile(state.AuditPolicyBackupPath))
        {
            return "Windows Security deployment was withheld because the original audit policy could not be captured.";
        }

        if (requestedAreas.Contains(AgentConfigurationAreaKind.ProcessCommandLineAuditing) &&
            !state.ProcessCommandLineLogging.IsAvailable)
        {
            return "Windows Security deployment was withheld because the process command-line auditing registry baseline is unavailable: " +
                   FirstNonEmpty(state.ProcessCommandLineLogging.Error, "unknown registry read failure");
        }

        if (requestedAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityEventLog) &&
            (state.EventLogs.Length == 0 ||
             state.EventLogs.Any(eventLog => !eventLog.StateAvailable || !eventLog.Exists)))
        {
            var unavailable = state.EventLogs.FirstOrDefault(eventLog => !eventLog.StateAvailable || !eventLog.Exists);
            return "Windows Security deployment was withheld because the Security-channel baseline is unavailable: " +
                   (unavailable == null
                       ? "no Security-channel snapshot was recorded"
                       : FirstNonEmpty(
                           unavailable.StateError,
                           unavailable.Exists ? "unknown event-log read failure" : "the Security channel does not exist"));
        }

        return string.Empty;
    }

    private List<AgentMonitoringDeploymentAreaResult> DeployWindowsSecurity(
        AgentHostMonitoringConfiguration configuration,
        MonitoringDeploymentState previousState,
        IReadOnlyCollection<AgentConfigurationAreaKind> requestedAreas,
        WindowsSecurityDeploymentPlan plan,
        AgentConfigurationCommand command)
    {
        if (configuration.SettingsSnapshot != null)
            return DeploySettingsSnapshot(configuration, previousState, command, plan.SettingsPlan);
        var results = new List<AgentMonitoringDeploymentAreaResult>();
        AgentMonitoringDeploymentAreaResult? commandLineResult = null;
        if (requestedAreas.Contains(AgentConfigurationAreaKind.ProcessCommandLineAuditing))
        {
            // The Audit child may not exist yet. Apply this separately journaled mutation before
            // capturing a SACL identity for its Policies\System parent, then durably record it.
            commandLineResult = DeployProcessCommandLineLogging(
                configuration.SecurityAuditPolicy,
                previousState,
                command);
            previousState.AreaResults = MergeAppliedAreaResults(previousState.AreaResults, [commandLineResult]);
            if (commandLineResult.Status == AgentConfigurationOperationStatus.Success)
            {
                // The success result and clearing of the pre-write uncertainty marker become
                // durable together. A crash before this save leaves reversal conservative.
                previousState.ProcessCommandLineMutationMayHaveOccurred = false;
            }
            SaveOriginalState(previousState, command);
            if (commandLineResult.Status == AgentConfigurationOperationStatus.Failed &&
                command is not DeployHostMonitoringConfigurationCommand { SettingsBackupFolder.Length: > 0 })
                return [commandLineResult];
        }

        AgentMonitoringDeploymentAreaResult? auditPolicyResult = null;
        if (requestedAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy))
        {
            ObjectAuditPlan? objectAuditPlan = null;
            var objectPlanningWarning = string.Empty;
            try
            {
                if (AgentObjectAccessAuditingService.Requested(configuration.SecurityAuditPolicy))
                {
                    if (commandLineResult?.Status == AgentConfigurationOperationStatus.Failed)
                        throw new InvalidOperationException("Object auditing was withheld because the related command-line policy change failed.");
                    objectAuditPlan = _objectAccessAuditing.Prepare(
                        configuration.SecurityAuditPolicy,
                        configuration.ConfigurationHash, plan.RootBackup);
                }
            }
            catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex) || ex is JsonException)
            {
                if (command is DeployHostMonitoringConfigurationCommand { SettingsBackupFolder.Length: > 0 })
                    objectPlanningWarning = "Object auditing skipped: " + ex.Message;
                else auditPolicyResult = new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = true,
                    Message = "Object-auditing planning failed after command-line policy deployment; the original-state record was retained for reversal.",
                    TechnicalDetail = ex.Message
                };
            }

            if (configuration.SecurityAuditPolicy.ConfigureAuditPolicy)
                RecordSavedApplyAttempt(previousState, command, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy);
            auditPolicyResult ??= DeploySecurityAuditPolicy(
                configuration.SecurityAuditPolicy,
                previousState,
                plan.AuditPolicyPath,
                plan.AuditPolicyEntries,
                objectAuditPlan);
            if (!string.IsNullOrEmpty(objectPlanningWarning))
                auditPolicyResult = auditPolicyResult with
                {
                    Status = auditPolicyResult.Status == AgentConfigurationOperationStatus.Failed ? auditPolicyResult.Status : AgentConfigurationOperationStatus.Warning,
                    Message = auditPolicyResult.Message + " " + objectPlanningWarning
                };
            results.Add(auditPolicyResult);
        }

        if (commandLineResult != null) results.Add(commandLineResult);

        if (auditPolicyResult?.Status == AgentConfigurationOperationStatus.Failed &&
            command is not DeployHostMonitoringConfigurationCommand { SettingsBackupFolder.Length: > 0 })
            return results;

        if (requestedAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityEventLog))
        {
            if (configuration.EventLogs.ConfigureChannels || configuration.EventLogs.ConfigureRetention)
                RecordSavedApplyAttempt(previousState, command, AgentConfigurationAreaKind.WindowsSecurityEventLog);
            results.Add(DeployEventLogs(
                configuration.EventLogs with { ChannelNames = ["Security"] },
                AgentConfigurationAreaKind.WindowsSecurityEventLog,
                plan.EventLogEntries));
        }

        return results;
    }

    private List<AgentMonitoringDeploymentAreaResult> DeployLegacy(
        AgentHostMonitoringConfiguration configuration,
        MonitoringDeploymentState previousState,
        IEnumerable<AgentConfigurationAreaKind> requestedAreas)
    {
        var areas = AgentHostMonitoringConfigurationAreas.ResolveEffective(requestedAreas);
        var results = new List<AgentMonitoringDeploymentAreaResult>();
        if (areas.Contains(AgentConfigurationAreaKind.Sysmon))
        {
            results.Add(DeploySysmon(configuration.Sysmon));
        }

        if (areas.Contains(AgentConfigurationAreaKind.WindowsEventLogs))
        {
            results.Add(DeployEventLogs(
                configuration.EventLogs,
                AgentConfigurationAreaKind.WindowsEventLogs));
        }

        if (areas.Contains(AgentConfigurationAreaKind.PowerShellAuditing))
        {
            results.Add(DeployPowerShellAuditing(configuration.PowerShellAuditing, previousState));
        }

        if (areas.Contains(AgentConfigurationAreaKind.Etw))
        {
            results.Add(DeployEtw(configuration.Etw));
        }

        if (areas.Contains(AgentConfigurationAreaKind.ScheduledDumps))
        {
            results.Add(DeployScheduledDumps(configuration.ScheduledDumps));
        }

        return results;
    }

    private List<AgentMonitoringDeploymentAreaResult> ReverseWindowsSecurity(
        MonitoringDeploymentState previousState,
        IReadOnlyCollection<AgentConfigurationAreaKind> requestedAreas)
    {
        var results = new List<AgentMonitoringDeploymentAreaResult>();
        if (requestedAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy))
        {
            results.Add(ReverseSecurityAuditPolicy(previousState));
        }

        if (requestedAreas.Contains(AgentConfigurationAreaKind.ProcessCommandLineAuditing))
        {
            results.Add(ReverseProcessCommandLineLogging(previousState));
        }

        if (requestedAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityEventLog))
        {
            results.Add(ReverseEventLogs(previousState, AgentConfigurationAreaKind.WindowsSecurityEventLog));
        }

        return results;
    }

    private List<AgentMonitoringDeploymentAreaResult> ReverseLegacy(
        AgentHostMonitoringConfiguration configuration,
        MonitoringDeploymentState previousState,
        AgentConfigurationCommand command,
        IEnumerable<AgentConfigurationAreaKind> requestedAreas)
    {
        var areas = AgentHostMonitoringConfigurationAreas.ResolveEffective(requestedAreas);
        var results = new List<AgentMonitoringDeploymentAreaResult>();
        if (areas.Contains(AgentConfigurationAreaKind.Sysmon))
        {
            results.Add(ReverseSysmon(previousState));
        }

        if (areas.Contains(AgentConfigurationAreaKind.WindowsEventLogs))
        {
            results.Add(ReverseEventLogs(previousState, AgentConfigurationAreaKind.WindowsEventLogs));
        }

        if (areas.Contains(AgentConfigurationAreaKind.PowerShellAuditing))
        {
            results.Add(ReversePowerShellAuditing(previousState));
        }

        if (areas.Contains(AgentConfigurationAreaKind.Etw))
        {
            results.Add(ReverseEtw(configuration.Etw));
        }

        if (areas.Contains(AgentConfigurationAreaKind.ScheduledDumps))
        {
            results.Add(ReverseScheduledDumps(configuration, previousState, command));
        }

        return results;
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
        MonitoringDeploymentState previousState,
        string auditPolicyPath,
        SecurityAuditPolicyProfileEntry[]? auditPolicyEntries,
        ObjectAuditPlan? objectAuditPlan)
    {
        return TryArea(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, reverseSupported: true, () =>
        {
            if (!intent.ConfigureAuditPolicy)
            {
                return Skipped(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, "Security audit policy deployment is disabled.");
            }

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

            var output = ApplySecurityAuditPolicyProfile(auditPolicyPath, auditPolicyEntries);
            var objectResult = objectAuditPlan == null ? null : _objectAccessAuditing.Deploy(objectAuditPlan);
            if (objectResult != null)
                AppendLog(new { action = "object-audit-deploy", timestampUtc = DateTime.UtcNow,
                    objectAuditPlan!.ConfigurationHash, result = objectResult });
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                Status = objectResult?.Gaps.Length > 0 ? AgentConfigurationOperationStatus.Warning : AgentConfigurationOperationStatus.Success,
                ReverseSupported = !string.IsNullOrWhiteSpace(previousState.AuditPolicyBackupPath),
                Message = "Security audit policy was applied from the selected agent-owned profile.",
                TechnicalDetail = output + (objectResult == null ? string.Empty : Environment.NewLine + objectResult.Detail)
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult DeployProcessCommandLineLogging(
        AgentSecurityAuditMonitoringIntent intent,
        MonitoringDeploymentState previousState,
        AgentConfigurationCommand command)
    {
        return TryArea(AgentConfigurationAreaKind.ProcessCommandLineAuditing, reverseSupported: true, () =>
        {
            if (!intent.EnableProcessCommandLineLogging)
            {
                return Skipped(
                    AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                    "Process command-line logging deployment is disabled.");
            }

            _objectAccessAuditing.EnsureNoCommandLinePolicyConflict();
            var current = _hostState.CaptureRegistryValue(
                AuditPolicyRegistryPath,
                ProcessCommandLineLoggingValueName);
            if (!current.IsAvailable)
                throw new InvalidOperationException("Current process command-line logging policy could not be read before deployment: " +
                                                    FirstNonEmpty(current.Error, "unknown registry read failure"));
            if (current.ValueExisted && current.ValueKind == RegistryValueKind.DWord && current.Value is int value && value == 1)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                    Status = AgentConfigurationOperationStatus.Success,
                    ReverseSupported = true,
                    Message = "Process command-line logging policy was already enabled; no registry write was needed.",
                    TechnicalDetail = $@"HKLM\{AuditPolicyRegistryPath}\{ProcessCommandLineLoggingValueName}=1"
                };
            }
            // This marker is intentionally durable before the host write. If the process dies
            // after SetRegistryValue but before its success result is saved, restart reversal
            // must still restore the exact captured value/absence.
            previousState.ProcessCommandLineMutationMayHaveOccurred = true;
            SaveOriginalState(previousState, command);
            _hostState.SetRegistryValue(
                AuditPolicyRegistryPath,
                ProcessCommandLineLoggingValueName,
                1,
                RegistryValueKind.DWord);
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

    private AgentMonitoringDeploymentAreaResult DeployEventLogs(
        AgentEventLogMonitoringIntent intent,
        AgentConfigurationAreaKind area,
        IReadOnlyCollection<EventLogProfileEntry>? validatedEntries = null)
    {
        return TryArea(area, reverseSupported: true, () =>
        {
            if (!intent.ConfigureChannels && !intent.ConfigureRetention)
            {
                return Skipped(area, "Event-log configuration is disabled.");
            }

            var entries = validatedEntries?.ToArray() ?? LoadEventLogProfile(intent).ToArray();
            if (entries.Length == 0 && intent.ChannelNames.Length == 0)
            {
                return Skipped(area, "No event-log channels were configured.");
            }

            if (entries.Length == 0)
            {
                entries = intent.ChannelNames
                    .Where(channel => !string.IsNullOrWhiteSpace(channel))
                    .Select(channel => new EventLogProfileEntry { Name = channel, Enable = true })
                    .ToArray();
            }

            entries = entries
                .Where(entry => area == AgentConfigurationAreaKind.WindowsSecurityEventLog
                    ? string.Equals(entry.Name, "Security", StringComparison.OrdinalIgnoreCase)
                    : !string.Equals(entry.Name, "Security", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (entries.Length == 0)
            {
                return Skipped(
                    area,
                    area == AgentConfigurationAreaKind.WindowsSecurityEventLog
                        ? "The Windows Security scope contains no Security channel setting."
                        : "The legacy event-log scope contains no non-Security channel setting.");
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

                    var enableArguments = BuildEventLogEnableArguments(entry.Name, entry.Enable, area);
                    if (intent.ConfigureChannels && !string.IsNullOrWhiteSpace(enableArguments))
                    {
                        _processRunner("wevtutil.exe", enableArguments, true);
                    }

                    if (intent.ConfigureRetention && entry.SizeBytes > 0)
                    {
                        _processRunner("wevtutil.exe", $"sl \"{entry.Name}\" /ms:{entry.SizeBytes} /rt:false /ab:false", true);
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
                Area = area,
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
        // SACL recovery is independently journaled before native writes, including interrupted
        // deployments that never returned a successful area result to the original-state file.
        ObjectAuditResult? objectResult = null;
        try
        {
            if (previousState.ObjectAuditJournalExpected) _objectAccessAuditing.RequireRecoveryJournal();
            if (_objectAccessAuditing.HasPendingRestore)
            {
                objectResult = _objectAccessAuditing.Restore();
                AppendLog(new { action = "object-audit-restore", timestampUtc = DateTime.UtcNow, result = objectResult });
                if (objectResult.Gaps.Length > 0)
                    return new AgentMonitoringDeploymentAreaResult
                    {
                        Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                        Status = AgentConfigurationOperationStatus.Failed,
                        ReverseSupported = true,
                        Message = "Object-auditing restoration has conflicts; audit policy was retained for review.",
                        TechnicalDetail = objectResult.Detail
                    };
            }
        }
        catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex) || ex is JsonException)
        {
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                Status = AgentConfigurationOperationStatus.Failed,
                ReverseSupported = true,
                Message = "Object-auditing recovery state is unavailable; audit policy restoration withheld.",
                TechnicalDetail = ex.Message
            };
        }
        if (!WasDeploymentAreaApplied(previousState, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy) &&
            objectResult == null && !previousState.ObjectAuditJournalExpected)
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

            var output = _processRunner("auditpol.exe", $"/restore /file:\"{previousState.AuditPolicyBackupPath}\"", true);
            return new AgentMonitoringDeploymentAreaResult
            {
                Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                Status = objectResult?.CompatibilityWarnings.Length > 0 ? AgentConfigurationOperationStatus.Warning : AgentConfigurationOperationStatus.Success,
                OriginalStateRestored = true,
                ReverseSupported = true,
                Message = "Security audit policy was restored from the pre-deployment backup.",
                TechnicalDetail = output + (objectResult == null ? string.Empty : Environment.NewLine + objectResult.Detail)
            };
        });
    }

    private AgentMonitoringDeploymentAreaResult ReverseProcessCommandLineLogging(
        MonitoringDeploymentState previousState)
    {
        if (!previousState.ProcessCommandLineMutationMayHaveOccurred &&
            !WasDeploymentAreaApplied(previousState, AgentConfigurationAreaKind.ProcessCommandLineAuditing))
        {
            return Skipped(AgentConfigurationAreaKind.ProcessCommandLineAuditing, "Process command-line logging deployment was not applied; original state was retained for audit only.");
        }

        return TryArea(AgentConfigurationAreaKind.ProcessCommandLineAuditing, reverseSupported: true, () =>
        {
            _objectAccessAuditing.EnsureNoCommandLinePolicyConflict();
            var baseline = previousState.ProcessCommandLineLogging;
            if (!baseline.IsAvailable)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = false,
                    Message = "Process command-line logging registry baseline is unavailable.",
                    TechnicalDetail = baseline.Error
                };
            }

            if (previousState.ProcessCommandLineMutationMayHaveOccurred)
            {
                var current = _hostState.CaptureRegistryValue(
                    AuditPolicyRegistryPath,
                    ProcessCommandLineLoggingValueName);
                if (!current.IsAvailable)
                {
                    return new AgentMonitoringDeploymentAreaResult
                    {
                        Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                        Status = AgentConfigurationOperationStatus.Failed,
                        ReverseSupported = true,
                        Message = "Interrupted process command-line logging recovery could not verify the current registry value.",
                        TechnicalDetail = FirstNonEmpty(current.Error, "unknown registry read failure")
                    };
                }
                if (RegistryValueMatchesBaseline(current, baseline))
                {
                    return new AgentMonitoringDeploymentAreaResult
                    {
                        Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                        Status = AgentConfigurationOperationStatus.Success,
                        ReverseSupported = true,
                        Message = "Process command-line logging already matches the captured pre-deployment state.",
                        TechnicalDetail = "The pre-write recovery marker was retained, but no registry restoration was required."
                    };
                }
                if (!IsEnabledProcessCommandLineValue(current))
                {
                    return new AgentMonitoringDeploymentAreaResult
                    {
                        Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                        Status = AgentConfigurationOperationStatus.Failed,
                        ReverseSupported = true,
                        Message = "Interrupted process command-line logging recovery found registry drift.",
                        TechnicalDetail = "The current value matches neither the captured baseline nor DFIRoscope's intended DWORD 1; no registry write was attempted."
                    };
                }
            }

            if (baseline.ValueExisted)
            {
                _hostState.SetRegistryValue(
                    AuditPolicyRegistryPath,
                    ProcessCommandLineLoggingValueName,
                    GetRegistryValueForRestore(baseline),
                    baseline.ValueKind);
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
                    Status = AgentConfigurationOperationStatus.Success,
                    ReverseSupported = true,
                    Message = "Process command-line logging policy was restored from the pre-deployment snapshot.",
                    TechnicalDetail = $"{ProcessCommandLineLoggingValueName} restored as {baseline.ValueKind}."
                };
            }

            _hostState.DeleteRegistryValue(
                AuditPolicyRegistryPath,
                ProcessCommandLineLoggingValueName);
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

    private AgentMonitoringDeploymentAreaResult ReverseEventLogs(
        MonitoringDeploymentState previousState,
        AgentConfigurationAreaKind area)
    {
        if (!WasDeploymentAreaApplied(previousState, area))
        {
            return Skipped(area, "Event-log deployment was not applied; original state was retained for audit only.");
        }

        return TryArea(area, reverseSupported: true, () =>
        {
            var unavailableBaseline = previousState.EventLogs.FirstOrDefault(entry => !entry.StateAvailable);
            if (unavailableBaseline != null)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = area,
                    Status = AgentConfigurationOperationStatus.Failed,
                    ReverseSupported = false,
                    Message = "An event-log baseline is unavailable; no restore was attempted.",
                    TechnicalDetail = FirstNonEmpty(
                        unavailableBaseline.StateError,
                        unavailableBaseline.Name)
                };
            }

            if (previousState.EventLogs.Length == 0)
            {
                return new AgentMonitoringDeploymentAreaResult
                {
                    Area = area,
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
                    var enableArguments = BuildEventLogRestoreEnableArguments(entry.Name, entry.IsEnabled, area);
                    if (!string.IsNullOrWhiteSpace(enableArguments))
                    {
                        _processRunner("wevtutil.exe", enableArguments, true);
                    }

                    if (entry.MaximumSizeInBytes > 0)
                    {
                        _processRunner("wevtutil.exe", $"sl \"{entry.Name}\" /ms:{entry.MaximumSizeInBytes}{BuildRetentionArguments(entry.LogMode)}", true);
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
                Area = area,
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
        MonitoringDeploymentState previousState,
        AgentConfigurationCommand command)
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
            File.WriteAllText(GetConfigurationPath(command), JsonSerializer.Serialize(disabled, _jsonOptions));

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
        var legacyStateWithoutAreaResults = state.AreaResults.Length == 0 &&
                                            (state.ConfigurationAreas ?? []).Length == 0;
        return legacyStateWithoutAreaResults || state.SnapshotMutationAreas.Contains(area) ||
               state.AreaResults.Any(result =>
                   result.Area == area &&
                   result.Status is AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning);
    }

    private MonitoringDeploymentState? TryReuseActiveOriginalState(
        AgentHostMonitoringConfiguration configuration,
        AgentConfigurationCommand command,
        AgentConfigurationAreaKind[] requestedAreas,
        MonitoringDeploymentState? existing)
    {
        if (existing == null ||
            IsRestorationComplete(existing) ||
            (!existing.ObjectAuditJournalExpected && !existing.ProcessCommandLineMutationMayHaveOccurred && existing.SnapshotMutationAreas.Length == 0 &&
             !existing.AreaResults.Any(result => result.Status is
                AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning)) ||
            !string.Equals(existing.AgentId, FirstNonEmpty(command.AgentId, configuration.AgentId, AgentsViewModelLocalAgentId()), StringComparison.Ordinal) ||
            !string.Equals(existing.HostId, FirstNonEmpty(command.HostId, configuration.HostId, Environment.MachineName), StringComparison.OrdinalIgnoreCase) ||
            !AgentHostMonitoringConfigurationAreas.ResolveEffective(existing.ConfigurationAreas)
                .SequenceEqual(AgentHostMonitoringConfigurationAreas.ResolveEffective(requestedAreas)))
        {
            return null;
        }

        existing.ConfigurationHash = configuration.ConfigurationHash;
        existing.LastRevertedUtc = null;
        existing.LastRevertStatus = AgentConfigurationOperationStatus.Unknown;
        existing.LastRevertAreaResults = [];
        return existing;
    }

    private ObjectAuditParentRecoveryState GetObjectAuditParentRecoveryState(
        MonitoringDeploymentState? previousState,
        AgentConfigurationCommand command,
        AgentHostMonitoringConfiguration configuration,
        AgentConfigurationAreaKind[] requestedAreas)
    {
        if (!AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(requestedAreas))
            return new(false, 0, null);
        var journalEntryCount = 0;
        try
        {
            if (!_objectAccessAuditing.TryGetRecoveryJournalEntryCount(out journalEntryCount))
                return new(false, 0, null);
        }
        catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex) || ex is JsonException)
        {
            return new(true, 0, "Object-auditing recovery journal validation failed; deployment and baseline capture were withheld: " + ex.Message);
        }

        if (previousState == null)
            return new(true, journalEntryCount, "An object-auditing recovery journal exists, but its parent Windows Security original-state record is missing, unreadable, or malformed. Deployment and baseline recapture were withheld.");
        var expectedAgentId = FirstNonEmpty(command.AgentId, configuration.AgentId, AgentsViewModelLocalAgentId());
        var expectedHostId = FirstNonEmpty(command.HostId, configuration.HostId, Environment.MachineName);
        if (!previousState.ObjectAuditJournalExpected ||
            !string.Equals(previousState.AgentId, expectedAgentId, StringComparison.Ordinal) ||
            !string.Equals(previousState.HostId, expectedHostId, StringComparison.OrdinalIgnoreCase) ||
            !AgentHostMonitoringConfigurationAreas.ResolveEffective(previousState.ConfigurationAreas)
                .SequenceEqual(AgentHostMonitoringConfigurationAreas.ResolveEffective(requestedAreas)))
            return new(true, journalEntryCount, "The object-auditing recovery journal has no compatible parent Windows Security original-state record for this Agent, host, and scope. Deployment and baseline recapture were withheld.");
        if (IsRestorationComplete(previousState) && journalEntryCount > 0)
            return new(true, journalEntryCount, "The parent Windows Security original-state record reports completed recovery, but its object-auditing journal still contains pending entries. Deployment and baseline recapture were withheld.");
        return new(true, journalEntryCount, null);
    }

    internal static bool IsRestorationComplete(AgentMonitoringDeploymentAreaResult result) =>
        result.Status == AgentConfigurationOperationStatus.Success ||
        (result.Status == AgentConfigurationOperationStatus.Warning && result.OriginalStateRestored);

    private static bool IsRestorationComplete(MonitoringDeploymentState state) =>
        state.LastRevertStatus == AgentConfigurationOperationStatus.Success ||
        (state.LastRevertStatus == AgentConfigurationOperationStatus.Warning &&
         state.LastRevertAreaResults.Length > 0 && state.LastRevertAreaResults.All(r =>
             r.Status == AgentConfigurationOperationStatus.Skipped || IsRestorationComplete(r)) &&
         state.AreaResults.Where(r => r.Status is AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning)
             .All(applied => state.LastRevertAreaResults.Any(restored => restored.Area == applied.Area && IsRestorationComplete(restored))) &&
         state.SnapshotMutationAreas.Length == 0 && !state.ProcessCommandLineMutationMayHaveOccurred);

    private static AgentMonitoringDeploymentAreaResult[] MergeAppliedAreaResults(
        IReadOnlyCollection<AgentMonitoringDeploymentAreaResult> previous,
        IReadOnlyCollection<AgentMonitoringDeploymentAreaResult> current)
    {
        var merged = current.ToList();
        foreach (var prior in previous.Where(result => result.Status is
                     AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning))
        {
            var currentIndex = merged.FindIndex(result => result.Area == prior.Area);
            if (currentIndex < 0)
            {
                merged.Add(prior);
            }
            else if (merged[currentIndex].Status is not
                     (AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning))
            {
                merged[currentIndex] = prior;
            }
        }

        return merged.ToArray();
    }

    internal static string? BuildEventLogEnableArguments(
        string channelName,
        bool enable,
        AgentConfigurationAreaKind area)
    {
        if (!enable ||
            string.IsNullOrWhiteSpace(channelName) ||
            area == AgentConfigurationAreaKind.WindowsSecurityEventLog ||
            !channelName.Contains('/'))
        {
            return null;
        }

        return $"sl \"{channelName}\" /e:true";
    }

    internal static string? BuildEventLogRestoreEnableArguments(
        string channelName,
        bool enable,
        AgentConfigurationAreaKind area)
    {
        if (string.IsNullOrWhiteSpace(channelName) ||
            area == AgentConfigurationAreaKind.WindowsSecurityEventLog ||
            !channelName.Contains('/'))
        {
            return null;
        }

        return $"sl \"{channelName}\" /e:{enable.ToString().ToLowerInvariant()}";
    }

    private MonitoringDeploymentState CaptureOriginalState(
        AgentHostMonitoringConfiguration configuration,
        AgentConfigurationCommand command,
        AgentConfigurationAreaKind[] requestedAreas)
    {
        var effectiveAreas = AgentHostMonitoringConfigurationAreas.ResolveEffective(requestedAreas);
        if (AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(requestedAreas))
        {
            var captureCommandLine = effectiveAreas.Contains(AgentConfigurationAreaKind.ProcessCommandLineAuditing);
            var commandLineState = captureCommandLine
                ? CaptureProcessCommandLineLoggingState()
                : new CapturedRegistryValueState { IsAvailable = true };
            var captureSecurityEventLog = effectiveAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityEventLog);
            var securityEventLogNames = captureSecurityEventLog
                ? new[] { "Security" }
                : [];
            var securityAuditPolicyBackupPath = effectiveAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy)
                ? _auditPolicyBackup()
                : string.Empty;
            return new MonitoringDeploymentState
            {
                CapturedAtUtc = DateTime.UtcNow,
                AgentId = FirstNonEmpty(command.AgentId, configuration.AgentId, AgentsViewModelLocalAgentId()),
                HostId = FirstNonEmpty(command.HostId, configuration.HostId, Environment.MachineName),
                ConfigurationHash = configuration.ConfigurationHash,
                ConfigurationAreas = effectiveAreas,
                ProcessCommandLineLogging = commandLineState,
                AuditPolicyBackupPath = securityAuditPolicyBackupPath,
                AuditPolicySummary = SummarizeAuditPolicyBackup(securityAuditPolicyBackupPath),
                EventLogs = securityEventLogNames.Select(CaptureEventLogState).ToArray()
            };
        }

        var captureLegacyEventLogs = effectiveAreas.Contains(AgentConfigurationAreaKind.WindowsEventLogs);
        var eventLogNames = captureLegacyEventLogs
            ? LoadEventLogProfile(configuration.EventLogs)
                .Select(entry => entry.Name)
                .Concat(configuration.EventLogs.ChannelNames)
                .Where(name =>
                    !string.IsNullOrWhiteSpace(name) &&
                    !string.Equals(name, "Security", StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray()
            : [];

        var captureSysmon = effectiveAreas.Contains(AgentConfigurationAreaKind.Sysmon);
        var sysmon = captureSysmon ? _sysmonService.LoadSettings() : null;
        var sysmonExecutablePath = sysmon?.IsServiceStateAvailable == true
            ? _sysmonService.FindSysmonExecutablePath() ?? string.Empty
            : string.Empty;
        var capturePowerShell = effectiveAreas.Contains(AgentConfigurationAreaKind.PowerShellAuditing);
        var powerShell = capturePowerShell ? _powerShellAuditingService.LoadSettings() : null;
        return new MonitoringDeploymentState
        {
            CapturedAtUtc = DateTime.UtcNow,
            AgentId = FirstNonEmpty(command.AgentId, configuration.AgentId, AgentsViewModelLocalAgentId()),
            HostId = FirstNonEmpty(command.HostId, configuration.HostId, Environment.MachineName),
            ConfigurationHash = configuration.ConfigurationHash,
            ConfigurationAreas = effectiveAreas,
            SysmonStateAvailable = sysmon?.IsServiceStateAvailable,
            SysmonStateError = sysmon == null
                ? string.Empty
                : FirstNonEmpty(sysmon.ServiceError, sysmon.ServiceStatusDetail),
            SysmonWasInstalled = sysmon?.IsInstalled == true,
            SysmonWasRunning = sysmon?.IsRunning == true,
            SysmonChannelWasAvailable = sysmon?.IsChannelAvailable == true,
            SysmonExecutablePath = sysmonExecutablePath,
            SysmonConfigurationSummary = sysmon == null
                ? string.Empty
                : CaptureSysmonConfigurationSummary(sysmon.IsInstalled, sysmonExecutablePath),
            PowerShellStateAvailable = powerShell?.IsAvailable,
            PowerShellStateError = powerShell == null
                ? string.Empty
                : FirstNonEmpty(powerShell.Error, powerShell.StatusDetail),
            PowerShell = powerShell == null
                ? new PowerShellAuditState()
                : new PowerShellAuditState
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

    private CapturedRegistryValueState CaptureProcessCommandLineLoggingState()
    {
        var capture = _hostState.CaptureRegistryValue(
            AuditPolicyRegistryPath,
            ProcessCommandLineLoggingValueName);
        if (!capture.IsAvailable || !capture.ValueExisted)
        {
            return new CapturedRegistryValueState
            {
                IsAvailable = capture.IsAvailable,
                Error = capture.Error,
                ValueExisted = false
            };
        }

        return (capture.ValueKind, capture.Value) switch
        {
            (RegistryValueKind.DWord, int value) => new CapturedRegistryValueState
            {
                IsAvailable = true,
                ValueExisted = true,
                ValueKind = capture.ValueKind,
                DWordValue = value
            },
            (RegistryValueKind.QWord, long value) => new CapturedRegistryValueState
            {
                IsAvailable = true,
                ValueExisted = true,
                ValueKind = capture.ValueKind,
                QWordValue = value
            },
            (RegistryValueKind.String or RegistryValueKind.ExpandString, string value) =>
                new CapturedRegistryValueState
                {
                    IsAvailable = true,
                    ValueExisted = true,
                    ValueKind = capture.ValueKind,
                    StringValue = value
                },
            (RegistryValueKind.MultiString, string[] value) => new CapturedRegistryValueState
            {
                IsAvailable = true,
                ValueExisted = true,
                ValueKind = capture.ValueKind,
                MultiStringValue = value.ToArray()
            },
            (RegistryValueKind.Binary or RegistryValueKind.None, byte[] value) =>
                new CapturedRegistryValueState
                {
                    IsAvailable = true,
                    ValueExisted = true,
                    ValueKind = capture.ValueKind,
                    BinaryValue = value.ToArray()
                },
            _ => new CapturedRegistryValueState
            {
                IsAvailable = false,
                Error = $"Registry value kind '{capture.ValueKind}' could not be captured exactly.",
                ValueExisted = true,
                ValueKind = capture.ValueKind
            }
        };
    }

    private static object GetRegistryValueForRestore(CapturedRegistryValueState state) =>
        state.ValueKind switch
        {
            RegistryValueKind.DWord => state.DWordValue,
            RegistryValueKind.QWord => state.QWordValue,
            RegistryValueKind.String or RegistryValueKind.ExpandString => state.StringValue,
            RegistryValueKind.MultiString => state.MultiStringValue.ToArray(),
            RegistryValueKind.Binary or RegistryValueKind.None => state.BinaryValue.ToArray(),
            _ => throw new InvalidOperationException(
                $"Registry value kind '{state.ValueKind}' cannot be restored exactly.")
        };

    private static bool IsEnabledProcessCommandLineValue(AgentMonitoringRegistryValueCapture capture) =>
        capture.ValueExisted && capture.ValueKind == RegistryValueKind.DWord && capture.Value is int value && value == 1;

    private static bool RegistryValueMatchesBaseline(
        AgentMonitoringRegistryValueCapture current,
        CapturedRegistryValueState baseline)
    {
        if (!current.IsAvailable || current.ValueExisted != baseline.ValueExisted) return false;
        if (!current.ValueExisted) return true;
        if (current.ValueKind != baseline.ValueKind) return false;
        var expected = GetRegistryValueForRestore(baseline);
        return (current.Value, expected) switch
        {
            (byte[] actual, byte[] original) => actual.SequenceEqual(original),
            (string[] actual, string[] original) => actual.SequenceEqual(original, StringComparer.Ordinal),
            _ => Equals(current.Value, expected)
        };
    }

    private EventLogState CaptureEventLogState(string name)
    {
        var capture = _hostState.CaptureEventLog(name);
        return new EventLogState
        {
            Name = name,
            StateAvailable = capture.IsAvailable,
            StateError = capture.Error,
            Exists = capture.Exists,
            IsEnabled = capture.IsEnabled,
            MaximumSizeInBytes = capture.MaximumSizeInBytes,
            LogMode = capture.LogMode
        };
    }

    private void SaveOriginalState(MonitoringDeploymentState state, AgentConfigurationCommand command)
    {
        Directory.CreateDirectory(_sessionPaths.SessionRoot);
        RequireBackupCoverage(state.ConfigurationAreas);
        state.PortableBackupId = Guid.NewGuid().ToString("N");
        var json = JsonSerializer.Serialize(state, _jsonOptions);
        // The portable backup is durable before publishing the session's recovery reference
        // and before callers perform any host write. Manual form saves use separate slots.
        var auditPolicy = string.IsNullOrWhiteSpace(state.AuditPolicyBackupPath) || !File.Exists(state.AuditPolicyBackupPath)
            ? [] : ReadBoundedAuditBackup(state.AuditPolicyBackupPath);
        _portableStore.WriteOnce(GetPortableBackupSlot(command) + "-" + state.PortableBackupId,
            new PortableMonitoringBackup(json, auditPolicy));
        WriteOriginalStateAtomically(GetOriginalStatePath(command), json);

        if (!AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(ResolveCommandAreas(command)))
        {
            try
            {
                WriteOriginalStateAtomically(LegacyDeploymentStatePath, json);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to update legacy monitoring deployment state: {ex.Message}");
            }
        }
    }

    private static void WriteOriginalStateAtomically(string path, string json)
    {
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var bytes = Encoding.UTF8.GetBytes(json);
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private MonitoringDeploymentState? TryReadDeploymentState(AgentConfigurationCommand command)
    {
        // Check retained originals independently of the mutable session reference. Losing or
        // downgrading that reference must never turn an existing deployment into a fresh one.
        var prefix = GetPortableBackupSlot(command);
        var hasPortableBackups = _portableStore.HasBackups(prefix);
        MonitoringDeploymentState? state;
        string json;
        try
        {
            var originalStatePath = GetOriginalStatePath(command);
            var isWindowsSecurity = AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(
                ResolveCommandAreas(command));
            var path = File.Exists(originalStatePath)
                ? originalStatePath
                : !isWindowsSecurity && File.Exists(LegacyDeploymentStatePath)
                    ? LegacyDeploymentStatePath
                    : string.Empty;
            if (string.IsNullOrWhiteSpace(path))
            {
                if (hasPortableBackups)
                    throw new InvalidOperationException("Monitoring recovery reference is missing while portable originals exist; deployment/revert withheld.");
                return null;
            }

            json = File.ReadAllText(path);
            state = JsonSerializer.Deserialize<MonitoringDeploymentState>(json, _jsonOptions);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            if (hasPortableBackups)
                throw new InvalidOperationException("Monitoring recovery reference cannot be read while portable originals exist; deployment/revert withheld.", ex);
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to read monitoring deployment state: {ex.Message}");
            return null;
        }
        if (hasPortableBackups && string.IsNullOrEmpty(state?.PortableBackupId))
            throw new InvalidOperationException("Monitoring recovery reference lost its protected backup identity; deployment/revert withheld.");
        if (!string.IsNullOrEmpty(state?.PortableBackupId))
        {
            if (!Guid.TryParseExact(state.PortableBackupId, "N", out _))
                throw new InvalidOperationException("Invalid monitoring backup identity.");
            // These failures intentionally remain outside the legacy nullable read catch.
            var backup = _portableStore.Read<PortableMonitoringBackup>(prefix + "-" + state.PortableBackupId)
                ?? throw new InvalidOperationException("Required portable monitoring backup is missing; deployment/revert withheld.");
            if (!string.Equals(backup.StateJson, json, StringComparison.Ordinal))
                throw new InvalidOperationException("Portable monitoring backup and session recovery record differ; review is required before deployment/revert.");
            if (backup.AuditPolicy.Length > 0 &&
                (!File.Exists(state.AuditPolicyBackupPath) ||
                 !backup.AuditPolicy.SequenceEqual(ReadBoundedAuditBackup(state.AuditPolicyBackupPath))))
                throw new InvalidOperationException("The original audit policy backup is missing or differs from the protected portable original.");
        }
        return state;
    }

    private string GetPortableBackupSlot(AgentConfigurationCommand command) =>
        MonitoringConfigurationStore.AutomaticSlot(_sessionPaths.SessionRoot,
            AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(ResolveCommandAreas(command)));

    private static byte[] ReadBoundedAuditBackup(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > 4 * 1024 * 1024)
            throw new InvalidOperationException("Audit-policy backup has an invalid size.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static void RequireBackupCoverage(IEnumerable<AgentConfigurationAreaKind> requestedAreas)
    {
        // Every added managed area must deliberately supply both capture and restore semantics.
        // Legacy unsupported restoration remains visible in BuildOriginalStateAreas/ReverseLegacy.
        foreach (var area in AgentHostMonitoringConfigurationAreas.ResolveEffective(requestedAreas))
            if (area is not (AgentConfigurationAreaKind.WindowsSecurityAuditPolicy or
                AgentConfigurationAreaKind.ProcessCommandLineAuditing or AgentConfigurationAreaKind.WindowsSecurityEventLog or
                AgentConfigurationAreaKind.Sysmon or AgentConfigurationAreaKind.WindowsEventLogs or
                AgentConfigurationAreaKind.PowerShellAuditing or AgentConfigurationAreaKind.Etw or AgentConfigurationAreaKind.ScheduledDumps))
                throw new InvalidOperationException($"Monitoring area {area} has no registered backup/restore coverage.");
    }

    private sealed record PortableMonitoringBackup(string StateJson, byte[] AuditPolicy);

    private AgentMonitoringDeploymentResult RunWithRecoveryFailureResult(
        AgentConfigurationCommand command, AgentMonitoringDeploymentAction action,
        Func<AgentMonitoringDeploymentResult> operation)
    {
        var started = DateTime.UtcNow;
        try { return operation(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or
                                      CryptographicException or JsonException or ArgumentException or NotSupportedException or
                                      TimeoutException or Win32Exception)
        {
            // Do not re-read an invalid backup while constructing the failure response, and
            // never mistake failed recovery validation for an absent first-deployment baseline.
            var result = new AgentMonitoringDeploymentResult
            {
                AgentId = command.AgentId, HostId = command.HostId,
                ConfigurationVersion = command.ConfigurationVersion, ConfigurationHash = command.ConfigurationHash,
                Action = action, StartedAtUtc = started, CompletedAtUtc = DateTime.UtcNow,
                Status = AgentConfigurationOperationStatus.Failed, LastError = ex.Message,
                Warnings = ["Monitoring did not complete. Retain the session and settings/SecurityConfig for recovery review."]
            };
            AppendLog(result);
            return result;
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
        var partial = areas.Any(area => area.Status is
            AgentConfigurationOperationStatus.Warning or
            AgentConfigurationOperationStatus.Unsupported or
            AgentConfigurationOperationStatus.Failed);
        var summary = partial
            ? $"Original host monitoring state captured with partial restore coverage for {available}/{areas.Length} areas."
            : $"Original host monitoring state captured for {areas.Length} areas.";
        if (!string.IsNullOrWhiteSpace(state.LatestSettingsBackupPath))
            summary += $" Latest pre-apply settings saved to {state.LatestSettingsBackupPath}. Use Restore saved config to choose this or an older save.";

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
        if (IncludesOriginalArea(state, AgentConfigurationAreaKind.Sysmon))
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
        }

        if (IncludesOriginalArea(state, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy))
        {
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
        }

        if (IncludesOriginalArea(state, AgentConfigurationAreaKind.ProcessCommandLineAuditing))
        {
            var commandLineState = state.ProcessCommandLineLogging;
            yield return new AgentMonitoringOriginalStateArea
            {
                Area = AgentConfigurationAreaKind.ProcessCommandLineAuditing,
            Status = commandLineState.IsAvailable
                ? AgentConfigurationOperationStatus.Success
                : AgentConfigurationOperationStatus.Failed,
            RestoreSupported = commandLineState.IsAvailable,
            Summary = !commandLineState.IsAvailable
                ? "Process command-line logging registry state was unavailable during baseline capture."
                : commandLineState.ValueExisted
                ? "Process command-line logging registry value existed before deployment."
                : "Process command-line logging registry value was absent before deployment.",
            Detail = !commandLineState.IsAvailable
                ? commandLineState.Error
                : commandLineState.ValueExisted
                ? $"{ProcessCommandLineLoggingValueName}: {FormatCapturedRegistryValue(commandLineState)}."
                : $@"HKLM\{AuditPolicyRegistryPath}\{ProcessCommandLineLoggingValueName} was not configured.",
            RestoreGuidance = !commandLineState.IsAvailable
                ? "No registry mutation is safe until the exact prior value and registry kind can be read."
                : commandLineState.ValueExisted
                ? "Revert restores the previous value and registry kind exactly."
                : $"Revert removes the value if {ProductIdentity.DisplayName} created it."
            };
        }

        if (IncludesOriginalArea(state, AgentConfigurationAreaKind.PowerShellAuditing))
        {
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
        }

        var stateAreas = state.ConfigurationAreas ?? [];
        var eventLogArea = stateAreas.Contains(AgentConfigurationAreaKind.WindowsSecurityEventLog)
            ? AgentConfigurationAreaKind.WindowsSecurityEventLog
            : AgentConfigurationAreaKind.WindowsEventLogs;
        if (IncludesOriginalArea(state, eventLogArea))
        {
            var eventLogBaselineUnavailable = state.EventLogs.Any(log => !log.StateAvailable);
            yield return new AgentMonitoringOriginalStateArea
            {
                Area = eventLogArea,
            Status = eventLogBaselineUnavailable
                ? AgentConfigurationOperationStatus.Failed
                : state.EventLogs.Length > 0
                ? AgentConfigurationOperationStatus.Success
                : AgentConfigurationOperationStatus.Unsupported,
            RestoreSupported = state.EventLogs.Length > 0 && !eventLogBaselineUnavailable,
            Summary = eventLogBaselineUnavailable
                ? "One or more event-log settings were unavailable during baseline capture."
                : state.EventLogs.Length > 0
                ? $"Event-log settings were captured for {state.EventLogs.Length} channels."
                : "No event-log settings were captured.",
            Detail = string.Join("; ", state.EventLogs.Select(log =>
                log.StateAvailable
                    ? $"{log.Name}: exists={log.Exists}, enabled={log.IsEnabled}, maxBytes={log.MaximumSizeInBytes}, mode={log.LogMode}"
                    : $"{log.Name}: unavailable ({log.StateError})")),
            RestoreGuidance = state.EventLogs.Length > 0 && !eventLogBaselineUnavailable
                ? "Revert restores captured enablement, size, and retention settings where the log still exists."
                : "Manual event-log retention review is required."
            };
        }
    }

    private static bool IncludesOriginalArea(
        MonitoringDeploymentState state,
        AgentConfigurationAreaKind area) =>
        (state.ConfigurationAreas ?? []).Length == 0 || (state.ConfigurationAreas ?? []).Contains(area);

    private static string FormatCapturedRegistryValue(CapturedRegistryValueState state) =>
        state.ValueKind switch
        {
            RegistryValueKind.DWord => $"DWORD {state.DWordValue}",
            RegistryValueKind.QWord => $"QWORD {state.QWordValue}",
            RegistryValueKind.String => $"String '{TrimForDisplay(state.StringValue, 256)}'",
            RegistryValueKind.ExpandString => $"Expandable string '{TrimForDisplay(state.StringValue, 256)}'",
            RegistryValueKind.MultiString => $"Multi-string with {state.MultiStringValue.Length} entries",
            RegistryValueKind.Binary or RegistryValueKind.None => $"{state.ValueKind} with {state.BinaryValue.Length} bytes",
            _ => state.ValueKind.ToString()
        };

    private static bool IsReadableNonEmptyFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);
            return stream.Length > 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                      ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private string BackupAuditPolicy()
    {
        try
        {
            var backupPath = _portableStore.CreateAuditPolicyBackupPath();
            _processRunner("auditpol.exe", $"/backup /file:\"{backupPath}\"", true);
            return backupPath;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or
                                      TimeoutException or Win32Exception)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to back up audit policy before monitoring deploy: {ex.Message}");
            return string.Empty;
        }
    }

    private string ApplySecurityAuditPolicyProfile(
        string auditPolicyPath,
        SecurityAuditPolicyProfileEntry[]? entries)
    {
        if (string.Equals(Path.GetExtension(auditPolicyPath), ".csv", StringComparison.OrdinalIgnoreCase))
        {
            return _processRunner("auditpol.exe", $"/restore /file:\"{auditPolicyPath}\"", true);
        }

        if (entries == null)
        {
            throw new InvalidOperationException(
                "The Security audit policy profile was not validated before original-state capture.");
        }

        var results = new List<string>(entries.Length);
        for (var index = 0; index < entries.Length; index++)
        {
            var entry = entries[index];
            var subcategory = entry.Subcategory.Trim();
            var identifier = AgentSecurityAuditPolicyProfileResolver.GetAuditPolSubcategoryIdentifier(entry);
            var output = _processRunner(
                "auditpol.exe",
                $"/set /subcategory:\"{identifier}\" " +
                $"/success:{(entry.Success ? "enable" : "disable")} " +
                $"/failure:{(entry.Failure ? "enable" : "disable")}",
                true);
            results.Add($"{subcategory}: {output}");
        }

        return TrimForDisplay(
            $"Applied {entries.Length} audit subcategories. {string.Join("; ", results)}",
            4000);
    }

    private string ResolveWindowsSecurityEventLogProfilePath(string profileId)
    {
        var profile = ResolveProfile(ConfigProfileKind.WindowsSecurityEventLogs, profileId);
        if (profile == null)
        {
            return string.Empty;
        }

        var path = _configProfiles.ResolveProfileFilePath(profile);
        if (string.IsNullOrWhiteSpace(path) ||
            !string.Equals(Path.GetExtension(path), ".json", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        var profileRoot = Path.GetFullPath(Path.Combine(_configProfiles.ConfigRoot, "WindowsSecurity"))
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var normalizedPath = Path.GetFullPath(path);
        return normalizedPath.StartsWith(profileRoot, StringComparison.OrdinalIgnoreCase)
            ? normalizedPath
            : string.Empty;
    }

    private static EventLogProfileEntry[] ValidateWindowsSecurityEventLogProfile(string path)
    {
        var profileLength = new FileInfo(path).Length;
        if (profileLength <= 0 || profileLength > 256 * 1024)
        {
            throw new InvalidOperationException(
                "The Windows Security event-log profile must be non-empty and no larger than 256 KB.");
        }

        var entries = JsonSerializer.Deserialize<EventLogProfileEntry[]>(
            File.ReadAllText(path),
            SecurityProfileJsonOptions) ?? [];
        if (entries.Length != 1 ||
            !string.Equals(entries[0].Name?.Trim(), "Security", StringComparison.OrdinalIgnoreCase) ||
            entries[0].SizeBytes < 0 ||
            entries[0].SizeBytes > 64L * 1024 * 1024 * 1024)
        {
            throw new InvalidOperationException(
                "The Windows Security event-log profile must contain exactly one bounded Security-channel setting.");
        }

        return entries;
    }

    private IEnumerable<EventLogProfileEntry> LoadEventLogProfile(AgentEventLogMonitoringIntent intent)
    {
        var sourceOwnedProfile = ResolveProfile(ConfigProfileKind.WindowsSecurityEventLogs, intent.ProfileId);
        var profileKind = sourceOwnedProfile != null &&
                          string.Equals(sourceOwnedProfile.Id, intent.ProfileId, StringComparison.OrdinalIgnoreCase)
            ? ConfigProfileKind.WindowsSecurityEventLogs
            : ConfigProfileKind.EventLogs;
        var path = FirstNonEmpty(intent.ProfileId.Length == 0 ? string.Empty : ResolveProfilePath(profileKind, intent.ProfileId), string.Empty);
        if (string.IsNullOrWhiteSpace(path))
        {
            path = ResolveProfilePath(profileKind, string.Empty);
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
            : profiles.FirstOrDefault(profile =>
                string.Equals(profile.Id, profileId, StringComparison.OrdinalIgnoreCase));
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
            OriginalState = BuildOriginalStateSnapshot(originalState ?? TryReadDeploymentState(command))
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

    private bool EventLogExists(string name)
    {
        var result = _processRunner("wevtutil.exe", $"gl \"{name}\"", false);
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

    private sealed record WindowsSecurityDeploymentPlan(
        string AuditPolicyPath,
        SecurityAuditPolicyProfileEntry[]? AuditPolicyEntries,
        EventLogProfileEntry[] EventLogEntries)
    {
        public ObjectAuditPlan? SettingsPlan { get; init; }
        public WindowsSecuritySettingsSnapshot? RootBackup { get; init; }
    }

    private sealed record ObjectAuditParentRecoveryState(
        bool JournalExists,
        int JournalEntryCount,
        string? Error);

    private sealed class EventLogProfileEntry
    {
        public string Name { get; init; } = string.Empty;

        public long SizeBytes { get; init; }

        public bool Enable { get; init; }

        public bool Optional { get; init; }
    }

    private sealed class MonitoringDeploymentState
    {
        public string PortableBackupId { get; set; } = string.Empty;

        public string LatestSettingsBackupPath { get; set; } = string.Empty;

        public DateTime CapturedAtUtc { get; init; }

        public string AgentId { get; init; } = string.Empty;

        public string HostId { get; init; } = string.Empty;

        public string ConfigurationHash { get; set; } = string.Empty;

        public AgentConfigurationAreaKind[] ConfigurationAreas { get; init; } = [];

        public bool? SysmonStateAvailable { get; init; }

        public string SysmonStateError { get; init; } = string.Empty;

        public bool SysmonWasInstalled { get; init; }

        public bool SysmonWasRunning { get; init; }

        public bool SysmonChannelWasAvailable { get; init; }

        public string SysmonExecutablePath { get; init; } = string.Empty;

        public string SysmonConfigurationSummary { get; init; } = string.Empty;

        public CapturedRegistryValueState ProcessCommandLineLogging { get; init; } = new();

        public bool ProcessCommandLineMutationMayHaveOccurred { get; set; }

        public AgentConfigurationAreaKind[] SnapshotMutationAreas { get; set; } = [];

        public string AuditPolicyBackupPath { get; set; } = string.Empty;

        public bool ObjectAuditJournalExpected { get; set; }

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

        public bool StateAvailable { get; init; } = true;

        public string StateError { get; init; } = string.Empty;

        public bool Exists { get; init; }

        public bool IsEnabled { get; init; }

        public long MaximumSizeInBytes { get; init; }

        public string LogMode { get; init; } = string.Empty;
    }

    private sealed class CapturedRegistryValueState
    {
        public bool IsAvailable { get; init; }

        public string Error { get; init; } = string.Empty;

        public bool ValueExisted { get; init; }

        public RegistryValueKind ValueKind { get; init; }

        public int DWordValue { get; init; }

        public long QWordValue { get; init; }

        public string StringValue { get; init; } = string.Empty;

        public string[] MultiStringValue { get; init; } = [];

        public byte[] BinaryValue { get; init; } = [];
    }
}

internal sealed record AgentMonitoringRegistryValueCapture(
    bool IsAvailable,
    bool ValueExisted,
    RegistryValueKind ValueKind,
    object? Value,
    string Error = "");

internal sealed record AgentMonitoringEventLogCapture(
    bool IsAvailable,
    bool Exists,
    bool IsEnabled,
    long MaximumSizeInBytes,
    string LogMode,
    string Error = "");

internal interface IAgentMonitoringHostStateAccessor
{
    AgentMonitoringRegistryValueCapture CaptureRegistryValue(string subKeyPath, string valueName);

    void SetRegistryValue(
        string subKeyPath,
        string valueName,
        object value,
        RegistryValueKind valueKind);

    void DeleteRegistryValue(string subKeyPath, string valueName);

    AgentMonitoringEventLogCapture CaptureEventLog(string name);
}

internal sealed class WindowsAgentMonitoringHostStateAccessor : IAgentMonitoringHostStateAccessor
{
    public AgentMonitoringRegistryValueCapture CaptureRegistryValue(
        string subKeyPath,
        string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: false);
            if (key == null || !key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase))
            {
                return new AgentMonitoringRegistryValueCapture(
                    IsAvailable: true,
                    ValueExisted: false,
                    RegistryValueKind.None,
                    Value: null);
            }

            var valueKind = key.GetValueKind(valueName);
            var value = key.GetValue(
                valueName,
                defaultValue: null,
                RegistryValueOptions.DoNotExpandEnvironmentNames);
            return new AgentMonitoringRegistryValueCapture(
                IsAvailable: true,
                ValueExisted: true,
                valueKind,
                value);
        }
        catch (Exception ex)
        {
            return new AgentMonitoringRegistryValueCapture(
                IsAvailable: false,
                ValueExisted: false,
                RegistryValueKind.None,
                Value: null,
                Error: ex.Message);
        }
    }

    public void SetRegistryValue(
        string subKeyPath,
        string valueName,
        object value,
        RegistryValueKind valueKind)
    {
        using var key = Registry.LocalMachine.CreateSubKey(subKeyPath)
            ?? throw new InvalidOperationException($"Registry key 'HKLM\\{subKeyPath}' could not be opened.");
        key.SetValue(valueName, value, valueKind);
    }

    public void DeleteRegistryValue(string subKeyPath, string valueName)
    {
        using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: true);
        key?.DeleteValue(valueName, throwOnMissingValue: false);
    }

    public AgentMonitoringEventLogCapture CaptureEventLog(string name)
    {
        try
        {
            using var configuration = new EventLogConfiguration(name);
            return new AgentMonitoringEventLogCapture(
                IsAvailable: true,
                Exists: true,
                configuration.IsEnabled,
                configuration.MaximumSizeInBytes,
                configuration.LogMode.ToString());
        }
        catch (EventLogNotFoundException ex)
        {
            return new AgentMonitoringEventLogCapture(
                IsAvailable: true,
                Exists: false,
                IsEnabled: false,
                MaximumSizeInBytes: 0,
                LogMode: string.Empty,
                Error: ex.Message);
        }
        catch (Exception ex)
        {
            return new AgentMonitoringEventLogCapture(
                IsAvailable: false,
                Exists: false,
                IsEnabled: false,
                MaximumSizeInBytes: 0,
                LogMode: string.Empty,
                Error: ex.Message);
        }
    }
}
