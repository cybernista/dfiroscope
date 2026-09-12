using System.Text.Json;
using Microsoft.Win32;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed partial class AgentMonitoringConfigurationService
{
    private AgentConfigurationCheckResult CheckSettingsSnapshot(CheckHostMonitoringConfigurationCommand command,
        AgentHostMonitoringConfiguration configuration, ObjectAuditParentRecoveryState recovery, bool journalExpected, CaptureHealthReport? captureHealth)
    {
        var findings = new List<AgentConfigurationFinding>();
        try
        {
            ValidateObjectAuditScope(configuration, ResolveAreas(command, configuration));
            if (!string.IsNullOrEmpty(recovery.Error)) throw new InvalidOperationException(recovery.Error);
            if (journalExpected && !recovery.JournalExists)
                throw new InvalidOperationException("The expected object-auditing recovery journal is missing; original-state recovery cannot be verified.");
            var desired = configuration.SettingsSnapshot!;
            if (!string.Equals(desired.ComputerName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The saved settings belong to another computer.");
            var actual = ExportSettings(new GetHostMonitoringConfigurationCommand
            {
                AgentId = command.AgentId, HostId = command.HostId, ConfigurationAreas = command.ConfigurationAreas,
                ExportSettingsAreas = desired.Areas
            }).SettingsSnapshot!;
            foreach (var area in desired.Areas)
            {
                var matches = actual.HasArea(area) && JsonSerializer.Serialize(actual.Select([area]) with
                    { Version = desired.Version, CapturedAtUtc = desired.CapturedAtUtc, Gaps = [] }) == JsonSerializer.Serialize(desired.Select([area]) with { Gaps = [] });
                if (area is WindowsSecuritySettingsArea.RegistryAuditing or WindowsSecuritySettingsArea.UserFolderAuditing)
                {
                    var registryArea = area == WindowsSecuritySettingsArea.RegistryAuditing;
                    var expectedObjects = registryArea ? desired.RegistryAuditing! : desired.UserFolderAuditing!;
                    var actualObjects = _objectAccessAuditing.ExportSettings(registryArea, expectedObjects.RootConfigurationOnly);
                    matches = _objectAccessAuditing.SettingsMatch(expectedObjects, actualObjects, registryArea);
                }
                findings.Add(new()
                {
                    Area = area == WindowsSecuritySettingsArea.CommandLine ? AgentConfigurationAreaKind.ProcessCommandLineAuditing :
                        area is WindowsSecuritySettingsArea.EventLogChannel or WindowsSecuritySettingsArea.EventLogRetention ?
                            AgentConfigurationAreaKind.WindowsSecurityEventLog : AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                    Severity = matches ? AgentConfigurationFindingSeverity.Info : AgentConfigurationFindingSeverity.Warning,
                    Message = matches ? $"{area}: current settings match the saved values." : $"{area}: current settings differ or could not be observed.",
                    TechnicalDetail = string.Join("; ", actual.Gaps),
                    AuditPolicyStates = area == WindowsSecuritySettingsArea.AuditPolicy && actual.AuditPolicy != null
                        ? actual.AuditPolicy.Select(setting => new AgentAuditPolicySubcategoryState(
                            _auditPolicyDisplayName(setting.Subcategory),
                            (setting.Flags & 1) != 0,
                            (setting.Flags & 2) != 0)).ToArray()
                        : []
                });
            }
        }
        catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex) || ex is JsonException)
        { findings.Add(new() { Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, Severity = AgentConfigurationFindingSeverity.Blocked, Message = ex.Message }); }
        if (recovery.JournalExists)
            findings.Add(new() { Area = AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
                Severity = recovery.JournalEntryCount > 0 && !AgentObjectAccessAuditingService.Requested(configuration.SecurityAuditPolicy)
                    ? AgentConfigurationFindingSeverity.Warning : AgentConfigurationFindingSeverity.Info,
                Message = "Targeted object-auditing recovery journal remains available.",
                TechnicalDetail = $"{recovery.JournalEntryCount} object(s) retained for exact restoration; unchecked object settings do not remove an active deployment." });
        AgentConfigurationCheckService.CheckWindowsSecuritySourceHealth(findings, captureHealth);
        return new()
        {
            TargetKind = AgentConfigurationTargetKind.HostMonitoring, AgentId = command.AgentId, HostId = command.HostId,
            ConfigurationVersion = configuration.ConfigurationVersion, ConfigurationHash = configuration.ConfigurationHash,
            OverallState = findings.Any(f => f.Severity == AgentConfigurationFindingSeverity.Blocked) ? AgentConfigurationCheckState.Blocked :
                findings.Any(f => f.Severity == AgentConfigurationFindingSeverity.Warning) ? AgentConfigurationCheckState.Warning : AgentConfigurationCheckState.Ready,
            Findings = findings.ToArray()
        };
    }

    private AgentHostMonitoringConfiguration ExportSettings(GetHostMonitoringConfigurationCommand command)
    {
        if (!AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(command.ConfigurationAreas) ||
            command.ExportSettingsAreas.Length is < 1 or > 6 ||
            command.ExportSettingsAreas.Any(a => a == WindowsSecuritySettingsArea.Unknown || !Enum.IsDefined(a)) ||
            command.ExportSettingsAreas.Distinct().Count() != command.ExportSettingsAreas.Length)
            throw new InvalidOperationException("Export requires explicit supported Windows Security settings areas.");
        var snapshot = new WindowsSecuritySettingsSnapshot { ComputerName = Environment.MachineName, CapturedAtUtc = DateTime.UtcNow };
        var gaps = new List<string>();
        foreach (var area in command.ExportSettingsAreas)
        {
            try
            {
                var candidate = area switch
                {
                    WindowsSecuritySettingsArea.AuditPolicy => snapshot with { AuditPolicy = _readSystemAuditPolicy() },
                    WindowsSecuritySettingsArea.CommandLine => snapshot with { CommandLine = ReadCommandLineSetting() },
                    WindowsSecuritySettingsArea.EventLogChannel => snapshot with { EventLogEnabled = ReadSecurityLog().IsEnabled },
                    WindowsSecuritySettingsArea.EventLogRetention => snapshot with
                    { EventLogRetention = ReadRetention() },
                    WindowsSecuritySettingsArea.UserFolderAuditing => snapshot with { UserFolderAuditing = _objectAccessAuditing.ExportSettings(false) },
                    WindowsSecuritySettingsArea.RegistryAuditing => snapshot with { RegistryAuditing = _objectAccessAuditing.ExportSettings(true) },
                    _ => throw new InvalidOperationException("Unsupported settings area.")
                };
                if (candidate.UserFolderAuditing?.RootConfigurationOnly == true || candidate.RegistryAuditing?.RootConfigurationOnly == true)
                    candidate = candidate with { Version = 2 };
                candidate.Validate();
                if (JsonSerializer.SerializeToUtf8Bytes(candidate).Length > 240 * 1024)
                    throw new InvalidOperationException("Area exceeds the bounded settings transfer size; select fewer or smaller areas.");
                snapshot = candidate;
            }
            catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex) || ex is JsonException)
            { gaps.Add($"{area}: {ex.Message}"[..Math.Min(2048, $"{area}: {ex.Message}".Length)]); }
        }
        snapshot = snapshot with { Gaps = gaps.ToArray() };
        snapshot.Validate();
        return snapshot.ToConfiguration(command.AgentId, command.HostId);
    }

    private CommandLineSetting ReadCommandLineSetting()
    {
        var value = _hostState.CaptureRegistryValue(AuditPolicyRegistryPath, ProcessCommandLineLoggingValueName);
        if (!value.IsAvailable) throw new InvalidOperationException(value.Error);
        if (!value.ValueExisted) return new(false, 0);
        if (value.ValueKind != RegistryValueKind.DWord || value.Value is not int number || number is not (0 or 1))
            throw new InvalidOperationException("Command-line policy has an unsupported registry type/value; it was not represented as disabled.");
        return new(true, number);
    }

    private AgentMonitoringEventLogCapture ReadSecurityLog()
    {
        var log = _hostState.CaptureEventLog("Security");
        if (!log.IsAvailable || !log.Exists) throw new InvalidOperationException("Security channel settings are unavailable: " + log.Error);
        return log;
    }
    private SecurityLogRetentionSetting ReadRetention()
    {
        var log = ReadSecurityLog();
        return new(log.MaximumSizeInBytes, log.LogMode);
    }

    private ObjectAuditPlan? ValidateSettingsForDeployment(WindowsSecuritySettingsSnapshot snapshot, string hash)
    {
        snapshot.Validate();
        if (!string.Equals(snapshot.ComputerName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Load requires a settings export from this computer.");
        if (snapshot.Areas.Length == 0) throw new InvalidOperationException("Select at least one captured area to load.");
        if (snapshot.AuditPolicy is { } policy &&
            !_readSystemAuditPolicy().Select(p => p.Subcategory).ToHashSet().SetEquals(policy.Select(p => p.Subcategory)))
            throw new InvalidOperationException("The saved system audit subcategory inventory does not match this Windows host.");
        if (snapshot.CommandLine != null) { _objectAccessAuditing.EnsureNoCommandLinePolicyConflict(); ReadCommandLineSetting(); }
        if (snapshot.EventLogEnabled is { } enabled && ReadSecurityLog().IsEnabled != enabled)
            throw new InvalidOperationException("Windows does not support changing Security channel enablement; the exported state does not match.");
        return snapshot.UserFolderAuditing == null && snapshot.RegistryAuditing == null ? null :
            _objectAccessAuditing.PrepareSettings(snapshot, hash);
    }

    private List<AgentMonitoringDeploymentAreaResult> DeploySettingsSnapshot(AgentHostMonitoringConfiguration configuration,
        MonitoringDeploymentState baseline, AgentConfigurationCommand command, ObjectAuditPlan? objectPlan)
    {
        var snapshot = configuration.SettingsSnapshot!;
        var results = new List<AgentMonitoringDeploymentAreaResult>();
        bool Apply(AgentConfigurationAreaKind area, Action mutation)
        {
            // Durable uncertainty survives a crash or a partially failed native operation.
            baseline.SnapshotMutationAreas = baseline.SnapshotMutationAreas.Append(area).Distinct().ToArray();
            SaveOriginalState(baseline, command);
            var result = TryArea(area, true, () =>
            {
                mutation();
                return new AgentMonitoringDeploymentAreaResult { Area = area, Status = AgentConfigurationOperationStatus.Success,
                    ReverseSupported = true, Message = "Saved current Windows settings loaded and verified." };
            });
            results.Add(result);
            return result.Status == AgentConfigurationOperationStatus.Success;
        }
        if (snapshot.CommandLine is { } commandLine && !Apply(AgentConfigurationAreaKind.ProcessCommandLineAuditing, () =>
        {
            if (commandLine.Exists) _hostState.SetRegistryValue(AuditPolicyRegistryPath, ProcessCommandLineLoggingValueName, commandLine.Value, RegistryValueKind.DWord);
            else _hostState.DeleteRegistryValue(AuditPolicyRegistryPath, ProcessCommandLineLoggingValueName);
            if (ReadCommandLineSetting() != commandLine) throw new InvalidOperationException("Command-line policy verification failed.");
        })) return results;
        if ((snapshot.AuditPolicy != null || objectPlan != null) && !Apply(AgentConfigurationAreaKind.WindowsSecurityAuditPolicy, () =>
        {
            if (snapshot.AuditPolicy is { } policy)
            {
                foreach (var entry in policy)
                    _processRunner("auditpol.exe", $"/set /subcategory:\"{entry.Subcategory:B}\" /success:{((entry.Flags & 1) != 0 ? "enable" : "disable")} /failure:{((entry.Flags & 2) != 0 ? "enable" : "disable")}", true);
                var actual = _readSystemAuditPolicy().ToDictionary(e => e.Subcategory, e => e.Flags);
                if (policy.Any(e => !actual.TryGetValue(e.Subcategory, out var flags) || flags != e.Flags))
                    throw new InvalidOperationException("System audit policy verification failed.");
            }
            if (objectPlan != null)
            {
                var outcome = _objectAccessAuditing.Deploy(objectPlan);
                if (outcome.Gaps.Length > 0) throw new InvalidOperationException(outcome.Detail);
            }
        })) return results;
        if (snapshot.EventLogEnabled != null || snapshot.EventLogRetention != null)
            Apply(AgentConfigurationAreaKind.WindowsSecurityEventLog, () =>
            {
                if (snapshot.EventLogRetention is { } log)
                {
                    _processRunner("wevtutil.exe", $"sl Security /ms:{log.MaximumSizeBytes} /rt:{(log.LogMode == "Circular" ? "false" : "true")} /ab:{(log.LogMode == "AutoBackup" ? "true" : "false")}", true);
                    if (ReadRetention() != log) throw new InvalidOperationException("Security log retention verification failed.");
                }
                if (snapshot.EventLogEnabled is { } enabled && ReadSecurityLog().IsEnabled != enabled)
                    throw new InvalidOperationException("Security channel verification failed.");
            });
        return results;
    }
}
