using System.Text.Json;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed partial class AgentMonitoringConfigurationService
{
    private void RecordSavedApplyAttempt(MonitoringDeploymentState state, AgentConfigurationCommand command, AgentConfigurationAreaKind area)
    {
        if (command is not DeployHostMonitoringConfigurationCommand { SettingsBackupFolder.Length: > 0 }) return;
        state.SnapshotMutationAreas = state.SnapshotMutationAreas.Append(area).Distinct().ToArray();
        SaveOriginalState(state, command);
    }

    // Only preconfigured Apply supplies a Save receipt. Restore and legacy callers keep
    // their existing backup contract. Imported values never replace protected recovery state.
    private SavedSettingsApplyPlan? PrepareSavedSettingsApply(DeployHostMonitoringConfigurationCommand command,
        AgentHostMonitoringConfiguration configuration, AgentConfigurationAreaKind[] areas)
    {
        if (string.IsNullOrEmpty(command.SettingsBackupFolder) && string.IsNullOrEmpty(command.SettingsBackupFingerprint)) return null;
        if (!AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(areas) || configuration.SettingsSnapshot != null ||
            command.SettingsBackupFolder.Length > 1024 || !Path.IsPathFullyQualified(command.SettingsBackupFolder) ||
            command.SettingsBackupFingerprint.Length != 64 || !command.SettingsBackupFingerprint.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Invalid Save result for preconfigured Apply. No Windows settings were changed.");
        var saved = new WindowsSettingsFolderStore().Load(command.SettingsBackupFolder);
        if (!string.Equals(saved.ComputerName, Environment.MachineName, StringComparison.OrdinalIgnoreCase) ||
            WindowsSettingsFolderStore.SnapshotFingerprint(saved) != command.SettingsBackupFingerprint)
            throw new InvalidOperationException("The saved backup changed or belongs to another computer. Save again before Apply. No Windows settings were changed.");

        var current = ExportSettings(new GetHostMonitoringConfigurationCommand
        {
            AgentId = command.AgentId, HostId = command.HostId, ConfigurationAreas = areas,
            ExportSettingsAreas = saved.Areas
        }).SettingsSnapshot!;
        var gaps = new Dictionary<AgentConfigurationAreaKind, List<string>>();
        bool Covered(bool requested, WindowsSecuritySettingsArea area, AgentConfigurationAreaKind owner)
        {
            if (!requested) return false;
            var savedObjects = area == WindowsSecuritySettingsArea.UserFolderAuditing ? saved.UserFolderAuditing :
                area == WindowsSecuritySettingsArea.RegistryAuditing ? saved.RegistryAuditing : null;
            if (savedObjects?.RootConfigurationOnly == true)
            {
                if (!gaps.TryGetValue(owner, out var rootMessages)) gaps[owner] = rootMessages = [];
                rootMessages.AddRange(savedObjects.ScopeNotes.Select(n => $"{area}: {n}"));
                if (rootMessages.Count == 0) gaps.Remove(owner);
                // Each root is matched to its saved original again immediately before planning.
                // One failed root must not disable the other backed-up roots in this area.
                if (savedObjects.Entries.Length > 0) return true;
            }
            var matches = saved.HasArea(area) && current.HasArea(area) &&
                JsonSerializer.Serialize(saved.Select([area]) with { Gaps = [] }) ==
                JsonSerializer.Serialize(current.Select([area]) with { Version = saved.Version, CapturedAtUtc = saved.CapturedAtUtc, Gaps = [] });
            if (matches) return true;
            if (!gaps.TryGetValue(owner, out var messages)) gaps[owner] = messages = [];
            var reason = !saved.HasArea(area) ? "these settings were not included in the saved backup" :
                !current.HasArea(area) ? "the current settings could not be read" : "the current settings changed since Save";
            messages.Add($"{area} skipped: {reason}.");
            return false;
        }
        var audit = configuration.SecurityAuditPolicy;
        var logs = configuration.EventLogs;
        var effective = configuration with
        {
            SecurityAuditPolicy = audit with
            {
                ConfigureAuditPolicy = Covered(audit.ConfigureAuditPolicy, WindowsSecuritySettingsArea.AuditPolicy, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy),
                EnableProcessCommandLineLogging = Covered(audit.EnableProcessCommandLineLogging, WindowsSecuritySettingsArea.CommandLine, AgentConfigurationAreaKind.ProcessCommandLineAuditing),
                AuditUserDataFolders = Covered(audit.AuditUserDataFolders, WindowsSecuritySettingsArea.UserFolderAuditing, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy),
                AuditRegistryWrites = Covered(audit.AuditRegistryWrites, WindowsSecuritySettingsArea.RegistryAuditing, AgentConfigurationAreaKind.WindowsSecurityAuditPolicy)
            },
            EventLogs = logs with
            {
                ConfigureChannels = Covered(logs.ConfigureChannels, WindowsSecuritySettingsArea.EventLogChannel, AgentConfigurationAreaKind.WindowsSecurityEventLog),
                ConfigureRetention = Covered(logs.ConfigureRetention, WindowsSecuritySettingsArea.EventLogRetention, AgentConfigurationAreaKind.WindowsSecurityEventLog)
            }
        };
        // Object auditing depends on the audit-policy owner. An unavailable policy backup
        // must not leave enabled object intent that could escape that owner's coverage.
        if (!effective.SecurityAuditPolicy.ConfigureAuditPolicy)
            effective = effective with { SecurityAuditPolicy = effective.SecurityAuditPolicy with { AuditUserDataFolders = false, AuditRegistryWrites = false } };
        return new(effective, command.SettingsBackupFolder, gaps, saved);
    }

    private sealed record SavedSettingsApplyPlan(AgentHostMonitoringConfiguration Configuration, string Folder,
        Dictionary<AgentConfigurationAreaKind, List<string>> Gaps, WindowsSecuritySettingsSnapshot Snapshot)
    {
        public void AddCoverageResults(List<AgentMonitoringDeploymentAreaResult> results)
        {
            foreach (var (area, messages) in Gaps)
            {
                var index = results.FindIndex(result => result.Area == area);
                var existing = index < 0 ? Skipped(area, "No covered settings were applied.") : results[index];
                var replacement = existing with
                {
                    Status = existing.Status is AgentConfigurationOperationStatus.Failed or AgentConfigurationOperationStatus.Skipped ? existing.Status : AgentConfigurationOperationStatus.Warning,
                    Message = existing.Message + " " + string.Join(" ", messages)
                };
                if (index < 0) results.Add(replacement); else results[index] = replacement;
            }
        }
    }

    private void VerifySavedSettingsApply(SavedSettingsApplyPlan saved, WindowsSecurityDeploymentPlan plan,
        List<AgentMonitoringDeploymentAreaResult> results)
    {
        for (var index = 0; index < results.Count; index++)
        {
            var result = results[index];
            if (result.Status is not (AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning or AgentConfigurationOperationStatus.Failed)) continue;
            try
            {
                switch (result.Area)
                {
                    case AgentConfigurationAreaKind.WindowsSecurityAuditPolicy when saved.Configuration.SecurityAuditPolicy.ConfigureAuditPolicy:
                        if (plan.AuditPolicyEntries == null) throw new InvalidOperationException("Effective readback requires a GUID-based audit profile.");
                        var actual = _readSystemAuditPolicy().ToDictionary(entry => entry.Subcategory, entry => entry.Flags);
                        foreach (var entry in plan.AuditPolicyEntries)
                        {
                            if (!Guid.TryParse(entry.SubcategoryGuid, out var id) || !actual.TryGetValue(id, out var flags) ||
                                ((flags & 1) != 0) != entry.Success || ((flags & 2) != 0) != entry.Failure)
                                throw new InvalidOperationException($"Effective audit policy does not match {entry.Subcategory}.");
                        }
                        break;
                    case AgentConfigurationAreaKind.ProcessCommandLineAuditing when saved.Configuration.SecurityAuditPolicy.EnableProcessCommandLineLogging:
                        if (ReadCommandLineSetting() != new CommandLineSetting(true, 1))
                            throw new InvalidOperationException("Effective process command-line policy is not enabled.");
                        break;
                    case AgentConfigurationAreaKind.WindowsSecurityEventLog:
                        var log = ReadSecurityLog();
                        foreach (var entry in plan.EventLogEntries)
                        {
                            if (saved.Configuration.EventLogs.ConfigureChannels && log.IsEnabled != entry.Enable ||
                                saved.Configuration.EventLogs.ConfigureRetention && entry.SizeBytes > 0 &&
                                (log.MaximumSizeInBytes != entry.SizeBytes || log.LogMode != "Circular"))
                                throw new InvalidOperationException("Effective Security log settings do not match the requested profile.");
                        }
                        break;
                }
                results[index] = result with { Message = result.Message + " Effective settings verified." };
            }
            catch (Exception ex) when (AgentObjectAccessAuditingService.IsTargetFailure(ex) || ex is JsonException)
            {
                // Preserve Warning for uncertain post-write state so the existing recovery
                // coverage union still includes the attempted area.
                results[index] = result with { Status = result.Status == AgentConfigurationOperationStatus.Failed ? result.Status : AgentConfigurationOperationStatus.Warning,
                    Message = result.Message + " Verification failed; changes may have occurred.", TechnicalDetail = result.TechnicalDetail + " " + ex.Message };
            }
        }
    }
}
