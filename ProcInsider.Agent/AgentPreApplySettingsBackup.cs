using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed partial class AgentMonitoringConfigurationService
{
    // Runs inside the serialized Agent operation before any Windows writes. Portable
    // settings are reviewed input; the protected original journal stays recovery authority.
    private string SavePreApplySettings(AgentHostMonitoringConfiguration configuration,
        AgentConfigurationCommand command, AgentConfigurationAreaKind[] requestedAreas)
    {
        if (!AgentHostMonitoringConfigurationAreas.IsWindowsSecurityOnly(requestedAreas)) return string.Empty;
        var areas = new List<WindowsSecuritySettingsArea>();
        if (configuration.SettingsSnapshot is { } loaded) areas.AddRange(loaded.Areas);
        else
        {
            if (configuration.SecurityAuditPolicy.ConfigureAuditPolicy)
                areas.Add(WindowsSecuritySettingsArea.AuditPolicy);
            if (configuration.SecurityAuditPolicy.EnableProcessCommandLineLogging)
                areas.Add(WindowsSecuritySettingsArea.CommandLine);
            if (configuration.EventLogs.ConfigureChannels)
                areas.Add(WindowsSecuritySettingsArea.EventLogChannel);
            if (configuration.EventLogs.ConfigureRetention)
                areas.Add(WindowsSecuritySettingsArea.EventLogRetention);
            if (configuration.SecurityAuditPolicy.AuditUserDataFolders)
                areas.Add(WindowsSecuritySettingsArea.UserFolderAuditing);
            if (configuration.SecurityAuditPolicy.AuditRegistryWrites)
                areas.Add(WindowsSecuritySettingsArea.RegistryAuditing);
        }
        if (areas.Count == 0) return string.Empty;
        var snapshot = ExportSettings(new GetHostMonitoringConfigurationCommand
        {
            AgentId = command.AgentId, HostId = command.HostId, ConfigurationAreas = requestedAreas,
            ExportSettingsAreas = areas.ToArray()
        }).SettingsSnapshot!;
        if (!areas.ToHashSet().SetEquals(snapshot.Areas))
            throw new InvalidOperationException("Apply was withheld because the current settings could not be fully saved. " +
                string.Join("; ", snapshot.Gaps) + " Review or deselect the unavailable area before applying again. No Windows settings were changed.");
        return _saveSettingsFolder(
            Path.Combine(_portableStore.DirectoryPath,
                WindowsSettingsFolderStore.DefaultName(snapshot.ComputerName, snapshot.CapturedAtUtc)), snapshot);
    }
}
