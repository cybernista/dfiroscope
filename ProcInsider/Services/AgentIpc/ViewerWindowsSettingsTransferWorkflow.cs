using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

/// <summary>Owns the portable selection/observation/persistence sequence independently of the shell.</summary>
public sealed class ViewerWindowsSettingsTransferWorkflow(ViewerHostMonitoringActionService actions,
    WindowsSettingsFolderStore store)
{
    public Task<WindowsSettingsFolderEntry[]> ListAsync(ViewerHostMonitoringActionTarget target, string directory) => Task.Run(() =>
    {
        actions.RequireCurrentSettingsTarget(target);
        var entries = store.ListSavedFolders(directory, Environment.MachineName);
        actions.RequireCurrentSettingsTarget(target);
        return entries;
    });

    public Task<WindowsSettingsFolderEntry> InspectAsync(ViewerHostMonitoringActionTarget target, string folder) => Task.Run(() =>
    {
        actions.RequireCurrentSettingsTarget(target);
        var entry = store.InspectSavedFolder(folder, Environment.MachineName);
        actions.RequireCurrentSettingsTarget(target);
        return entry;
    });

    public async Task<WindowsSettingsRestoreResult> RestoreAsync(ViewerHostMonitoringActionTarget target,
        WindowsSettingsFolderEntry chosen, WindowsSecuritySettingsArea[] areas, CancellationToken cancellationToken = default)
    {
        actions.RequireCurrentSettingsTarget(target);
        cancellationToken.ThrowIfCancellationRequested();
        var current = await LoadAsync(target, chosen.FolderPath).ConfigureAwait(false);
        if (!chosen.IsAvailable || WindowsSettingsFolderStore.SnapshotFingerprint(current) != chosen.Fingerprint)
            throw new InvalidOperationException("The saved configuration changed after selection. Select it again and review its current settings before restoring.");
        if (areas.Length == 0) throw new InvalidOperationException("Choose at least one saved settings area to restore.");
        var selected = current.Select(areas);
        var requiredAreas = selected.Areas.Select(area => area switch
        {
            WindowsSecuritySettingsArea.AuditPolicy or WindowsSecuritySettingsArea.UserFolderAuditing or WindowsSecuritySettingsArea.RegistryAuditing
                => AgentConfigurationAreaKind.WindowsSecurityAuditPolicy,
            WindowsSecuritySettingsArea.CommandLine => AgentConfigurationAreaKind.ProcessCommandLineAuditing,
            WindowsSecuritySettingsArea.EventLogChannel or WindowsSecuritySettingsArea.EventLogRetention => AgentConfigurationAreaKind.WindowsSecurityEventLog,
            _ => throw new InvalidOperationException("Unsupported saved settings area.")
        }).Distinct().ToArray();
        var saved = await actions.SaveConfigurationAsync(target,
            selected.ToConfiguration(target.AgentId, target.HostId), cancellationToken).ConfigureAwait(false);
        if (!saved.Succeeded) return new(chosen.FolderPath, saved, null, requiredAreas);
        var expectedHash = saved.Response?.HostMonitoringConfiguration?.ConfigurationHash;
        if (string.IsNullOrWhiteSpace(expectedHash))
            throw new InvalidOperationException("The Agent did not confirm the identity of the configuration to restore.");
        var applied = await actions.DeploySavedConfigurationAsync(target, cancellationToken,
            expectedConfigurationHash: expectedHash).ConfigureAwait(false);
        return new(chosen.FolderPath, saved, applied, requiredAreas);
    }
    public async Task<string> SaveAsync(ViewerHostMonitoringActionTarget target, WindowsSecuritySettingsArea[] areas, string file)
        => (await SaveWithResultAsync(target, areas, file)).Message;

    public async Task<WindowsSettingsSaveResult> SaveWithResultAsync(ViewerHostMonitoringActionTarget target, WindowsSecuritySettingsArea[] areas, string file)
    {
        var result = await actions.ExportCurrentSettingsAsync(target, areas);
        if (!result.Succeeded || result.Response?.HostMonitoringConfiguration?.SettingsSnapshot is not { } snapshot)
            throw new InvalidOperationException(result.Diagnostic);
        return await Task.Run(() =>
        {
            actions.RequireCurrentSettingsTarget(target);
            var path = store.Save(file, snapshot);
            var message = "Current Windows settings saved to " + path +
                (snapshot.Gaps.Length == 0 ? string.Empty : ". Areas not exported: " + string.Join("; ", snapshot.Gaps)) +
                (snapshot.RegistryAuditing?.ScopeNotes.Length > 0 ? ". Scope: " + string.Join("; ", snapshot.RegistryAuditing.ScopeNotes) : string.Empty);
            return new WindowsSettingsSaveResult(path, snapshot, message);
        });
    }

    public Task<WindowsSecuritySettingsSnapshot> LoadAsync(ViewerHostMonitoringActionTarget target, string folder) => Task.Run(() =>
    {
        actions.RequireCurrentSettingsTarget(target);
        var snapshot = store.Load(folder);
        actions.RequireCurrentSettingsTarget(target);
        if (!string.Equals(snapshot.ComputerName, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Choose a settings export from this computer.");
        return snapshot;
    });
}

public sealed record WindowsSettingsSaveResult(string ManifestPath, WindowsSecuritySettingsSnapshot Snapshot, string Message)
{
    public WindowsSettingsFolderEntry Entry => new(System.IO.Path.GetDirectoryName(ManifestPath)!, Snapshot, string.Empty);
}

public sealed record WindowsSettingsRestoreResult(string FolderPath,
    ViewerHostMonitoringActionResult Saved, ViewerHostMonitoringActionResult? Applied, AgentConfigurationAreaKind[] RequiredAreas)
{
    private bool IsConfirmed(AgentConfigurationAreaKind required) =>
        Applied?.Response?.MonitoringDeployment?.AreaResults?.Where(area => area.Area == required).ToArray()
            is [{ Status: AgentConfigurationOperationStatus.Success }];
    public bool Succeeded => Applied is { Succeeded: true, Response.MonitoringDeployment: { } result } &&
        result.Status == AgentConfigurationOperationStatus.Success && (result.Warnings?.Length ?? 0) == 0 &&
        string.IsNullOrWhiteSpace(result.LastError) && result.AreaResults is { Length: > 0 } areas &&
        RequiredAreas.Length > 0 && RequiredAreas.All(IsConfirmed) &&
        areas.All(area => area.Status is AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Skipped);
    public string Summary => Succeeded ? "Saved configuration restored successfully." :
        Applied is { Succeeded: true, Response.MonitoringDeployment: not null }
            ? "Restoration has warnings or incomplete results. Review the details below."
            : Applied == null ? "Restoration was not started." : "Restoration was not confirmed as successful.";
    public string Details => string.Join(Environment.NewLine + Environment.NewLine,
        new[] { "Selected backup: " + FolderPath, (Applied ?? Saved).Diagnostic, Applied?.Response?.MonitoringDeployment?.LastError ?? string.Empty }
            .Concat(Applied?.Response?.MonitoringDeployment?.Warnings ?? [])
            .Concat(Applied == null ? [] : RequiredAreas.Where(area => !IsConfirmed(area)).Select(area =>
                "Restoration was not confirmed for " + System.Text.RegularExpressions.Regex.Replace(area.ToString(), "([a-z])([A-Z])", "$1 $2") + "."))
            .Concat(Applied?.Response?.MonitoringDeployment?.AreaResults?.Select(area =>
                $"{System.Text.RegularExpressions.Regex.Replace(area.Area.ToString(), "([a-z])([A-Z])", "$1 $2")}: {area.Status}\n{area.Message}\n{area.TechnicalDetail}") ?? [])
            .Where(text => !string.IsNullOrWhiteSpace(text)));
}
