using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

/// <summary>Retains the reviewed backup and exact target across draft save and Apply.</summary>
public sealed class ViewerPreconfiguredAuditApplyWorkflow(ViewerHostMonitoringActionService actions, WindowsSettingsFolderStore store)
{
    public async Task<WindowsSettingsApplyResult> ApplyAsync(ViewerHostMonitoringActionTarget target,
        WindowsSettingsFolderEntry backup, AgentHostMonitoringConfiguration configuration, CancellationToken cancellationToken = default)
    {
        actions.RequireCurrentSettingsTarget(target);
        cancellationToken.ThrowIfCancellationRequested();
        var current = await Task.Run(() => store.InspectSavedFolder(backup.FolderPath, Environment.MachineName), cancellationToken);
        actions.RequireCurrentSettingsTarget(target);
        if (!backup.IsAvailable || !current.IsAvailable || current.Fingerprint != backup.Fingerprint)
            throw new InvalidOperationException("The saved backup is unavailable or changed. Save the current configuration again before Apply.");
        var required = new[]
        {
            configuration.SecurityAuditPolicy.ConfigureAuditPolicy ? AgentConfigurationAreaKind.WindowsSecurityAuditPolicy : AgentConfigurationAreaKind.Unknown,
            configuration.SecurityAuditPolicy.EnableProcessCommandLineLogging ? AgentConfigurationAreaKind.ProcessCommandLineAuditing : AgentConfigurationAreaKind.Unknown,
            configuration.EventLogs.ConfigureChannels || configuration.EventLogs.ConfigureRetention ? AgentConfigurationAreaKind.WindowsSecurityEventLog : AgentConfigurationAreaKind.Unknown
        }.Where(area => area != AgentConfigurationAreaKind.Unknown).ToArray();
        var saved = await actions.SaveConfigurationAsync(target, configuration, cancellationToken);
        if (!saved.Succeeded) return new(backup.FolderPath, saved, null, required);
        var hash = saved.Response?.HostMonitoringConfiguration?.ConfigurationHash;
        if (string.IsNullOrWhiteSpace(hash)) throw new InvalidOperationException("The Agent did not confirm the saved draft identity. No Apply command was sent.");
        var applied = await actions.DeploySavedConfigurationAsync(target, cancellationToken,
            expectedConfigurationHash: hash, settingsBackup: backup);
        return new(backup.FolderPath, saved, applied, required);
    }
}

public sealed record WindowsSettingsApplyResult(string BackupFolder, ViewerHostMonitoringActionResult Saved,
    ViewerHostMonitoringActionResult? Applied, AgentConfigurationAreaKind[] RequiredAreas)
{
    private bool IsConfirmed(AgentConfigurationAreaKind required) =>
        Applied?.Response?.MonitoringDeployment?.AreaResults?.Where(area => area.Area == required).ToArray()
            is [{ Status: AgentConfigurationOperationStatus.Success }];
    public bool Succeeded => Saved.Succeeded && Applied is { Succeeded: true, Response.MonitoringDeployment: { } result } &&
        result.Status == AgentConfigurationOperationStatus.Success && (result.Warnings?.Length ?? 0) == 0 &&
        string.IsNullOrWhiteSpace(result.LastError) && result.AreaResults is { Length: > 0 } areas &&
        RequiredAreas.Length > 0 && RequiredAreas.All(IsConfirmed) && areas.Select(area => area.Area).Distinct().Count() == areas.Length &&
        areas.All(area => area.Status is AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Skipped);
    public bool HasCompleteResults => Saved.Succeeded && Applied?.Response?.MonitoringDeployment is { AreaResults: { Length: > 0 } areas } deployment &&
        deployment.Status is AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning or AgentConfigurationOperationStatus.Failed &&
        RequiredAreas.Length > 0 && areas.Select(area => area.Area).Distinct().Count() == areas.Length &&
        RequiredAreas.All(required => areas.Any(area => area.Area == required)) &&
        areas.All(area => area.Status is AgentConfigurationOperationStatus.Success or AgentConfigurationOperationStatus.Warning or
            AgentConfigurationOperationStatus.Failed or AgentConfigurationOperationStatus.Skipped);
    public string Summary => Succeeded ? "Audit settings applied and verified." :
        Applied == null ? "Apply was not started." :
        !HasCompleteResults ? "Apply could not be confirmed. Review the details before trying again." :
        Applied!.Response!.MonitoringDeployment!.Status == AgentConfigurationOperationStatus.Failed ||
        Applied.Response.MonitoringDeployment.AreaResults.Any(area => area.Status == AgentConfigurationOperationStatus.Failed)
            ? "Some audit settings could not be applied." :
        Applied.Response.MonitoringDeployment.AreaResults.All(area => area.Status == AgentConfigurationOperationStatus.Skipped)
            ? "No requested audit settings were applied. Review the skipped actions." : "Applied with warnings. Some requested settings need attention.";
    public string Details => "Backup: " + BackupFolder + Environment.NewLine +
        string.Join(Environment.NewLine, new[] { Saved.Diagnostic, Applied?.Diagnostic, Applied?.Response?.MonitoringDeployment?.LastError }
            .Concat(Applied?.Response?.MonitoringDeployment?.Warnings ?? [])
            .Concat(RequiredAreas.Where(area => !IsConfirmed(area)).Select(area => $"Apply was not confirmed for {area}."))
            .Concat(Applied?.Response?.MonitoringDeployment?.AreaResults?.Select(area =>
                $"{area.Area}: {area.Status} — {area.Message} {area.TechnicalDetail}") ?? [])
            .Where(text => !string.IsNullOrWhiteSpace(text)));
}
