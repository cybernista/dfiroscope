using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.ViewModels;

public partial class HostMonitoringConfigurationViewModel : ViewModelBase
{
    public HostMonitoringConfigurationViewModel(
        IEnumerable<ConfigProfileDefinition> etwProfiles,
        IEnumerable<ConfigProfileDefinition> sysmonProfiles,
        IEnumerable<ConfigProfileDefinition> securityMonitoringProfiles,
        IEnumerable<ConfigProfileDefinition> powerShellAuditingProfiles,
        IEnumerable<ConfigProfileDefinition> eventLogProfiles)
    {
        AddProfiles(EtwProfiles, etwProfiles);
        AddProfiles(SysmonProfiles, sysmonProfiles);
        AddProfiles(SecurityMonitoringProfiles, securityMonitoringProfiles);
        AddProfiles(PowerShellAuditingProfiles, powerShellAuditingProfiles);
        AddProfiles(EventLogProfiles, eventLogProfiles);
    }

    public ObservableCollection<ConfigProfileDefinition> EtwProfiles { get; } = new();

    public ObservableCollection<ConfigProfileDefinition> SysmonProfiles { get; } = new();

    public ObservableCollection<ConfigProfileDefinition> SecurityMonitoringProfiles { get; } = new();

    public ObservableCollection<ConfigProfileDefinition> PowerShellAuditingProfiles { get; } = new();

    public ObservableCollection<ConfigProfileDefinition> EventLogProfiles { get; } = new();

    public bool HasEtwProfiles => EtwProfiles.Count > 0;

    public bool HasSysmonProfiles => SysmonProfiles.Count > 0;

    public bool HasSecurityMonitoringProfiles => SecurityMonitoringProfiles.Count > 0;

    public bool HasPowerShellAuditingProfiles => PowerShellAuditingProfiles.Count > 0;

    public bool HasEventLogProfiles => EventLogProfiles.Count > 0;

    [ObservableProperty]
    private ConfigProfileDefinition? selectedEtwProfile;

    [ObservableProperty]
    private ConfigProfileDefinition? selectedSysmonProfile;

    [ObservableProperty]
    private ConfigProfileDefinition? selectedSecurityMonitoringProfile;

    [ObservableProperty]
    private ConfigProfileDefinition? selectedPowerShellAuditingProfile;

    [ObservableProperty]
    private ConfigProfileDefinition? selectedEventLogProfile;

    [ObservableProperty]
    private bool installOrUpdateSysmon;

    [ObservableProperty]
    private bool verifySysmonService;

    [ObservableProperty]
    private bool configureAuditPolicy;

    [ObservableProperty]
    private bool enableProcessCommandLineLogging;

    [ObservableProperty]
    private bool configureEventLogChannels;

    [ObservableProperty]
    private bool configureEventLogRetention;

    [ObservableProperty]
    private bool enablePowerShellScriptBlockLogging;

    [ObservableProperty]
    private bool enablePowerShellModuleLogging;

    [ObservableProperty]
    private bool enablePowerShellTranscription;

    [ObservableProperty]
    private string transcriptDirectory = string.Empty;

    [ObservableProperty]
    private bool configureEtwSession;

    /// <summary>
    /// Gets whether this draft requests the agent's monitoring deployment path. Profile selection
    /// alone is intentionally not a deployment request.
    /// </summary>
    public bool HasRequestedDeployment =>
        InstallOrUpdateSysmon ||
        VerifySysmonService ||
        ConfigureAuditPolicy ||
        EnableProcessCommandLineLogging ||
        ConfigureEventLogChannels ||
        ConfigureEventLogRetention ||
        EnablePowerShellScriptBlockLogging ||
        EnablePowerShellModuleLogging ||
        EnablePowerShellTranscription ||
        ConfigureEtwSession;

    /// <summary>
    /// Loads a saved monitoring configuration into an existing draft. New drafts deliberately use
    /// the all-unchecked property defaults above; this method preserves stored host intent.
    /// </summary>
    public void ApplyExistingConfiguration(
        AgentHostMonitoringConfiguration configuration,
        ConfigProfileDefinition? fallbackEtwProfile = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        SelectedSysmonProfile = SelectProfile(SysmonProfiles, configuration.Sysmon.ProfileId);
        SelectedSecurityMonitoringProfile = SelectProfile(
            SecurityMonitoringProfiles,
            configuration.SecurityAuditPolicy.PolicyProfileId);
        SelectedPowerShellAuditingProfile = SelectProfile(
            PowerShellAuditingProfiles,
            configuration.PowerShellAuditing.ProfileId);
        SelectedEventLogProfile = SelectProfile(EventLogProfiles, configuration.EventLogs.ProfileId);
        SelectedEtwProfile = SelectProfile(
            EtwProfiles,
            configuration.Etw.ProfileId ?? fallbackEtwProfile?.Id);
        InstallOrUpdateSysmon = configuration.Sysmon.InstallOrUpdate;
        VerifySysmonService = configuration.Sysmon.VerifyService;
        ConfigureAuditPolicy = configuration.SecurityAuditPolicy.ConfigureAuditPolicy;
        EnableProcessCommandLineLogging = configuration.SecurityAuditPolicy.EnableProcessCommandLineLogging;
        ConfigureEventLogChannels = configuration.EventLogs.ConfigureChannels;
        ConfigureEventLogRetention = configuration.EventLogs.ConfigureRetention;
        EnablePowerShellScriptBlockLogging = configuration.PowerShellAuditing.EnableScriptBlockLogging;
        EnablePowerShellModuleLogging = configuration.PowerShellAuditing.EnableModuleLogging;
        EnablePowerShellTranscription = configuration.PowerShellAuditing.EnableTranscription;
        TranscriptDirectory = configuration.PowerShellAuditing.TranscriptDirectory;
        ConfigureEtwSession = configuration.Etw.ConfigureSession;
    }

    public static ConfigProfileDefinition? SelectProfile(
        IEnumerable<ConfigProfileDefinition> profiles,
        string? profileId)
    {
        ConfigProfileDefinition? fallback = null;
        foreach (var profile in profiles)
        {
            if (!string.IsNullOrWhiteSpace(profileId) &&
                string.Equals(profile.Id, profileId, System.StringComparison.OrdinalIgnoreCase))
            {
                return profile;
            }

            if (fallback == null || profile.IsDefault)
            {
                fallback = profile;
            }
        }

        return fallback;
    }

    private static void AddProfiles(
        ObservableCollection<ConfigProfileDefinition> target,
        IEnumerable<ConfigProfileDefinition> profiles)
    {
        foreach (var profile in profiles)
        {
            target.Add(profile);
        }
    }
}
