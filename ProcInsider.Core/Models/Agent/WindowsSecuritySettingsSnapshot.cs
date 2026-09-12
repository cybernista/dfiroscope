namespace ProcInsider.Models.Agent;

public enum WindowsSecuritySettingsArea
{
    Unknown = 0, AuditPolicy = 1, CommandLine = 2, EventLogChannel = 3,
    EventLogRetention = 4, UserFolderAuditing = 5, RegistryAuditing = 6
}

/// <summary>Observed values, never a deployment journal. Null sections mean not captured/selected.</summary>
public sealed record WindowsSecuritySettingsSnapshot
{
    public int Version { get; init; } = 1;
    public string ComputerName { get; init; } = string.Empty;
    public DateTime CapturedAtUtc { get; init; }
    public AuditSubcategorySetting[]? AuditPolicy { get; init; }
    public CommandLineSetting? CommandLine { get; init; }
    public bool? EventLogEnabled { get; init; }
    public SecurityLogRetentionSetting? EventLogRetention { get; init; }
    public ObjectAuditingSettings? UserFolderAuditing { get; init; }
    public ObjectAuditingSettings? RegistryAuditing { get; init; }
    public string[] Gaps { get; init; } = [];

    [System.Text.Json.Serialization.JsonIgnore]
    public WindowsSecuritySettingsArea[] Areas => Enum.GetValues<WindowsSecuritySettingsArea>().Where(HasArea).ToArray();
    public bool HasArea(WindowsSecuritySettingsArea area) => area switch
    {
        WindowsSecuritySettingsArea.AuditPolicy => AuditPolicy != null,
        WindowsSecuritySettingsArea.CommandLine => CommandLine != null,
        WindowsSecuritySettingsArea.EventLogChannel => EventLogEnabled != null,
        WindowsSecuritySettingsArea.EventLogRetention => EventLogRetention != null,
        WindowsSecuritySettingsArea.UserFolderAuditing => UserFolderAuditing != null,
        WindowsSecuritySettingsArea.RegistryAuditing => RegistryAuditing != null,
        _ => false
    };

    public WindowsSecuritySettingsSnapshot Select(IEnumerable<WindowsSecuritySettingsArea> areas)
    {
        var selected = areas.ToHashSet();
        if (selected.Any(a => !HasArea(a))) throw new InvalidOperationException("A selected settings area was not captured.");
        return this with
        {
            AuditPolicy = selected.Contains(WindowsSecuritySettingsArea.AuditPolicy) ? AuditPolicy : null,
            CommandLine = selected.Contains(WindowsSecuritySettingsArea.CommandLine) ? CommandLine : null,
            EventLogEnabled = selected.Contains(WindowsSecuritySettingsArea.EventLogChannel) ? EventLogEnabled : null,
            EventLogRetention = selected.Contains(WindowsSecuritySettingsArea.EventLogRetention) ? EventLogRetention : null,
            UserFolderAuditing = selected.Contains(WindowsSecuritySettingsArea.UserFolderAuditing) ? UserFolderAuditing : null,
            RegistryAuditing = selected.Contains(WindowsSecuritySettingsArea.RegistryAuditing) ? RegistryAuditing : null
        };
    }

    public void Validate()
    {
        if (Version is not (1 or 2) || string.IsNullOrWhiteSpace(ComputerName) || ComputerName.Length > 128 ||
            CapturedAtUtc.Kind != DateTimeKind.Utc || CapturedAtUtc == default || Gaps == null || Gaps.Length > 128 ||
            Gaps.Any(g => g == null || g.Length > 2048))
            throw new InvalidOperationException("Unsupported or malformed Windows settings snapshot.");
        if (AuditPolicy != null && (AuditPolicy.Length is < 1 or > 256 ||
            AuditPolicy.Any(p => p == null || p.Subcategory == Guid.Empty || p.Flags is < 1 or > 4) ||
            AuditPolicy.Select(p => p.Subcategory).Distinct().Count() != AuditPolicy.Length))
            throw new InvalidOperationException("Invalid system audit policy values.");
        if (CommandLine is { } c && ((!c.Exists && c.Value != 0) || (c.Exists && c.Value is not (0 or 1))))
            throw new InvalidOperationException("Command-line auditing must be absent, disabled or enabled DWORD policy.");
        if (EventLogRetention is { } e && (e.MaximumSizeBytes < 65536 || e.MaximumSizeBytes > 64L * 1024 * 1024 * 1024 ||
            e.MaximumSizeBytes % 65536 != 0 || e.LogMode is not ("Circular" or "AutoBackup" or "Retain")))
            throw new InvalidOperationException("Invalid Security log retention values.");
        ValidateObjects(UserFolderAuditing);
        ValidateObjects(RegistryAuditing);
        if (Version == 1 && (UserFolderAuditing?.RootConfigurationOnly == true || RegistryAuditing?.RootConfigurationOnly == true) ||
            Version == 2 && (UserFolderAuditing is { RootConfigurationOnly: false } || RegistryAuditing is { RootConfigurationOnly: false }))
            throw new InvalidOperationException("Object audit mode does not match the settings snapshot version.");
    }

    public void ValidateIntent(AgentHostMonitoringConfiguration configuration)
    {
        Validate();
        var expected = ToConfiguration(configuration.AgentId, configuration.HostId);
        var actual = configuration.SecurityAuditPolicy;
        if (actual.ConfigureAuditPolicy != expected.SecurityAuditPolicy.ConfigureAuditPolicy ||
            actual.EnableProcessCommandLineLogging != expected.SecurityAuditPolicy.EnableProcessCommandLineLogging ||
            actual.AuditUserDataFolders != expected.SecurityAuditPolicy.AuditUserDataFolders ||
            actual.AuditRegistryWrites != expected.SecurityAuditPolicy.AuditRegistryWrites ||
            configuration.EventLogs.ConfigureChannels != expected.EventLogs.ConfigureChannels ||
            configuration.EventLogs.ConfigureRetention != expected.EventLogs.ConfigureRetention ||
            !string.IsNullOrEmpty(actual.PolicyProfileId) || !string.IsNullOrEmpty(actual.AuditPolicyPath) ||
            !string.IsNullOrEmpty(configuration.EventLogs.ProfileId))
            throw new InvalidOperationException("Snapshot area selection and deployment intent do not agree.");
    }

    private static void ValidateObjects(ObjectAuditingSettings? settings)
    {
        if (settings == null) return;
        if (settings.ScopeNotes == null || settings.ScopeNotes.Length > 128 || settings.ScopeNotes.Any(n => n == null || n.Length > 2048) ||
            settings.Entries == null || settings.Entries.Length > 8192 ||
            settings.Entries.Any(e => e == null || string.IsNullOrWhiteSpace(e.Path) || e.Path.Length > 1024 ||
                string.IsNullOrWhiteSpace(e.Identity) || e.Identity.Length > 2048 || e.Sacl == null || e.Sacl.Length > 65536) ||
            settings.Entries.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != settings.Entries.Length)
            throw new InvalidOperationException("Invalid bounded object-auditing snapshot.");
    }

    public AgentHostMonitoringConfiguration ToConfiguration(string agentId, string hostId) =>
        AgentHostMonitoringConfigurationAreas.CreateWindowsSecurityScopedDraft(new()
        {
            AgentId = agentId, HostId = hostId, ConfigurationVersion = "monitoring-snapshot-v1", SettingsSnapshot = this,
            SecurityAuditPolicy = new()
            {
                ConfigureAuditPolicy = AuditPolicy != null || UserFolderAuditing != null || RegistryAuditing != null,
                EnableProcessCommandLineLogging = CommandLine != null,
                AuditUserDataFolders = UserFolderAuditing != null, AuditRegistryWrites = RegistryAuditing != null
            },
            EventLogs = new() { ConfigureChannels = EventLogEnabled != null, ConfigureRetention = EventLogRetention != null }
        });
}

public sealed record AuditSubcategorySetting(Guid Subcategory, uint Flags);
public sealed record CommandLineSetting(bool Exists, int Value);
public sealed record SecurityLogRetentionSetting(long MaximumSizeBytes, string LogMode);
public sealed record ObjectAuditingSettings(ObjectAuditingSetting[] Entries)
{
    public bool RootConfigurationOnly { get; init; }
    public string[] ScopeNotes { get; init; } = [];
}
public sealed record ObjectAuditingSetting(string Path, string Identity, string Sacl);
