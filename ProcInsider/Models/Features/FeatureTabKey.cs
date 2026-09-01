namespace ProcInsider.Models.Features;

/// <summary>
/// Identifies a viewer tab without relying on its collection position.
/// </summary>
public readonly record struct FeatureTabKey
{
    public FeatureTabKey(FeatureTabSurface surface, string tabId)
    {
        if (string.IsNullOrWhiteSpace(tabId))
        {
            throw new ArgumentException("Feature tab IDs cannot be empty.", nameof(tabId));
        }

        Surface = surface;
        TabId = tabId.Trim();
    }

    public FeatureTabSurface Surface { get; }

    public string TabId { get; }

    public override string ToString() => $"{Surface.ToString().ToLowerInvariant()}:{TabId}";
}

public enum FeatureTabSurface
{
    Explorer,
    Data,
    AppInfo
}

/// <summary>
/// Stable Explorer tab keys. Search and Sigma deliberately remain distinct even
/// though they share one release feature.
/// </summary>
public static class ExplorerTabKeys
{
    public static readonly FeatureTabKey Explore = new(FeatureTabSurface.Explorer, "explore");
    public static readonly FeatureTabKey Agents = new(FeatureTabSurface.Explorer, "agents");
    public static readonly FeatureTabKey Search = new(FeatureTabSurface.Explorer, "search");
    public static readonly FeatureTabKey Sigma = new(FeatureTabSurface.Explorer, "sigma");
    public static readonly FeatureTabKey Ai = new(FeatureTabSurface.Explorer, "ai");
    public static readonly FeatureTabKey Network = new(FeatureTabSurface.Explorer, "network");
    public static readonly FeatureTabKey Memory = new(FeatureTabSurface.Explorer, "memory");
    public static readonly FeatureTabKey Infrastructure = new(FeatureTabSurface.Explorer, "infrastructure");
}

/// <summary>
/// Stable Data tab keys. Tabs sharing a release feature intentionally retain
/// distinct keys so navigation never depends on collection position.
/// </summary>
public static class DataTabKeys
{
    public static readonly FeatureTabKey Properties = new(FeatureTabSurface.Data, "properties");
    public static readonly FeatureTabKey ProcessStatistics = new(FeatureTabSurface.Data, "process-statistics");
    public static readonly FeatureTabKey AppInfo = new(FeatureTabSurface.Data, "app-info");
    public static readonly FeatureTabKey Notes = new(FeatureTabSurface.Data, "notes");
    public static readonly FeatureTabKey Modules = new(FeatureTabSurface.Data, "modules");
    public static readonly FeatureTabKey Handles = new(FeatureTabSurface.Data, "handles");
    public static readonly FeatureTabKey MemoryDumps = new(FeatureTabSurface.Data, "memory-dumps");
    public static readonly FeatureTabKey PeAnalysis = new(FeatureTabSurface.Data, "pe-analysis");
    public static readonly FeatureTabKey SystemMemory = new(FeatureTabSurface.Data, "system-memory");
    public static readonly FeatureTabKey Network = new(FeatureTabSurface.Data, "network");
    public static readonly FeatureTabKey Filesystem = new(FeatureTabSurface.Data, "filesystem");
    public static readonly FeatureTabKey SystemActivity = new(FeatureTabSurface.Data, "system-activity");
    public static readonly FeatureTabKey RuntimeEvents = new(FeatureTabSurface.Data, "runtime-events");
    public static readonly FeatureTabKey EtwEvents = new(FeatureTabSurface.Data, "etw-events");
    public static readonly FeatureTabKey SecurityEvents = new(FeatureTabSurface.Data, "security-events");
    public static readonly FeatureTabKey PowerShellEvents = new(FeatureTabSurface.Data, "powershell-events");
    public static readonly FeatureTabKey WindowsOtherEvents = new(FeatureTabSurface.Data, "windows-other-events");
    public static readonly FeatureTabKey SysmonEvents = new(FeatureTabSurface.Data, "sysmon-events");
    public static readonly FeatureTabKey Ai = new(FeatureTabSurface.Data, "ai");
    public static readonly FeatureTabKey Baseline = new(FeatureTabSurface.Data, "baseline");
    public static readonly FeatureTabKey InfrastructureCase = new(FeatureTabSurface.Data, "infrastructure-case");
}
