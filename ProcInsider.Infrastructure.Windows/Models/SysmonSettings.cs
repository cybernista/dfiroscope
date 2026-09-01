namespace ProcInsider.Models;

/// <summary>
/// Represents the app integration state and detected machine status for Sysmon.
/// </summary>
public class SysmonSettings
{
    public bool IntegrationEnabled { get; set; }

    public bool IsServiceStateAvailable { get; set; }

    public string ServiceStatusDetail { get; set; } = string.Empty;

    public string ServiceError { get; set; } = string.Empty;

    public bool IsInstalled { get; set; }

    public bool IsRunning { get; set; }

    public bool IsChannelAvailable { get; set; }

    public bool IsChannelEnabled { get; set; }

    public bool IsWatcherAccessible { get; set; }

    public string ChannelStatusDetail { get; set; } = string.Empty;

    public string ChannelError { get; set; } = string.Empty;
}
