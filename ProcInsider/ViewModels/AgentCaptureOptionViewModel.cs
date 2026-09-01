using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public enum AgentCaptureOptionKind
{
    Unknown = 0,
    ProcessLiveEvents = 1,
    EtwEvents = 2,
    SecurityEvents = 3,
    PowerShellEvents = 4,
    WindowsOtherEvents = 5,
    SysmonEvents = 6,
    ModuleEnrichment = 7,
    HandleEnrichment = 8,
    NetworkCapture = 9,
    ZeekAnalysis = 10,
    ProcessMonitorCapture = 11,
    FilesystemArtifactImport = 12,
    MemoryImageImport = 13,
    VolatilityAnalysis = 14,
    PeAnalysis = 15,
}

public partial class AgentCaptureOptionViewModel : ViewModelBase
{
    public AgentCaptureOptionViewModel(
        AgentCaptureOptionKind kind,
        string displayName,
        string description,
        bool isSelected,
        bool canConfigure,
        bool canStart,
        bool canStop)
    {
        Kind = kind;
        DisplayName = displayName;
        Description = description;
        IsIncluded = isSelected;
        CanConfigure = canConfigure;
        CanStart = canStart;
        CanStop = canStop;
        StatusText = canConfigure
            ? isSelected ? "Enabled in draft configuration." : "Available."
            : "Available through a dedicated command or picker.";
    }

    public AgentCaptureOptionKind Kind { get; }

    public string DisplayName { get; }

    public string Description { get; }

    [ObservableProperty]
    private bool isPublished = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConfigurationDisplay))]
    private bool isIncluded;

    [ObservableProperty]
    private bool canConfigure;

    [ObservableProperty]
    private bool canStart;

    [ObservableProperty]
    private bool canStop;

    [ObservableProperty]
    private string statusText = "Available.";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CountDisplay))]
    private int capturedItemCount;

    public string CountDisplay => CapturedItemCount.ToString("N0");

    public string ConfigurationDisplay => CanConfigure
        ? IsIncluded ? "Enabled" : "Disabled"
        : "Dedicated";

    partial void OnCanConfigureChanged(bool value)
    {
        OnPropertyChanged(nameof(ConfigurationDisplay));
    }

    public AgentCaptureOptionViewModel Clone()
    {
        return new AgentCaptureOptionViewModel(
            Kind,
            DisplayName,
            Description,
            IsIncluded,
            CanConfigure,
            CanStart,
            CanStop)
        {
            StatusText = StatusText,
            CapturedItemCount = CapturedItemCount,
            IsPublished = IsPublished
        };
    }

    public static IReadOnlyList<AgentCaptureOptionViewModel> CreateDefaultOptions(IFeatureCatalog? catalog = null)
    {
        List<AgentCaptureOptionViewModel> options =
        [
            new(AgentCaptureOptionKind.ProcessLiveEvents, "Process/live events", "Runtime process snapshots and start/stop deltas.", true, true, true, true),
            new(AgentCaptureOptionKind.EtwEvents, "ETW events", "Events from the selected bundled ETW capture profile.", false, true, true, true),
            new(AgentCaptureOptionKind.SecurityEvents, "Security events", "Windows Security event-log records correlated to processes.", true, true, true, true),
            new(AgentCaptureOptionKind.PowerShellEvents, "PowerShell events", "PowerShell operational logs and transcript-derived events.", true, true, true, true),
            new(AgentCaptureOptionKind.WindowsOtherEvents, "Windows events", "Supported non-Security Windows operational logs.", true, true, true, true),
            new(AgentCaptureOptionKind.SysmonEvents, "Sysmon events", "Sysmon operational events when Sysmon is installed and readable.", true, true, true, true),
            new(AgentCaptureOptionKind.ModuleEnrichment, "Module enrichment", "Agent module inventory sweep for staged processes.", true, true, true, false),
            new(AgentCaptureOptionKind.HandleEnrichment, "Handle enrichment", "Agent handle inventory sweep for staged processes.", true, true, true, false),
            new(AgentCaptureOptionKind.PeAnalysis, "PE analysis", "Safe deferred background PE metadata analysis; printable strings are extracted immediately only by the explicit selected-process action.", true, true, true, false),
            new(AgentCaptureOptionKind.NetworkCapture, "Network capture", "Packet Monitor metadata capture with PCAPNG finalization on stop.", false, true, true, true),
            new(AgentCaptureOptionKind.ZeekAnalysis, "Zeek analysis", "Zeek import can run after network capture or from a selected PCAP segment.", false, true, false, false),
            new(AgentCaptureOptionKind.ProcessMonitorCapture, "Process Monitor", "Sysinternals Process Monitor capture/import path.", false, false, true, true),
            new(AgentCaptureOptionKind.FilesystemArtifactImport, "Filesystem imports", "NTFS and Prefetch imports require an analyst-selected file or folder.", false, false, false, false),
            new(AgentCaptureOptionKind.MemoryImageImport, "Memory image import", "Full-memory image import requires an analyst-selected image or acquisition handoff.", false, false, false, false),
            new(AgentCaptureOptionKind.VolatilityAnalysis, "Volatility analysis", "Volatility runs require a staged memory image.", false, false, false, false),
        ];

        ApplyFeaturePublication(options, catalog ?? CurrentEducationalReleaseProfile.RuntimeCatalog);
        return options;
    }

    public static void ApplyFeaturePublication(
        IEnumerable<AgentCaptureOptionViewModel> options,
        IFeatureCatalog catalog)
    {
        foreach (var option in options)
        {
            var featureId = GetFeatureId(option.Kind);
            option.IsPublished = featureId.HasValue && catalog.IsPublished(featureId.Value);
            if (!option.IsPublished)
            {
                option.CanStart = false;
                option.CanStop = false;
                option.StatusText = $"Unavailable in educational release '{catalog.ReleaseId}'.";
            }
        }
    }

    public static FeatureId? GetFeatureId(AgentCaptureOptionKind kind) => kind switch
    {
        AgentCaptureOptionKind.ProcessLiveEvents => FeatureIds.AgentsAndCapture,
        AgentCaptureOptionKind.ProcessMonitorCapture => FeatureIds.EventTelemetry,
        AgentCaptureOptionKind.EtwEvents or AgentCaptureOptionKind.SecurityEvents or
        AgentCaptureOptionKind.PowerShellEvents or AgentCaptureOptionKind.WindowsOtherEvents or
        AgentCaptureOptionKind.SysmonEvents => FeatureIds.EventTelemetry,
        AgentCaptureOptionKind.ModuleEnrichment or AgentCaptureOptionKind.HandleEnrichment =>
            FeatureIds.ModulesAndHandles,
        AgentCaptureOptionKind.PeAnalysis => FeatureIds.DumpsAndPeAnalysis,
        AgentCaptureOptionKind.NetworkCapture or AgentCaptureOptionKind.ZeekAnalysis => FeatureIds.NetworkAndZeek,
        AgentCaptureOptionKind.FilesystemArtifactImport => FeatureIds.FilesystemArtifacts,
        AgentCaptureOptionKind.MemoryImageImport or AgentCaptureOptionKind.VolatilityAnalysis =>
            FeatureIds.SystemMemoryAndVolatility,
        _ => null
    };

    public static IReadOnlyList<AgentCaptureOptionViewModel> CloneOptions(IEnumerable<AgentCaptureOptionViewModel> options)
    {
        return options.Select(option => option.Clone()).ToList();
    }

    public static bool IsSelected(
        IEnumerable<AgentCaptureOptionViewModel>? options,
        AgentCaptureOptionKind kind,
        bool fallback)
    {
        if (options == null)
        {
            return fallback;
        }

        var option = options.FirstOrDefault(candidate => candidate.Kind == kind);
        return option?.CanConfigure == true && option.IsPublished && option.IsIncluded;
    }

    public static void ApplyConfiguration(
        IEnumerable<AgentCaptureOptionViewModel> options,
        AgentCaptureConfiguration configuration)
    {
        foreach (var option in options)
        {
            if (!option.CanConfigure)
            {
                option.IsIncluded = false;
                continue;
            }

            option.IsIncluded = option.Kind switch
            {
                AgentCaptureOptionKind.ProcessLiveEvents => configuration.SourceToggles.Runtime &&
                                                            configuration.RuntimeProcessSnapshots.Enabled,
                AgentCaptureOptionKind.EtwEvents => configuration.SourceToggles.Etw,
                AgentCaptureOptionKind.SecurityEvents => configuration.SourceToggles.Security,
                AgentCaptureOptionKind.PowerShellEvents => configuration.SourceToggles.PowerShell,
                AgentCaptureOptionKind.WindowsOtherEvents => configuration.SourceToggles.WindowsOther,
                AgentCaptureOptionKind.SysmonEvents => configuration.SourceToggles.Sysmon,
                AgentCaptureOptionKind.ModuleEnrichment => configuration.ArtifactCapture.CaptureModules,
                AgentCaptureOptionKind.HandleEnrichment => configuration.ArtifactCapture.CaptureHandles,
                AgentCaptureOptionKind.PeAnalysis => configuration.ArtifactCapture.CapturePeMetadata,
                AgentCaptureOptionKind.NetworkCapture => configuration.NetworkCapture.Enabled,
                AgentCaptureOptionKind.ZeekAnalysis => configuration.Zeek.Enabled ||
                                                       configuration.Zeek.RunAfterNetworkCapture,
                _ => option.IsIncluded
            };
        }
    }

    public static void ApplyTelemetryStats(
        IEnumerable<AgentCaptureOptionViewModel> options,
        TelemetryStoreStats stats)
    {
        foreach (var option in options)
        {
            option.CapturedItemCount = option.Kind switch
            {
                AgentCaptureOptionKind.ProcessLiveEvents => stats.ProcessCount + stats.RuntimeEventCount,
                AgentCaptureOptionKind.EtwEvents => stats.EtwEventCount,
                AgentCaptureOptionKind.SecurityEvents => stats.SecurityEventCount,
                AgentCaptureOptionKind.PowerShellEvents => stats.PowerShellEventCount,
                AgentCaptureOptionKind.WindowsOtherEvents => stats.OtherWindowsEventCount,
                AgentCaptureOptionKind.SysmonEvents => stats.SysmonEventCount,
                AgentCaptureOptionKind.ModuleEnrichment => stats.ModuleObservationCount,
                AgentCaptureOptionKind.HandleEnrichment => stats.HandleObservationCount,
                AgentCaptureOptionKind.PeAnalysis => stats.PeAnalysisCount,
                AgentCaptureOptionKind.NetworkCapture => stats.NetworkCaptureCount,
                AgentCaptureOptionKind.ZeekAnalysis => stats.ZeekNetworkArtifactCount,
                AgentCaptureOptionKind.ProcessMonitorCapture => stats.ProcessMonitorEventCount,
                AgentCaptureOptionKind.FilesystemArtifactImport => stats.FilesystemArtifactCount,
                AgentCaptureOptionKind.MemoryImageImport => stats.MemoryImageCount + stats.MemoryDumpCount,
                AgentCaptureOptionKind.VolatilityAnalysis => stats.VolatilityPluginRunCount,
                _ => 0
            };
        }
    }
}
