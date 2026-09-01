using System;
using System.Collections.Generic;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model for a single process row in the DataGrid.
/// Wraps ProcessInfo and provides display-friendly properties.
/// </summary>
public partial class ProcessRowViewModel : ViewModelBase
{
    private readonly ProcessInfo _processInfo;
    private ProcessStatisticsRecord? _statistics;
    private ProcessRiskProjectionSummaryRecord _riskProjection =
        ProcessRiskProjectionSummaryRecord.Unavailable(
            ProcessRiskProjectionReadState.NotReady,
            "The process-risk projection has not been loaded for this row.");

    [ObservableProperty]
    private int moduleCount;

    [ObservableProperty]
    private int handleCount;

    [ObservableProperty]
    private int runtimeEventCount;

    [ObservableProperty]
    private int etwEventCount;

    [ObservableProperty]
    private int securityEventCount;

    [ObservableProperty]
    private int powerShellEventCount;

    [ObservableProperty]
    private int otherWindowsEventCount;

    [ObservableProperty]
    private int sysmonEventCount;

    public ProcessRowViewModel(ProcessInfo processInfo)
    {
        _processInfo = processInfo;
        ModuleCount = Math.Max(processInfo.ModuleCount, processInfo.CachedModules.Count);
        HandleCount = Math.Max(processInfo.HandleCount, processInfo.CachedHandles.Count);
    }

    /// <summary>
    /// Gets the underlying process info.
    /// </summary>
    public ProcessInfo ProcessInfo => _processInfo;
    public bool IsLoadingPlaceholder => false;

    /// <summary>
    /// Gets the unique key for this process instance.
    /// </summary>
    public string UniqueKey => _processInfo.GetUniqueKey();
    public string ProcessKey => _processInfo.GetUniqueKey();

    // Display properties with tree indentation for ProcessName

    /// <summary>
    /// Process name with indentation for tree display.
    /// </summary>
    public string ProcessNameDisplay
    {
        get
        {
            var indent = new string(' ', _processInfo.TreeDepth * 4);
            var prefix = _processInfo.TreeDepth > 0 ? "└─ " : "";
            prefix = _processInfo.TreeDepth > 0 ? "|-- " : "";
            return $"{indent}{prefix}{_processInfo.ProcessName}";
        }
    }

    /// <summary>
    /// Process name without indentation (for sorting/filtering).
    /// </summary>
    public string ProcessName => _processInfo.ProcessName;

    public int ProcessId => _processInfo.ProcessId;
    public int ParentProcessId => _processInfo.ParentProcessId;
    public string ParentProcessName => _processInfo.ParentProcessName;
    public string ProcessPath => _processInfo.ProcessPath;
    public string CommandLine => _processInfo.CommandLine;
    public string UserName => _processInfo.UserName;
    public int SessionId => _processInfo.SessionId;
    public string Architecture => _processInfo.Architecture;

    public string StartTimeDisplay => _processInfo.StartTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "<not available>";
    public string EndTimeDisplay => _processInfo.EndTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "";

    public string StatusDisplay => _processInfo.Status.ToString();
    public bool IsExited => _processInfo.Status == ProcessStatus.Exited;

    public ProcessRiskProjectionReadState RiskReadState => _riskProjection.ReadState;

    public int? RiskScore => _riskProjection.Score;

    public string RiskDisplay => _riskProjection.ReadState switch
    {
        ProcessRiskProjectionReadState.Available when _riskProjection.Score.HasValue =>
            $"{_riskProjection.Score.Value.ToString(CultureInfo.InvariantCulture)} {_riskProjection.Band}",
        ProcessRiskProjectionReadState.Available => "Unknown",
        ProcessRiskProjectionReadState.Unsupported => "Unsupported",
        ProcessRiskProjectionReadState.Stale => "Stale",
        ProcessRiskProjectionReadState.Failed => "Failed",
        ProcessRiskProjectionReadState.AmbiguousLegacyKey => "Ambiguous",
        _ => "Not ready"
    };

    public string RiskTooltip
    {
        get
        {
            if (_riskProjection.ReadState != ProcessRiskProjectionReadState.Available)
            {
                return string.IsNullOrWhiteSpace(_riskProjection.Diagnostic)
                    ? RiskDisplay
                    : $"{RiskDisplay}: {_riskProjection.Diagnostic}";
            }

            var score = _riskProjection.Score.HasValue
                ? _riskProjection.Score.Value.ToString(CultureInfo.InvariantCulture)
                : "not projected";
            return $"Process Risk Score: {score}; band {_riskProjection.Band}; " +
                   $"confidence {_riskProjection.Confidence:P0}; coverage {_riskProjection.Coverage:P0}. " +
                   $"{_riskProjection.Diagnostic}".Trim();
        }
    }

    public string ModuleCaptureStatusDisplay => _processInfo.ModuleCaptureStatus.ToString();
    public string ModuleLastCapturedDisplay => _processInfo.ModuleLastCaptured?.ToString("yyyy-MM-dd HH:mm:ss") ?? "";
    public string ModuleCaptureError => _processInfo.ModuleCaptureError;
    public string ModuleSummaryDisplay => FormatArtifactSummary(ModuleCount, _processInfo.ModuleCaptureStatus);
    public string ModuleSummaryTooltip => FormatArtifactTooltip(
        "Modules",
        ModuleCount,
        _processInfo.ModuleCaptureStatus,
        _processInfo.ModuleLastCaptured,
        _processInfo.ModuleCaptureError);

    public string HandleCaptureStatusDisplay => _processInfo.HandleCaptureStatus.ToString();
    public string HandleLastCapturedDisplay => _processInfo.HandleLastCaptured?.ToString("yyyy-MM-dd HH:mm:ss") ?? "";
    public string HandleCaptureError => _processInfo.HandleCaptureError;
    public string HandleSummaryDisplay => FormatArtifactSummary(HandleCount, _processInfo.HandleCaptureStatus);
    public string HandleSummaryTooltip => FormatArtifactTooltip(
        "Handles",
        HandleCount,
        _processInfo.HandleCaptureStatus,
        _processInfo.HandleLastCaptured,
        _processInfo.HandleCaptureError);

    public string CpuUsage => _processInfo.CpuUsageFormatted;
    public string MemoryUsage => _processInfo.MemoryUsageFormatted;
    public long? TotalProcessorTimeTicks => _statistics?.TotalProcessorTimeTicks;
    public long? ReadBytes => _statistics?.ReadBytes;
    public long? WrittenBytes => _statistics?.WrittenBytes;
    public string CpuTime => ProcessStatisticsRowViewModel.FormatDuration(_statistics?.TotalProcessorTime);
    public string BytesRead => ProcessStatisticsRowViewModel.FormatBytes(ReadBytes);
    public string BytesWritten => ProcessStatisticsRowViewModel.FormatBytes(WrittenBytes);

    public string CompanyName => _processInfo.CompanyName;
    public string FileDescription => _processInfo.FileDescription;
    public string Sha256Hash => _processInfo.Sha256Hash;

    public int TreeDepth => _processInfo.TreeDepth;

    /// <summary>
    /// Updates this view model from a new ProcessInfo snapshot.
    /// </summary>
    public void UpdateFrom(ProcessInfo updated)
    {
        _processInfo.ProcessKey = updated.ProcessKey;
        _processInfo.MemoryUsageBytes = updated.MemoryUsageBytes;
        _processInfo.CpuUsage = updated.CpuUsage;
        _processInfo.Status = updated.Status;
        _processInfo.EndTime = updated.EndTime;
        _processInfo.ModuleCaptureStatus = updated.ModuleCaptureStatus;
        _processInfo.ModuleCount = updated.ModuleCount;
        _processInfo.ModuleLastCaptured = updated.ModuleLastCaptured;
        _processInfo.ModuleCaptureError = updated.ModuleCaptureError;
        _processInfo.HandleCaptureStatus = updated.HandleCaptureStatus;
        _processInfo.HandleCount = updated.HandleCount;
        _processInfo.HandleLastCaptured = updated.HandleLastCaptured;
        _processInfo.HandleCaptureError = updated.HandleCaptureError;
        _processInfo.TreeDepth = updated.TreeDepth;
        _processInfo.ParentProcessKey = updated.ParentProcessKey;
        _processInfo.ParentProcessName = updated.ParentProcessName;
        _processInfo.CaseId = updated.CaseId;
        _processInfo.EvidenceSessionId = updated.EvidenceSessionId;
        _processInfo.CaptureId = updated.CaptureId;
        _processInfo.SourceIdentityId = updated.SourceIdentityId;
        _processInfo.HostId = updated.HostId;
        _processInfo.ExecutionRootId = updated.ExecutionRootId;

        // Notify all properties changed
        OnPropertyChanged(string.Empty);
    }

    public void SetStatistics(ProcessStatisticsRecord? statistics)
    {
        _statistics = statistics;
        OnPropertyChanged(nameof(TotalProcessorTimeTicks));
        OnPropertyChanged(nameof(ReadBytes));
        OnPropertyChanged(nameof(WrittenBytes));
        OnPropertyChanged(nameof(CpuTime));
        OnPropertyChanged(nameof(BytesRead));
        OnPropertyChanged(nameof(BytesWritten));
    }

    public void SetRiskProjection(ProcessRiskProjectionSummaryRecord summary)
    {
        _riskProjection = summary ?? throw new ArgumentNullException(nameof(summary));
        OnPropertyChanged(nameof(RiskReadState));
        OnPropertyChanged(nameof(RiskScore));
        OnPropertyChanged(nameof(RiskDisplay));
        OnPropertyChanged(nameof(RiskTooltip));
    }

    public void RefreshDisplay()
    {
        OnPropertyChanged(string.Empty);
    }

    public InspectorPayload ToInspectorPayload()
    {
        var properties = new List<PropertyItemViewModel>
        {
            new("Identity", "Process", ProcessName),
            new("Identity", "PID", ProcessId.ToString()),
            new("Identity", "Process Key", ProcessKey),
            new("Parent", "Parent PID", ParentProcessId.ToString()),
            new("Parent", "Parent Process Key", string.IsNullOrWhiteSpace(_processInfo.ParentProcessKey) ? "<not available>" : _processInfo.ParentProcessKey),
            new("Parent", "Parent Name", ParentProcessName),
            new("Image", "Path", ProcessPath),
            new("Image", "Command Line", CommandLine),
            new("Image", "Company", CompanyName),
            new("Image", "Description", FileDescription),
            new("Image", "SHA256", Sha256Hash),
            new("Runtime", "User", UserName),
            new("Runtime", "Session", SessionId.ToString()),
            new("Runtime", "Architecture", Architecture),
            new("Runtime", "Start Time", StartTimeDisplay),
            new("Runtime", "End Time", EndTimeDisplay),
            new("Runtime", "Status", StatusDisplay),
            new("Artifacts", "Modules", ModuleSummaryDisplay),
            new("Artifacts", "Handles", HandleSummaryDisplay),
            new("Events", "Runtime", RuntimeEventCount.ToString()),
            new("Events", "ETW", EtwEventCount.ToString()),
            new("Events", "Security", SecurityEventCount.ToString()),
            new("Events", "PowerShell", PowerShellEventCount.ToString()),
            new("Events", "Windows Other", OtherWindowsEventCount.ToString()),
            new("Events", "Sysmon", SysmonEventCount.ToString())
        };

        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.Process,
            TargetKind = "Process",
            TargetTable = "Processes",
            TargetId = ProcessKey,
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            ProcessName = ProcessName,
            DisplayPath = ProcessPath,
            CaseId = _processInfo.CaseId,
            EvidenceSessionId = _processInfo.EvidenceSessionId,
            CaptureId = _processInfo.CaptureId,
            SourceIdentityId = _processInfo.SourceIdentityId,
            HostId = _processInfo.HostId,
            ExecutionRootId = _processInfo.ExecutionRootId,
            Header = $"{ProcessName} (PID {ProcessId})",
            Subtitle = string.IsNullOrWhiteSpace(ProcessPath) ? StatusDisplay : ProcessPath,
            EmptyStateMessage = "Select a process, module, handle, or event to inspect it here.",
            Properties = properties
        };
    }

    private static string FormatArtifactSummary(int count, ArtifactCaptureStatus status)
    {
        return status == ArtifactCaptureStatus.Captured
            ? count.ToString()
            : $"{count} ({status})";
    }

    private static string FormatArtifactTooltip(
        string label,
        int count,
        ArtifactCaptureStatus status,
        DateTime? lastCaptured,
        string error)
    {
        var captured = lastCaptured?.ToString("yyyy-MM-dd HH:mm:ss") ?? "<not captured>";
        var text = $"{label}: {count}\nStatus: {status}\nLast captured: {captured}";
        return string.IsNullOrWhiteSpace(error) ? text : $"{text}\nError: {error}";
    }
}
