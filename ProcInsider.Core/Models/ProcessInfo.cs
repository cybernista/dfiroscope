using System;
using System.Collections.Generic;

namespace ProcInsider.Models;

/// <summary>
/// Represents a snapshot of process information.
/// Uses PID + StartTime as a stable identity since Windows can reuse PIDs.
/// </summary>
public class ProcessInfo
{
    public string ProcessEntityId { get; set; } = string.Empty;
    // Stable identity: PID + StartTime combination
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public DateTime? StartTime { get; set; }

    // Process hierarchy
    public int ParentProcessId { get; set; }
    public string ParentProcessKey { get; set; } = string.Empty;
    public string ParentProcessEntityId { get; set; } = string.Empty;
    public string ParentProcessName { get; set; } = "<unknown>";

    // Basic info
    public string ProcessName { get; set; } = "<unknown>";
    public string ProcessGuid { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = "<not available>";
    public string CommandLine { get; set; } = "<not available>";
    public string UserName { get; set; } = "<not available>";
    public int SessionId { get; set; }
    public string Architecture { get; set; } = "<not available>";

    // Status tracking
    public DateTime? EndTime { get; set; }
    public ProcessStatus Status { get; set; } = ProcessStatus.Running;

    // Process-level artifact capture summaries.
    public ArtifactCaptureStatus ModuleCaptureStatus { get; set; } = ArtifactCaptureStatus.Pending;
    public int ModuleCount { get; set; }
    public DateTime? ModuleLastCaptured { get; set; }
    public string ModuleCaptureError { get; set; } = string.Empty;
    public ArtifactCaptureStatus HandleCaptureStatus { get; set; } = ArtifactCaptureStatus.Pending;
    public int HandleCount { get; set; }
    public DateTime? HandleLastCaptured { get; set; }
    public string HandleCaptureError { get; set; } = string.Empty;

    // Performance metrics
    public double CpuUsage { get; set; }
    public long MemoryUsageBytes { get; set; }
    public TimeSpan? TotalProcessorTime { get; set; }
    public TimeSpan? UserProcessorTime { get; set; }
    public TimeSpan? PrivilegedProcessorTime { get; set; }
    public long? ReadBytes { get; set; }
    public long? WrittenBytes { get; set; }
    public string StatisticsCollectionError { get; set; } = string.Empty;

    // File metadata
    public string CompanyName { get; set; } = "<not available>";
    public string FileDescription { get; set; } = "<not available>";
    public string Sha256Hash { get; set; } = "<not available>";

    // Evidence identity from staged records. These are empty for live-only compatibility rows.
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;

    // Cached inspector snapshots captured while the process was still available.
    public List<ModuleInfo> CachedModules { get; set; } = new();
    public List<HandleInfo> CachedHandles { get; set; } = new();

    // Tree display
    public int TreeDepth { get; set; }

    /// <summary>
    /// Creates a unique key for this process instance.
    /// PID alone is not unique since Windows reuses PIDs.
    /// </summary>
    public string GetUniqueKey()
    {
        if (!string.IsNullOrWhiteSpace(ProcessKey))
        {
            return ProcessKey;
        }

        var startTimeTicks = StartTime?.Ticks ?? 0;
        return $"{ProcessId}_{startTimeTicks}";
    }

    /// <summary>
    /// Formats memory usage for display.
    /// </summary>
    public string MemoryUsageFormatted
    {
        get
        {
            if (MemoryUsageBytes < 1024)
                return $"{MemoryUsageBytes} B";
            if (MemoryUsageBytes < 1024 * 1024)
                return $"{MemoryUsageBytes / 1024.0:F1} KB";
            if (MemoryUsageBytes < 1024 * 1024 * 1024)
                return $"{MemoryUsageBytes / (1024.0 * 1024.0):F1} MB";
            return $"{MemoryUsageBytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }

    /// <summary>
    /// Formats CPU usage for display.
    /// </summary>
    public string CpuUsageFormatted => CpuUsage >= 0 ? $"{CpuUsage:F1}%" : "<not available>";
}

/// <summary>
/// Process status enum.
/// </summary>
public enum ProcessStatus
{
    Running,
    Exited,
    NotFound
}
