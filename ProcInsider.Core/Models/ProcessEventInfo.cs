using System;

namespace ProcInsider.Models;

/// <summary>
/// Represents a normalized event associated with a specific process instance.
/// </summary>
public class ProcessEventInfo
{
    public long SequenceId { get; set; }
    public DateTime TimestampUtc { get; set; }
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public DateTime? ProcessStartTimeUtc { get; set; }
    public string ProcessName { get; set; } = "<unknown>";
    public int ParentProcessId { get; set; }
    public int? EventCode { get; set; }
    public ProcessEventCategory Category { get; set; }
    public ProcessEventAction Action { get; set; }
    public string Target { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string RiskFlags { get; set; } = string.Empty;
    public bool IsInteresting { get; set; }
    public int RepeatCount { get; set; } = 1;
    public long EstimatedSizeBytes { get; set; }
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;

    /// <summary>
    /// Returns a local display timestamp.
    /// </summary>
    public string GetDisplayTime()
    {
        return TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    }

    /// <summary>
    /// Increments the repeat count when similar events are merged.
    /// </summary>
    public void IncrementRepeatCount()
    {
        RepeatCount++;
    }
}
