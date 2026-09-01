using System;

namespace ProcInsider.Models;

public sealed class ProcessStatisticsRecord : IHasProcessEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public string SampleId { get; set; } = string.Empty;
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public string ProcessName { get; set; } = "<unknown>";
    public ProcessStatus Status { get; set; } = ProcessStatus.Running;
    public DateTime ObservedUtc { get; set; }
    public long? TotalProcessorTimeTicks { get; set; }
    public long? UserProcessorTimeTicks { get; set; }
    public long? PrivilegedProcessorTimeTicks { get; set; }
    public long? ReadBytes { get; set; }
    public long? WrittenBytes { get; set; }
    public string CollectionError { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;

    public TimeSpan? TotalProcessorTime
    {
        get => TotalProcessorTimeTicks.HasValue ? TimeSpan.FromTicks(TotalProcessorTimeTicks.Value) : null;
        set => TotalProcessorTimeTicks = value?.Ticks;
    }

    public TimeSpan? UserProcessorTime
    {
        get => UserProcessorTimeTicks.HasValue ? TimeSpan.FromTicks(UserProcessorTimeTicks.Value) : null;
        set => UserProcessorTimeTicks = value?.Ticks;
    }

    public TimeSpan? PrivilegedProcessorTime
    {
        get => PrivilegedProcessorTimeTicks.HasValue ? TimeSpan.FromTicks(PrivilegedProcessorTimeTicks.Value) : null;
        set => PrivilegedProcessorTimeTicks = value?.Ticks;
    }

    public bool HasAnyCounter =>
        TotalProcessorTimeTicks.HasValue ||
        UserProcessorTimeTicks.HasValue ||
        PrivilegedProcessorTimeTicks.HasValue ||
        ReadBytes.HasValue ||
        WrittenBytes.HasValue;
}
