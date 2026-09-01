using System;
using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class ProcessStatisticsRowViewModel : ViewModelBase
{
    private readonly ProcessStatisticsRecord _record;

    public ProcessStatisticsRowViewModel(ProcessStatisticsRecord record)
    {
        _record = record;
    }

    public ProcessStatisticsRecord Record => _record;
    public string SampleId => _record.SampleId;
    public string ProcessKey => _record.ProcessKey;
    public string ProcessEntityId => _record.ProcessEntityId;
    public int ProcessId => _record.ProcessId;
    public string ProcessGuid => _record.ProcessGuid;
    public string ProcessName => _record.ProcessName;
    public string ProcessDisplay => $"{ProcessName} ({ProcessId})";
    public string Status => _record.Status.ToString();
    public ProcessStatus StatusValue => _record.Status;
    public DateTime ObservedUtc => _record.ObservedUtc;
    public string ObservedDisplay => ObservedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public long? TotalProcessorTimeTicks => _record.TotalProcessorTimeTicks;
    public long? UserProcessorTimeTicks => _record.UserProcessorTimeTicks;
    public long? PrivilegedProcessorTimeTicks => _record.PrivilegedProcessorTimeTicks;
    public TimeSpan? TotalProcessorTime => _record.TotalProcessorTime;
    public long? ReadBytes => _record.ReadBytes;
    public long? WrittenBytes => _record.WrittenBytes;
    public string CpuTimeDisplay => FormatDuration(_record.TotalProcessorTime);
    public string UserCpuTimeDisplay => FormatDuration(_record.UserProcessorTime);
    public string PrivilegedCpuTimeDisplay => FormatDuration(_record.PrivilegedProcessorTime);
    public string ReadBytesDisplay => FormatBytes(_record.ReadBytes);
    public string WrittenBytesDisplay => FormatBytes(_record.WrittenBytes);
    public string CollectionState => _record.HasAnyCounter ? "Available" : "Unavailable";
    public string CollectionError => string.IsNullOrWhiteSpace(_record.CollectionError)
        ? string.Empty
        : _record.CollectionError;
    public string Source => _record.Source;
    public string CaseId => _record.CaseId;
    public string EvidenceSessionId => _record.EvidenceSessionId;
    public string CaptureId => _record.CaptureId;
    public string SourceIdentityId => _record.SourceIdentityId;
    public string HostId => _record.HostId;
    public string ExecutionRootId => _record.ExecutionRootId;

    public bool MatchesScope(ExplorerScope scope)
    {
        if (!MatchesIdentityValue(CaseId, scope.CaseId) ||
            !MatchesIdentityValue(EvidenceSessionId, scope.EvidenceSessionId) ||
            !MatchesIdentityValue(CaptureId, scope.CaptureId) ||
            !MatchesIdentityValue(SourceIdentityId, scope.SourceIdentityId) ||
            !MatchesIdentityValue(HostId, scope.HostId) ||
            !MatchesIdentityValue(ExecutionRootId, scope.ExecutionRootId))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(scope.ProcessKey) &&
            !string.Equals(ProcessKey, scope.ProcessKey, StringComparison.Ordinal))
        {
            return false;
        }

        return !scope.Status.HasValue || StatusValue == scope.Status.Value;
    }

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.ProcessStatistics,
            TargetKind = "ProcessStatistics",
            TargetTable = "ProcessStatistics",
            TargetId = SampleId,
            ArtifactId = SampleId,
            CaseId = CaseId,
            EvidenceSessionId = EvidenceSessionId,
            CaptureId = CaptureId,
            SourceIdentityId = SourceIdentityId,
            HostId = HostId,
            ExecutionRootId = ExecutionRootId,
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            ProcessName = ProcessName,
            Header = $"Process statistics | {ProcessDisplay}",
            Subtitle = $"Last sample {ObservedDisplay}",
            EmptyStateMessage = "Select a process statistic row to inspect it here.",
            RawText = BuildRawText(),
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Sample ID", SampleId),
                new("Identity", "Process Key", ProcessKey),
                new("Identity", "Process Entity", ProcessEntityId),
                new("Provenance", "Source Run", _record.SourceRunId),
                new("Provenance", "Ingestion Job", _record.IngestionJobId),
                new("Identity", "Process", ProcessDisplay),
                new("Identity", "Process GUID", EmptyDisplay(ProcessGuid)),
                new("Identity", "Status", Status),
                new("Time", "Observed", ObservedDisplay),
                new("CPU", "Total", CpuTimeDisplay),
                new("CPU", "User", UserCpuTimeDisplay),
                new("CPU", "Kernel", PrivilegedCpuTimeDisplay),
                new("I/O", "Bytes Read", ReadBytesDisplay),
                new("I/O", "Bytes Written", WrittenBytesDisplay),
                new("Collection", "State", CollectionState),
                new("Collection", "Error", EmptyDisplay(CollectionError)),
                new("Evidence", "Source", EmptyDisplay(Source)),
                new("Evidence", "Case", EmptyDisplay(CaseId)),
                new("Evidence", "Session", EmptyDisplay(EvidenceSessionId)),
                new("Evidence", "Capture", EmptyDisplay(CaptureId)),
                new("Evidence", "Host", EmptyDisplay(HostId))
            }
        };
    }

    public static string FormatDuration(TimeSpan? value)
    {
        if (!value.HasValue)
        {
            return "<not available>";
        }

        var duration = value.Value;
        if (duration.TotalDays >= 1)
        {
            return $"{(int)duration.TotalDays}d {duration.Hours}h {duration.Minutes}m";
        }

        if (duration.TotalHours >= 1)
        {
            return $"{(int)duration.TotalHours}h {duration.Minutes}m {duration.Seconds}s";
        }

        if (duration.TotalMinutes >= 1)
        {
            return $"{(int)duration.TotalMinutes}m {duration.Seconds}s";
        }

        return $"{Math.Max(0, duration.TotalSeconds):F1}s";
    }

    public static string FormatBytes(long? bytes)
    {
        if (!bytes.HasValue)
        {
            return "<not available>";
        }

        return FormatBytes(bytes.Value);
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "0 B";
        }

        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0 ? $"{bytes} B" : $"{value:F1} {units[unit]}";
    }

    private string BuildRawText()
    {
        return string.Join(Environment.NewLine, new[]
        {
            $"SampleId: {SampleId}",
            $"ProcessKey: {ProcessKey}",
            $"Process: {ProcessDisplay}",
            $"Status: {Status}",
            $"Observed: {ObservedDisplay}",
            $"TotalProcessorTimeTicks: {TotalProcessorTimeTicks?.ToString() ?? "<null>"}",
            $"UserProcessorTimeTicks: {UserProcessorTimeTicks?.ToString() ?? "<null>"}",
            $"PrivilegedProcessorTimeTicks: {PrivilegedProcessorTimeTicks?.ToString() ?? "<null>"}",
            $"ReadBytes: {ReadBytes?.ToString() ?? "<null>"}",
            $"WrittenBytes: {WrittenBytes?.ToString() ?? "<null>"}",
            $"CollectionError: {CollectionError}",
            $"Source: {Source}"
        });
    }

    private static bool MatchesIdentityValue(string actual, string? expected)
    {
        return string.IsNullOrWhiteSpace(expected) ||
               string.Equals(actual, expected, StringComparison.Ordinal);
    }

    private static string EmptyDisplay(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "<none>" : value;
    }
}
