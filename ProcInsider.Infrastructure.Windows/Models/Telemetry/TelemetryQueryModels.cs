using System;

namespace ProcInsider.Models;

public class ProcessCorrelationHint
{
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessGuid { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public DateTime? EventTimeUtc { get; set; }
}

public class TelemetryQueryOptions
{
    public bool IncludeExited { get; set; } = true;
    public int MaxCount { get; set; } = 10000;
}

public class TelemetryStoreStats
{
    public int ProcessCount { get; set; }
    public int ProcessObservationCount { get; set; }
    public int RunningProcessCount { get; set; }
    public int ExitedProcessCount { get; set; }
    public int EventCount { get; set; }
    public int RuntimeEventCount { get; set; }
    public int EtwEventCount { get; set; }
    public int SecurityEventCount { get; set; }
    public int PowerShellEventCount { get; set; }
    public int OtherWindowsEventCount { get; set; }
    public int SysmonEventCount { get; set; }
    public int ProcessMonitorEventCount { get; set; }
    public int ModuleObservationCount { get; set; }
    public int HandleObservationCount { get; set; }
    public int MemoryDumpCount { get; set; }
    public int MemoryImageCount { get; set; }
    public int VolatilityPluginRunCount { get; set; }
    public int PeAnalysisCount { get; set; }
    public int NetworkCaptureCount { get; set; }
    public int ZeekNetworkArtifactCount { get; set; }
    public int FilesystemArtifactCount { get; set; }
    public long EstimatedMemoryBytes { get; set; }
    public long TotalEventsCollected { get; set; }
    public long TotalModuleObservationsCollected { get; set; }
    public long TotalHandleObservationsCollected { get; set; }
    public string StatusMessage { get; set; } = "Telemetry staging is ready.";
}

public sealed class EvidenceRootSummary
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public int ProcessCount { get; set; }
    public int ProcessObservationCount { get; set; }
    public int EventCount { get; set; }
    public int ModuleCount { get; set; }
    public int HandleCount { get; set; }
    public int NetworkCaptureCount { get; set; }
    public int FilesystemArtifactCount { get; set; }
    public int SourceRunCount { get; set; }
    public int MissingSourceRunLinkCount { get; set; }
}

public class ProcessProjectionQuery
{
    public bool IncludeExited { get; set; } = true;
    public int MaxCount { get; set; } = 10000;
}

public class EventProjectionQuery
{
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public string? Source { get; set; }
    public int MaxCount { get; set; } = 10000;
}

public class ModuleProjectionQuery
{
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public bool IncludeUnloaded { get; set; } = true;
    public int MaxCount { get; set; } = 10000;
}

public class HandleProjectionQuery
{
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public bool IncludeClosed { get; set; } = true;
    public int MaxCount { get; set; } = 10000;
}

public class ProcessArtifactCounts
{
    public int ModuleCount { get; set; }
    public int HandleCount { get; set; }
}

public class ProcessSourceEventCounts
{
    public int RuntimeEventCount { get; set; }
    public int EtwEventCount { get; set; }
    public int SecurityEventCount { get; set; }
    public int PowerShellEventCount { get; set; }
    public int OtherWindowsEventCount { get; set; }
    public int SysmonEventCount { get; set; }
}

public class TelemetrySearchQuery
{
    public string Text { get; set; } = string.Empty;
    public TelemetrySearchSyntax Syntax { get; set; } = TelemetrySearchSyntax.Keyword;
    public AdvancedSearchExpression? AdvancedExpression { get; set; }
    public TelemetrySearchScopeMode ScopeMode { get; set; } = TelemetrySearchScopeMode.RecordScoped;
    public bool IncludeProcesses { get; set; } = true;
    public bool IncludeEvents { get; set; } = true;
    public bool IncludeModules { get; set; } = true;
    public bool IncludeHandles { get; set; } = true;
    public bool IncludeCorrelationEvidence { get; set; }
    public int MaxResults { get; set; } = 1000;
}

public enum TelemetrySearchSyntax
{
    Keyword,
    Advanced
}

public enum TelemetrySearchScopeMode
{
    RecordScoped
}

public enum AdvancedSearchExpressionKind
{
    Term,
    Not,
    And,
    Or
}

public sealed class AdvancedSearchExpression
{
    public AdvancedSearchExpressionKind Kind { get; init; }
    public string Field { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public bool IsQuoted { get; init; }
    public IReadOnlyList<AdvancedSearchExpression> Children { get; init; } = Array.Empty<AdvancedSearchExpression>();

    public static AdvancedSearchExpression Term(string value, string field = "", bool isQuoted = false)
    {
        return new AdvancedSearchExpression
        {
            Kind = AdvancedSearchExpressionKind.Term,
            Field = field,
            Value = value,
            IsQuoted = isQuoted
        };
    }

    public static AdvancedSearchExpression Unary(
        AdvancedSearchExpressionKind kind,
        AdvancedSearchExpression child)
    {
        return new AdvancedSearchExpression
        {
            Kind = kind,
            Children = new[] { child }
        };
    }

    public static AdvancedSearchExpression Binary(
        AdvancedSearchExpressionKind kind,
        AdvancedSearchExpression left,
        AdvancedSearchExpression right)
    {
        return new AdvancedSearchExpression
        {
            Kind = kind,
            Children = new[] { left, right }
        };
    }
}

public sealed class AdvancedSearchParseResult
{
    public AdvancedSearchExpression? Expression { get; init; }
    public IReadOnlyList<AdvancedSearchDiagnostic> Diagnostics { get; init; } = Array.Empty<AdvancedSearchDiagnostic>();
    public bool IsValid => Expression != null && Diagnostics.Count == 0;
}

public sealed class AdvancedSearchDiagnostic
{
    public string Message { get; init; } = string.Empty;
    public int Position { get; init; }
}

public class TelemetrySearchResult
{
    public string Kind { get; set; } = string.Empty;
    public string RecordKey { get; set; } = string.Empty;
    public string ProcessEntityId { get; set; } = string.Empty;
    public DateTime? TimestampUtc { get; set; }
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "<unknown>";
    public string Title { get; set; } = string.Empty;
    public string Subtitle { get; set; } = string.Empty;
    public string MatchedField { get; set; } = string.Empty;
    public string MatchedValue { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string EvidenceKind { get; set; } = string.Empty;
    public EvidenceCorrelationState? CorrelationState { get; set; }
    public string CorrelationMethod { get; set; } = string.Empty;
    public int CorrelationCandidateCount { get; set; }
    public string CorrelationDiagnostics { get; set; } = string.Empty;
    public string ResolverVersion { get; set; } = string.Empty;
}
