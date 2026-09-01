using System.Collections.Generic;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public sealed class SystemActivityRowViewModel : ViewModelBase
{
    private readonly SystemActivityRecord _activity;

    public SystemActivityRowViewModel(SystemActivityRecord activity)
    {
        _activity = activity;
    }

    public long SourceSequenceId => _activity.SourceSequenceId;
    public string TimestampDisplay => _activity.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string Activity => _activity.Activity;
    public string Result => _activity.Result.ToString();
    public string EventIdDisplay => _activity.EventId?.ToString() ?? string.Empty;
    public string SubjectAccount => _activity.SubjectAccount;
    public string TargetAccount => _activity.TargetAccount;
    public string MemberAccount => _activity.MemberAccount;
    public string TargetGroup => _activity.TargetGroup;
    public string SourceHost => _activity.SourceHost;
    public string SourceAddress => _activity.SourceAddress;
    public string LogonType => _activity.LogonType;
    public string ProcessKey => _activity.ProcessKey;
    public int ProcessId => _activity.ProcessId;
    public string ProcessName => _activity.ProcessName;
    public string ProcessPath => _activity.ProcessPath;
    public string Provider => _activity.Provider;
    public string LogName => _activity.LogName;
    public string RecordId => _activity.RecordId;
    public string Summary => _activity.Summary;
    public string Details => _activity.Details;
    public bool HasProcessCorrelation => !string.IsNullOrWhiteSpace(ProcessKey);

    public string ProcessDisplay => HasProcessCorrelation
        ? $"{ProcessName} ({ProcessId})"
        : string.Empty;

    public string SourceDisplay => string.IsNullOrWhiteSpace(LogName)
        ? _activity.Source
        : $"{LogName} / {_activity.Source}";

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.Event,
            TargetKind = "SystemActivity",
            TargetTable = "ProcessEvents",
            TargetId = HasProcessCorrelation
                ? $"{ProcessKey}:system-activity:{SourceSequenceId}"
                : $"system-activity:{SourceSequenceId}",
            ArtifactId = SourceSequenceId.ToString(),
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            ProcessName = ProcessName,
            Header = Activity,
            Subtitle = $"{TimestampDisplay} | Event {EventIdDisplay}",
            EmptyStateMessage = "Select a system activity row to inspect it here.",
            RawText = string.IsNullOrWhiteSpace(Details) ? Summary : Details,
            Properties = new List<PropertyItemViewModel>
            {
                new("Activity", "Time", TimestampDisplay),
                new("Activity", "Activity", Activity),
                new("Activity", "Result", Result),
                new("Activity", "Summary", Summary),
                new("Accounts", "Subject", EmptyDisplay(SubjectAccount)),
                new("Accounts", "Target Account", EmptyDisplay(TargetAccount)),
                new("Accounts", "Member", EmptyDisplay(MemberAccount)),
                new("Accounts", "Target Group", EmptyDisplay(TargetGroup)),
                new("Logon", "Type", EmptyDisplay(LogonType)),
                new("Logon", "Logon ID", EmptyDisplay(_activity.LogonId)),
                new("Origin", "Source Host", EmptyDisplay(SourceHost)),
                new("Origin", "Source Address", EmptyDisplay(SourceAddress)),
                new("Process", "Process", EmptyDisplay(ProcessDisplay)),
                new("Process", "Path", EmptyDisplay(ProcessPath)),
                new("Evidence", "Source", SourceDisplay),
                new("Evidence", "Provider", EmptyDisplay(Provider)),
                new("Evidence", "Log", EmptyDisplay(LogName)),
                new("Evidence", "Event ID", EmptyDisplay(EventIdDisplay)),
                new("Evidence", "Record ID", EmptyDisplay(RecordId)),
                new("Evidence", "Sequence", SourceSequenceId.ToString())
            }
        };
    }

    public TelemetrySearchResult ToNavigationResult()
    {
        return new TelemetrySearchResult
        {
            Kind = "SystemActivity",
            TimestampUtc = _activity.TimestampUtc,
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            ProcessName = string.IsNullOrWhiteSpace(ProcessName) ? "<unknown>" : ProcessName,
            Title = Activity,
            Subtitle = Summary,
            MatchedField = "SystemActivity",
            MatchedValue = Summary,
            Source = _activity.Source
        };
    }

    public bool MatchesScope(ExplorerScope scope)
        => SystemActivityNormalizer.MatchesScope(_activity, scope);

    private static string EmptyDisplay(string value)
        => string.IsNullOrWhiteSpace(value) ? "<none>" : value;
}
