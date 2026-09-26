using ProcInsider.Models;
using ProcInsider.Features.NativeEventProfiles;
using System.Collections.Generic;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model wrapper for a normalized process event.
/// </summary>
public class EventRowViewModel : ViewModelBase
{
    private readonly ProcessEventInfo _eventInfo;

    public EventRowViewModel(ProcessEventInfo eventInfo, string? eventSource = null)
    {
        _eventInfo = eventInfo;
        // Legacy selected-process Security projections predate retained provider/channel fields.
        // That established source has one exact native identity; other source families never infer one.
        Description = eventInfo.RawProvider.Length == 0 && eventInfo.RawLogName.Length == 0 &&
            string.Equals(eventSource, "Security", System.StringComparison.OrdinalIgnoreCase)
            ? EventsTextProjection.Describe(eventInfo.EventCode, "Microsoft-Windows-Security-Auditing", "Security")
            : EventsTextProjection.Describe(eventInfo.EventCode, eventInfo.RawProvider, eventInfo.RawLogName);
    }

    public long SequenceId => _eventInfo.SequenceId;
    public System.DateTime TimestampUtc => _eventInfo.TimestampUtc;
    public int? EventCode => _eventInfo.EventCode;
    public string Description { get; }
    private string _detailsSummary = "Profile Details pending";
    public string DetailsSummary { get => _detailsSummary; internal set => SetProperty(ref _detailsSummary, value); }
    public string TimeDisplay => _eventInfo.GetDisplayTime();
    public string EventCodeDisplay => _eventInfo.EventCode?.ToString() ?? string.Empty;
    public string ProcessGuid => _eventInfo.ProcessGuid;
    public string CategoryDisplay => _eventInfo.Category.ToString();
    public string ActionDisplay => _eventInfo.Action.ToString();
    public string Target => _eventInfo.Target;
    public string Summary => _eventInfo.Summary;
    public string Details => _eventInfo.Details;
    public string RawProvider => _eventInfo.RawProvider;
    public string RawLogName => _eventInfo.RawLogName;
    public string RiskFlags => _eventInfo.RiskFlags;
    public bool IsInteresting => _eventInfo.IsInteresting;
    public int RepeatCount => _eventInfo.RepeatCount;

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.Event,
            TargetKind = "Event",
            TargetTable = "ProcessEvents",
            TargetId = string.IsNullOrWhiteSpace(_eventInfo.ProcessKey)
                ? $"event:{SequenceId}"
                : $"{_eventInfo.ProcessKey}:event:{SequenceId}",
            ArtifactId = SequenceId.ToString(),
            ProcessKey = _eventInfo.ProcessKey,
            ProcessId = _eventInfo.ProcessId,
            ProcessName = _eventInfo.ProcessName,
            Header = $"{CategoryDisplay} | {ActionDisplay}",
            Subtitle = $"{TimeDisplay} | Count {RepeatCount}",
            EmptyStateMessage = "Select an event to inspect it here.",
            RawText = string.IsNullOrWhiteSpace(Details)
                ? $"{Target}{System.Environment.NewLine}{Summary}"
                : Details,
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Sequence", SequenceId.ToString()),
                new("Identity", "Time", TimeDisplay),
                new("Identity", "Event Code", EventCodeDisplay),
                new("Identity", "Process Guid", string.IsNullOrWhiteSpace(ProcessGuid) ? "<none>" : ProcessGuid),
                new("Identity", "Process Entity", _eventInfo.ProcessEntityId),
                new("Provenance", "Source Run", _eventInfo.SourceRunId),
                new("Provenance", "Ingestion Job", _eventInfo.IngestionJobId),
                new("Identity", "Category", CategoryDisplay),
                new("Identity", "Action", ActionDisplay),
                new("Process", "Target", Target),
                new("Process", "Summary", Summary),
                new("Process", "Flags", string.IsNullOrWhiteSpace(RiskFlags) ? "<none>" : RiskFlags),
                new("Process", "Repeat Count", RepeatCount.ToString()),
                new("Process", "Interesting", IsInteresting ? "Yes" : "No")
            }
        };
    }
}
