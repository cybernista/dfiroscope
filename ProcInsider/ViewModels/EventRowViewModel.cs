using ProcInsider.Models;
using System.Collections.Generic;

namespace ProcInsider.ViewModels;

/// <summary>
/// View model wrapper for a normalized process event.
/// </summary>
public class EventRowViewModel : ViewModelBase
{
    private readonly ProcessEventInfo _eventInfo;

    public EventRowViewModel(ProcessEventInfo eventInfo)
    {
        _eventInfo = eventInfo;
    }

    public long SequenceId => _eventInfo.SequenceId;
    public string TimeDisplay => _eventInfo.GetDisplayTime();
    public string EventCodeDisplay => _eventInfo.EventCode?.ToString() ?? string.Empty;
    public string ProcessGuid => _eventInfo.ProcessGuid;
    public string CategoryDisplay => _eventInfo.Category.ToString();
    public string ActionDisplay => _eventInfo.Action.ToString();
    public string Target => _eventInfo.Target;
    public string Summary => _eventInfo.Summary;
    public string Details => _eventInfo.Details;
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
