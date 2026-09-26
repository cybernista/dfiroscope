using System.Text.Json;
using ProcInsider.Services.Events;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal enum EventsComparisonMode { All, Preset, Manual }
internal enum EventsComparisonValueState { Value, Empty, Missing, Unavailable, NoExtraction, DifferentSchema }
internal sealed record EventsComparisonValue(EventsComparisonValueState State, string? Original)
{
    public string Display => State == EventsComparisonValueState.Value ? Original! : State switch
    {
        EventsComparisonValueState.Empty => "<empty>", EventsComparisonValueState.Missing => "<missing>",
        EventsComparisonValueState.NoExtraction => "<no extraction>", EventsComparisonValueState.DifferentSchema => "<different schema>",
        _ => "<unavailable>"
    };
}
internal sealed record EventsComparisonField(NativeEventType Type, string Path)
{
    public string Description => $"{Type.EventId} v{Type.Version?.ToString() ?? "unknown"} / {Path}\n{Type.Provider} / {Type.Channel}";
}
internal sealed class EventsComparisonFieldChoice(EventsComparisonField field, bool selected, Action changed) : ViewModelBase
{
    public EventsComparisonField Field { get; } = field;
    public string Description => Field.Description;
    private bool _selected = selected;
    public bool IsSelected { get => _selected; set { if (SetProperty(ref _selected, value)) changed(); } }
}
internal sealed class EventsComparisonEvent(EventsWorkspaceRowViewModel row, EventFieldExtraction extraction)
{
    public EventsWorkspaceRowViewModel Row { get; } = row;
    public EventReference Reference => Row.Reference;
    public string Label => $"Event {Reference.SequenceId} · {Row.TimeDisplay} · record {Row.Evidence.Native.RawRecordId}";
    public EventFieldExtraction Extraction { get; } = extraction;
    private readonly IReadOnlyDictionary<string, string> _values = extraction.Fields.ToDictionary(f => f.Path, f => f.Value, StringComparer.Ordinal);
    public string Header => $"Event {Reference.SequenceId} · {Row.TimeDisplay}\n{Row.Provider} / {Row.Channel} / {Row.EventCodeDisplay} / version {Extraction.EventType?.Version?.ToString() ?? "unknown"}\n" +
        $"Record: {Row.Evidence.Native.RawRecordId}\nReference: {JsonSerializer.Serialize(Reference)}\nIngestion job: {Row.Evidence.Native.IngestionJobId}\nExtraction: {Extraction.Status}: {Extraction.Diagnostic}";
    internal EventsComparisonValue Get(EventsComparisonField field)
    {
        if (Extraction.EventType == null)
            return new(Extraction.Status == EventFieldExtractionStatus.Unavailable ? EventsComparisonValueState.NoExtraction : EventsComparisonValueState.Unavailable, null);
        if (Extraction.EventType != field.Type)
            return new(Extraction.EventType.Provider == field.Type.Provider && Extraction.EventType.Channel == field.Type.Channel &&
                Extraction.EventType.EventId == field.Type.EventId && (Extraction.EventType.Version == null || field.Type.Version == null)
                ? EventsComparisonValueState.Unavailable : EventsComparisonValueState.DifferentSchema, null);
        if (_values.TryGetValue(field.Path, out var value)) return new(value.Length == 0 ? EventsComparisonValueState.Empty : EventsComparisonValueState.Value, value);
        return new(Extraction.Status == EventFieldExtractionStatus.Available ? EventsComparisonValueState.Missing : EventsComparisonValueState.Unavailable, null);
    }
}
internal sealed record EventsComparisonCell(EventsComparisonValue Value, bool IsDifferent)
{
    public string Display => Value.Display;
    public string Detail => $"State: {Value.State}; exact ordinal string equality\n{Value.Original}";
}
// Cells are produced only when requested by the virtualized grid, avoiding a dense event × field allocation.
internal sealed class EventsComparisonRow(EventsComparisonField field, EventsComparisonEvent[] events, int reference, bool hasDifferences)
{
    public EventsComparisonField Field { get; } = field;
    public string Description => Field.Description;
    public bool HasDifferences { get; } = hasDifferences;
    public EventsComparisonRow Cells => this;
    public EventsComparisonCell this[int index]
    {
        get { var value = events[index].Get(Field); return new(value, value != events[reference].Get(Field)); }
    }
}
