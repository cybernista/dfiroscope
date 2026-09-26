using ProcInsider.Features.NativeEventProfiles;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.ViewModels;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class EventsWorkspaceRowViewModel : EventRowViewModel
{
    internal EventsWorkspaceRowViewModel(EventsRow row) : base(row.Native.ToProcessEventInfo(), row.Native.Source)
    { Evidence = row; DetailsSummary = "Profile Details pending"; }
    public EventsRow Evidence { get; }
    public EventReference Reference => Evidence.Reference;
    private EventFieldExtraction? _extraction;
    public EventFieldExtraction? Extraction { get => _extraction; internal set => SetProperty(ref _extraction, value); }
    public NativeEventPresentation? Presentation { get; private set; }
    public IEnumerable<NativeEventDisplayField> HighFields => Presentation?.Fields.Where(f => f.Priority == NativeEventFieldPriority.High) ?? [];
    public IEnumerable<NativeEventDisplayField> MediumFields => Presentation?.Fields.Where(f => f.Priority == NativeEventFieldPriority.Medium) ?? [];
    public IEnumerable<NativeEventDisplayField> LowFields => Presentation?.Fields.Where(f => f.Priority == NativeEventFieldPriority.Low) ?? [];
    private string _presentationStatus = "Profile Details pending";
    public string ProfileStatus => Presentation?.Status ?? _presentationStatus;
    internal void MarkPresentationUnavailable(string status)
    {
        if (Presentation != null) return;
        _presentationStatus = status; DetailsSummary = status; OnPropertyChanged(nameof(ProfileStatus));
    }
    private bool _highlightsExpanded;
    public bool HighlightsExpanded { get => _highlightsExpanded; set { if (SetProperty(ref _highlightsExpanded, value)) RefreshExpandedFields(); } }
    private bool _showHigh = true, _showMedium = true, _showLow = true;
    public IReadOnlyList<NativeEventDisplayField>? ExpandedFields { get; private set; }
    internal void SetHighlightCategories(bool high, bool medium, bool low)
    {
        _showHigh = high; _showMedium = medium; _showLow = low;
        if (HighlightsExpanded) RefreshExpandedFields();
    }
    private void RefreshExpandedFields()
    {
        ExpandedFields = !HighlightsExpanded ? null : Presentation?.Fields.Where(f => f.Priority switch
        {
            NativeEventFieldPriority.High => _showHigh,
            NativeEventFieldPriority.Medium => _showMedium,
            _ => _showLow
        }).OrderBy(f => f.Priority).ToArray() ?? [];
        OnPropertyChanged(nameof(ExpandedFields));
    }
    internal void ApplyPresentation(NativeEventPresentation presentation)
    {
        Presentation = presentation; Extraction = presentation.Extraction; DetailsSummary = presentation.Summary;
        OnPropertyChanged(nameof(HighFields)); OnPropertyChanged(nameof(MediumFields)); OnPropertyChanged(nameof(LowFields));
        OnPropertyChanged(nameof(ProfileStatus));
        RefreshExpandedFields();
    }
    public string Provider => TelemetryEventRecord.DisplaySourceMetadata(Evidence.Native.Source, Evidence.Native.RawProvider);
    public string Channel => TelemetryEventRecord.DisplaySourceMetadata(Evidence.Native.Source, Evidence.Native.RawLogName);
    // Formatting, comparison and extracted columns interpret captured metadata, never browse labels.
    internal EventFieldExtraction ExtractNativeFields(CancellationToken token) => Extraction ??
        NativeEventFieldExtractor.Extract(Details, EventCode, Evidence.Native.RawProvider, Evidence.Native.RawLogName, token);
    public string Host => Reference.HostId;
    public string Correlation => $"{Evidence.CorrelationState} ({Evidence.CandidateCount})";
    public string Actor => Evidence.Identities.FirstOrDefault(i => i.Role == EventIdentityRole.Actor) is { } identity ? IdentityDisplay(identity) : "";
    public string TargetIdentity => Evidence.Identities.FirstOrDefault(i => i.Role == EventIdentityRole.Target) is { } identity ? IdentityDisplay(identity) : "";
    internal static string IdentityDisplay(EventIdentity identity) => identity.Display +
        (identity.NativePrefix.StartsWith("Derived:", StringComparison.Ordinal) ? " (derived process user)" :
            identity.NativePrefix == "Sysmon User (execution context)" ? " (execution context)" : "");

    internal InspectorPayload CreatePayload()
    {
        var native = Evidence.Native;
        var payload = ToInspectorPayload();
        payload.TargetId = JsonSerializer.Serialize(Reference);
        payload.CaseId = Reference.CaseId;
        payload.EvidenceSessionId = Reference.EvidenceSessionId;
        payload.CaptureId = Reference.CaptureId;
        payload.SourceIdentityId = Reference.SourceIdentityId;
        payload.HostId = Reference.HostId;
        payload.SourceRunId = Reference.SourceRunId;
        payload.IngestionJobId = native.IngestionJobId;
        payload.ExecutionRootId = native.ExecutionRootId;
        // Native process hints are properties, never an authoritative process target for an unresolved event.
        payload.ProcessKey = "";
        payload.ProcessId = 0;
        payload.ProcessName = "";
        payload.Header = $"{Evidence.Native.Source} {EventCodeDisplay} · {Description}";
        payload.Subtitle = $"{TimeDisplay} · {Provider} · {Channel}";
        payload.RawText = native.Details;
        payload.RawXml = native.Details;
        List<PropertyItemViewModel> properties =
        [
            new("Event", "Details", DetailsSummary),
            new("Event", "Sequence", SequenceId.ToString()), new("Event", "Source family", Evidence.Native.Source),
            new("Event", "Provider", Provider), new("Event", "Channel", Channel),
            new("Event", "Native record ID", native.RawRecordId),
            new("Provenance", "Case", Reference.CaseId), new("Provenance", "Session", Reference.EvidenceSessionId),
            new("Provenance", "Capture", Reference.CaptureId), new("Provenance", "Host", Host),
            new("Provenance", "Source", Reference.SourceIdentityId), new("Provenance", "Source run", Reference.SourceRunId),
            new("Provenance", "Ingestion job", native.IngestionJobId),
            new("Correlation", "State / candidates", Correlation),
            new("Correlation", "Canonical process entity", Evidence.CanonicalProcessEntityId),
            new("Correlation", "Native process entity", native.ProcessEntityId),
            new("Correlation", "Native process key", native.ProcessKey),
            new("Correlation", "Native PID (hint)", native.ProcessId.ToString()),
            new("Correlation", "Diagnostics", Evidence.CorrelationDiagnostics)
        ];
        var extracted = new List<PropertyItemViewModel>
        {
            new("Event extracted", "Extraction status", Extraction == null ? "Pending" : $"{Extraction.Status}: {Extraction.Diagnostic}"),
            new("Event extracted", "Extractor version", EventFieldExtraction.ExtractorVersion)
        };
        if (Extraction != null)
            extracted.AddRange(Extraction.Fields.OrderBy(f => f.Path, StringComparer.Ordinal)
                .Select(f => new PropertyItemViewModel("Event extracted", f.Path, f.Value)));
        properties.InsertRange(properties.FindLastIndex(p => p.Group == "Event") + 1, extracted);
        if (Evidence.Audit is { } audit)
        {
            properties.Add(new("Auditing", "Category key", audit.CategoryKey));
            properties.Add(new("Auditing", "Subcategory key", audit.SubcategoryKey));
            properties.Add(new("Auditing", "Interpretation", audit.Description));
        }
        foreach (var identity in Evidence.Identities)
        {
            properties.Add(new(identity.Role.ToString(), "Identity", IdentityDisplay(identity)));
            var origin = identity.NativePrefix.StartsWith("Derived:", StringComparison.Ordinal)
                ? identity.NativePrefix : $"native {identity.NativePrefix}";
            properties.Add(new(identity.Role.ToString(), "Interpretation", $"{identity.Status}; {identity.Scope}; {origin}; logon {identity.LogonId}"));
        }
        payload.Properties = properties;
        return payload;
    }
}
