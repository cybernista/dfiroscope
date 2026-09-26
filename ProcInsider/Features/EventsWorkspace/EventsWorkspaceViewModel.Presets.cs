using ProcInsider.Services;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed partial class EventsWorkspaceViewModel
{
    private Lazy<NativeEventPresetStore> _presets = null!;
    private NativeEventPresetEditorViewModel? _presetEditor;
    private bool _keepCurrentLayout;
    private bool _explicitPresetLayout;
    private string _presetStatus = "";
    private IReadOnlyList<NativeEventPresetColumn> _presetColumns = [];
    private IReadOnlyList<NativeEventPresetProfile> _presetProfiles = [];
    internal sealed record GridColumnState(string Key, int Order, double Width);
    internal IReadOnlyList<GridColumnState> GridColumns { get; set; } = [];
    internal bool HasCustomColumnOrder { get; set; }
    public bool KeepCurrentLayout { get => _keepCurrentLayout; set { if (SetProperty(ref _keepCurrentLayout, value) && !value) PublishFieldChoices([]); } }
    public string PresetStatus { get => _presetStatus; private set => SetProperty(ref _presetStatus, value); }
    public IReadOnlyList<NativeEventPresetColumn> PresetColumns => _presetColumns;
    public IEnumerable<NativeEventPresetColumn> DisplayExtractedColumns => SelectedExtractedFields.Select(f =>
        _presetColumns.FirstOrDefault(c => c.Identity == f.Identity) ?? new NativeEventPresetColumn(f.Identity, f.Name, 220));
    private static bool TypeScopeChanged(EventsFilter before, EventsFilter after) => AssociationScope(before) != AssociationScope(after);
    private static NativeEventPresetAssociation? AssociationScope(EventsFilter filter)
    {
        if (filter.MissingEventId || filter.GreenSelectors.Count > 0 || filter.ExactEvent != null) return null;
        string? Exact(EventSort column, string? pivot, out bool valid)
        {
            valid = true;
            if (!filter.Columns.TryGetValue(column, out var criteria) || !criteria.IsActive) return pivot;
            if (criteria.AllValues || criteria.Values.Count != 1 || criteria.Values[0] == null || !string.IsNullOrWhiteSpace(criteria.Text) || criteria.Minimum != null || criteria.Maximum != null)
            { valid = false; return null; }
            var value = criteria.Values[0];
            valid = pivot == null || pivot == value;
            return value;
        }
        var provider = Exact(EventSort.Provider, filter.Provider, out var p);
        var channel = Exact(EventSort.Channel, filter.Channel, out var c);
        var eventId = Exact(EventSort.EventId, filter.EventId?.ToString(System.Globalization.CultureInfo.InvariantCulture), out var e);
        return p && c && e && int.TryParse(eventId, out var id) ? new(provider, channel, id) : null;
    }
    internal void ActivateAssociatedPreset()
    {
        if (KeepCurrentLayout) { PresetStatus = "Keep current layout: automatic preset application suppressed."; return; }
        if (IsDisposed || !FeaturePublication.IsPublished(EventsWorkspaceFeatureComposition.Id) ||
            (!FeaturePublication.WindowsSecurityEvents && !FeaturePublication.EventTelemetry)) return;
        if (AssociationScope(_filter) is not { } scope) { PresetStatus = "No exact event-type filter association; layout retained."; return; }
        _presets.Value.Reload();
        if (_presets.Value.LoadError.Length > 0) { PresetStatus = _presets.Value.LoadError; return; }
        var matches = _presets.Value.Snapshot().Where(p => p.Association == scope).ToArray();
        if (matches.Length == 1) ApplyPreset(matches[0]);
        else PresetStatus = matches.Length == 0 ? "No preset associated with this exact event-type filter; layout retained." : "Multiple presets match this event-type filter; choose one manually. Layout retained.";
    }
    internal void ApplyPreset(NativeEventPreset preset)
    {
        if (IsDisposed || !FeaturePublication.IsPublished(EventsWorkspaceFeatureComposition.Id) ||
            (!FeaturePublication.WindowsSecurityEvents && !FeaturePublication.EventTelemetry)) return;
        // Publish the entire layout as one transition. Query, sort and selection are untouched.
        foreach (var column in Enum.GetValues<EventSort>().Where(c => c != EventSort.Sequence))
            ListingColumns.GetColumn(column.ToString()).IsVisible = preset.Columns.Any(c => c.Identity.BuiltIn == column);
        _presetColumns = preset.Columns;
        _presetProfiles = preset.Profiles;
        _explicitPresetLayout = true;
        HasCustomColumnOrder = false;
        _fieldOverrides.Clear();
        _publishingFields = true;
        foreach (var field in _extractedFields) field.IsVisible = false;
        foreach (var column in preset.Columns.Where(c => c.Identity.BuiltIn == null))
        {
            var choice = _extractedFields.FirstOrDefault(f => f.Identity == column.Identity);
            if (choice == null) { choice = CreateFieldChoice(column.Identity, "Saved preset", column.Label, ProcInsider.Services.Events.NativeEventFieldPriority.Medium, false); _extractedFields = _extractedFields.Append(choice).ToArray(); }
            choice.IsVisible = true;
        }
        _publishingFields = false;
        FieldChooser.SetFields(_extractedFields);
        GridColumns = preset.Columns.Select((c, i) => new GridColumnState(c.Identity.Key, i, c.Width)).ToArray();
        OnPropertyChanged(nameof(ExtractedFields)); OnPropertyChanged(nameof(PresetColumns));
        PresetStatus = $"Applied {preset.Name} ({preset.Columns.Length} columns), saved revision {preset.Revision}.";
        StartComparison();
    }
    internal IEnumerable<NativeEventPresetColumn> CurrentPresetColumns()
    {
        var columns = Enum.GetValues<EventSort>().Where(c => c != EventSort.Sequence && ListingColumns.GetColumn(c.ToString()).IsVisible)
            .Select(c => _presetColumns.FirstOrDefault(p => p.Identity.BuiltIn == c) ?? new NativeEventPresetColumn(new(c, null, null), c.ToString(), 180))
            .Concat(DisplayExtractedColumns);
        return columns.Select(c => GridColumns.FirstOrDefault(g => g.Key == c.Identity.Key) is { } state ? c with { Width = state.Width } : c)
            .OrderBy(c => GridColumns.FirstOrDefault(g => g.Key == c.Identity.Key)?.Order ?? int.MaxValue).ToArray();
    }
    internal NativeEventPresetEditorViewModel PresetEditor => _presetEditor ??= new(_presets.Value, _profiles.Value, ApplyPreset, CurrentPresetColumns,
        () => ExtractedFields.Select(f => f.Path), () => _presetProfiles);
    internal void ShowPresets(System.Windows.Window? owner)
    {
        if (IsDisposed || !FeaturePublication.IsPublished(EventsWorkspaceFeatureComposition.Id) ||
            (!FeaturePublication.WindowsSecurityEvents && !FeaturePublication.EventTelemetry)) return;
        PresetEditor.RefreshAvailablePaths();
        new NativeEventPresetEditorWindow { Owner = owner, DataContext = PresetEditor }.ShowDialog();
    }
}
