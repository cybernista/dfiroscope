using ProcInsider.Features.NativeEventProfiles;
using ProcInsider.Services.Events;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed record ExtractedEventColumnHeader(NativeEventColumnIdentity Identity, string Label, ColumnFilterViewModel Filter)
{
    public override string ToString() => Label;
}

internal sealed class ExtractedEventFieldChoice(string path, Action changed) : ViewModelBase
{
    public string Path { get; } = path;
    public NativeEventColumnIdentity Identity { get; init; } = new(null, null, path);
    public string Profile { get; init; } = "All schemas (manual)";
    public string Name { get; init; } = path;
    public NativeEventFieldPriority Priority { get; init; } = NativeEventFieldPriority.Medium;
    public int Order { get; init; }
    public bool IsAutomatic { get; set; }
    private bool _visible;
    public bool IsVisible { get => _visible; set { if (SetProperty(ref _visible, value)) changed(); } }
}

internal sealed partial class EventsWorkspaceViewModel
{
    private readonly Dictionary<string, ExtractedEventColumnHeader> _nativeHeaders = new(StringComparer.Ordinal);
    private NativeEventColumnIdentity? _extractedSort;
    public NativeEventColumnIdentity? ExtractedSort => _extractedSort;
    internal ExtractedEventColumnHeader ExtractedHeader(NativeEventPresetColumn column)
    {
        if (!_nativeHeaders.TryGetValue(column.Identity.Key, out var header))
        {
            var identity = column.Identity;
            header = new(identity, column.Label, new(identity.Key, ColumnFilterKind.Values,
                (search, sort, token) => _session.Reader.ColumnValuesAsync(_filter, identity, search, token, sort), ApplyColumnFilters));
        }
        return _nativeHeaders[column.Identity.Key] = header with { Label = column.Label };
    }
    internal void SortExtractedColumn(NativeEventColumnIdentity column)
    {
        _descending = _extractedSort == column && !_descending;
        _extractedSort = column; _offset = 0;
        OnPropertyChanged(nameof(ExtractedSort)); OnPropertyChanged(nameof(Descending));
        InvestigationChanged?.Invoke(); StartRefresh();
    }
    private void CloseExtractedHeaders(bool reset = false)
    {
        foreach (var header in _nativeHeaders.Values) { if (reset) header.Filter.Reset(false); else header.Filter.Close(); }
    }
    private readonly Dictionary<NativeEventType, string> _detailsProfiles = [];
    private readonly HashSet<(NativeEventType Type, string Path)> _pinnedFields = [];
    private IReadOnlyList<ContextualEventField> _contextualFields = [];
    private string _fieldSearch = "";
    private NativeEventProfile? _detailsProfileChoice;
    private bool _mediumExpanded, _lowExpanded;
    private bool _showHighHighlights = true, _showMediumHighlights = true, _showLowHighlights = true;
    public bool ShowHighHighlights { get => _showHighHighlights; set { if (SetProperty(ref _showHighHighlights, value)) UpdateHighlightCategories(); } }
    public bool ShowMediumHighlights { get => _showMediumHighlights; set { if (SetProperty(ref _showMediumHighlights, value)) UpdateHighlightCategories(); } }
    public bool ShowLowHighlights { get => _showLowHighlights; set { if (SetProperty(ref _showLowHighlights, value)) UpdateHighlightCategories(); } }
    private void UpdateHighlightCategories()
    {
        foreach (var row in Rows) row.SetHighlightCategories(ShowHighHighlights, ShowMediumHighlights, ShowLowHighlights);
    }
    public bool MediumExpanded { get => _mediumExpanded; set => SetProperty(ref _mediumExpanded, value); }
    public bool LowExpanded { get => _lowExpanded; set => SetProperty(ref _lowExpanded, value); }
    public string FieldSearch { get => _fieldSearch; set { if (SetProperty(ref _fieldSearch, value)) NotifyFieldViews(); } }
    public NativeEventProfile? DetailsProfileChoice { get => _detailsProfileChoice; set => SetProperty(ref _detailsProfileChoice, value); }
    public IReadOnlyList<NativeEventProfile> MatchingDetailsProfiles => !_profiles.IsValueCreated ? [] :
        _profiles.Value.Snapshot().Where(p => p.Matches(SelectedEvent?.Extraction?.EventType)).ToArray();
    public string ContextualStatus => (SelectedEvent?.ProfileStatus ?? "Select an event to inspect its native fields.") +
        (_profiles.IsValueCreated && _profiles.Value.LoadError.Length > 0 ? " " + _profiles.Value.LoadError : "");
    public IEnumerable<ContextualEventField> HighFields => FilterFields(_contextualFields.Where(f => f.Priority == NativeEventFieldPriority.High));
    public IEnumerable<ContextualEventField> MediumFields => FilterFields(_contextualFields.Where(f => f.Priority == NativeEventFieldPriority.Medium));
    public IEnumerable<ContextualEventField> LowFields => FilterFields(_contextualFields.Where(f => f.Priority == NativeEventFieldPriority.Low));
    public IEnumerable<ContextualEventField> PinnedFields => FilterFields(_contextualFields.Where(f => f.IsPinned));
    public string FieldSearchStatus => $"{FilterFields(_contextualFields).Count()} of {_contextualFields.Count} native fields match name/path/value search.";
    private IEnumerable<ContextualEventField> FilterFields(IEnumerable<ContextualEventField> fields) => fields.Where(f =>
        string.IsNullOrEmpty(FieldSearch) || f.Label.Contains(FieldSearch, StringComparison.OrdinalIgnoreCase) ||
        f.Path.Contains(FieldSearch, StringComparison.OrdinalIgnoreCase) || f.DisplayValue.Contains(FieldSearch, StringComparison.OrdinalIgnoreCase));
    private void NotifyFieldViews()
    {
        OnPropertyChanged(nameof(HighFields)); OnPropertyChanged(nameof(MediumFields)); OnPropertyChanged(nameof(LowFields));
        OnPropertyChanged(nameof(PinnedFields)); OnPropertyChanged(nameof(FieldSearchStatus));
    }
    internal void UseDetailsProfile()
    {
        if (IsDisposed || _suspended || !FeaturePublication.IsPublished(EventsWorkspaceFeatureComposition.Id) ||
            (!FeaturePublication.WindowsSecurityEvents && !FeaturePublication.EventTelemetry) ||
            DetailsProfileChoice is not { } profile || !MatchingDetailsProfiles.Any(p => p.Id == profile.Id && p.Revision == profile.Revision)) return;
        _detailsProfiles[profile.EventType] = profile.Id;
        ProfilesChanged(this, EventArgs.Empty);
    }
    private void ProfilesChanged(object? sender, EventArgs e)
    {
        if (!_dispatcher.CheckAccess()) { _dispatcher.BeginInvoke(() => ProfilesChanged(sender, e)); return; }
        if (IsDisposed) return;
        _filter = _filter with { TextProjection = new EventsTextProjection(_profiles.Value.Snapshot(), _detailsProfiles) };
        // Retire the entire old page when its Details authority changes, including in-flight SQL/facets.
        Invalidate(false);
        Status = "Profiles changed; activate or refresh this workspace to read current Details.";
        InvestigationChanged?.Invoke(); FiltersChanged?.Invoke();
        StartRefresh();
    }
    private void RefreshContextualFields()
    {
        var presentation = SelectedEvent?.Presentation;
        var type = presentation?.Extraction.EventType;
        var fields = presentation?.Fields.AsEnumerable() ?? [];
        if (type != null)
            fields = fields.Concat(_pinnedFields.Where(p => p.Type == type && !fields.Any(f => f.Path == p.Path)).Select(p =>
                new NativeEventDisplayField(p.Path, p.Path, NativeEventFieldPriority.Medium, true, null,
                    presentation!.Extraction.Status == EventFieldExtractionStatus.Available ? "<missing>" : "<unavailable>"))).ToArray();
        _contextualFields = fields.Select(f => new ContextualEventField(f, type != null && _pinnedFields.Contains((type, f.Path)), pinned =>
        {
            if (type == null) return;
            if (pinned) _pinnedFields.Add((type, f.Path)); else _pinnedFields.Remove((type, f.Path));
            NotifyFieldViews();
        })).ToArray();
        DetailsProfileChoice = presentation?.Profile;
        OnPropertyChanged(nameof(MatchingDetailsProfiles)); OnPropertyChanged(nameof(ContextualStatus));
        NotifyFieldViews();
    }
    private CancellationTokenSource _extraction = new();
    private long _extractionRevision;
    private IReadOnlyList<ExtractedEventFieldChoice> _extractedFields = [];
    public IReadOnlyList<ExtractedEventFieldChoice> ExtractedFields => _extractedFields;
    public ExtractedEventFieldChooser FieldChooser { get; } = new();
    private readonly Dictionary<string, bool> _fieldOverrides = new(StringComparer.Ordinal);
    private bool _publishingFields;
    public IEnumerable<ExtractedEventFieldChoice> SelectedExtractedFields => _extractedFields.Where(f => f.IsVisible);
    private string _extractedFieldsStatus = "No displayed events.";
    public string ExtractedFieldsStatus { get => _extractedFieldsStatus; private set => SetProperty(ref _extractedFieldsStatus, value); }

    private void CancelExtraction()
    {
        ++_extractionRevision;
        _extraction.Cancel();
    }
    private void BeginExtraction()
    {
        CancelExtraction();
        _extraction.Dispose(); _extraction = new();
        if (_suspended || IsDisposed) return;
        if (Rows.Count == 0) { PublishFieldChoices([]); ExtractedFieldsStatus = "No displayed events."; return; }
        ExtractedFieldsStatus = "Extracting fields from the displayed page…";
        Track(ExtractPageAsync(Rows.ToArray(), _loadedBinding, _extractionRevision, _extraction.Token));
    }
    private async Task ExtractPageAsync(EventsWorkspaceRowViewModel[] rows, EventsReadBinding? binding, long revision, CancellationToken token)
    {
        BeginPreparing();
        try
        {
            var results = await Task.Run(() => rows.Select(row =>
            {
                token.ThrowIfCancellationRequested();
                return row.ExtractNativeFields(token);
            }).ToArray(), token);
            if (token.IsCancellationRequested || IsDisposed || _suspended || revision != _extractionRevision ||
                binding != _session.Binding || binding != _loadedBinding || !Rows.SequenceEqual(rows)) return;
            for (var i = 0; i < rows.Length; i++) rows[i].Extraction = results[i];
            PublishFieldChoices(results.SelectMany(r => r.Fields).Select(f => f.Path));
            var unavailable = results.Count(r => r.Status != EventFieldExtractionStatus.Available);
            ExtractedFieldsStatus = $"{results.SelectMany(r => r.Fields).Select(f => f.Path).Distinct(StringComparer.Ordinal).Count()} fields on this displayed page ({rows.Length} events); {unavailable} partial/unavailable. Selected fields from other pages remain listed.";
            if (_selected != null && rows.Contains(_selected))
            {
                RetireAi();
                InspectorPaneViewModel.Load(_selected.CreatePayload());
                OnPropertyChanged(nameof(AiDetailsInvestigationViewModel));
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { if (revision == _extractionRevision && !IsDisposed) ExtractedFieldsStatus = "Event field extraction unavailable."; }
        finally { EndPreparing(); }
    }
    private void PublishFieldChoices(IEnumerable<string> paths)
    {
        UpdateHighlightCategories();
        var displayedFields = Rows.Where(r => r.Presentation != null).SelectMany(r => r.Presentation!.Fields.Select((field, order) =>
            new DisplayedEventField(r, field, order))).ToArray();
        var candidates = displayedFields.Where(f => f.Field.Priority != NativeEventFieldPriority.High).Select(f =>
            CreateFieldChoice(new(null, f.Row.Extraction!.EventType?.Version == null ? null : f.Row.Extraction.EventType, f.Field.Path),
                ProfileDisplay(f.Row), f.Field.Label, f.Field.Priority, false, f.Order));

        // High columns are the compact default listing projection. The native path, not a profile
        // label, identifies the evidence field; use an unscoped path so the same field from every
        // displayed event schema shares one column while every row retains its own extracted value.
        candidates = candidates.Concat(displayedFields.Where(f => f.Field.Priority == NativeEventFieldPriority.High)
            .GroupBy(f => f.Field.Path, StringComparer.Ordinal)
            .Select(group =>
            {
                var first = group.OrderBy(f => f.Order).First();
                var labels = group.Select(f => f.Field.Label).Distinct(StringComparer.Ordinal).ToArray();
                return CreateFieldChoice(new(null, null, first.Field.Path), "All displayed schemas (High)",
                    labels.Length == 1 ? labels[0] : first.Field.Path, NativeEventFieldPriority.High, true,
                    group.Min(f => f.Order));
            }));
        candidates = candidates.Concat(StatisticsFields.Select(f => CreateFieldChoice(
            new(null, f.EventType.Version == null ? null : f.EventType, f.Path),
            f.EventType.Version == null ? "All schemas (manual)" : $"Statistics — {f.EventType.Provider} / {f.EventType.Channel} / {f.EventType.EventId} v{f.EventType.Version}",
            f.Path, NativeEventFieldPriority.Medium, false)));
        // Unqualified manually selected paths remain an explicit compatibility choice.
        var describedPaths = candidates.Select(f => f.Path).ToHashSet(StringComparer.Ordinal);
        candidates = candidates.Concat(paths.Distinct(StringComparer.Ordinal)
            .Where(p => !describedPaths.Contains(p)).Select(p => CreateFieldChoice(new(null, null, p), "All schemas (manual)", p, NativeEventFieldPriority.Medium, false)));
        var previous = _extractedFields.ToDictionary(f => f.Identity.Key, StringComparer.Ordinal);
        var retained = _extractedFields.Where(f =>
            !IsSupersededAutomaticHighField(f) &&
            (_nativeHeaders.TryGetValue(f.Identity.Key, out var header) && header.Filter.IsActive || _extractedSort == f.Identity ||
             f.IsVisible && (_fieldOverrides.ContainsKey(f.Identity.Key) || !f.IsAutomatic || KeepCurrentLayout || _explicitPresetLayout))).ToArray();
        _publishingFields = true;
        try
        {
            _extractedFields = candidates.Concat(retained).DistinctBy(f => f.Identity.Key)
                .OrderBy(f => f.Profile, StringComparer.OrdinalIgnoreCase).ThenBy(f => f.Identity.EventType?.ToString(), StringComparer.Ordinal).ThenBy(f => f.Order)
                .Select(f =>
                {
                    var key = f.Identity.Key;
                    var selected = _fieldOverrides.TryGetValue(key, out var manual) ? manual :
                        KeepCurrentLayout || _explicitPresetLayout ? previous.GetValueOrDefault(key)?.IsVisible == true : f.IsAutomatic;
                    f.IsVisible = selected;
                    return f;
                }).ToArray();
        }
        finally { _publishingFields = false; }
        FieldChooser.SetFields(_extractedFields);
        OnPropertyChanged(nameof(ExtractedFields));
        OnPropertyChanged(nameof(SelectedExtractedFields));
    }
    private ExtractedEventFieldChoice CreateFieldChoice(NativeEventColumnIdentity identity, string profile, string name, NativeEventFieldPriority priority, bool automatic, int order = int.MaxValue)
    {
        ExtractedEventFieldChoice choice = null!;
        choice = new(identity.Path!, () =>
        {
            if (_publishingFields) return;
            choice.IsAutomatic = false;
            _fieldOverrides[identity.Key] = choice.IsVisible;
            OnPropertyChanged(nameof(SelectedExtractedFields));
        }) { Identity = identity, Profile = profile, Name = name, Priority = priority, IsAutomatic = automatic, Order = order };
        return choice;
    }

    private static string ProfileDisplay(EventsWorkspaceRowViewModel row) => row.Extraction!.EventType?.Version == null
        ? "All schemas (manual)" : row.Presentation!.Profile is { } profile ? profile.Id + " — " + profile.Name : row.Extraction.EventType is { } type
            ? $"{type.EventId} v{type.Version} — {row.ProfileStatus} — {type.Provider} / {type.Channel}" : row.ProfileStatus;

    private static bool IsSupersededAutomaticHighField(ExtractedEventFieldChoice field) =>
        field.IsAutomatic && field.Priority == NativeEventFieldPriority.High && field.Identity.EventType != null;

    private sealed record DisplayedEventField(EventsWorkspaceRowViewModel Row, NativeEventDisplayField Field, int Order);
}

internal sealed class ContextualEventField(NativeEventDisplayField item, bool pinned, Action<bool> changed) : ViewModelBase
{
    public string Path => item.Path;
    public string Label => item.Label;
    public string DisplayValue => item.DisplayValue;
    public NativeEventFieldPriority Priority => item.Priority;
    public string Classification => item.IsDefaultPriority ? "Medium (unclassified default)" : Priority.ToString();
    private bool _isPinned = pinned;
    public bool IsPinned { get => _isPinned; set { if (SetProperty(ref _isPinned, value)) changed(value); } }
}
