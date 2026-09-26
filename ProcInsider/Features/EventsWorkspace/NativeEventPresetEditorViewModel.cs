using ProcInsider.Features.NativeEventProfiles;
using System.Collections.ObjectModel;
using System.Collections.Immutable;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal partial class NativeEventPresetColumnDraft : ObservableObject
{
    public NativeEventColumnIdentity Identity { get; }
    public string Description => Identity.Description;
    [ObservableProperty] private string label;
    [ObservableProperty] private double width;
    public NativeEventPresetColumnDraft(NativeEventPresetColumn column) { Identity = column.Identity; label = column.Label; width = column.Width; }
    public NativeEventPresetColumn Snapshot() => new(Identity, Label, Width);
}

/// <summary>Workspace-owned draft. Closing/remounting a view never discards this state.</summary>
internal partial class NativeEventPresetEditorViewModel : ObservableObject
{
    private readonly NativeEventPresetStore _store;
    private readonly NativeEventProfileStore _profiles;
    private readonly Action<NativeEventPreset> _apply;
    private readonly Func<IEnumerable<NativeEventPresetColumn>> _current;
    private readonly Func<IEnumerable<NativeEventPresetProfile>> _currentProfiles;
    private readonly Func<IEnumerable<string>> _paths;
    private string _id = Guid.NewGuid().ToString("N");
    private Guid? _expected;
    private bool _loading;
    private ImmutableArray<NativeEventPresetProfile> _references = [];
    public ObservableCollection<NativeEventPreset> Presets { get; } = [];
    public ObservableCollection<NativeEventProfile> Profiles { get; } = [];
    public ObservableCollection<NativeEventPresetColumnDraft> Columns { get; } = [];
    public IEnumerable<EventSort> OrdinaryColumns => Enum.GetValues<EventSort>().Where(c => c != EventSort.Sequence);
    public IEnumerable<string> ManualPaths => _paths();
    public int ColumnCount => Columns.Count;
    public string ProfileRevisions => string.Join("; ", _references.Select(r => $"{r.Id} ({string.Join('/', r.Categories)}) @ {r.Revision}"));
    [ObservableProperty] private NativeEventPreset? selectedPreset;
    [ObservableProperty] private NativeEventProfile? selectedProfile;
    [ObservableProperty] private NativeEventPresetColumnDraft? selectedColumn;
    [ObservableProperty] private EventSort selectedOrdinaryColumn = EventSort.Timestamp;
    [ObservableProperty] private string manualPath = "";
    [ObservableProperty] private bool high = true;
    [ObservableProperty] private bool medium;
    [ObservableProperty] private bool low;
    [ObservableProperty] private string presetName = "New preset";
    [ObservableProperty] private bool associate;
    [ObservableProperty] private string associationProvider = "";
    [ObservableProperty] private string associationChannel = "";
    [ObservableProperty] private string associationEventId = "";
    [ObservableProperty] private string status = "";
    [ObservableProperty] private bool isDirty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanEdit))] private bool isBusy;
    public bool CanEdit => !IsBusy;
    internal void RefreshAvailablePaths() => OnPropertyChanged(nameof(ManualPaths));
    partial void OnSelectedProfileChanged(NativeEventProfile? value) => RefreshCategories();
    private void RefreshCategories()
    {
        var categories = _references.FirstOrDefault(r => r.Id == SelectedProfile?.Id)?.Categories;
        High = categories?.Contains(NativeEventFieldPriority.High) ?? true;
        Medium = categories?.Contains(NativeEventFieldPriority.Medium) ?? false;
        Low = categories?.Contains(NativeEventFieldPriority.Low) ?? false;
    }

    internal NativeEventPresetEditorViewModel(NativeEventPresetStore store, NativeEventProfileStore profiles,
        Action<NativeEventPreset> apply, Func<IEnumerable<NativeEventPresetColumn>> current, Func<IEnumerable<string>> paths,
        Func<IEnumerable<NativeEventPresetProfile>>? currentProfiles = null)
    {
        _store = store; _profiles = profiles; _apply = apply; _current = current; _paths = paths;
        _currentProfiles = currentProfiles ?? (() => []);
        PropertyChanged += (_, e) => { if (!_loading && e.PropertyName is nameof(PresetName) or nameof(Associate) or nameof(AssociationProvider) or nameof(AssociationChannel) or nameof(AssociationEventId)) IsDirty = true; };
        Columns.CollectionChanged += (_, _) => { OnPropertyChanged(nameof(ColumnCount)); if (!_loading) IsDirty = true; };
        RefreshLists();
        SelectedPreset = Presets.FirstOrDefault();
        if (SelectedPreset != null) Load(SelectedPreset);
        Status = _store.LoadError;
    }
    private void RefreshLists()
    {
        var selected = SelectedPreset?.Id;
        Presets.Clear(); foreach (var p in _store.Snapshot()) Presets.Add(p);
        SelectedPreset = Presets.FirstOrDefault(p => p.Id == selected);
        Profiles.Clear(); foreach (var p in _profiles.Snapshot()) Profiles.Add(p);
        SelectedProfile = Profiles.FirstOrDefault();
        OnPropertyChanged(nameof(ManualPaths));
    }
    private bool ReplaceDraft()
    {
        if (IsBusy) return false;
        if (!IsDirty) return true;
        Status = "Save or discard the current draft before replacing it."; return false;
    }
    private void Add(NativeEventPresetColumn column)
    {
        if (Columns.Any(c => c.Identity == column.Identity)) return;
        var draft = new NativeEventPresetColumnDraft(column);
        draft.PropertyChanged += (_, _) => { if (!_loading) IsDirty = true; };
        Columns.Add(draft);
    }
    private void Load(NativeEventPreset p)
    {
        _loading = true;
        try
        {
            _id = p.Id; _expected = p.Revision; PresetName = p.Name; _references = p.Profiles;
            Columns.Clear(); foreach (var c in p.Columns) Add(c);
            Associate = p.Association != null; AssociationProvider = p.Association?.Provider ?? "";
            AssociationChannel = p.Association?.Channel ?? ""; AssociationEventId = p.Association?.EventId.ToString() ?? "";
            RefreshCategories(); IsDirty = false; OnPropertyChanged(nameof(ProfileRevisions));
        }
        finally { _loading = false; }
    }
    [RelayCommand] private void New()
    {
        if (!ReplaceDraft()) return;
        Load(new(Guid.NewGuid().ToString("N"), Guid.NewGuid(), "New preset", _currentProfiles(), _current(), null));
        _expected = null; IsDirty = true; Status = "New draft from this workspace's current visible columns.";
    }
    [RelayCommand] private void Edit() { if (ReplaceDraft() && SelectedPreset is { } p) { Load(p); Status = "Editing frozen saved layout. Profile updates require Update profile revisions."; } }
    [RelayCommand] private void Duplicate()
    {
        if (!ReplaceDraft() || SelectedPreset is not { } p) return;
        Load(p); _id = Guid.NewGuid().ToString("N"); _expected = null; PresetName += " (copy)";
        Associate = false; IsDirty = true; Status = "Independent copy; association disabled to avoid an accidental conflict.";
    }
    [RelayCommand] private void DiscardAndReload()
    {
        if (IsBusy) return;
        _store.Reload(); _profiles.Reload(); RefreshLists();
        SelectedPreset ??= Presets.FirstOrDefault();
        Load(SelectedPreset ?? new(Guid.NewGuid().ToString("N"), Guid.NewGuid(), "New preset", [], [], null));
        if (SelectedPreset == null) _expected = null;
        Status = _store.LoadError + " " + _profiles.LoadError;
    }
    [RelayCommand] private void AddProfile()
    {
        if (IsBusy || SelectedProfile is not { } profile) return;
        var categories = Enum.GetValues<NativeEventFieldPriority>().Where(c => c switch { NativeEventFieldPriority.High => High, NativeEventFieldPriority.Medium => Medium, _ => Low }).ToImmutableArray();
        if (_profiles.LoadError.Length > 0) { Status = _profiles.LoadError; return; }
        // Deliberately change the recipe; retain order/widths of surviving exact identities.
        _references = _references.Where(r => r.Id != profile.Id).ToImmutableArray();
        if (!categories.IsEmpty) _references = _references.Add(new(profile.Id, profile.Revision, categories));
        IsDirty = true;
        UpdateProfiles();
    }
    [RelayCommand] private void UpdateProfiles()
    {
        if (IsBusy) return;
        _profiles.Reload();
        if (_profiles.LoadError.Length > 0) { Status = _profiles.LoadError; return; }
        var profiles = _profiles.Snapshot().ToDictionary(p => p.Id, StringComparer.Ordinal);
        if (_references.Any(r => !profiles.ContainsKey(r.Id))) { Status = "A referenced profile is missing; draft retained."; return; }
        var resolved = _references.SelectMany(r => NativeEventPreset.Compose(profiles[r.Id], r.Categories)).DistinctBy(c => c.Identity).ToArray();
        var old = Columns.Select(c => c.Snapshot()).ToArray();
        Columns.Clear();
        foreach (var c in old.Where(c => c.Identity.EventType == null || resolved.Any(r => r.Identity == c.Identity)))
            Add(resolved.FirstOrDefault(r => r.Identity == c.Identity) is { } updated ? updated with { Width = c.Width } : c);
        foreach (var c in resolved) Add(c);
        _references = _references.Select(r => r with { Revision = profiles[r.Id].Revision }).ToImmutableArray();
        IsDirty = true; OnPropertyChanged(nameof(ProfileRevisions)); RefreshLists();
        Status = "Draft updated to current saved profiles; surviving columns retain order and widths. Save and apply explicitly.";
    }
    [RelayCommand] private void AddOrdinary() { if (!IsBusy) Add(new(new(SelectedOrdinaryColumn, null, null), SelectedOrdinaryColumn.ToString(), 180)); }
    [RelayCommand] private void AddManual()
    {
        if (IsBusy) return;
        var identity = new NativeEventColumnIdentity(null, null, ManualPath);
        try { identity.Validate(); Add(new(identity, ManualPath, 220)); }
        catch (FormatException ex) { Status = ex.Message; }
    }
    [RelayCommand] private void RemoveColumn() { if (!IsBusy && SelectedColumn is { } c) Columns.Remove(c); }
    [RelayCommand] private void MoveUp() => Move(-1);
    [RelayCommand] private void MoveDown() => Move(1);
    private void Move(int delta)
    {
        if (IsBusy || SelectedColumn is not { } c) return;
        var index = Columns.IndexOf(c); var target = index + delta;
        if (target >= 0 && target < Columns.Count) Columns.Move(index, target);
    }
    [RelayCommand] private void Apply()
    { if (!IsBusy && SelectedPreset is { } p) { _apply(p); Status = "Applied saved preset to this workspace. Draft edits are applied only after saving."; } }
    [RelayCommand] private Task SaveAsync() => SaveDraftAsync();
    internal async Task SaveDraftAsync(CancellationToken token = default)
    {
        if (IsBusy) return;
        try
        {
            NativeEventPresetAssociation? association = null;
            if (Associate)
            {
                if (!int.TryParse(AssociationEventId, out var id)) throw new FormatException("Enter the associated Event ID.");
                association = new(AssociationProvider.Length == 0 ? null : AssociationProvider, AssociationChannel.Length == 0 ? null : AssociationChannel, id);
            }
            var draft = new NativeEventPreset(_id, Guid.NewGuid(), PresetName, _references, Columns.Select(c => c.Snapshot()), association);
            IsBusy = true;
            var saved = await Task.Run(() => _store.Save(draft, _expected, token), token);
            RefreshLists(); SelectedPreset = Presets.Single(p => p.Id == saved.Id); Load(saved);
            Status = "Saved for this Windows user. Apply explicitly to change this workspace's layout.";
        }
        catch (OperationCanceledException) { Status = "Save canceled before commit; draft retained."; }
        catch (Exception ex) when (NativeEventProfileStore.IsExpected(ex)) { Status = ex.Message; }
        finally { IsBusy = false; }
    }
}
