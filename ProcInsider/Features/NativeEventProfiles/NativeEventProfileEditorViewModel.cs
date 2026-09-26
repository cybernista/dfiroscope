using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Services.Events;
using ProcInsider.Features.WindowsSecurityDetails;

namespace ProcInsider.Features.NativeEventProfiles;

internal partial class NativeEventProfileFieldDraft : ObservableObject
{
    public string Path { get; }
    [ObservableProperty] private string label;
    [ObservableProperty] private NativeEventFieldPriority priority;
    [ObservableProperty] private int order;
    [ObservableProperty] private bool isDefaultPriority;
    public string Classification => IsDefaultPriority ? "Medium (unclassified default)" : "Explicit";
    public NativeEventProfileFieldDraft(NativeEventProfileField field, bool isDefault = false)
    { Path = field.Path; label = field.Label; priority = field.Priority; order = field.Order; isDefaultPriority = isDefault; }
    partial void OnPriorityChanged(NativeEventFieldPriority value) => IsDefaultPriority = false;
    partial void OnIsDefaultPriorityChanged(bool value) => OnPropertyChanged(nameof(Classification));
    public NativeEventProfileField Snapshot() => new(Path, Label, Priority, Order);
}

/// <summary>One editor owns its draft and sample. The shared store publishes immutable saved revisions only.</summary>
internal partial class NativeEventProfileEditorViewModel : ObservableObject
{
    private readonly NativeEventProfileStore _store;
    private readonly EventFieldExtraction? _sample;
    private readonly Func<NativeEventType, bool> _allowsType;
    private SecurityDetailsDefinition? _legacy;
    public string LegacyDefinition => _legacy == null ? "No legacy definition for this selected event." :
        $"Preserved legacy definition for {_legacy.EventId}:\n{_legacy.Template}\n" +
        string.Join("\n", _legacy.Layouts.Select(l => $"Layout v{l.Version}: {string.Join(", ", l.Fields)}"));
    private string _id = Guid.NewGuid().ToString("N");
    private Guid? _expectedRevision;
    private bool _loading;
    private bool _changingSelection;
    public ObservableCollection<NativeEventProfile> Profiles { get; } = [];
    public ObservableCollection<NativeEventProfileFieldDraft> Fields { get; } = [];
    public Array Priorities => Enum.GetValues<NativeEventFieldPriority>();
    public string Coverage => NativeEventProfileDefaults.Coverage;
    public string SampleDescription => _sample?.EventType is { } type
        ? $"Selected event sample: {type.Provider} / {type.Channel} / {type.EventId} v{type.Version?.ToString() ?? "unknown"}. {_sample.Status}. {_sample.Diagnostic}"
        : "No extracted selected-event sample. Enter exact native scope and paths, or select an event before opening this editor.";
    private NativeEventProfile? selectedProfile;
    public NativeEventProfile? SelectedProfile
    {
        get => selectedProfile;
        set
        {
            if (_changingSelection || ReferenceEquals(value, selectedProfile)) return;
            if (IsBusy || value is null) return;
            if (IsDirty) { PendingProfile = value; return; }
            SelectAndLoad(value);
        }
    }
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasPendingProfile), nameof(PendingMessage))]
    private NativeEventProfile? pendingProfile;
    public bool HasPendingProfile => PendingProfile != null;
    public string PendingMessage => $"Unsaved changes. Switch to {PendingProfile?.Name}?";
    [ObservableProperty] private NativeEventProfileFieldDraft? selectedField;
    [ObservableProperty] private string profileName = "New profile";
    [ObservableProperty] private string provider = "Microsoft-Windows-Security-Auditing";
    [ObservableProperty] private string channel = "Security";
    [ObservableProperty] private string eventId = "";
    [ObservableProperty] private string version = "";
    [ObservableProperty] private string newPath = "";
    [ObservableProperty] private string status = "";
    [ObservableProperty] private bool isDirty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanEdit))] private bool isBusy;
    public bool CanEdit => !IsBusy;
    public string SavedOrigin => SelectedProfile is null ? "No saved profile selected" :
        (_store.IsBundled(SelectedProfile) ? "Bundled default" : "User profile (takes precedence over the same bundled ID)") +
        $"; {SelectedProfile.EventType.Provider} / {SelectedProfile.EventType.Channel} / {SelectedProfile.EventType.EventId} v{SelectedProfile.EventType.Version}";

    public NativeEventProfileEditorViewModel(NativeEventProfileStore store, EventFieldExtraction? sample, SecurityDetailsDefinition? legacy = null, string legacyError = "", Func<NativeEventType, bool>? allowsType = null)
    {
        _store = store; _sample = sample; _legacy = legacy; _allowsType = allowsType ?? (_ => true);
        PropertyChanged += (_, e) =>
        {
            if (!_loading && e.PropertyName is nameof(ProfileName) or nameof(Provider) or nameof(Channel) or nameof(EventId) or nameof(Version)) IsDirty = true;
        };
        RefreshList();
        SelectedProfile = Profiles.FirstOrDefault(p => p.Matches(sample?.EventType)) ?? Profiles.FirstOrDefault();
        if (SelectedProfile != null) Load(SelectedProfile);
        Status = string.Join(" ", new[] { store.LoadError, legacyError }.Where(s => s.Length > 0));
    }
    private void SetSelection(NativeEventProfile? profile)
    {
        _changingSelection = true;
        try { SetProperty(ref selectedProfile, profile, nameof(SelectedProfile)); OnPropertyChanged(nameof(SavedOrigin)); }
        finally { _changingSelection = false; }
    }
    private void SelectAndLoad(NativeEventProfile profile)
    {
        Load(profile); SetSelection(profile); PendingProfile = null;
        Status = "Editing saved revision. Priority describes usefulness, not severity.";
    }
    private void RefreshList()
    {
        var id = SelectedProfile?.Id;
        _changingSelection = true;
        try { Profiles.Clear(); foreach (var p in _store.Snapshot().Where(p => _allowsType(p.EventType))) Profiles.Add(p); }
        finally { _changingSelection = false; }
        SetSelection(Profiles.FirstOrDefault(p => p.Id == id));
        OnPropertyChanged(nameof(SelectedProfile));
    }
    [RelayCommand] private void KeepEditing() { if (!IsBusy) PendingProfile = null; }
    [RelayCommand] private void DiscardAndSwitch()
    {
        if (!IsBusy && PendingProfile is { } target) SelectAndLoad(target);
    }
    [RelayCommand] private Task SaveAndSwitchAsync() => SavePendingSwitchAsync();
    internal async Task SavePendingSwitchAsync(CancellationToken token = default)
    {
        if (IsBusy || PendingProfile is not { } target) return;
        await SaveDraftAsync(token);
        if (IsDirty) return;
        var current = Profiles.FirstOrDefault(p => p.Id == target.Id);
        if (current != null) SelectAndLoad(current);
        else { PendingProfile = null; Status = "Draft saved, but the requested profile is no longer available."; }
    }
    private bool CanReplaceDraft()
    {
        if (IsBusy) return false;
        if (!IsDirty) return true;
        Status = "Save the draft or use Discard draft / reload before replacing it."; return false;
    }
    private void AddDraft(NativeEventProfileField field, bool isDefault = false)
    {
        var draft = new NativeEventProfileFieldDraft(field, isDefault);
        draft.PropertyChanged += (_, _) => { if (!_loading) IsDirty = true; };
        Fields.Add(draft);
    }
    private void Load(NativeEventProfile profile)
    {
        _loading = true;
        try
        {
            _id = profile.Id; _expectedRevision = profile.Revision;
            ProfileName = profile.Name; Provider = profile.EventType.Provider; Channel = profile.EventType.Channel;
            EventId = profile.EventType.EventId.ToString(CultureInfo.InvariantCulture); Version = profile.EventType.Version!.Value.ToString(CultureInfo.InvariantCulture);
            Fields.Clear(); foreach (var field in profile.Fields) AddDraft(field);
            SelectedField = null; IsDirty = false;
        }
        finally { _loading = false; }
    }
    [RelayCommand] private void Edit()
    { if (CanReplaceDraft() && SelectedProfile is { } profile) { Load(profile); Status = "Editing saved revision. Priority describes usefulness, not severity."; } }
    [RelayCommand] private void New()
    {
        if (!CanReplaceDraft()) return;
        SetSelection(null); PendingProfile = null;
        _id = Guid.NewGuid().ToString("N"); _expectedRevision = null; Fields.Clear(); SelectedField = null;
        ProfileName = _sample?.EventType is { } type ? NativeEventProfileDefaults.SuggestName(type) : "New profile";
        Provider = _sample?.EventType?.Provider ?? "Microsoft-Windows-Security-Auditing";
        Channel = _sample?.EventType?.Channel ?? "Security";
        EventId = _sample?.EventType?.EventId.ToString(CultureInfo.InvariantCulture) ?? "";
        Version = _sample?.EventType?.Version?.ToString(CultureInfo.InvariantCulture) ?? "";
        IsDirty = true; Status = "New unsaved profile. Add observed fields or enter exact native paths. Unclassified fields default to Medium.";
        if (_sample?.EventType?.Version != null) AddObserved();
    }
    [RelayCommand] private void Duplicate()
    {
        if (!CanReplaceDraft() || SelectedProfile is not { } profile) return;
        Load(profile); _id = Guid.NewGuid().ToString("N"); _expectedRevision = null;
        SetSelection(null); PendingProfile = null;
        ProfileName += " (copy)"; IsDirty = true;
        Status = "Independent copy with its own ID. Scope stays exact; saved profiles can share a type without combining native fields.";
    }
    internal void LoadLegacyFile(string path)
    {
        if (!CanReplaceDraft()) return;
        try
        {
            var definitions = SecurityDetailsStore.ReadFile(path);
            if (_sample?.EventType is not { Version: not null } type ||
                type.Provider != SecurityDetailsTemplate.Provider || type.Channel != "Security" ||
                !definitions.TryGetValue(type.EventId, out var definition))
            { Status = "Select an extracted Security event with a known native version represented in this file. The draft and source file are unchanged."; return; }
            _legacy = definition;
            OnPropertyChanged(nameof(LegacyDefinition));
            ImportLegacyFields();
        }
        catch (Exception ex) when (SecurityDetailsStore.IsExpected(ex))
        { Status = "Previous definitions could not be imported. Source file and draft preserved. " + ex.Message; }
    }
    [RelayCommand] private void ImportLegacyFields()
    {
        if (!CanReplaceDraft()) return;
        if (_legacy == null || _sample?.EventType is not { Version: not null } type ||
            type.Provider != SecurityDetailsTemplate.Provider || type.Channel != "Security" || type.EventId != _legacy.EventId ||
            _sample.Status is not (EventFieldExtractionStatus.Available or EventFieldExtractionStatus.Partial))
        { Status = "Select an extracted Security event with an exact schema and a preserved legacy definition first."; return; }
        var template = SecurityDetailsTemplate.Compile(_legacy.Template);
        var translated = template.NamedReferences.Where(name => _sample.Fields.Count(f =>
            f.Path.StartsWith("EventData/" + Uri.EscapeDataString(name) + "[", StringComparison.Ordinal)) == 1)
            .Select(name => new NativeEventProfileField("EventData/" + Uri.EscapeDataString(name) + "[1]", name, NativeEventFieldPriority.High, 0)).ToArray();
        New();
        ProfileName = NativeEventProfileDefaults.SuggestName(type) + " — Legacy fields";
        Fields.Clear();
        for (var i = 0; i < translated.Length; i++) AddDraft(translated[i] with { Order = i });
        AddObserved();
        IsDirty = true;
        Status = $"Imported {translated.Length} unique observed named references as High into a new unsaved exact-schema profile. " +
            $"{template.NamedReferences.Count() - translated.Length} missing/ambiguous named references were not translated. " +
            (template.UsesPositions || _legacy.Layouts.Length > 0 ? "Positional references/layouts are not translated. " : "") +
            (template.HasLiterals ? "Literal text/layout formatting is not translated. " : "") +
            "The complete original remains available below and in the unchanged previous settings file. Save, then choose this Details profile in the workspace.";
    }
    [RelayCommand] private void DiscardAndReload()
    {
        if (IsBusy) return;
        PendingProfile = null;
        _store.Reload(); RefreshList();
        if ((SelectedProfile ?? Profiles.FirstOrDefault()) is { } profile) SelectAndLoad(profile);
        else { Fields.Clear(); _id = Guid.NewGuid().ToString("N"); _expectedRevision = null; IsDirty = false; }
        Status = _store.LoadError.Length > 0 ? _store.LoadError : "Draft discarded; saved profiles reloaded.";
    }
    private NativeEventType ReadType()
    {
        if (!int.TryParse(EventId, NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id is < 0 or > 65535 ||
            !int.TryParse(Version, NumberStyles.None, CultureInfo.InvariantCulture, out var version) || version is < 0 or > 255)
            throw new FormatException("Enter an exact event ID (0–65535) and native version (0–255). Unknown is not a wildcard.");
        var type = new NativeEventType(Provider, Channel, id, version);
        if (!_allowsType(type))
            throw new FormatException("This editor is limited to the native event source family available in its owning view.");
        return type;
    }
    [RelayCommand] private void AddObserved()
    {
        if (IsBusy) return;
        try
        {
            if (_sample is null || _sample.EventType != ReadType()) throw new FormatException("The selected-event sample must match all four scope values exactly.");
            var known = Fields.Select(f => f.Path).ToHashSet(StringComparer.Ordinal);
            foreach (var field in _sample.Fields.Where(f => !known.Contains(f.Path)))
            {
                if (Fields.Count >= NativeEventFieldExtractor.MaximumFields) throw new FormatException("At most 512 profile fields are supported.");
                AddDraft(new(field.Path, DefaultLabel(field.Path), NativeEventFieldPriority.Medium, NextOrder()), true); IsDirty = true;
            }
            Status = "Added missing observed paths as Medium (unclassified default). Existing classifications and every native occurrence are retained.";
        }
        catch (FormatException ex) { Status = ex.Message; }
    }
    private int NextOrder() => Fields.Count == 0 ? 0 : Math.Min(65535, Fields.Max(f => f.Order) + 1);
    private static string DefaultLabel(string path) => path.Length <= 256 ? path : path[..255] + "…";
    [RelayCommand] private void AddField()
    {
        if (IsBusy) return;
        try
        {
            var field = new NativeEventProfileField(NewPath, DefaultLabel(NewPath), NativeEventFieldPriority.Medium, NextOrder());
            _ = new NativeEventProfile(_id, Guid.NewGuid(), ProfileName, ReadType(), Fields.Select(f => f.Snapshot()).Append(field));
            AddDraft(field, true); NewPath = ""; IsDirty = true;
        }
        catch (FormatException ex) { Status = ex.Message; }
    }
    [RelayCommand] private void RemoveField()
    { if (!IsBusy && SelectedField is { } field) { Fields.Remove(field); SelectedField = null; IsDirty = true; } }
    [RelayCommand] private void MoveUp() => Move(-1);
    [RelayCommand] private void MoveDown() => Move(1);
    private void Move(int delta)
    {
        if (IsBusy || SelectedField is not { } field) return;
        var index = Fields.IndexOf(field); var target = index + delta;
        if (target < 0 || target >= Fields.Count) return;
        Fields.Move(index, target);
        for (var i = 0; i < Fields.Count; i++) Fields[i].Order = i;
        IsDirty = true;
    }
    [RelayCommand] private Task SaveAsync() => SaveDraftAsync();
    internal async Task SaveDraftAsync(CancellationToken token = default)
    {
        if (IsBusy) return;
        try
        {
            token.ThrowIfCancellationRequested();
            var draft = new NativeEventProfile(_id, Guid.NewGuid(), ProfileName, ReadType(), Fields.Select(f => f.Snapshot()));
            IsBusy = true;
            var saved = await Task.Run(() => _store.Save(draft, _expectedRevision, token), token);
            RefreshList(); Load(saved); SetSelection(Profiles.Single(p => p.Id == saved.Id));
            PendingProfile = null;
            Status = "Saved for this Windows user across captures and Viewer restarts. Previous definition files remain unchanged.";
        }
        catch (OperationCanceledException) { Status = "Save canceled before commit; draft retained."; }
        catch (Exception ex) when (NativeEventProfileStore.IsExpected(ex)) { Status = ex.Message; }
        finally { IsBusy = false; }
    }
}
