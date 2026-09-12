using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.WindowsSecurityDetails;

public interface ISecurityDetailsDialogs
{
    string? ChooseImport();
    string? ChooseExport();
    bool ConfirmDiscard();
}

public partial class SecurityDefinitionRow : ObservableObject
{
    private readonly SecurityDetailsEditorViewModel _owner;
    internal SecurityDetailsDefinition Saved { get; private set; }
    private readonly bool _newRow;
    [ObservableProperty] private string template;
    [ObservableProperty] private string error = "";
    [ObservableProperty] private bool isSaved;
    public int EventId => Saved.EventId;
    public bool IsDirty => !IsSaved || Template != Saved.Template;
    public SecurityDefinitionRow(SecurityDetailsDefinition definition, SecurityDetailsEditorViewModel owner, bool isNew = false)
    { Saved = definition; template = definition.Template; _owner = owner; _newRow = isNew; isSaved = !isNew; }
    partial void OnTemplateChanged(string value) { OnPropertyChanged(nameof(IsDirty)); _owner.UpdatePreview(); }
    [RelayCommand] private Task SaveAsync() => _owner.SaveAsync(this);
    [RelayCommand] private void Revert()
    {
        if (_owner.IsBusy) return;
        if (_newRow && !IsSaved) _owner.Rows.Remove(this);
        else Template = Saved.Template;
        Error = "";
    }
    internal void Accept(SecurityDetailsDefinition definition)
    { Saved = definition; IsSaved = true; Template = definition.Template; Error = ""; OnPropertyChanged(nameof(IsDirty)); }
}

public partial class SecurityDetailsEditorViewModel : ObservableObject
{
    private readonly SecurityDetailsStore _store;
    private readonly ISecurityDetailsDialogs _dialogs;
    private Dictionary<int, SecurityEventPayload> _samples = new();
    public Task SamplesTask { get; }
    public ObservableCollection<SecurityDefinitionRow> Rows { get; } = new();
    [ObservableProperty] private SecurityDefinitionRow? selectedRow;
    [ObservableProperty] private string newEventId = "";
    [ObservableProperty] private string status = "";
    [ObservableProperty] private string preview = "Select a definition to preview it.";
    [ObservableProperty] private string fieldGuide = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanEdit))] private bool isBusy;
    public bool CanEdit => !IsBusy;

    public SecurityDetailsEditorViewModel(SecurityDetailsStore store, ISecurityDetailsDialogs dialogs, Func<EventRowViewModel[]> samples)
    {
        _store = store; _dialogs = dialogs; Reload(); Status = store.LoadError;
        SamplesTask = LoadSamplesAsync(samples());
    }

    private async Task LoadSamplesAsync(EventRowViewModel[] rows)
    {
        _samples = await Task.Run(() =>
        {
            var samples = new Dictionary<int, SecurityEventPayload>();
            foreach (var row in rows)
                if (row.EventCode is int id && !samples.ContainsKey(id) && SecurityDetailsTemplate.Parse(row.Details, id) is { } payload)
                    samples.Add(id, payload);
            return samples;
        });
        UpdatePreview();
    }

    private void Reload()
    {
        var selected = SelectedRow?.EventId;
        Rows.Clear();
        foreach (var definition in _store.Snapshot()) Rows.Add(new(definition, this));
        SelectedRow = Rows.FirstOrDefault(r => r.EventId == selected) ?? Rows.FirstOrDefault();
    }
    partial void OnSelectedRowChanged(SecurityDefinitionRow? value) => UpdatePreview();
    private SecurityEventPayload? Sample(int eventId) => _samples.GetValueOrDefault(eventId);

    public void UpdatePreview()
    {
        if (SelectedRow is not { } row) { Preview = "Select a definition to preview it."; FieldGuide = ""; return; }
        var sample = Sample(row.EventId);
        FieldGuide = sample is null ? "No eligible sample in the currently loaded process events. Named fields can still be saved."
            : $"Captured version {sample.Version}; positions count from 1.\n" +
              string.Join("\n", sample.Fields.Select((f, i) => $"${i + 1}   ${f.Name}$"));
        try
        {
            var formatter = SecurityDetailsTemplate.Compile(row.Template);
            Preview = sample is null ? "No sample is available for this event ID."
                : formatter.Format(sample, row.Saved.Layouts);
            if (formatter.UsesPositions && sample != null && row.IsDirty)
                Preview += "\nSave will validate and register this captured version/layout for positional fields.";
        }
        catch (FormatException ex) { Preview = ex.Message; }
    }

    [RelayCommand] private void Add()
    {
        if (IsBusy) return;
        if (!int.TryParse(NewEventId, out var id) || id is < 0 or > 65535) { Status = "Enter an event ID between 0 and 65535."; return; }
        var existing = Rows.FirstOrDefault(r => r.EventId == id);
        if (existing != null) { SelectedRow = existing; Status = "This event ID already has a row."; return; }
        var row = new SecurityDefinitionRow(new(id, "", []), this, true);
        var index = Rows.TakeWhile(r => r.EventId < id).Count();
        Rows.Insert(index, row); SelectedRow = row; NewEventId = ""; Status = "Enter a definition and save its row.";
    }

    public async Task SaveAsync(SecurityDefinitionRow row)
    {
        if (IsBusy) return;
        try
        {
            var formatter = SecurityDetailsTemplate.Compile(row.Template);
            var layouts = row.Saved.Layouts;
            if (formatter.UsesPositions)
            {
                var sample = Sample(row.EventId);
                if (sample != null)
                    layouts = layouts.Where(l => l.Version != sample.Version).Append(new(sample.Version, sample.Fields.Select(f => f.Name).ToArray())).ToArray();
                if (layouts.Length == 0) throw new FormatException("Positional fields need a captured sample or an imported validated layout. Use named fields when no sample is available.");
            }
            var definition = new SecurityDetailsDefinition(row.EventId, row.Template, layouts);
            IsBusy = true;
            await Task.Run(() => _store.Save(definition));
            row.Accept(definition); UpdatePreview(); Status = $"Saved event {row.EventId} for all captures.";
        }
        catch (Exception ex) when (SecurityDetailsStore.IsExpected(ex)) { row.Error = ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand] private async Task ImportAsync()
    {
        if (IsBusy) return;
        if (Rows.Any(r => r.IsDirty)) { Status = "Save or revert unsaved rows before importing."; return; }
        var path = _dialogs.ChooseImport();
        if (path is null) return;
        IsBusy = true;
        try { await Task.Run(() => _store.Import(path)); Reload(); Status = "Imported definitions. Event IDs omitted from the file kept their saved definitions."; }
        catch (Exception ex) when (SecurityDetailsStore.IsExpected(ex)) { Status = ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand] private async Task ExportAsync()
    {
        if (IsBusy) return;
        var path = _dialogs.ChooseExport();
        if (path is null) return;
        IsBusy = true;
        try { await Task.Run(() => _store.Export(path)); Status = "Exported the saved table. Unsaved drafts and captured values are excluded."; }
        catch (Exception ex) when (SecurityDetailsStore.IsExpected(ex)) { Status = ex.Message; }
        finally { IsBusy = false; }
    }

    public bool CanClose() => !IsBusy && (!Rows.Any(r => r.IsDirty) || _dialogs.ConfirmDiscard());
}
