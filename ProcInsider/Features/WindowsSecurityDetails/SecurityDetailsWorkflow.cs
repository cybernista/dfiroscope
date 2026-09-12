using System.Windows;
using Microsoft.Win32;
using ProcInsider.Services;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.WindowsSecurityDetails;

/// <summary>Published Security module owns configuration, dialog lifetime and revision notifications.</summary>
public sealed class SecurityDetailsWorkflow : IDisposable
{
    private readonly EventsViewModel _events;
    private readonly SecurityDetailsStore _store;
    private bool _disposed;
    public SecurityDetailsWorkflow(EventsViewModel events)
    {
        _events = events;
        _store = new SecurityDetailsStore(SessionPathService.GetWindowsSecurityDetailsDefinitionsPath());
        _events.ConfigureSecurityDetails(_store);
        _store.Changed += OnChanged;
    }
    private void OnChanged(object? sender, EventArgs e) { if (!_disposed) _events.RefreshSecurityDetails(); }
    public void ShowEditor(Window? owner)
    {
        if (_disposed) return;
        var dialog = new SecurityDetailsEditorWindow { Owner = owner };
        dialog.DataContext = new SecurityDetailsEditorViewModel(_store, new Dialogs(dialog), () => _events.Events.ToArray());
        dialog.ShowDialog();
    }
    public void Dispose() { _disposed = true; _store.Changed -= OnChanged; }

    private sealed class Dialogs(Window owner) : ISecurityDetailsDialogs
    {
        public string? ChooseImport()
        {
            var picker = new OpenFileDialog { Filter = "Details definitions (*.json)|*.json", CheckFileExists = true };
            return picker.ShowDialog(owner) == true ? picker.FileName : null;
        }
        public string? ChooseExport()
        {
            var picker = new SaveFileDialog { Filter = "Details definitions (*.json)|*.json", FileName = "windows-security-details.json", DefaultExt = ".json", AddExtension = true };
            return picker.ShowDialog(owner) == true ? picker.FileName : null;
        }
        public bool ConfirmDiscard() => MessageBox.Show(owner, "Discard unsaved definition edits? Saved definitions will remain in force.",
            "Unsaved definitions", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
    }
}
