using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using ProcInsider.Services.Events;

namespace ProcInsider.Features.NativeEventProfiles;

public partial class NativeEventProfileEditorWindow : Window
{
    public NativeEventProfileEditorWindow() => InitializeComponent();
    private void OnProfileSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DataContext is not NativeEventProfileEditorViewModel editor || sender is not ListBox list) return;
        editor.SelectedProfile = list.SelectedItem as NativeEventProfile;
        // WPF selection is a request; an unsaved draft keeps its current selection until resolved.
        list.SetCurrentValue(Selector.SelectedItemProperty, editor.SelectedProfile);
    }
    private void OnImportPreviousFile(object sender, RoutedEventArgs e)
    {
        if (DataContext is not NativeEventProfileEditorViewModel editor || editor.IsBusy) return;
        var picker = new Microsoft.Win32.OpenFileDialog { Filter = "Previous Details definitions (*.json)|*.json", CheckFileExists = true };
        if (picker.ShowDialog(this) == true) editor.LoadLegacyFile(picker.FileName);
    }
    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (DataContext is not NativeEventProfileEditorViewModel editor) return;
        e.Cancel = editor.IsBusy || (editor.IsDirty && MessageBox.Show(this,
            "Discard unsaved profile edits? Saved profiles will remain available.", "Unsaved profile",
            MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes);
    }
}
