using System.Windows;
using ProcInsider.ViewModels;

namespace ProcInsider;

public partial class WindowsSettingsTransferDialog : Window
{
    private readonly Func<string, Task>? _browse;
    public WindowsSettingsTransferDialog(WindowsSettingsTransferViewModel settings, Func<string, Task>? browse = null)
    {
        _browse = browse;
        Settings = settings;
        DataContext = settings;
        InitializeComponent();
    }
    public WindowsSettingsTransferViewModel Settings { get; }
    private void Backup_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        // A new backup always requires a fresh review acknowledgement.
        if (Acknowledgement != null) Acknowledgement.IsChecked = false;
    }
    private async void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        { Title = "Choose a saved configuration folder", InitialDirectory = Settings.BackupDirectory, Multiselect = false };
        if (_browse == null || dialog.ShowDialog(this) != true) return;
        IsEnabled = false;
        try { await _browse(dialog.FolderName); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Cannot read saved configuration", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { IsEnabled = true; }
    }
    private void Accept_Click(object sender, RoutedEventArgs e)
    {
        if (Settings.IsLoading && Acknowledgement.IsChecked != true) return;
        if (!Settings.CanRestore) return;
        if (Settings.SelectedAreas.Length == 0)
        {
            MessageBox.Show(this, "Select at least one available configuration area.", Settings.Title);
            return;
        }
        DialogResult = true;
    }
}
