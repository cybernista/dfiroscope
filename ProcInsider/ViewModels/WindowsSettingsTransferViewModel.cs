using System.Collections.ObjectModel;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public sealed class WindowsSettingsTransferViewModel : ViewModelBase
{
    public WindowsSettingsTransferViewModel(WindowsSecuritySettingsSnapshot? snapshot = null)
    {
        IsLoading = snapshot != null;
        SetSnapshot(snapshot);
    }

    public WindowsSettingsTransferViewModel(IEnumerable<WindowsSettingsFolderEntry> backups, string directory, string error = "")
    {
        IsLoading = true;
        HasBackupPicker = true;
        BackupDirectory = directory;
        DiscoveryStatus = error;
        foreach (var backup in backups) Backups.Add(new(backup));
        SelectedBackup = Backups.FirstOrDefault(b => b.Entry.IsAvailable) ?? Backups.FirstOrDefault();
        if (SelectedBackup == null) SetSnapshot(null);
        if (string.IsNullOrEmpty(DiscoveryStatus)) DiscoveryStatus = Backups.Count == 0
            ? "No saved configurations found here. Use Browse to choose a saved configuration folder."
            : $"{Backups.Count} saved folder(s), newest first. Times are shown in your local time zone.";
    }

    public bool HasBackupPicker { get; }
    public string BackupDirectory { get; } = string.Empty;
    public string DiscoveryStatus { get; } = string.Empty;
    public ObservableCollection<WindowsSettingsBackupChoice> Backups { get; } = [];
    private WindowsSettingsBackupChoice? _selectedBackup;
    public WindowsSettingsBackupChoice? SelectedBackup
    {
        get => _selectedBackup;
        set
        {
            if (SetProperty(ref _selectedBackup, value))
            {
                SetSnapshot(value?.Entry.Snapshot);
                OnPropertyChanged(nameof(CanRestore));
            }
        }
    }
    public bool CanRestore => !IsLoading || (HasBackupPicker ? SelectedBackup?.Entry.IsAvailable == true : Areas.Any(a => a.IsAvailable));
    public void AddBackup(WindowsSettingsFolderEntry entry)
    {
        var previous = Backups.FirstOrDefault(b => string.Equals(b.Entry.FolderPath, entry.FolderPath, StringComparison.OrdinalIgnoreCase));
        if (previous != null) Backups.Remove(previous);
        var choice = new WindowsSettingsBackupChoice(entry);
        var ordered = Backups.Append(choice).OrderByDescending(b => b.Entry.Snapshot?.CapturedAtUtc ?? DateTime.MinValue).ToArray();
        Backups.Clear();
        foreach (var item in ordered) Backups.Add(item);
        SelectedBackup = choice;
    }

    private void SetSnapshot(WindowsSecuritySettingsSnapshot? snapshot)
    {
        Areas.Clear();
        foreach (var (area, name) in new (WindowsSecuritySettingsArea, string)[]
        {
            (WindowsSecuritySettingsArea.AuditPolicy, "system audit policy"),
            (WindowsSecuritySettingsArea.CommandLine, "process command-line logging settings"),
            (WindowsSecuritySettingsArea.EventLogChannel, "Security event log channel settings"),
            (WindowsSecuritySettingsArea.EventLogRetention, "Security event log retention settings"),
            (WindowsSecuritySettingsArea.UserFolderAuditing, "user-folder auditing settings"),
            (WindowsSecuritySettingsArea.RegistryAuditing, "registry auditing settings")
        })
            Areas.Add(new(area, (IsLoading ? "Restore " : "Save ") + name, !IsLoading || snapshot?.HasArea(area) == true));
        Details = !IsLoading
            ? "Saving configuration reads this computer's current supported settings, including disabled values. It does not change Windows settings. Each save creates a new hostname/timestamp subfolder under the location chosen in the save dialog."
            : snapshot == null ? (_selectedBackup?.Entry.Error ?? "Select a saved configuration to review its contents.")
            : $"Saved on {snapshot.ComputerName} at {snapshot.CapturedAtUtc.ToLocalTime():f}. Missing settings areas are disabled. " +
                (snapshot.UserFolderAuditing != null || snapshot.RegistryAuditing != null
                    ? "Object-auditing settings require matching objects and verified recovery state. Conflicts are reported without claiming a successful restore. " : string.Empty) +
                string.Join("; ", snapshot.Gaps.Concat(snapshot.UserFolderAuditing?.ScopeNotes ?? []).Concat(snapshot.RegistryAuditing?.ScopeNotes ?? []));
        if (_selectedBackup != null) Details += Environment.NewLine + Environment.NewLine + "Folder: " + _selectedBackup.Entry.FolderPath;
        OnPropertyChanged(nameof(Details));
    }
    public bool IsLoading { get; }
    public string Title => IsLoading ? "Restore saved config" : "Save current computer configuration";
    public string ActionLabel => IsLoading ? "Restore selected settings" : "Save selected settings...";
    public string Details { get; private set; } = string.Empty;
    public ObservableCollection<WindowsSettingsAreaSelection> Areas { get; } = [];
    public WindowsSecuritySettingsArea[] SelectedAreas => Areas.Where(a => a.IsAvailable && a.IsSelected).Select(a => a.Area).ToArray();
}

public sealed record WindowsSettingsBackupChoice(WindowsSettingsFolderEntry Entry)
{
    public string Label => Entry.Snapshot is { } snapshot
        ? $"{snapshot.CapturedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss.fff} — {snapshot.ComputerName} — {snapshot.Areas.Length} settings {(snapshot.Areas.Length == 1 ? "area" : "areas")}"
        : "Unavailable — " + System.IO.Path.GetFileName(Entry.FolderPath);
}

public sealed class WindowsSettingsAreaSelection(WindowsSecuritySettingsArea area, string label, bool available)
{
    public WindowsSecuritySettingsArea Area { get; } = area;
    public string Label { get; } = label;
    public bool IsAvailable { get; } = available;
    public bool IsSelected { get; set; } = available;
}
