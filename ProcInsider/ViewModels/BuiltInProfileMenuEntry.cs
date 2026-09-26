using System.Collections.ObjectModel;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed record BuiltInProfileMenuEntry(
    string Header,
    ConfigProfileKind Kind,
    ConfigProfileDefinition? Profile = null)
{
    public string ToolTip => Profile?.Description ?? "Open the existing bundled profile folder.";
}

public sealed class BuiltInProfileMenuGroup : ViewModelBase
{
    private bool _isAvailable;

    public BuiltInProfileMenuGroup(ConfigProfileKind kind) => Kind = kind;

    public ConfigProfileKind Kind { get; }
    public ObservableCollection<BuiltInProfileMenuEntry> Entries { get; } = new();
    public bool IsAvailable
    {
        get => _isAvailable;
        private set => SetProperty(ref _isAvailable, value);
    }

    public void Replace(IEnumerable<ConfigProfileDefinition> profiles)
    {
        Entries.Clear();
        foreach (var profile in profiles)
            Entries.Add(new(string.IsNullOrWhiteSpace(profile.DisplayName) ? profile.Id : profile.DisplayName,
                Kind, profile));
        IsAvailable = Entries.Count > 0;
        if (IsAvailable) Entries.Add(new("Open profile folder", Kind));
    }
}
