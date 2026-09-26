using CommunityToolkit.Mvvm.ComponentModel;

namespace ProcInsider.ViewModels;

/// <summary>Transient display choices owned by one investigation, keyed by the listing's stable sort members.</summary>
public sealed class ListingColumnSettings
{
    private readonly Dictionary<string, ListingColumnChoice> _columns = new(StringComparer.Ordinal);

    public ListingColumnChoice GetColumn(string key)
    {
        if (!_columns.TryGetValue(key, out var choice)) _columns.Add(key, choice = new());
        return choice;
    }
}

public sealed class ListingColumnChoice : ObservableObject
{
    private bool _isVisible = true;
    public bool IsVisible { get => _isVisible; set => SetProperty(ref _isVisible, value); }
}
