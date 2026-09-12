using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Shared;

public partial class ColumnHeaderFilterControl : UserControl
{
    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(nameof(Title), typeof(string), typeof(ColumnHeaderFilterControl));
    public static readonly DependencyProperty FilterProperty = DependencyProperty.Register(nameof(Filter), typeof(ColumnFilterViewModel), typeof(ColumnHeaderFilterControl));
    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public ColumnFilterViewModel? Filter { get => (ColumnFilterViewModel?)GetValue(FilterProperty); set => SetValue(FilterProperty, value); }
    public ColumnHeaderFilterControl() { InitializeComponent(); Unloaded += (_, _) => Filter?.Close(); }
    private async void OpenFilter(object sender, RoutedEventArgs e) { e.Handled = true; if (Filter != null) await Filter.OpenAsync(); }
    private void PopupClosed(object? sender, EventArgs e) => Filter?.Close();
    private void PopupOpened(object? sender, EventArgs e) => FilterPopup.Child?.MoveFocus(new TraversalRequest(FocusNavigationDirection.First));
    private void PopupKeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Escape) { Filter?.Close(); FilterButton.Focus(); e.Handled = true; } }
}

public sealed class ColumnFilterLookupConverter : IMultiValueConverter
{
    public object? Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        => values.Length == 2 && values[0] is IReadOnlyDictionary<string, ColumnFilterViewModel> filters && values[1] is string key && filters.TryGetValue(key, out var filter) ? filter : null;
    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
