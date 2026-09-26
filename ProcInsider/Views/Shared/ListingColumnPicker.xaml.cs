using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Shared;

/// <summary>WPF bridge: combines analyst choices with the columns' existing publication bindings.</summary>
public partial class ListingColumnPicker : UserControl
{
    public static readonly DependencyProperty GridProperty = DependencyProperty.Register(
        nameof(Grid), typeof(DataGrid), typeof(ListingColumnPicker), new PropertyMetadata(null, Rebind));
    public static readonly DependencyProperty SettingsProperty = DependencyProperty.Register(
        nameof(Settings), typeof(ListingColumnSettings), typeof(ListingColumnPicker), new PropertyMetadata(null, Rebind));
    public static readonly DependencyProperty AvailableVisibilityProperty = DependencyProperty.RegisterAttached(
        "AvailableVisibility", typeof(Visibility), typeof(ListingColumnPicker), new PropertyMetadata(Visibility.Collapsed));
    public static Visibility GetAvailableVisibility(DependencyObject value) => (Visibility)value.GetValue(AvailableVisibilityProperty);
    public static void SetAvailableVisibility(DependencyObject value, Visibility visibility) => value.SetValue(AvailableVisibilityProperty, visibility);
    public DataGrid? Grid { get => (DataGrid?)GetValue(GridProperty); set => SetValue(GridProperty, value); }
    public ListingColumnSettings? Settings { get => (ListingColumnSettings?)GetValue(SettingsProperty); set => SetValue(SettingsProperty, value); }
    private readonly List<ColumnEntry> _entries = [];

    public ListingColumnPicker()
    {
        InitializeComponent();
        Loaded += (_, _) => BindColumns();
        Unloaded += (_, _) => DetachColumns();
    }

    private static void Rebind(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        var picker = (ListingColumnPicker)sender;
        picker.DetachColumns();
        if (picker.IsLoaded) picker.BindColumns();
    }

    private void BindColumns()
    {
        DetachColumns();
        if (Grid == null || Settings == null) return;
        foreach (var column in Grid.Columns)
        {
            if (string.IsNullOrEmpty(column.SortMemberPath)) continue;
            var entry = new ColumnEntry(column, Settings.GetColumn(column.SortMemberPath),
                BindingOperations.GetBindingBase(column, DataGridColumn.VisibilityProperty),
                column.ReadLocalValue(DataGridColumn.VisibilityProperty));
            _entries.Add(entry);
            // Preserve the original binding and its source. Visibility can never exceed publication eligibility.
            if (entry.OriginalBinding != null)
                BindingOperations.SetBinding(column, AvailableVisibilityProperty, entry.OriginalBinding);
            else SetAvailableVisibility(column, column.Visibility);
            var visibility = new MultiBinding { Converter = ColumnVisibilityConverter.Instance };
            visibility.Bindings.Add(new Binding { Source = column, Path = new PropertyPath(AvailableVisibilityProperty) });
            visibility.Bindings.Add(new Binding(nameof(ListingColumnChoice.IsVisible)) { Source = entry.Choice });
            BindingOperations.SetBinding(column, DataGridColumn.VisibilityProperty, visibility);
        }
        ColumnMenu.ItemsSource = _entries;
    }

    private void DetachColumns()
    {
        ColumnMenu.IsOpen = false;
        ColumnMenu.ItemsSource = null;
        foreach (var entry in _entries)
        {
            if (entry.OriginalBinding != null)
                BindingOperations.SetBinding(entry.Column, DataGridColumn.VisibilityProperty, entry.OriginalBinding);
            else if (entry.OriginalValue == DependencyProperty.UnsetValue)
                entry.Column.ClearValue(DataGridColumn.VisibilityProperty);
            else entry.Column.SetValue(DataGridColumn.VisibilityProperty, entry.OriginalValue);
            entry.Column.ClearValue(AvailableVisibilityProperty);
        }
        _entries.Clear();
    }

    private void OpenColumns(object sender, RoutedEventArgs args)
    {
        ColumnMenu.PlacementTarget = (Button)sender;
        ColumnMenu.Placement = PlacementMode.Bottom;
        ColumnMenu.IsOpen = true;
    }

    private sealed record ColumnEntry(DataGridColumn Column, ListingColumnChoice Choice, BindingBase? OriginalBinding, object OriginalValue);

    private sealed class ColumnVisibilityConverter : IMultiValueConverter
    {
        internal static readonly ColumnVisibilityConverter Instance = new();
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) =>
            values is [Visibility.Visible, true] ? Visibility.Visible : Visibility.Collapsed;
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }
}
