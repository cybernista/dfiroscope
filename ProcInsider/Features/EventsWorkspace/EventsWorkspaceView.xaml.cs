using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Controls.Primitives;

namespace ProcInsider.Features.InvestigationWorkspaces;

public partial class EventsWorkspaceView : UserControl
{
    private EventsWorkspaceViewModel? _owner;
    private readonly Dictionary<string, (object Header, DataGridLength Width, int Order)> _ordinaryDefaults = new(StringComparer.Ordinal);
    public EventsWorkspaceView()
    {
        InitializeComponent();
        foreach (var column in EventsGrid.Columns.OfType<DataGridTextColumn>()) column.ElementStyle = (Style)FindResource("ListingValue");
        ExtractedFieldsPopup.Closed += (_, _) => _owner?.FieldChooser.Close();
        foreach (var column in EventsGrid.Columns.Where(c => c != HighlightsColumn)) _ordinaryDefaults.Add(column.SortMemberPath, (column.Header, column.Width, EventsGrid.Columns.IndexOf(column)));
        ProfilesButton.Click += (_, _) => (DataContext as EventsWorkspaceViewModel)?.ShowProfiles(Window.GetWindow(this));
        UseDetailsProfileButton.Click += (_, _) => (DataContext as EventsWorkspaceViewModel)?.UseDetailsProfile();
        PresetsButton.Click += (_, _) => { Capture(); (DataContext as EventsWorkspaceViewModel)?.ShowPresets(Window.GetWindow(this)); };
        EventsGrid.ColumnReordered += (_, _) =>
        {
            if (_restoring || _updatingColumns) return;
            if (_owner != null) _owner.HasCustomColumnOrder = true;
            HighlightsColumn.DisplayIndex = 0; CaptureColumns();
        };
        Loaded += (_, _) =>
        {
            _owner ??= DataContext as EventsWorkspaceViewModel;
            if (_owner != null) { _owner.PropertyChanged -= OwnerChanged; _owner.PropertyChanged += OwnerChanged; }
            Restore();
        };
        Unloaded += (_, _) => { Capture(); ExtractedFieldsPopup.IsOpen = false; if (_owner != null) _owner.PropertyChanged -= OwnerChanged; };
        DataContextChanged += (_, _) =>
        {
            Capture();
            ExtractedFieldsPopup.IsOpen = false;
            if (_owner != null) _owner.PropertyChanged -= OwnerChanged;
            _owner = DataContext as EventsWorkspaceViewModel;
            if (IsLoaded && _owner != null) _owner.PropertyChanged += OwnerChanged;
            Restore();
        };
        AddHandler(ScrollViewer.ScrollChangedEvent, new ScrollChangedEventHandler((_, _) => CapturePosition()));
        AddHandler(System.Windows.Controls.Primitives.Thumb.DragCompletedEvent,
            new System.Windows.Controls.Primitives.DragCompletedEventHandler((_, _) => Capture()));
    }
    private static IEnumerable<T> Children<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T typed) yield return typed;
            foreach (var nested in Children<T>(child)) yield return nested;
        }
    }
    private bool _restoring;
    private void OwnerChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(EventsWorkspaceViewModel.Sort) or nameof(EventsWorkspaceViewModel.Descending) or nameof(EventsWorkspaceViewModel.ExtractedSort)) UpdateSortIndicators();
        if (e.PropertyName == nameof(EventsWorkspaceViewModel.SelectedExtractedFields)) UpdateExtractedColumns();
        if (e.PropertyName == nameof(EventsWorkspaceViewModel.PresetColumns)) { UpdateExtractedColumns(); RestoreColumns(); }
        if (e.PropertyName == nameof(EventsWorkspaceViewModel.LoadedBinding)) ExtractedFieldsPopup.IsOpen = false;
    }
    private readonly Dictionary<string, DataGridColumn> _extractedColumns = new(StringComparer.Ordinal);
    private bool _updatingColumns;
    private void UpdateExtractedColumns()
    {
        _updatingColumns = true;
        try
        {
        var selected = _owner?.DisplayExtractedColumns.ToDictionary(c => c.Identity.Key, StringComparer.Ordinal) ?? [];
        var membershipChanged = !_extractedColumns.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(selected.Keys);
        foreach (var path in _extractedColumns.Keys.Where(path => !selected.ContainsKey(path)).ToArray())
        { EventsGrid.Columns.Remove(_extractedColumns[path]); _extractedColumns.Remove(path); }
        foreach (var pair in selected)
        {
            var path = pair.Key;
            var definition = pair.Value;
            if (_extractedColumns.TryGetValue(path, out var existing)) { existing.Header = _owner!.ExtractedHeader(definition); continue; }
            // A MultiBinding avoids WPF inferring a sortable member from the value binding;
            // the ordinary Fields picker admits only columns with a SortMemberPath.
            var binding = new MultiBinding { Mode = BindingMode.OneWay, Converter = ExtractedEventFieldValueConverter.Instance, ConverterParameter = definition.Identity };
            binding.Bindings.Add(new Binding(nameof(EventsWorkspaceRowViewModel.Extraction)));
            var column = new DataGridTextColumn
            {
                Header = _owner!.ExtractedHeader(definition), Width = _owner.GridColumns.FirstOrDefault(c => c.Key == path)?.Width ?? definition.Width, CanUserSort = true,
                Binding = binding,
                ElementStyle = (Style)FindResource("ListingValue"),
                HeaderStyle = new Style(typeof(DataGridColumnHeader), (Style)FindResource("ColumnFilterHeaderStyle")) { Setters =
                {
                    new Setter(ToolTipProperty, definition.Identity.Description),
                    new Setter(ContentControl.ContentTemplateProperty, FindResource("ExtractedColumnHeaderTemplate"))
                } }
            };
            _extractedColumns.Add(path, column); EventsGrid.Columns.Add(column);
        }
        if (membershipChanged && _owner?.HasCustomColumnOrder == true) RestoreColumns();
        else if (membershipChanged && _owner?.PresetColumns.Count == 0 && !_owner.KeepCurrentLayout)
        {
            var index = EventsGrid.Columns.Count - selected.Count;
            foreach (var key in selected.Keys) _extractedColumns[key].DisplayIndex = index++;
        }
        UpdateSortIndicators();
        }
        finally { _updatingColumns = false; }
    }
    private string ColumnKey(DataGridColumn column) => !string.IsNullOrEmpty(column.SortMemberPath)
        ? new NativeEventColumnIdentity(Enum.Parse<EventSort>(column.SortMemberPath), null, null).Key
        : _extractedColumns.First(p => ReferenceEquals(p.Value, column)).Key;
    private void CaptureColumns()
    {
        if (_restoring || _updatingColumns || _owner == null) return;
        _owner.GridColumns = EventsGrid.Columns.Where(c => c != HighlightsColumn).Select(c => new EventsWorkspaceViewModel.GridColumnState(ColumnKey(c), c.DisplayIndex,
            double.IsFinite(c.ActualWidth) && c.ActualWidth > 0 ? c.ActualWidth : c.Width.Value)).ToArray();
    }
    private void RestoreColumns()
    {
        if (_owner == null) return;
        _updatingColumns = true;
        try
        {
            foreach (var column in EventsGrid.Columns.Where(c => !string.IsNullOrEmpty(c.SortMemberPath)))
            {
                var defaults = _ordinaryDefaults[column.SortMemberPath];
                column.Header = defaults.Header; column.Width = defaults.Width; column.DisplayIndex = defaults.Order;
            }
            var columns = EventsGrid.Columns.Where(c => c != HighlightsColumn).ToDictionary(ColumnKey, StringComparer.Ordinal);
            foreach (var definition in _owner.PresetColumns)
                if (definition.Identity.BuiltIn != null && columns.TryGetValue(definition.Identity.Key, out var ordinary)) ordinary.Header = definition.Label;
            // Set requested columns first; hidden ordinary columns follow without affecting query criteria.
            HighlightsColumn.DisplayIndex = 0;
            var index = 1;
            foreach (var state in _owner.GridColumns.OrderBy(s => s.Order))
                if (columns.TryGetValue(state.Key, out var column)) { column.Width = state.Width; column.DisplayIndex = index++; }
        }
        finally { _updatingColumns = false; }
    }
    private void SortEvents(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true;
        if (_owner == null) return;
        if (e.Column.Header is ExtractedEventColumnHeader native) _owner.SortExtractedColumn(native.Identity);
        else if (Enum.TryParse<EventSort>(e.Column.SortMemberPath, out var column)) _owner.SortColumn(column);
    }
    private void UpdateSortIndicators()
    {
        foreach (var column in EventsGrid.Columns)
            column.SortDirection = (_owner?.ExtractedSort is { } native ? column.Header is ExtractedEventColumnHeader h && h.Identity == native : column.SortMemberPath == _owner?.Sort.ToString())
                ? _owner.Descending ? ListSortDirection.Descending : ListSortDirection.Ascending : null;
    }
    private void CapturePosition()
    {
        if (_restoring || _owner == null || !IsLoaded) return;
        if (Children<ScrollViewer>(EventsGrid).FirstOrDefault() is { } scroll)
        { _owner.VerticalOffset = scroll.VerticalOffset; _owner.HorizontalOffset = scroll.HorizontalOffset; }
        if (Children<ScrollViewer>(SupportingGrid).FirstOrDefault(s => s.Name == "InspectorRawContentScrollViewer") is { } inspector)
            _owner.InspectorOffset = inspector.VerticalOffset;
    }
    private void Capture()
    {
        if (_restoring || _owner == null) return;
        CapturePosition();
        CaptureColumns();
        _owner.Layout = new(LayoutGrid.RowDefinitions[0].Height.Value, LayoutGrid.RowDefinitions[2].Height.Value,
            SupportingGrid.ColumnDefinitions[2].Width.Value, SupportingGrid.ColumnDefinitions[0].Width.Value);
    }
    private void Restore()
    {
        _owner ??= DataContext as EventsWorkspaceViewModel;
        if (_owner == null) return;
        UpdateExtractedColumns();
        RestoreColumns();
        UpdateSortIndicators();
        _restoring = true;
        var owner = _owner;
        var layout = owner.Layout;
        LayoutGrid.RowDefinitions[0].Height = new(layout.ListingWeight, GridUnitType.Star);
        LayoutGrid.RowDefinitions[2].Height = new(layout.DataWeight, GridUnitType.Star);
        SupportingGrid.ColumnDefinitions[0].Width = new(layout.DataWidth, GridUnitType.Star);
        SupportingGrid.ColumnDefinitions[2].Width = new(layout.DetailsWidth, GridUnitType.Star);
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            if (ReferenceEquals(owner, _owner) && Children<ScrollViewer>(EventsGrid).FirstOrDefault() is { } scroll)
            { scroll.ScrollToVerticalOffset(owner.VerticalOffset); scroll.ScrollToHorizontalOffset(owner.HorizontalOffset); }
            if (ReferenceEquals(owner, _owner) && Children<ScrollViewer>(SupportingGrid).FirstOrDefault(s => s.Name == "InspectorRawContentScrollViewer") is { } inspector)
                inspector.ScrollToVerticalOffset(owner.InspectorOffset);
            _restoring = false;
        }));
    }
}
