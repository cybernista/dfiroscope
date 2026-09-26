using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;

namespace ProcInsider.Features.InvestigationWorkspaces;

public partial class EventsComparisonView : UserControl
{
    private EventsWorkspaceViewModel? _owner;
    private readonly DataGridTemplateColumn _currentColumn;
    private readonly Dictionary<EventsComparisonEvent, (DataGridTemplateColumn Column, int Index)> _pinnedColumns = [];
    private double? _pendingHorizontalOffset;
    public EventsComparisonView()
    {
        InitializeComponent();
        _currentColumn = new DataGridTemplateColumn
        {
            HeaderTemplate = (DataTemplate)FindResource("CurrentComparisonHeader"), Width = 240,
            CellTemplate = CellTemplate(0)
        };
        ComparisonGrid.Columns.Add(_currentColumn);
        Loaded += (_, _) => Bind();
        Unloaded += (_, _) => { if (_owner != null) _owner.PropertyChanged -= Changed; ManualButton.IsChecked = false; };
        DataContextChanged += (_, _) => Bind();
    }
    private void Bind()
    {
        if (_owner != null) _owner.PropertyChanged -= Changed;
        if (!ReferenceEquals(_owner, DataContext)) _pendingHorizontalOffset = null;
        _owner = DataContext as EventsWorkspaceViewModel;
        if (IsLoaded && _owner != null) _owner.PropertyChanged += Changed;
        UpdateColumns();
    }
    private void Changed(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(EventsWorkspaceViewModel.ComparisonColumns))
        {
            if (_owner?.ComparisonReference == null) _pendingHorizontalOffset ??= FindScroll(ComparisonGrid)?.HorizontalOffset;
            UpdateColumns();
        }
        if (e.PropertyName == nameof(EventsWorkspaceViewModel.ComparisonRows) && _owner?.ComparisonReference is { } reference &&
            _pendingHorizontalOffset is { } offset)
        {
            var owner = _owner;
            Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
            {
                if (!ReferenceEquals(owner, _owner) || owner.ComparisonReference != reference) return;
                ComparisonGrid.UpdateLayout();
                FindScroll(ComparisonGrid)?.ScrollToHorizontalOffset(offset);
                _pendingHorizontalOffset = null;
            }));
        }
    }
    private void UpdateColumns()
    {
        _currentColumn.Header = _owner?.ComparisonReference;
        var pinned = _owner?.ComparisonEvents ?? [];
        var retained = pinned.ToHashSet();
        foreach (var item in _pinnedColumns.Keys.Where(item => !retained.Contains(item)).ToArray())
        {
            ComparisonGrid.Columns.Remove(_pinnedColumns[item].Column);
            _pinnedColumns.Remove(item);
        }
        for (var i = 0; i < pinned.Count; i++)
        {
            var item = pinned[i];
            var index = i + 1;
            if (!_pinnedColumns.TryGetValue(item, out var retainedColumn))
            {
                var column = new DataGridTemplateColumn
                {
                    Header = item, HeaderTemplate = (DataTemplate)FindResource("ComparisonHeader"), Width = 240,
                    CellTemplate = CellTemplate(index)
                };
                _pinnedColumns.Add(item, (column, index)); ComparisonGrid.Columns.Add(column);
            }
            else if (retainedColumn.Index != index)
            {
                // A removed pin shifts cell indices without replacing retained controls or widths.
                retainedColumn.Column.CellTemplate = CellTemplate(index);
                _pinnedColumns[item] = (retainedColumn.Column, index);
            }
        }
    }
    private DataTemplate CellTemplate(int index)
    {
        // Translate the workspace's event cells into WPF bindings; XAML owns presentation.
        var factory = new FrameworkElementFactory(typeof(ContentPresenter));
        factory.SetBinding(ContentPresenter.ContentProperty, new Binding($"Cells[{index}]"));
        factory.SetValue(ContentPresenter.ContentTemplateProperty, FindResource("ComparisonCell"));
        return new DataTemplate { VisualTree = factory };
    }
    private static ScrollViewer? FindScroll(DependencyObject parent)
    {
        if (parent is ScrollViewer scroll) return scroll;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            if (FindScroll(VisualTreeHelper.GetChild(parent, i)) is { } child) return child;
        return null;
    }
}
