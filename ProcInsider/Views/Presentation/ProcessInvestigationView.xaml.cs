using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using ProcInsider.Models;
using ProcInsider.Services.Presentation;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Presentation;

public partial class ProcessInvestigationView : UserControl
{
    private IProcessListingPresentation? _viewModel;
    private bool _isRestoringProcessViewport;

    public ProcessInvestigationView()
    {
        InitializeComponent();
        Loaded += (_, _) => BindPresentation();
        Unloaded += (_, _) => DetachPresentation();
        DataContextChanged += (_, _) => { DetachPresentation(); if (IsLoaded) BindPresentation(); };
    }

    private void BindPresentation()
    {
        if (ReferenceEquals(_viewModel, DataContext)) return;
        DetachPresentation();
        _viewModel = DataContext as IProcessListingPresentation;
        if (_viewModel == null) return;
        _viewModel.ProcessRowNavigationRequested += OnProcessRowNavigationRequested;
        _viewModel.ProcessViewportAnchorCaptureRequested += CaptureProcessViewportAnchor;
        _viewModel.ProcessViewportAnchorRestoreRequested += RestoreProcessViewportAnchor;
        RestoreProcessSortIndicators();
    }

    private void DetachPresentation()
    {
        if (_viewModel == null) return;
        _viewModel.ProcessRowNavigationRequested -= OnProcessRowNavigationRequested;
        _viewModel.ProcessViewportAnchorCaptureRequested -= CaptureProcessViewportAnchor;
        _viewModel.ProcessViewportAnchorRestoreRequested -= RestoreProcessViewportAnchor;
        _viewModel = null;
    }

    private void OnProcessRowNavigationRequested(ProcessRowViewModel row)
    {
        var presentation = _viewModel;
        Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
        {
            if (IsLoaded && ReferenceEquals(presentation, _viewModel)) ProcessDataGrid.ScrollIntoView(row);
        }));
    }

    private void ProcessDataGrid_Sorting(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; // We handle sorting ourselves

        if (_viewModel == null || e.Column.SortMemberPath == null)
            return;

        // Get column name for sorting
        var columnName = e.Column.SortMemberPath;

        _viewModel.SortVisibleProcessRows(columnName);
        ApplyProcessSortIndicators(
            ProcessDataGrid,
            e.Column,
            _viewModel.GetSortDirection(columnName));
    }

    private void ProcessDataGrid_TargetUpdated(object sender, DataTransferEventArgs e)
    {
        if (e.Property == ItemsControl.ItemsSourceProperty)
            RestoreProcessSortIndicators();
    }

    private void ProcessDataGrid_Loaded(object sender, RoutedEventArgs e) => RestoreProcessSortIndicators();

    private void RestoreProcessSortIndicators()
    {
        if (_viewModel != null)
            SynchronizeProcessSortIndicators(ProcessDataGrid, _viewModel.GetSortDirection);
    }

    internal static void SynchronizeProcessSortIndicators(
        DataGrid grid, Func<string, ListSortDirection?> getDirection)
    {
        // WPF clears column directions when ItemsSource changes. Restore only the
        // presentation state; the Listing query/tree owner still orders the rows.
        foreach (var column in grid.Columns)
            column.SortDirection = getDirection(column.SortMemberPath);
    }

    internal static void ApplyProcessSortIndicators(
        DataGrid grid,
        DataGridColumn activeColumn,
        ListSortDirection? direction)
    {
        ArgumentNullException.ThrowIfNull(grid);
        ArgumentNullException.ThrowIfNull(activeColumn);

        foreach (var column in grid.Columns)
        {
            column.SortDirection = ReferenceEquals(column, activeColumn) ? direction : null;
        }
    }

    private void ProcessDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is DataGrid grid && grid.SelectedItem is ProcessListingPlaceholder)
        {
            grid.UnselectAll();
        }
    }

    private void ProcessDataGrid_LoadingRow(object sender, DataGridRowEventArgs e)
    {
        _viewModel?.RequestProcessListingRange(e.Row.GetIndex(), 1);
    }

    private void ProcessDataGrid_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (!_isRestoringProcessViewport &&
            (Math.Abs(e.VerticalChange) > double.Epsilon ||
             Math.Abs(e.ViewportHeightChange) > double.Epsilon))
        {
            _viewModel?.NotifyProcessViewportChanged();
        }
    }

    private ViewerProcessViewportAnchor? CaptureProcessViewportAnchor()
    {
        var row = FindVisualChildren<DataGridRow>(ProcessDataGrid)
            .Select(candidate => new
            {
                Row = candidate,
                Top = candidate.TranslatePoint(new Point(0, 0), ProcessDataGrid).Y
            })
            .Where(candidate =>
                candidate.Row.DataContext is ProcessRowViewModel &&
                candidate.Top + candidate.Row.ActualHeight > 0 &&
                candidate.Top < ProcessDataGrid.ActualHeight)
            .OrderBy(candidate => candidate.Top)
            .FirstOrDefault();
        if (row?.Row.DataContext is not ProcessRowViewModel process)
        {
            return null;
        }

        return new ViewerProcessViewportAnchor(
            process.ProcessInfo.ProcessEntityId ?? string.Empty,
            process.ProcessKey,
            row.Top);
    }

    private void RestoreProcessViewportAnchor(ProcessRowViewModel row, double relativeOffset)
    {
        var presentation = _viewModel;
        _isRestoringProcessViewport = true;
        ProcessDataGrid.ScrollIntoView(row);
        Dispatcher.BeginInvoke(
            DispatcherPriority.Loaded,
            new Action(() =>
            {
                try
                {
                    if (!IsLoaded || !ReferenceEquals(presentation, _viewModel)) return;
                    ProcessDataGrid.UpdateLayout();
                    if (ProcessDataGrid.ItemContainerGenerator.ContainerFromItem(row) is not DataGridRow container ||
                        FindVisualChild<ScrollViewer>(ProcessDataGrid) is not { } scrollViewer)
                    {
                        return;
                    }

                    var currentOffset = container.TranslatePoint(
                        new Point(0, 0),
                        ProcessDataGrid).Y;
                    scrollViewer.ScrollToVerticalOffset(
                        Math.Max(0, scrollViewer.VerticalOffset + currentOffset - relativeOffset));
                }
                finally
                {
                    _isRestoringProcessViewport = false;
                }
            }));
    }

    private static T? FindVisualChild<T>(DependencyObject parent)
        where T : DependencyObject
        => FindVisualChildren<T>(parent).FirstOrDefault();

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject parent)
        where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match)
            {
                yield return match;
            }

            foreach (var descendant in FindVisualChildren<T>(child))
            {
                yield return descendant;
            }
        }
    }

}
