using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.Search;

public partial class ExplorerSearchView : UserControl
{
    public ExplorerSearchView()
    {
        InitializeComponent();
    }

    private void SearchTextBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter ||
            DataContext is not SearchViewModel search)
        {
            return;
        }

        e.Handled = true;
        if (search.SearchCommand.CanExecute(null))
        {
            search.SearchCommand.Execute(null);
        }
    }

    private void SearchResultsDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (!IsResultRowDoubleClick(sender, e) ||
            DataContext is not SearchViewModel search)
        {
            return;
        }

        if (search.OpenResultCommand.CanExecute(null))
        {
            search.OpenResultCommand.Execute(null);
        }
    }

    private static bool IsResultRowDoubleClick(object sender, MouseButtonEventArgs e)
    {
        return sender is DataGrid { SelectedItem: not null } &&
               FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject) != null;
    }

    private static T? FindAncestor<T>(DependencyObject? current)
        where T : DependencyObject
    {
        while (current != null)
        {
            if (current is T match)
            {
                return match;
            }

            try
            {
                current = VisualTreeHelper.GetParent(current);
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

        return null;
    }
}
