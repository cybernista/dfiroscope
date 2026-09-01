using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using ProcInsider.ViewModels;

namespace ProcInsider.Views.Features.Search;

public partial class ExplorerSigmaView : UserControl
{
    public ExplorerSigmaView()
    {
        InitializeComponent();
    }

    private void SigmaFindingsDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (!IsFindingRowDoubleClick(sender, e) ||
            DataContext is not SigmaViewModel sigma)
        {
            return;
        }

        if (sigma.OpenFindingCommand.CanExecute(null))
        {
            sigma.OpenFindingCommand.Execute(null);
        }
    }

    private static bool IsFindingRowDoubleClick(object sender, MouseButtonEventArgs e)
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
