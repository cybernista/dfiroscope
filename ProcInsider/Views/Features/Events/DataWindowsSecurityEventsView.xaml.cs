using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace ProcInsider.Views.Features.Events;

public partial class DataWindowsSecurityEventsView : UserControl
{
    public DataWindowsSecurityEventsView() => InitializeComponent();

    private void AuditGrid_TargetUpdated(object sender, DataTransferEventArgs e)
    {
        if (e.Property == ItemsControl.ItemsSourceProperty)
            RestoreSortIndicators((DataGrid)sender);
    }

    private void AuditGrid_Loaded(object sender, RoutedEventArgs e) => RestoreSortIndicators((DataGrid)sender);

    private static void RestoreSortIndicators(DataGrid grid)
    {
        // A new grid can display an already sorted view after a tab switch.
        // Reflect that existing order without toggling or reapplying a sort.
        foreach (var column in grid.Columns)
        {
            column.SortDirection = null;
            foreach (var sort in grid.Items.SortDescriptions)
            {
                if (sort.PropertyName == column.SortMemberPath)
                {
                    column.SortDirection = sort.Direction;
                    break;
                }
            }
        }
    }
}
