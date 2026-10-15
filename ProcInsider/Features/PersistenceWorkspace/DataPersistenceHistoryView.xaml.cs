using System.ComponentModel;
using System.Windows.Controls;
namespace ProcInsider.Features.InvestigationWorkspaces;
public partial class DataPersistenceHistoryView : UserControl
{
    public DataPersistenceHistoryView() { InitializeComponent(); Loaded += (_, _) => Arrows(); }
    private void Arrows() { if (DataContext is PersistenceWorkspaceViewModel owner) foreach (var column in HistoryGrid.Columns) column.SortDirection = column.SortMemberPath == owner.HistorySort ? owner.HistorySortDirection : null; }
    private async void SortHistory(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; if (DataContext is not PersistenceWorkspaceViewModel owner) return;
        owner.HistorySortDirection = e.Column.SortDirection == ListSortDirection.Ascending ? ListSortDirection.Descending : ListSortDirection.Ascending; owner.HistorySort = e.Column.SortMemberPath;
        await owner.SortHistoryAsync(owner.HistorySort, owner.HistorySortDirection); Arrows();
    }
}
