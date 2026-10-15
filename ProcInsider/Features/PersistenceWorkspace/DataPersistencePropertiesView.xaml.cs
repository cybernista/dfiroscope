using System.ComponentModel;
using System.Windows.Controls;
using System.Windows.Threading;
namespace ProcInsider.Features.InvestigationWorkspaces;
public partial class DataPersistencePropertiesView : UserControl
{
    public DataPersistencePropertiesView()
    {
        InitializeComponent(); Loaded += (_, _) => ReconcileSort();
        DataContextChanged += (_, args) => Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            if (IsLoaded && ReferenceEquals(DataContext, args.NewValue)) ReconcileSort();
        }));
    }
    private void ReconcileSort() { if (DataContext is PersistenceWorkspaceViewModel owner) { owner.ApplyPropertySort(); Arrows(); } }
    private void Arrows() { if (DataContext is PersistenceWorkspaceViewModel owner) foreach (var column in PropertiesGrid.Columns) column.SortDirection = column.SortMemberPath == owner.PropertySort ? owner.PropertySortDirection : null; }
    private void SortProperties(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; if (DataContext is not PersistenceWorkspaceViewModel owner) return;
        owner.PropertySortDirection = e.Column.SortDirection == ListSortDirection.Ascending ? ListSortDirection.Descending : ListSortDirection.Ascending; owner.PropertySort = e.Column.SortMemberPath;
        owner.ApplyPropertySort(); Arrows();
    }
}
