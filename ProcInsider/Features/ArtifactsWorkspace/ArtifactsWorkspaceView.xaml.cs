using System.ComponentModel;
using System.Windows.Controls;

namespace ProcInsider.Features.InvestigationWorkspaces;

public partial class ArtifactsWorkspaceView : UserControl
{
    public ArtifactsWorkspaceView() { InitializeComponent(); Loaded += (_, _) => Arrows(); }
    private void Arrows()
    {
        if (DataContext is not ArtifactsWorkspaceViewModel owner) return;
        foreach (var column in ListingGrid.Columns) column.SortDirection = column.SortMemberPath == owner.Sort.ToString() ? owner.Descending ? ListSortDirection.Descending : ListSortDirection.Ascending : null;
        foreach (var column in PropertiesGrid.Columns) column.SortDirection = column.SortMemberPath == owner.PropertySort ? owner.PropertySortDirection : null;
        foreach (var column in ReadOccurrencesGrid.Columns) column.SortDirection = column.SortMemberPath == owner.ReadOccurrenceSort ? owner.ReadOccurrenceSortDirection : null;
    }
    private async void SortListing(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; if (DataContext is not ArtifactsWorkspaceViewModel owner) return;
        var sort = Enum.Parse<ProcInsider.Models.ForensicArtifactResultColumn>(e.Column.SortMemberPath);
        owner.Descending = owner.Sort == sort && !owner.Descending; owner.Sort = sort; await owner.RefreshAsync(); Arrows();
    }
    private void SortProperties(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; if (DataContext is not ArtifactsWorkspaceViewModel owner) return;
        owner.PropertySortDirection = e.Column.SortDirection == ListSortDirection.Ascending ? ListSortDirection.Descending : ListSortDirection.Ascending; owner.PropertySort = e.Column.SortMemberPath; owner.ApplyPropertySort(); Arrows();
    }
    private void SortReadOccurrences(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; if (DataContext is not ArtifactsWorkspaceViewModel owner) return;
        owner.ReadOccurrenceSortDirection = e.Column.SortDirection == ListSortDirection.Ascending ? ListSortDirection.Descending : ListSortDirection.Ascending; owner.ReadOccurrenceSort = e.Column.SortMemberPath; owner.ApplyReadOccurrenceSort(); Arrows();
    }
}
