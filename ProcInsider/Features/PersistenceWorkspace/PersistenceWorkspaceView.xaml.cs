using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using ProcInsider.Features.PersistenceWorkspace;

namespace ProcInsider.Features.InvestigationWorkspaces;

public partial class PersistenceWorkspaceView : UserControl
{
    private PersistenceWorkspaceViewModel? _owner;
    public PersistenceWorkspaceView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => BindOwner();
        Loaded += (_, _) => BindOwner();
        Unloaded += (_, _) => { if (_owner != null) _owner.PropertyChanged -= Changed; _owner = null; };
    }
    private void BindOwner() { if (_owner != null) _owner.PropertyChanged -= Changed; _owner = DataContext as PersistenceWorkspaceViewModel; if (_owner != null && IsLoaded) _owner.PropertyChanged += Changed; Arrows(); }
    private void Changed(object? sender, PropertyChangedEventArgs e) { if (e.PropertyName == nameof(PersistenceWorkspaceViewModel.IsBusy)) Arrows(); }
    private void Arrows() { foreach (var grid in new[] { CurrentGrid, ChangesGrid }) foreach (var column in grid.Columns) column.SortDirection = _owner != null && column.SortMemberPath == _owner.Sort.ToString() ? _owner.Descending ? ListSortDirection.Descending : ListSortDirection.Ascending : null; }
    private async void SortListing(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true; if (_owner == null) return;
        var sort = Enum.Parse<PersistenceColumn>(e.Column.SortMemberPath);
        _owner.Descending = _owner.Sort == sort && !_owner.Descending; _owner.Sort = sort;
        await _owner.RefreshAsync(); Arrows();
    }
}
