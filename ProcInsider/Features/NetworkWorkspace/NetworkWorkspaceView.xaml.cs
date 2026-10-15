using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.ComponentModel;
using ProcInsider.Features.NetworkWorkspace;

namespace ProcInsider.Features.InvestigationWorkspaces;

public partial class NetworkWorkspaceView : UserControl
{
    private NetworkWorkspaceViewModel? _owner;
    public NetworkWorkspaceView()
    {
        InitializeComponent();
        Loaded+=(_,_)=>{_owner=DataContext as NetworkWorkspaceViewModel;Restore();};
        Unloaded+=(_,_)=>Capture();
        DataContextChanged+=(_,_)=>{Capture();_owner=DataContext as NetworkWorkspaceViewModel;if(IsLoaded)Restore();};
    }
    private static T? Descendant<T>(DependencyObject node) where T:DependencyObject
    {
        for(var i=0;i<VisualTreeHelper.GetChildrenCount(node);i++){var child=VisualTreeHelper.GetChild(node,i);if(child is T found)return found;if(Descendant<T>(child) is { } nested)return nested;}return null;
    }
    private void Capture()
    {
        if(_owner==null)return;
        if(Descendant<ScrollViewer>(NetworkGrid) is { } scroll){_owner.VerticalOffset=scroll.VerticalOffset;_owner.HorizontalOffset=scroll.HorizontalOffset;}
        _owner.Layout=_owner.Layout with{ListingWeight=LayoutGrid.RowDefinitions[0].ActualHeight,DataWeight=LayoutGrid.RowDefinitions[2].ActualHeight};
        foreach(var column in NetworkGrid.Columns)_owner.ColumnLayout[column.SortMemberPath]=(column.ActualWidth,column.DisplayIndex);
        if(Descendant<ScrollViewer>(PropertiesGrid) is { } properties)_owner.PropertiesOffset=properties.VerticalOffset;
    }
    private void Restore()
    {
        if(_owner==null)return;var layout=_owner.Layout;
        LayoutGrid.RowDefinitions[0].Height=new(layout.ListingWeight,GridUnitType.Star);LayoutGrid.RowDefinitions[2].Height=new(layout.DataWeight,GridUnitType.Star);
        foreach(var column in NetworkGrid.Columns)if(_owner.ColumnLayout.TryGetValue(column.SortMemberPath,out var saved)){if(saved.Width>0)column.Width=new(saved.Width);column.DisplayIndex=Math.Clamp(saved.Order,0,NetworkGrid.Columns.Count-1);}
        if(Descendant<ScrollViewer>(NetworkGrid) is { } scroll){scroll.ScrollToVerticalOffset(_owner.VerticalOffset);scroll.ScrollToHorizontalOffset(_owner.HorizontalOffset);}
        if(Descendant<ScrollViewer>(PropertiesGrid) is { } properties)properties.ScrollToVerticalOffset(_owner.PropertiesOffset);
    }
    private async void SortNetwork(object sender,DataGridSortingEventArgs e)
    {
        e.Handled=true;if(_owner==null)return;
        var sort=e.Column.SortMemberPath switch{"SourceAddress"=>NetworkSort.SourceEndpoint,"DestinationAddress"=>NetworkSort.DestinationEndpoint,"ProcessId"=>NetworkSort.ProcessId,"SourcePort"=>NetworkSort.SourcePort,"DestinationPort"=>NetworkSort.DestinationPort,_=>Enum.Parse<NetworkSort>(e.Column.SortMemberPath)};
        _owner.Descending=_owner.Sort==sort?!_owner.Descending:false;_owner.Sort=sort;
        foreach(var column in NetworkGrid.Columns)column.SortDirection=null;e.Column.SortDirection=_owner.Descending?ListSortDirection.Descending:ListSortDirection.Ascending;
        await _owner.ApplyCommand.ExecuteAsync(null);
    }
    private async void SortEndpoint(object sender,DataGridSortingEventArgs e)
    {
        e.Handled=true;if(_owner==null)return;
        var sort=Enum.Parse<EndpointSort>(e.Column.SortMemberPath);
        _owner.Descending=_owner.EndpointSort==sort?!_owner.Descending:false;_owner.EndpointSort=sort;
        foreach(var column in EndpointGrid.Columns)column.SortDirection=null;e.Column.SortDirection=_owner.Descending?ListSortDirection.Descending:ListSortDirection.Ascending;
        await _owner.ApplyCommand.ExecuteAsync(null);
    }
    private void SortProperties(object sender,DataGridSortingEventArgs e)
    {
        e.Handled=true;if(_owner==null)return;
        var direction=e.Column.SortDirection==ListSortDirection.Ascending?ListSortDirection.Descending:ListSortDirection.Ascending;
        _owner.PropertiesView.SortDescriptions.Clear();_owner.PropertiesView.SortDescriptions.Add(new(e.Column.SortMemberPath,direction));
        foreach(var column in PropertiesGrid.Columns)column.SortDirection=null;e.Column.SortDirection=direction;
    }}
