using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class SystemActivityViewModel : ViewModelBase
{
    private const int MaxVisibleActivities = 10000;

    private readonly TelemetryProjectionService _projectionService;
    private readonly InspectorPaneViewModel _inspectorPaneViewModel;
    private IReadOnlyList<ExplorerScope> _includedScopes = [];
    private IReadOnlyList<ExplorerScope> _excludedScopes = [];
    private ExplorerScope? _activeScope;
    private bool _hasGreenSelection;

    [ObservableProperty]
    private ObservableCollection<SystemActivityRowViewModel> activities = new();

    [ObservableProperty]
    private ICollectionView? activitiesView;

    [ObservableProperty]
    private SystemActivityRowViewModel? selectedActivity;

    [ObservableProperty]
    private string statusMessage = "Refresh from db to load normalized system activity.";

    [ObservableProperty]
    private int visibleActivityCount;

    public SystemActivityViewModel(
        TelemetryProjectionService projectionService,
        InspectorPaneViewModel inspectorPaneViewModel)
    {
        _projectionService = projectionService;
        _inspectorPaneViewModel = inspectorPaneViewModel;
        ActivitiesView = CollectionViewSource.GetDefaultView(Activities);
        ActivitiesView.Filter = FilterActivity;
    }

    [RelayCommand]
    public void RefreshActivities()
    {
        RefreshActivities(_activeScope);
    }

    public void RefreshActivities(ExplorerScope? scope)
    {
        ApplySnapshot(
            _projectionService.GetSystemActivities(BuildQuery(scope)),
            scope);
    }

    public void ApplySnapshot(
        IReadOnlyList<SystemActivityRecord> rows,
        ExplorerScope? scope)
        => ApplyPreparedSnapshot(PrepareSnapshotRows(rows), scope);

    internal static IReadOnlyList<SystemActivityRowViewModel> PrepareSnapshotRows(
        IReadOnlyList<SystemActivityRecord> rows) =>
        rows.Select(row => new SystemActivityRowViewModel(row)).ToArray();

    internal void ApplyPreparedSnapshot(
        IReadOnlyList<SystemActivityRowViewModel> rows,
        ExplorerScope? scope)
    {
        ArgumentNullException.ThrowIfNull(rows);
        _activeScope = scope;
        var previouslySelectedSequenceId = SelectedActivity?.SourceSequenceId;
        SelectedActivity = null;
        Activities = new ObservableCollection<SystemActivityRowViewModel>(rows);
        ActivitiesView = CollectionViewSource.GetDefaultView(Activities);
        ActivitiesView.Filter = FilterActivity;

        if (previouslySelectedSequenceId.HasValue)
        {
            SelectedActivity = Activities.FirstOrDefault(row => row.SourceSequenceId == previouslySelectedSequenceId.Value);
        }

        ActivitiesView.Refresh();
        UpdateStatusMessage();
    }

    public void ApplyScopedSelection(
        IReadOnlyList<ExplorerScope> includedScopes,
        IReadOnlyList<ExplorerScope> excludedScopes,
        bool hasGreenSelection)
    {
        _includedScopes = includedScopes;
        _excludedScopes = excludedScopes;
        _hasGreenSelection = hasGreenSelection;
        ActivitiesView?.Refresh();
        UpdateStatusMessage();
    }

    public void Clear()
    {
        SelectedActivity = null;
        Activities.Clear();
        VisibleActivityCount = 0;
        StatusMessage = "Refresh from db to load normalized system activity.";
    }

    internal static SystemActivityQuery BuildQuery(ExplorerScope? scope)
    {
        return new SystemActivityQuery
        {
            Scope = scope?.SystemActivityScope,
            AccountKey = scope?.AccountKey,
            CaseId = scope?.CaseId,
            EvidenceSessionId = scope?.EvidenceSessionId,
            CaptureId = scope?.CaptureId,
            SourceIdentityId = scope?.SourceIdentityId,
            HostId = scope?.HostId,
            ExecutionRootId = scope?.ExecutionRootId,
            MaxCount = MaxVisibleActivities
        };
    }

    private bool FilterActivity(object item)
    {
        if (item is not SystemActivityRowViewModel activity)
        {
            return false;
        }

        if (_hasGreenSelection &&
            !_includedScopes.Any(activity.MatchesScope))
        {
            return false;
        }

        return !_excludedScopes.Any(activity.MatchesScope);
    }

    private void UpdateStatusMessage()
    {
        if (Activities.Count == 0)
        {
            VisibleActivityCount = 0;
            StatusMessage = _activeScope == null
                ? "No normalized system activity is loaded."
                : $"No normalized system activity matched {_activeScope.Title}.";
            return;
        }

        VisibleActivityCount = Activities.Count(activity => FilterActivity(activity));
        if (VisibleActivityCount == Activities.Count)
        {
            StatusMessage = _activeScope == null ||
                _activeScope.SystemActivityScope == null && string.IsNullOrWhiteSpace(_activeScope.AccountKey)
                    ? $"Showing {VisibleActivityCount} normalized system activity rows."
                    : $"Showing {VisibleActivityCount} normalized system activity rows for {_activeScope.Title}.";
            return;
        }

        StatusMessage = _activeScope == null ||
            _activeScope.SystemActivityScope == null && string.IsNullOrWhiteSpace(_activeScope.AccountKey)
                ? $"Showing {VisibleActivityCount} of {Activities.Count} normalized system activity rows in green scopes."
                : $"Showing {VisibleActivityCount} of {Activities.Count} normalized system activity rows for {_activeScope.Title} in green scopes.";
    }

    partial void OnSelectedActivityChanged(SystemActivityRowViewModel? value)
    {
        if (value == null)
        {
            _inspectorPaneViewModel.Clear("Select a system activity row to inspect it here.");
            return;
        }

        _inspectorPaneViewModel.Load(value.ToInspectorPayload());
    }
}
