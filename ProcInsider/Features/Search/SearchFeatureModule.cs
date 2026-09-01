using System.ComponentModel;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.Search;

/// <summary>
/// Slice-owned activation, presentation, query, and workspace-lifecycle adapter
/// for Explorer Search. Sigma and shared infrastructure remain separate owners.
/// </summary>
public sealed class SearchFeatureModule : IDisposable
{
    private readonly Action<int> _resultCountChanged;
    private bool _disposed;

    public SearchFeatureModule(
        ISearchQueryService queryService,
        Action<TelemetrySearchResult> navigateToResult,
        FeatureAccessService featureAccess,
        Action<int> resultCountChanged)
    {
        ArgumentNullException.ThrowIfNull(queryService);
        ArgumentNullException.ThrowIfNull(navigateToResult);
        ArgumentNullException.ThrowIfNull(featureAccess);
        _resultCountChanged = resultCountChanged ?? throw new ArgumentNullException(nameof(resultCountChanged));
        ViewModel = new SearchViewModel(queryService, navigateToResult, featureAccess);
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    public SearchViewModel ViewModel { get; }

    public static ViewerFeatureDefinition<SearchFeatureModule> CreateDefinition(
        Func<SearchFeatureModule> moduleFactory)
    {
        ArgumentNullException.ThrowIfNull(moduleFactory);
        return new ViewerFeatureDefinition<SearchFeatureModule>(
            FeatureIds.SearchAndSigma,
            [FeatureIds.ProcessListing, FeatureIds.EventTelemetry],
            moduleFactory,
            [
                new ViewerFeatureTabDefinition<SearchFeatureModule>(
                    ExplorerTabKeys.Search,
                    "Search",
                    200,
                    module => module.CreateView(),
                    showCount: true)
            ],
            module => module.Dispose());
    }

    public ExplorerSearchView CreateView()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new ExplorerSearchView { DataContext = ViewModel };
    }

    public void ApplyAvailability(
        SnapshotAnalysisPreparationState analysisState,
        bool hasActiveQueryDatabase,
        bool isDirectArchivedDatabase,
        string analysisText = "")
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var databaseDescription = isDirectArchivedDatabase ? "archived database" : "snapshot";
        switch (analysisState)
        {
            case SnapshotAnalysisPreparationState.Preparing:
                ViewModel.SetSearchAvailability(
                    false,
                    FormatAvailability(
                        $"Search is unavailable while the {databaseDescription} search index is prepared.",
                        analysisText));
                break;
            case SnapshotAnalysisPreparationState.Ready when hasActiveQueryDatabase:
                ViewModel.SetSearchAvailability(
                    true,
                    FormatAvailability("Search is ready. Enter a keyword to search staged telemetry.", analysisText));
                break;
            case SnapshotAnalysisPreparationState.Canceled:
                ViewModel.SetSearchAvailability(
                    false,
                    FormatAvailability(
                        $"Search is unavailable because {databaseDescription} index preparation was canceled.",
                        analysisText));
                break;
            case SnapshotAnalysisPreparationState.Failed:
                ViewModel.SetSearchAvailability(
                    false,
                    FormatAvailability(
                        $"Search is unavailable because {databaseDescription} index preparation failed.",
                        analysisText));
                break;
            default:
                ViewModel.SetSearchAvailability(
                    false,
                    "Search is unavailable until snapshot analysis indexes are ready.");
                break;
        }
    }

    private static string FormatAvailability(string summary, string detail)
        => string.IsNullOrWhiteSpace(detail)
            ? summary
            : $"{summary} {detail}";

    public void DetachWorkspace()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ViewModel.SetSearchAvailability(false, "Search is unavailable until a capture snapshot is loaded.");
    }

    public void ClearResults()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ViewModel.SearchText = string.Empty;
        ViewModel.ResetState("Enter a keyword to search staged telemetry.");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        ViewModel.Dispose();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SearchViewModel.Results))
        {
            _resultCountChanged(ViewModel.Results.Count);
        }
    }
}
