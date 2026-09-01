using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProcInsider.Features.Search;
using ProcInsider.Models;
using ProcInsider.Models.Features;
using ProcInsider.Services;
using ProcInsider.Services.Features;

namespace ProcInsider.ViewModels;

public partial class SearchViewModel : ViewModelBase, IDisposable
{
    private const int DefaultMaxResults = 1000;

    private readonly ISearchQueryService _queryService;
    private readonly Action<TelemetrySearchResult> _navigateToResult;
    private readonly FeatureAccessService _featureAccess;
    private readonly object _searchSync = new();
    private CancellationTokenSource? _searchCancellation;
    private long _searchGeneration;
    private bool _disposed;

    [ObservableProperty]
    private string searchText = string.Empty;

    [ObservableProperty]
    private bool includeProcesses = true;

    [ObservableProperty]
    private bool includeEvents = true;

    [ObservableProperty]
    private bool includeModules = true;

    [ObservableProperty]
    private bool includeHandles = true;

    [ObservableProperty]
    private bool includeCorrelationEvidence;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SearchCommand))]
    private bool isSearching;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SearchCommand))]
    private bool isSearchAvailable = true;

    [ObservableProperty]
    private string statusMessage = "Enter a keyword to search staged telemetry.";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResults))]
    [NotifyPropertyChangedFor(nameof(IsEmpty))]
    private ObservableCollection<TelemetrySearchResult> results = new();

    [ObservableProperty]
    private ICollectionView? resultsView;

    [ObservableProperty]
    private TelemetrySearchResult? selectedResult;

    public bool HasResults => Results.Count > 0;
    public bool IsEmpty => !IsSearching && Results.Count == 0;

    public SearchViewModel(
        ISearchQueryService queryService,
        Action<TelemetrySearchResult> navigateToResult,
        FeatureAccessService? featureAccess = null)
    {
        _queryService = queryService ?? throw new ArgumentNullException(nameof(queryService));
        _navigateToResult = navigateToResult ?? throw new ArgumentNullException(nameof(navigateToResult));
        _featureAccess = featureAccess ?? new FeatureAccessService(CurrentEducationalReleaseProfile.RuntimeCatalog);
        RebuildResultsView();
    }

    [RelayCommand(CanExecute = nameof(CanSearch))]
    public async Task SearchAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!RequirePublished())
        {
            return;
        }

        var text = SearchText.Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            ResetState("Enter a keyword to search staged telemetry.");
            return;
        }

        if (!IncludeProcesses && !IncludeEvents && !IncludeModules && !IncludeHandles && !IncludeCorrelationEvidence)
        {
            ResetState("Select at least one telemetry category to search.");
            return;
        }

        var parseResult = AdvancedSearchParser.Parse(text);
        if (!parseResult.IsValid)
        {
            ResetState($"Search syntax error: {parseResult.Diagnostics[0].Message}");
            return;
        }

        var query = new TelemetrySearchQuery
        {
            Text = text,
            Syntax = TelemetrySearchSyntax.Advanced,
            AdvancedExpression = parseResult.Expression,
            IncludeProcesses = IncludeProcesses,
            IncludeEvents = IncludeEvents,
            IncludeModules = IncludeModules,
            IncludeHandles = IncludeHandles,
            IncludeCorrelationEvidence = IncludeCorrelationEvidence,
            MaxResults = DefaultMaxResults
        };

        var operation = BeginSearch();
        IsSearching = true;
        StatusMessage = "Searching staged telemetry...";
        try
        {
            var snapshot = await _queryService.SearchAsync(query, operation.Cancellation.Token);
            if (!IsCurrent(operation))
            {
                return;
            }

            Results = new ObservableCollection<TelemetrySearchResult>(snapshot);
            RebuildResultsView();
            SelectedResult = null;
            OnPropertyChanged(nameof(HasResults));
            OnPropertyChanged(nameof(IsEmpty));
            StatusMessage = Results.Count == DefaultMaxResults
                ? $"Showing first {Results.Count} results for \"{text}\"."
                : $"Found {Results.Count} results for \"{text}\".";
        }
        catch (OperationCanceledException) when (operation.Cancellation.IsCancellationRequested)
        {
            // Availability, workspace, clear, disposal, or a newer request owns the visible state.
        }
        catch (Exception ex)
        {
            if (IsCurrent(operation))
            {
                StatusMessage = $"Search failed: {ex.Message}";
            }
        }
        finally
        {
            CompleteSearch(operation);
        }
    }

    public void SetSearchAvailability(bool isAvailable, string status)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        IsSearchAvailable = isAvailable;
        if (!isAvailable)
        {
            ResetState(status);
            return;
        }

        StatusMessage = status;
    }

    public void SetExternalResults(IEnumerable<TelemetrySearchResult> results, string status)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(results);
        CancelPendingSearch();
        Results = new ObservableCollection<TelemetrySearchResult>(results);
        RebuildResultsView();
        SelectedResult = null;
        OnPropertyChanged(nameof(HasResults));
        OnPropertyChanged(nameof(IsEmpty));
        StatusMessage = status;
    }

    public void ResetState(string status)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CancelPendingSearch();
        Results = new ObservableCollection<TelemetrySearchResult>();
        RebuildResultsView();
        SelectedResult = null;
        OnPropertyChanged(nameof(HasResults));
        OnPropertyChanged(nameof(IsEmpty));
        StatusMessage = status;
    }

    [RelayCommand(CanExecute = nameof(CanUseFeature))]
    public void Clear()
    {
        if (!RequirePublished())
        {
            return;
        }

        SearchText = string.Empty;
        ResetState("Enter a keyword to search staged telemetry.");
    }

    [RelayCommand(CanExecute = nameof(CanOpenResult))]
    public void OpenResult()
    {
        if (!RequirePublished())
        {
            return;
        }

        if (SelectedResult != null)
        {
            _navigateToResult(SelectedResult);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CancelPendingSearch();
    }

    private bool CanOpenResult() =>
        _featureAccess.CanExecute(FeatureIds.SearchAndSigma, SelectedResult != null);

    private bool CanSearch() =>
        _featureAccess.CanExecute(FeatureIds.SearchAndSigma, IsSearchAvailable && !IsSearching);

    private bool CanUseFeature() => _featureAccess.IsPublished(FeatureIds.SearchAndSigma);

    private bool RequirePublished()
    {
        if (_featureAccess.TryAccess(FeatureIds.SearchAndSigma, out var unavailableMessage))
        {
            return true;
        }

        StatusMessage = unavailableMessage;
        return false;
    }

    private SearchOperation BeginSearch()
    {
        CancellationTokenSource? previous;
        SearchOperation operation;
        lock (_searchSync)
        {
            previous = _searchCancellation;
            var cancellation = new CancellationTokenSource();
            _searchCancellation = cancellation;
            operation = new SearchOperation(++_searchGeneration, cancellation);
        }

        previous?.Cancel();
        return operation;
    }

    private bool IsCurrent(SearchOperation operation)
    {
        lock (_searchSync)
        {
            return !_disposed &&
                   !operation.Cancellation.IsCancellationRequested &&
                   operation.Generation == _searchGeneration &&
                   ReferenceEquals(operation.Cancellation, _searchCancellation);
        }
    }

    private void CompleteSearch(SearchOperation operation)
    {
        var completedCurrent = false;
        lock (_searchSync)
        {
            if (operation.Generation == _searchGeneration &&
                ReferenceEquals(operation.Cancellation, _searchCancellation))
            {
                _searchCancellation = null;
                completedCurrent = true;
            }
        }

        operation.Cancellation.Dispose();
        if (completedCurrent)
        {
            IsSearching = false;
        }
    }

    private void CancelPendingSearch()
    {
        CancellationTokenSource? cancellation;
        lock (_searchSync)
        {
            cancellation = _searchCancellation;
            _searchCancellation = null;
            _searchGeneration++;
        }

        cancellation?.Cancel();
        IsSearching = false;
    }

    private void RebuildResultsView()
    {
        ResultsView = CollectionViewSource.GetDefaultView(Results);
        ResultsView.SortDescriptions.Clear();
        ResultsView.SortDescriptions.Add(new SortDescription(nameof(TelemetrySearchResult.Kind), ListSortDirection.Ascending));
        ResultsView.SortDescriptions.Add(new SortDescription(nameof(TelemetrySearchResult.TimestampUtc), ListSortDirection.Descending));
    }

    partial void OnIsSearchingChanged(bool value)
    {
        OnPropertyChanged(nameof(IsEmpty));
    }

    partial void OnSelectedResultChanged(TelemetrySearchResult? value)
    {
        OpenResultCommand.NotifyCanExecuteChanged();
        if (value != null && _featureAccess.IsPublished(FeatureIds.SearchAndSigma))
        {
            _navigateToResult(value);
        }
    }

    private sealed record SearchOperation(long Generation, CancellationTokenSource Cancellation);
}
