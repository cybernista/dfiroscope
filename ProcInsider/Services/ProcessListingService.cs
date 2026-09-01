using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ProcInsider.Models;
using ProcInsider.ViewModels;

namespace ProcInsider.Services;

public sealed class ProcessListingWindow
{
    public IReadOnlyList<ProcessRowViewModel> Rows { get; init; } = [];
    public int TotalCount { get; init; } = -1;
    public int Offset { get; init; }
    public int PageSize { get; init; }
    public string? NextCursor { get; init; }
    public bool HasMore { get; init; }
    public ProcessListingPagingMode PagingMode { get; init; }
    public TimeSpan QueryDuration { get; init; }
    public TimeSpan MaterializationDuration { get; init; }
}

public sealed record ProcessListingLoadProgress(
    int LoadedItems,
    int WindowItems,
    int TotalMatchingItems,
    string StageMessage = "");

/// <summary>
/// Narrow page source used by the virtualized collection. It keeps the cache and
/// viewport policy independently testable from SQLite and WPF windows.
/// </summary>
public interface IProcessListingPageSource
{
    Task<int> CountProcessesAsync(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default);

    Task<ProcessListingWindow> GetPageAsync(
        ProcessListingQuery query,
        CancellationToken cancellationToken = default);

    Task<int> GetProcessRowIndexAsync(
        string processKey,
        ProcessListingQuery query,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// VM-facing adapter over <see cref="IProcessListingQueryService"/>. Each request
/// materializes one bounded page and loads statistics only for that page.
/// Cross-page reuse and eviction are owned by <see cref="VirtualizedProcessCollection"/>.
/// </summary>
public sealed class ProcessListingService : IProcessListingPageSource, IViewerProcessNavigationListing
{
    private readonly SqliteStagingQueryService _queryService;
    private readonly IProcessListingQueryService _listingQueries;
    private readonly IProcessRiskProjectionQueryService? _riskQueries;

    public ProcessListingService(
        SqliteStagingQueryService queryService,
        bool includeProcessRisk = true)
    {
        _queryService = queryService;
        _listingQueries = queryService.ProcessListingQueries;
        _riskQueries = includeProcessRisk
            ? queryService.ProcessRiskProjectionQueries
            : null;
    }

    public int CountProcesses(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default)
        => _listingQueries.CountProcesses(filters, cancellationToken);

    public Task<int> CountProcessesAsync(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default)
        => _listingQueries.CountProcessesAsync(filters, cancellationToken);

    public ProcessListingWindow GetWindow(ProcessListingQuery query)
        => GetWindow(query, progress: null);

    public ProcessListingWindow GetWindow(
        ProcessListingQuery query,
        IProgress<ProcessListingLoadProgress>? progress)
    {
        var timer = Stopwatch.StartNew();
        var page = _listingQueries.GetProcessPage(query);
        timer.Stop();
        return BuildWindow(
            page,
            query.Offset,
            query.PageSize,
            progress,
            CancellationToken.None,
            timer.Elapsed);
    }

    public Task<ProcessListingWindow> GetWindowAsync(ProcessListingQuery query)
        => Task.Run(() => GetWindow(query));

    public Task<ProcessListingWindow> GetWindowAsync(
        ProcessListingQuery query,
        IProgress<ProcessListingLoadProgress>? progress)
        => Task.Run(() => GetWindow(query, progress));

    public async Task<ProcessListingWindow> GetPageAsync(
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
    {
        var queryTimer = Stopwatch.StartNew();
        var page = await _listingQueries
            .GetProcessPageAsync(query, cancellationToken)
            .ConfigureAwait(false);
        queryTimer.Stop();
        cancellationToken.ThrowIfCancellationRequested();
        return BuildWindow(
            page,
            query.Offset,
            query.PageSize,
            progress: null,
            cancellationToken,
            queryTimer.Elapsed);
    }

    public ProcessKeyLookupResult FindProcessByKey(string processKey)
        => _listingQueries.GetProcessByKey(processKey);

    public Task<ProcessKeyLookupResult> FindProcessByKeyAsync(string processKey)
        => _listingQueries.GetProcessByKeyAsync(processKey);

    public async Task<ProcessKeyLookupResult> FindProcessByKeyAsync(
        string processKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await _listingQueries.GetProcessByKeyAsync(processKey).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    public ProcessEntityLookupResult FindProcessByEntityId(string processEntityId)
        => _listingQueries.GetProcessByEntityId(processEntityId);

    public Task<ProcessEntityLookupResult> FindProcessByEntityIdAsync(string processEntityId)
        => _listingQueries.GetProcessByEntityIdAsync(processEntityId);

    public async Task<ProcessEntityLookupResult> FindProcessByEntityIdAsync(
        string processEntityId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await _listingQueries.GetProcessByEntityIdAsync(processEntityId).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    public async Task<ProcessListingWindow?> GetWindowForKeyAsync(
        string processKey,
        ProcessListingQuery baseQuery)
    {
        var rowIndex = await _listingQueries.GetProcessRowIndexAsync(processKey, baseQuery);
        if (rowIndex < 0)
        {
            return null;
        }

        var pageStart = (rowIndex / baseQuery.PageSize) * baseQuery.PageSize;
        return await GetWindowAsync(ClonePageQuery(baseQuery, pageStart, cursor: null));
    }

    public Task<int> GetProcessRowIndexAsync(
        string processKey,
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
        => _listingQueries.GetProcessRowIndexAsync(processKey, query, cancellationToken);

    private ProcessListingWindow BuildWindow(
        ProcessListingPage page,
        int offset,
        int pageSize,
        IProgress<ProcessListingLoadProgress>? progress,
        CancellationToken cancellationToken,
        TimeSpan queryDuration)
    {
        var materializationTimer = Stopwatch.StartNew();
        var ownerIds = page.Rows
            .Select(GetOwnershipId)
            .Where(owner => !string.IsNullOrWhiteSpace(owner))
            .ToArray();
        var latestStatisticsByOwner = _queryService
            .GetLatestProcessStatisticsForOwners(ownerIds, cancellationToken)
            .GroupBy(
                statistic => string.IsNullOrWhiteSpace(statistic.ProcessEntityId)
                    ? statistic.ProcessKey
                    : statistic.ProcessEntityId,
                StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
        var riskEntityIds = page.Rows
            .Select(record => record.ProcessEntityId?.Trim() ?? string.Empty)
            .Where(processEntityId => processEntityId.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        IReadOnlyDictionary<string, ProcessRiskProjectionSummaryRecord> riskByEntity;
        try
        {
            riskByEntity = _riskQueries == null || riskEntityIds.Length == 0
                ? new Dictionary<string, ProcessRiskProjectionSummaryRecord>(StringComparer.Ordinal)
                : _riskQueries
                    .GetCurrentSummaries(riskEntityIds, cancellationToken)
                    .ToDictionary(summary => summary.ProcessEntityId, StringComparer.Ordinal);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            riskByEntity = riskEntityIds.ToDictionary(
                processEntityId => processEntityId,
                processEntityId => ProcessRiskProjectionSummaryRecord.Unavailable(
                    ProcessRiskProjectionReadState.Failed,
                    $"The bounded process-risk summary read failed: {ex.Message}",
                    processEntityId),
                StringComparer.Ordinal);
        }

        var rows = new List<ProcessRowViewModel>(page.Rows.Count);
        var loadedItems = 0;

        progress?.Report(new ProcessListingLoadProgress(
            loadedItems,
            page.Rows.Count,
            page.TotalCount));

        foreach (var record in page.Rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ownerId = GetOwnershipId(record);
            var vm = new ProcessRowViewModel(record.ToProcessInfo());
            vm.SetStatistics(latestStatisticsByOwner.GetValueOrDefault(ownerId));
            var riskEntityId = record.ProcessEntityId?.Trim() ?? string.Empty;
            vm.SetRiskProjection(
                riskEntityId.Length == 0
                    ? ProcessRiskProjectionSummaryRecord.Unavailable(
                        ProcessRiskProjectionReadState.NotReady,
                        "This row has no durable ProcessEntityId; listing risk projection does not use ProcessKey or PID fallback.")
                    : riskByEntity.GetValueOrDefault(riskEntityId) ??
                      ProcessRiskProjectionSummaryRecord.Unavailable(
                          ProcessRiskProjectionReadState.NotReady,
                          "No current process-risk projection has been rebuilt for this exact process entity.",
                          riskEntityId));
            rows.Add(vm);

            loadedItems++;
            if (loadedItems == page.Rows.Count || loadedItems % 100 == 0)
            {
                progress?.Report(new ProcessListingLoadProgress(
                    loadedItems,
                    page.Rows.Count,
                    page.TotalCount));
            }
        }

        materializationTimer.Stop();
        return new ProcessListingWindow
        {
            Rows = rows,
            TotalCount = page.TotalCount,
            Offset = offset,
            PageSize = pageSize,
            NextCursor = page.NextCursor,
            HasMore = page.HasMore,
            PagingMode = page.PagingMode,
            QueryDuration = queryDuration,
            MaterializationDuration = materializationTimer.Elapsed
        };
    }

    private static string GetOwnershipId(ProcessRecord record)
        => string.IsNullOrWhiteSpace(record.ProcessEntityId)
            ? record.ProcessKey
            : record.ProcessEntityId;

    private static ProcessListingQuery ClonePageQuery(
        ProcessListingQuery query,
        int offset,
        string? cursor)
        => new()
        {
            Filters = query.Filters,
            Sort = query.Sort,
            Offset = offset,
            PageSize = query.PageSize,
            Cursor = cursor,
            IncludeTotalCount = query.IncludeTotalCount
        };
}
