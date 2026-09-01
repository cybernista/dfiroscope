using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.Features.Search;

/// <summary>
/// Narrow read-only use-case boundary for Explorer Search. Shared projection and
/// SQLite ownership remain outside the feature slice.
/// </summary>
public interface ISearchQueryService
{
    Task<IReadOnlyList<TelemetrySearchResult>> SearchAsync(
        TelemetrySearchQuery query,
        CancellationToken cancellationToken);
}

public sealed class SearchQueryService : ISearchQueryService
{
    private readonly TelemetryProjectionService _projectionService;

    public SearchQueryService(TelemetryProjectionService projectionService)
    {
        _projectionService = projectionService ?? throw new ArgumentNullException(nameof(projectionService));
    }

    public Task<IReadOnlyList<TelemetrySearchResult>> SearchAsync(
        TelemetrySearchQuery query,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return Task.Run<IReadOnlyList<TelemetrySearchResult>>(
            () =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var results = _projectionService.Search(query);
                cancellationToken.ThrowIfCancellationRequested();
                return results;
            },
            cancellationToken);
    }
}
