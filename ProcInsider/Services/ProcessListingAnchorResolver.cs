using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>Reuses bounded pages and exact anchors within one prepared snapshot generation.</summary>
public sealed class ProcessListingAnchorResolver(
    ProcessListingService listing, ProcessListingQuery query, ProcessListingWindow firstPage)
{
    private readonly Dictionary<(string Entity, string Key), (int Index, ProcessListingWindow? Page)> _anchors = new();
    private readonly Dictionary<int, ProcessListingWindow> _pages = new() { [0] = firstPage };

    public async Task<(int Index, ProcessListingWindow? Page)> ResolveAsync(
        string entity, string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_anchors.TryGetValue((entity, key), out var cached)) return cached;
        // A loaded exact entity establishes its sorted position without another ROW_NUMBER query.
        foreach (var (offset, page) in _pages)
        {
            for (var i = 0; i < page.Rows.Count; i++)
            {
                var row = page.Rows[i];
                if (!string.IsNullOrWhiteSpace(entity) &&
                    string.Equals(row.ProcessInfo.ProcessEntityId, entity, StringComparison.Ordinal))
                    return Remember(entity, key, (offset + i, page));
            }
        }
        var resolvedKey = key;
        if (!string.IsNullOrWhiteSpace(entity))
        {
            var lookup = await listing.FindProcessByEntityIdAsync(entity, cancellationToken);
            if (lookup.IsFound && !string.IsNullOrWhiteSpace(lookup.Process?.ProcessKey))
                resolvedKey = lookup.Process.ProcessKey;
        }
        if (string.IsNullOrWhiteSpace(resolvedKey)) return Remember(entity, key, (-1, null));
        var index = await listing.GetProcessRowIndexAsync(resolvedKey, query, cancellationToken);
        if (index < 0) return Remember(entity, key, (-1, null));
        var pageOffset = index / query.PageSize * query.PageSize;
        if (!_pages.TryGetValue(pageOffset, out var resultPage))
        {
            resultPage = await listing.GetPageAsync(new ProcessListingQuery
            {
                Filters = query.Filters, Sort = query.Sort, Offset = pageOffset,
                PageSize = query.PageSize, IncludeTotalCount = false
            }, cancellationToken);
            _pages.Add(pageOffset, resultPage);
        }
        if (!string.IsNullOrWhiteSpace(entity))
        {
            // A legacy key can name more than one durable entity. Its ranked page is a
            // hint only; never restore selection to a different entity at that position.
            var exactOffset = -1;
            for (var i = 0; i < resultPage.Rows.Count; i++)
                if (string.Equals(resultPage.Rows[i].ProcessInfo.ProcessEntityId, entity, StringComparison.Ordinal))
                { exactOffset = i; break; }
            if (exactOffset < 0) return Remember(entity, key, (-1, null));
            index = pageOffset + exactOffset;
        }
        return Remember(entity, key, (index, resultPage));
    }

    private (int Index, ProcessListingWindow? Page) Remember(string entity, string key,
        (int Index, ProcessListingWindow? Page) result)
    {
        _anchors[(entity, key)] = result;
        return result;
    }
}
