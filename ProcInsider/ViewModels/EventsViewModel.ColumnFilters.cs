using System.Globalization;
using ProcInsider.Services;

namespace ProcInsider.ViewModels;

public partial class EventsViewModel
{
    public IReadOnlyDictionary<string, ColumnFilterViewModel> HeaderFilters { get; }

    private IReadOnlyDictionary<string, ColumnFilterViewModel> CreateHeaderFilters()
        => new Dictionary<string, ColumnFilterViewModel>
        {
            ["TimestampUtc"] = Create("TimestampUtc", ColumnFilterKind.Timestamp),
            ["EventCode"] = Create("EventCode", ColumnFilterKind.Values),
            ["Description"] = Create("Description", ColumnFilterKind.Values),
            ["DetailsSummary"] = Create("DetailsSummary", ColumnFilterKind.Text)
        };

    private ColumnFilterViewModel Create(string key, ColumnFilterKind kind)
        => new(key, kind, (search, token) =>
        {
            token.ThrowIfCancellationRequested();
            var values = Events.Where(row => MatchesFilters(row, key))
                .Select(row => key == "EventCode" ? row.EventCode?.ToString(CultureInfo.InvariantCulture) : row.Description)
                .Where(value => ColumnTextFilter.Matches(value, search)).Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal).Take(257).ToArray();
            return Task.FromResult(new ColumnFilterValuePage(values.Take(256).ToArray(), values.Length > 256));
        }, ApplyFilters);

    private static bool MatchesHeader(EventRowViewModel row, string key, ColumnFilterCriteria filter)
        => key switch
        {
            "TimestampUtc" => filter.Matches(null, timestampUtc: row.TimestampUtc),
            "EventCode" => filter.Matches(row.EventCode?.ToString(CultureInfo.InvariantCulture)),
            "Description" => filter.Matches(row.Description),
            "DetailsSummary" => filter.Matches(row.DetailsSummary),
            _ => false
        };

    private void CloseHeaderFilters()
    {
        if (HeaderFilters != null) foreach (var filter in HeaderFilters.Values) filter.Close();
    }
}
