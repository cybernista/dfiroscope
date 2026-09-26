using System.Windows.Data;
using ProcInsider.Services;
using ProcInsider.ViewModels;

namespace ProcInsider.Features.InvestigationWorkspaces;

/// <summary>A local listing view: its filters never change evidence or column selections.</summary>
internal sealed class ExtractedEventFieldChooser
{
    private readonly List<ExtractedEventFieldChoice> _fields = [];
    public ListCollectionView Fields { get; }
    public IReadOnlyDictionary<string, ColumnFilterViewModel> HeaderFilters { get; }
    public ExtractedEventFieldChooser()
    {
        Fields = new(_fields);
        HeaderFilters = new[] { "Profile", "Priority", "Name" }.ToDictionary(key => key, key =>
            new ColumnFilterViewModel(key, ColumnFilterKind.Values, (search, sort, token) =>
            {
                token.ThrowIfCancellationRequested();
                var values = _fields.Where(f => Matches(f, key)).Select(f => Value(f, key))
                    .Where(v => ColumnTextFilter.Matches(v, search)).ToArray();
                return Task.FromResult(ColumnFilterValuePage.FromValues(values, sort));
            }, () => Fields.Refresh()));
        Fields.Filter = item => Matches((ExtractedEventFieldChoice)item);
    }
    private static string Value(ExtractedEventFieldChoice field, string key) => key switch
    { "Profile" => field.Profile, "Priority" => field.Priority.ToString(), _ => field.Name };
    private bool Matches(ExtractedEventFieldChoice field, string? except = null) =>
        HeaderFilters.All(p => p.Key == except || p.Value.Criteria.Matches(Value(field, p.Key)));
    internal void SetFields(IEnumerable<ExtractedEventFieldChoice> fields)
    {
        Close();
        _fields.Clear(); _fields.AddRange(fields);
        Fields.Refresh();
    }
    internal void Close() { foreach (var filter in HeaderFilters.Values) filter.Close(); }
}
