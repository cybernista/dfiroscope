namespace ProcInsider.Services;

/// <summary>Immutable applied header-filter snapshot. Values are ordinal exact exceptions
/// when AllValues is true, or explicit inclusions otherwise. Empty inclusions match nothing.</summary>
public sealed record ColumnFilterCriteria
{
    public bool AllValues { get; init; } = true;
    public IReadOnlyList<string?> Values { get; init; } = Array.Empty<string?>();
    public string? Text { get; init; }
    public long? Minimum { get; init; }
    public long? Maximum { get; init; }
    public DateTime? FromUtc { get; init; }
    public DateTime? ToUtc { get; init; }
    public bool IncludeMissing { get; init; }
    public bool IsActive => !AllValues || Values.Count != 0 || ColumnTextFilter.Normalize(Text) != null ||
        Minimum.HasValue || Maximum.HasValue || FromUtc.HasValue || ToUtc.HasValue;

    public void Validate()
    {
        if (Values.Count > 4096 || Minimum > Maximum || FromUtc > ToUtc ||
            ((Minimum.HasValue || Maximum.HasValue) && (FromUtc.HasValue || ToUtc.HasValue)) ||
            (FromUtc.HasValue && FromUtc.Value.Kind != DateTimeKind.Utc) ||
            (ToUtc.HasValue && ToUtc.Value.Kind != DateTimeKind.Utc))
            throw new ArgumentException("Invalid column filter bounds or selection size.");
    }

    public bool Matches(string? text, long? number = null, DateTime? timestampUtc = null)
    {
        Validate();
        if (Values.Contains(text, StringComparer.Ordinal) == AllValues || !ColumnTextFilter.Matches(text, Text))
            return false;
        if (Minimum.HasValue || Maximum.HasValue)
        {
            if (!number.HasValue) return IncludeMissing;
            if (number < Minimum || number > Maximum) return false;
        }
        if (FromUtc.HasValue || ToUtc.HasValue)
        {
            if (!timestampUtc.HasValue) return IncludeMissing;
            if (timestampUtc < FromUtc || timestampUtc > ToUtc) return false;
        }
        return true;
    }
}

public enum ColumnFilterValueSort { ValueAscending, ValueDescending, CountAscending, CountDescending }

public sealed record ColumnFilterValue(string? Value, long Count);

public sealed record ColumnFilterValuePage(IReadOnlyList<ColumnFilterValue> Entries, bool HasMore)
{
    public IReadOnlyList<string?> Values => Entries.Select(entry => entry.Value).ToArray();

    /// <summary>Group the full matching input before sorting and bounding the displayed values.</summary>
    public static ColumnFilterValuePage FromValues(IEnumerable<string?> values, ColumnFilterValueSort sort, int limit = 256)
    {
        var groups = values.GroupBy(value => value, StringComparer.Ordinal)
            .Select(group => new ColumnFilterValue(group.Key, group.LongCount()));
        var ordered = sort switch
        {
            ColumnFilterValueSort.ValueAscending => groups.OrderBy(entry => entry.Value, StringComparer.Ordinal),
            ColumnFilterValueSort.ValueDescending => groups.OrderByDescending(entry => entry.Value, StringComparer.Ordinal),
            ColumnFilterValueSort.CountAscending => groups.OrderBy(entry => entry.Count).ThenBy(entry => entry.Value, StringComparer.Ordinal),
            ColumnFilterValueSort.CountDescending => groups.OrderByDescending(entry => entry.Count).ThenBy(entry => entry.Value, StringComparer.Ordinal),
            _ => throw new ArgumentOutOfRangeException(nameof(sort))
        };
        var page = ordered.Take(limit + 1).ToArray();
        return new(page.Take(limit).ToArray(), page.Length > limit);
    }
}
