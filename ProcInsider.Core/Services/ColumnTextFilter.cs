namespace ProcInsider.Services;

/// <summary>
/// Shared column-filter language for projected rows and database callbacks.
/// Keep future matching modes here so every consumer uses the same semantics.
/// </summary>
public static class ColumnTextFilter
{
    public static string? Normalize(string? text) =>
        string.IsNullOrWhiteSpace(text) ? null : text.Trim();

    public static bool Matches(string? value, string? text)
    {
        var query = Normalize(text);
        return query == null || (value?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false);
    }
}
