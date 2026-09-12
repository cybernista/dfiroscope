using System.Globalization;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal sealed partial class ProcessListingQueryService
{
    public Task<ColumnFilterValuePage> GetColumnValuesAsync(ProcessListingFilterSet filters,
        ProcessListingSortColumn column, string? search, int limit = 256, CancellationToken cancellationToken = default)
        => Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var connection = OpenListingConnection();
            return RunCancellableColumnRead(connection, cancellationToken, () =>
            {
                using var command = connection.CreateCommand();
                var where = BuildFilterClause(filters, command.Parameters, connection, column);
                var source = BuildProcessSourceExpression(filters, connection);
                var expression = GetHeaderFilterExpression(column, connection);
                limit = Math.Clamp(limit, 1, 1000);
                var hasSearch = ColumnTextFilter.Normalize(search) != null;
                command.CommandText = $"""
                    SELECT DISTINCT CAST({expression} AS TEXT) AS FilterValue
                    FROM {source}
                    WHERE ({(string.IsNullOrEmpty(where) ? "1=1" : where)})
                      AND {(hasSearch ? $"dfiroscope_column_match(CAST({expression} AS TEXT), $FacetSearch)" : "1=1")}
                    ORDER BY FilterValue COLLATE BINARY LIMIT $FacetLimit;
                    """;
                if (hasSearch) command.Parameters.AddWithValue("$FacetSearch", search!);
                command.Parameters.AddWithValue("$FacetLimit", limit + 1);
                using var reader = command.ExecuteReader();
                var values = new List<string?>();
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    values.Add(reader.IsDBNull(0) ? null : reader.GetString(0));
                }
                return new ColumnFilterValuePage(values.Take(limit).ToArray(), values.Count > limit);
            });
        }, cancellationToken);

    // SqliteCommand.Cancel is a no-op in the pinned provider. Poll inside SQLite instead,
    // including the scan/sort before its first row. Clear the callback before pooling the handle.
    private static T RunCancellableColumnRead<T>(SqliteConnection connection, CancellationToken token, Func<T> read)
    {
        token.ThrowIfCancellationRequested();
        SQLitePCL.delegate_progress progress = _ => token.IsCancellationRequested ? 1 : 0;
        SQLitePCL.raw.sqlite3_progress_handler(connection.Handle, 1000, progress, null!);
        try
        {
            var result = read();
            token.ThrowIfCancellationRequested();
            return result;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 9 && token.IsCancellationRequested)
        {
            throw new OperationCanceledException("The column value query was cancelled.", ex, token);
        }
        finally
        {
            SQLitePCL.raw.sqlite3_progress_handler(connection.Handle, 0, null!, null!);
            GC.KeepAlive(progress);
        }
    }

    private void AddHeaderFilters(List<string> predicates, SqliteParameterCollection parameters,
        ProcessListingFilterSet filters, SqliteConnection connection, ProcessListingSortColumn? excludedColumn)
    {
        var index = 0;
        foreach (var (column, filter) in filters.ColumnFilters)
        {
            filter.Validate();
            if (column == excludedColumn || !filter.IsActive) continue;
            var expression = GetHeaderFilterExpression(column, connection);
            var prefix = $"$Header{index++}_";
            if (!filter.AllValues || filter.Values.Count != 0)
            {
                var selections = new List<string>();
                var names = new List<string>();
                foreach (var value in filter.Values)
                {
                    if (value == null) continue;
                    var parameter = prefix + names.Count;
                    parameters.AddWithValue(parameter, value);
                    names.Add(parameter);
                }
                if (names.Count != 0) selections.Add($"CAST({expression} AS TEXT) COLLATE BINARY IN ({string.Join(",", names)})");
                if (filter.Values.Contains(null)) selections.Add($"{expression} IS NULL");
                var match = selections.Count == 0 ? "0=1" : string.Join(" OR ", selections);
                // COALESCE ensures an unavailable value is retained unless explicitly excluded.
                predicates.Add(filter.AllValues ? $"NOT COALESCE(({match}), 0)" : $"({match})");
            }
            if (ColumnTextFilter.Normalize(filter.Text) != null)
            {
                parameters.AddWithValue(prefix + "Text", filter.Text);
                predicates.Add($"dfiroscope_column_match(CAST({expression} AS TEXT), {prefix}Text)");
            }
            var ranges = new List<string>();
            void AddBound(string suffix, object? value, string operation)
            {
                if (value == null) return;
                parameters.AddWithValue(prefix + suffix, value);
                ranges.Add($"{expression} {operation} {prefix}{suffix}");
            }
            AddBound("Min", filter.Minimum, ">=");
            AddBound("Max", filter.Maximum, "<=");
            AddBound("From", filter.FromUtc?.ToString("O", CultureInfo.InvariantCulture), ">=");
            AddBound("To", filter.ToUtc?.ToString("O", CultureInfo.InvariantCulture), "<=");
            if (ranges.Count != 0)
            {
                var range = string.Join(" AND ", ranges);
                predicates.Add(filter.IncludeMissing ? $"({expression} IS NULL OR ({range}))" : $"({range})");
            }
        }
    }

    private static string GetHeaderFilterExpression(ProcessListingSortColumn column, SqliteConnection connection)
        => column switch
        {
            ProcessListingSortColumn.Tree or ProcessListingSortColumn.ProcessName => "Processes.ProcessName",
            ProcessListingSortColumn.ProcessId => "Processes.ProcessId",
            ProcessListingSortColumn.ParentProcessId => "Processes.ParentProcessId",
            ProcessListingSortColumn.ParentProcessName => "Processes.ParentProcessName",
            ProcessListingSortColumn.ProcessPath => "Processes.ProcessPath",
            ProcessListingSortColumn.CommandLine => "Processes.CommandLine",
            ProcessListingSortColumn.UserName => "Processes.UserName",
            ProcessListingSortColumn.SessionId => "Processes.SessionId",
            ProcessListingSortColumn.Architecture => "Processes.Architecture",
            ProcessListingSortColumn.Status => "Processes.Status",
            ProcessListingSortColumn.CompanyName => "Processes.CompanyName",
            ProcessListingSortColumn.FileDescription => "Processes.FileDescription",
            ProcessListingSortColumn.Sha256Hash => "Processes.Sha256Hash",
            ProcessListingSortColumn.StartTime => "NULLIF(Processes.StartTimeUtc, '')",
            ProcessListingSortColumn.EndTime => "NULLIF(Processes.EndTimeUtc, '')",
            ProcessListingSortColumn.MemoryUsage => "Processes.MemoryUsageBytes",
            ProcessListingSortColumn.ModuleCount => "Processes.ModuleCount",
            ProcessListingSortColumn.HandleCount => "Processes.HandleCount",
            ProcessListingSortColumn.ProcessRisk => ConfigureProcessRiskSort(connection,
                new ProcessListingSortDescriptor { Column = ProcessListingSortColumn.ProcessRisk }) ? "Processes.ListingRiskSortScore" : "NULL",
            ProcessListingSortColumn.TotalProcessorTime or ProcessListingSortColumn.ReadBytes or ProcessListingSortColumn.WrittenBytes or
            ProcessListingSortColumn.RuntimeEventCount or ProcessListingSortColumn.EtwEventCount or ProcessListingSortColumn.SecurityEventCount or
            ProcessListingSortColumn.PowerShellEventCount or ProcessListingSortColumn.OtherWindowsEventCount or ProcessListingSortColumn.SysmonEventCount
                => BuildSummarySortExpression(connection, column) ?? "NULL",
            _ => throw new ArgumentOutOfRangeException(nameof(column), "Unsupported header-filter column.")
        };
}
