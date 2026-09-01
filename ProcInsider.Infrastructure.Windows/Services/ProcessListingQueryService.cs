using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

/// <summary>
/// Narrow read contract for the process listing, navigation, and exact process lookup family.
/// </summary>
public interface IProcessListingQueryService
{
    int CountProcesses(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default);

    ProcessListingPage GetProcessPage(
        ProcessListingQuery query,
        CancellationToken cancellationToken = default);

    Task<int> CountProcessesAsync(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default);

    Task<ProcessListingPage> GetProcessPageAsync(
        ProcessListingQuery query,
        CancellationToken cancellationToken = default);

    ProcessKeyLookupResult GetProcessByKey(string processKey);

    Task<ProcessKeyLookupResult> GetProcessByKeyAsync(string processKey);

    ProcessEntityLookupResult GetProcessByEntityId(string processEntityId);

    Task<ProcessEntityLookupResult> GetProcessByEntityIdAsync(string processEntityId);

    int GetProcessRowIndex(
        string processKey,
        ProcessListingQuery query,
        CancellationToken cancellationToken = default);

    Task<int> GetProcessRowIndexAsync(
        string processKey,
        ProcessListingQuery query,
        CancellationToken cancellationToken = default);

    IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeQueryPlans();
}

/// <summary>
/// Focused SQLite owner for process listing/count/page/navigation/exact-lookup reads.
/// The validated <see cref="SqliteStagingQueryService"/> remains the compatibility facade.
/// </summary>
internal sealed class ProcessListingQueryService : IProcessListingQueryService
{
    private static readonly ConditionalWeakTable<ProcessRecord, ListingCursorMetadata> ListingCursorMetadataByRecord = new();
    private readonly SqliteReadQueryContext _readContext;

    internal ProcessListingQueryService(SqliteReadQueryContext readContext)
    {
        _readContext = readContext;
    }

    public int CountProcesses(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = _readContext.OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        var whereClause = BuildFilterClause(filters, command.Parameters);
        var processSource = BuildProcessSourceExpression(filters, connection);
        command.CommandText = string.IsNullOrEmpty(whereClause)
            ? $"SELECT COUNT(*) FROM {processSource};"
            : $"SELECT COUNT(*) FROM {processSource} WHERE {whereClause};";
        using var registration = cancellationToken.Register(command.Cancel);
        var result = Convert.ToInt32(command.ExecuteScalar());
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    public ProcessListingPage GetProcessPage(
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
    {
        return _readContext.MeasureRead(
            "GetProcessPage",
            () =>
            {
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = _readContext.OpenReadOnlyConnection();

        var totalCount = -1;
        if (query.IncludeTotalCount)
        {
            using var countCommand = connection.CreateCommand();
            var countWhereClause = BuildFilterClause(query.Filters, countCommand.Parameters);
            var countProcessSource = BuildProcessSourceExpression(query.Filters, connection);
            countCommand.CommandText = string.IsNullOrEmpty(countWhereClause)
                ? $"SELECT COUNT(*) FROM {countProcessSource};"
                : $"SELECT COUNT(*) FROM {countProcessSource} WHERE {countWhereClause};";
            using var countRegistration = cancellationToken.Register(countCommand.Cancel);
            totalCount = Convert.ToInt32(countCommand.ExecuteScalar());
            cancellationToken.ThrowIfCancellationRequested();
        }

        // PAGE pass — reuse the same where clause with new parameter bindings
        var rows = new List<ProcessRecord>();
        using var pageCommand = connection.CreateCommand();
        var whereClause = BuildFilterClause(query.Filters, pageCommand.Parameters);
        var pageProcessSource = BuildProcessSourceExpression(query.Filters, connection);
        var riskSortAvailable = ConfigureProcessRiskSort(connection, query.Sort);
        if (riskSortAvailable)
        {
            pageProcessSource = BuildProcessRiskSortSource(pageProcessSource);
        }
        var orderByClause = BuildOrderByClause(query.Sort, riskSortAvailable);
        var requestedPageSize = Math.Clamp(query.PageSize, 1, 10000);
        var cursor = DecodeAndValidateCursor(query.Cursor, query.Sort);
        var useCursor = SupportsCursorPaging(query.Sort) &&
                        (cursor != null || Math.Max(query.Offset, 0) == 0);
        if (cursor != null)
        {
            var cursorPredicate = BuildCursorPredicate(query.Sort, cursor, pageCommand.Parameters);
            whereClause = string.IsNullOrEmpty(whereClause)
                ? cursorPredicate
                : $"({whereClause}) AND ({cursorPredicate})";
        }

        var whereFragment = string.IsNullOrEmpty(whereClause) ? string.Empty : $"WHERE {whereClause}";
        var offsetFragment = useCursor ? string.Empty : "OFFSET $Offset";
        var cursorValueExpression = GetCursorSortSpec(query.Sort.Column)?.Expression ?? "NULL";

        pageCommand.CommandText = $"""
            SELECT ProcessKey, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                   ModuleCaptureStatus, ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError,
                   HandleCaptureStatus, HandleCount, HandleLastCapturedUtc, HandleCaptureError,
                   ParentProcessId, ParentProcessKey, ParentProcessName, ProcessName, ProcessPath,
                   CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                   CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc,
                   LastObservedUtc, LastSource, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, ProcessEntityId, ParentProcessEntityId,
                   CAST({cursorValueExpression} AS TEXT) AS ListingCursorValue
            FROM {pageProcessSource}
            {whereFragment}
            ORDER BY {orderByClause}
            LIMIT $FetchSize {offsetFragment};
            """;
        pageCommand.Parameters.AddWithValue("$FetchSize", requestedPageSize + 1);
        if (!useCursor)
        {
            pageCommand.Parameters.AddWithValue("$Offset", Math.Max(query.Offset, 0));
        }

        using var pageRegistration = cancellationToken.Register(pageCommand.Cancel);
        using var reader = pageCommand.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            rows.Add(ReadProcess(reader));
        }

        var hasMore = rows.Count > requestedPageSize;
        if (hasMore)
        {
            rows.RemoveAt(rows.Count - 1);
        }

        return new ProcessListingPage
        {
            Rows = rows,
            TotalCount = totalCount,
            HasMore = hasMore,
            PagingMode = useCursor ? ProcessListingPagingMode.Cursor : ProcessListingPagingMode.Offset,
            NextCursor = hasMore && SupportsCursorPaging(query.Sort) && rows.Count > 0
                ? EncodeCursor(query.Sort, rows[^1])
                : null
        };
            },
            $"offset={query.Offset}; page_size={query.PageSize}; cursor={(string.IsNullOrWhiteSpace(query.Cursor) ? "none" : "set")}",
            page => page.Rows.Count);
    }

    public Task<int> CountProcessesAsync(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default)
        => Task.Run(() => CountProcesses(filters, cancellationToken), cancellationToken);

    public Task<ProcessListingPage> GetProcessPageAsync(
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
        => Task.Run(() => GetProcessPage(query, cancellationToken), cancellationToken);

    /// <summary>
    /// Looks up a single process record by its exact <paramref name="processKey"/>.
    /// Returns <see cref="ProcessKeyLookupResult.IsFound"/> = <c>false</c> when
    /// the key is not present in the database.
    /// </summary>
    public ProcessKeyLookupResult GetProcessByKey(string processKey)
    {
        using var connection = _readContext.OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        var processSource = GetProcessSource(connection);
        command.CommandText = """
            SELECT ProcessKey, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                   ModuleCaptureStatus, ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError,
                   HandleCaptureStatus, HandleCount, HandleLastCapturedUtc, HandleCaptureError,
                   ParentProcessId, ParentProcessKey, ParentProcessName, ProcessName, ProcessPath,
                   CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                   CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc,
                   LastObservedUtc, LastSource, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, ProcessEntityId, ParentProcessEntityId
            FROM {PROCESS_SOURCE}
            WHERE ProcessKey = $ProcessKey
            ORDER BY LastObservedUtc DESC
            LIMIT 1;
            """.Replace("{PROCESS_SOURCE}", processSource, StringComparison.Ordinal);
        command.Parameters.AddWithValue("$ProcessKey", processKey);
        using var reader = command.ExecuteReader();
        if (reader.Read())
            return new ProcessKeyLookupResult { IsFound = true, Process = ReadProcess(reader) };
        return new ProcessKeyLookupResult { IsFound = false };
    }

    /// <inheritdoc cref="GetProcessByKey"/>
    public Task<ProcessKeyLookupResult> GetProcessByKeyAsync(string processKey)
        => Task.Run(() => GetProcessByKey(processKey));

    public ProcessEntityLookupResult GetProcessByEntityId(string processEntityId)
    {
        if (string.IsNullOrWhiteSpace(processEntityId))
        {
            return new ProcessEntityLookupResult { IsFound = false };
        }

        using var connection = _readContext.OpenReadOnlyConnection();
        if (!TableExists(connection, "ProcessEntities"))
        {
            return new ProcessEntityLookupResult { IsFound = false };
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ProcessKey, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                   ModuleCaptureStatus, ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError,
                   HandleCaptureStatus, HandleCount, HandleLastCapturedUtc, HandleCaptureError,
                   ParentProcessId, ParentProcessKey, ParentProcessName, ProcessName, ProcessPath,
                   CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                   CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc,
                   LastObservedUtc, LastSource, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, ProcessEntityId, ParentProcessEntityId
            FROM ProcessEntities
            WHERE ProcessEntityId = $ProcessEntityId
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$ProcessEntityId", processEntityId);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new ProcessEntityLookupResult { IsFound = true, Process = ReadProcess(reader) }
            : new ProcessEntityLookupResult { IsFound = false };
    }

    public Task<ProcessEntityLookupResult> GetProcessByEntityIdAsync(string processEntityId)
        => Task.Run(() => GetProcessByEntityId(processEntityId));


    /// <summary>
    /// Returns the 0-based row index of <paramref name="processKey"/> within the
    /// result set produced by <paramref name="query"/> (respecting its filters and
    /// sort, but ignoring its <c>Offset</c> and <c>PageSize</c>).
    /// Returns <c>-1</c> when the key is not present in the filtered result set.
    /// </summary>
    public int GetProcessRowIndex(
        string processKey,
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
    {
        return _readContext.MeasureRead(
            "GetProcessRowIndex",
            () =>
            {
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = _readContext.OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        var whereClause = BuildFilterClause(query.Filters, command.Parameters);
        var whereFragment = string.IsNullOrEmpty(whereClause) ? string.Empty : $"WHERE {whereClause}";
        var processSource = BuildProcessSourceExpression(query.Filters, connection);
        var riskSortAvailable = ConfigureProcessRiskSort(connection, query.Sort);
        if (riskSortAvailable)
        {
            processSource = BuildProcessRiskSortSource(processSource);
        }
        var orderByClause = BuildOrderByClause(query.Sort, riskSortAvailable);
        command.Parameters.AddWithValue("$TargetKey", processKey);
        command.CommandText = $"""
            WITH ranked AS (
                SELECT ProcessKey,
                       CAST(ROW_NUMBER() OVER (ORDER BY {orderByClause}) AS INTEGER) - 1 AS idx
                FROM {processSource}
                {whereFragment}
            )
            SELECT idx FROM ranked WHERE ProcessKey = $TargetKey LIMIT 1;
            """;
        using var registration = cancellationToken.Register(command.Cancel);
        var scalar = command.ExecuteScalar();
        cancellationToken.ThrowIfCancellationRequested();
        return scalar == null || scalar == DBNull.Value ? -1 : Convert.ToInt32(scalar);
            },
            $"process_key={processKey}; page_size={query.PageSize}");
    }

    /// <inheritdoc cref="GetProcessRowIndex"/>
    public Task<int> GetProcessRowIndexAsync(
        string processKey,
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
        => Task.Run(
            () => GetProcessRowIndex(processKey, query, cancellationToken),
            cancellationToken);


    public IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeQueryPlans()
    {
        return _readContext.MeasureRead(
            "GetRepresentativeProcessListingQueryPlans",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var plans = new List<SqliteQueryPlanRecord>();
                var processTable = GetProcessTable(connection);

                AddQueryPlan(
                    plans,
                    connection,
                    "process page by start time",
                    $"""
                    SELECT ProcessKey
                    FROM {processTable}
                    ORDER BY StartTimeUtc DESC,
                             COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY DESC
                    LIMIT $PageSize OFFSET $Offset;
                    """,
                    command =>
                    {
                        command.Parameters.AddWithValue("$PageSize", 100);
                        command.Parameters.AddWithValue("$Offset", 0);
                    });
                AddQueryPlan(
                    plans,
                    connection,
                    "filtered process count",
                    $"SELECT COUNT(*) FROM {processTable} WHERE Status = $Status;",
                    command => command.Parameters.AddWithValue("$Status", ProcessStatus.Running.ToString()));
                AddQueryPlan(
                    plans,
                    connection,
                    "filtered process page",
                    $"""
                    SELECT ProcessKey
                    FROM {processTable}
                    WHERE ProcessName LIKE $ProcessName
                    ORDER BY ProcessName COLLATE NOCASE ASC,
                             COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY ASC
                    LIMIT $PageSize OFFSET $Offset;
                    """,
                    command =>
                    {
                        command.Parameters.AddWithValue("$ProcessName", "%svchost%");
                        command.Parameters.AddWithValue("$PageSize", 100);
                        command.Parameters.AddWithValue("$Offset", 0);
                    });
                AddQueryPlan(
                    plans,
                    connection,
                    "process row index",
                    $"""
                    WITH ranked AS (
                        SELECT ProcessKey,
                               ROW_NUMBER() OVER (
                                   ORDER BY ProcessName COLLATE NOCASE ASC,
                                            COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY ASC
                               ) AS RowNumber
                        FROM {processTable}
                    )
                    SELECT RowNumber FROM ranked WHERE ProcessKey = $ProcessKey LIMIT 1;
                    """,
                    command => command.Parameters.AddWithValue("$ProcessKey", string.Empty));
                AddQueryPlan(
                    plans,
                    connection,
                    "exact process key lookup",
                    $"SELECT ProcessKey FROM {processTable} WHERE ProcessKey = $ProcessKey LIMIT 1;",
                    command => command.Parameters.AddWithValue("$ProcessKey", string.Empty));
                if (TableExists(connection, "ProcessEntities"))
                {
                    AddQueryPlan(
                        plans,
                        connection,
                        "exact process entity lookup",
                        "SELECT ProcessEntityId FROM ProcessEntities WHERE ProcessEntityId = $ProcessEntityId LIMIT 1;",
                        command => command.Parameters.AddWithValue("$ProcessEntityId", string.Empty));
                }

                AddQueryPlan(
                    plans,
                    connection,
                    "process tree page",
                    $"""
                    SELECT ProcessKey
                    FROM {processTable}
                    ORDER BY COALESCE(NULLIF(ExecutionRootId, ''), ProcessKey) COLLATE NOCASE ASC,
                             TreeDepth ASC,
                             COALESCE(StartTimeUtc, FirstObservedUtc) ASC,
                             ProcessName COLLATE NOCASE ASC,
                             ProcessId ASC,
                             COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY ASC
                    LIMIT $PageSize OFFSET $Offset;
                    """,
                    command =>
                    {
                        command.Parameters.AddWithValue("$PageSize", 100);
                        command.Parameters.AddWithValue("$Offset", 0);
                    });

                return plans;
            },
            "representative process listing EXPLAIN QUERY PLAN reads",
            plans => plans.Count);
    }

    private string BuildFilterClause(ProcessListingFilterSet filters, SqliteParameterCollection parameters)
    {
        var predicates = new List<string>();

        if (!string.IsNullOrEmpty(filters.ProcessNameContains))
        {
            predicates.Add("ProcessName LIKE $ProcessNameContains");
            parameters.AddWithValue("$ProcessNameContains", $"%{filters.ProcessNameContains}%");
        }
        if (filters.ProcessIdEquals.HasValue)
        {
            predicates.Add("ProcessId = $ProcessIdEquals");
            parameters.AddWithValue("$ProcessIdEquals", filters.ProcessIdEquals.Value);
        }
        if (!string.IsNullOrEmpty(filters.ProcessIdContains))
        {
            predicates.Add("CAST(ProcessId AS TEXT) LIKE $ProcessIdContains");
            parameters.AddWithValue("$ProcessIdContains", $"%{filters.ProcessIdContains}%");
        }
        if (filters.ParentProcessIdEquals.HasValue)
        {
            predicates.Add("ParentProcessId = $ParentProcessIdEquals");
            parameters.AddWithValue("$ParentProcessIdEquals", filters.ParentProcessIdEquals.Value);
        }
        if (!string.IsNullOrEmpty(filters.ParentProcessIdContains))
        {
            predicates.Add("CAST(ParentProcessId AS TEXT) LIKE $ParentProcessIdContains");
            parameters.AddWithValue("$ParentProcessIdContains", $"%{filters.ParentProcessIdContains}%");
        }
        if (!string.IsNullOrEmpty(filters.ParentProcessNameContains))
        {
            predicates.Add("ParentProcessName LIKE $ParentProcessNameContains");
            parameters.AddWithValue("$ParentProcessNameContains", $"%{filters.ParentProcessNameContains}%");
        }
        if (!string.IsNullOrEmpty(filters.ProcessPathContains))
        {
            predicates.Add("ProcessPath LIKE $ProcessPathContains");
            parameters.AddWithValue("$ProcessPathContains", $"%{filters.ProcessPathContains}%");
        }
        if (!string.IsNullOrEmpty(filters.CommandLineContains))
        {
            predicates.Add("CommandLine LIKE $CommandLineContains");
            parameters.AddWithValue("$CommandLineContains", $"%{filters.CommandLineContains}%");
        }
        if (!string.IsNullOrEmpty(filters.UserNameContains))
        {
            predicates.Add("UserName LIKE $UserNameContains");
            parameters.AddWithValue("$UserNameContains", $"%{filters.UserNameContains}%");
        }
        if (filters.SessionIdEquals.HasValue)
        {
            predicates.Add("SessionId = $SessionIdEquals");
            parameters.AddWithValue("$SessionIdEquals", filters.SessionIdEquals.Value);
        }
        if (!string.IsNullOrEmpty(filters.ArchitectureContains))
        {
            predicates.Add("Architecture LIKE $ArchitectureContains");
            parameters.AddWithValue("$ArchitectureContains", $"%{filters.ArchitectureContains}%");
        }
        if (filters.Status.HasValue)
        {
            predicates.Add("Status = $Status");
            parameters.AddWithValue("$Status", filters.Status.Value.ToString());
        }
        if (!string.IsNullOrEmpty(filters.StatusContains))
        {
            predicates.Add("Status LIKE $StatusContains");
            parameters.AddWithValue("$StatusContains", $"%{filters.StatusContains}%");
        }
        if (!string.IsNullOrEmpty(filters.CompanyNameContains))
        {
            predicates.Add("CompanyName LIKE $CompanyNameContains");
            parameters.AddWithValue("$CompanyNameContains", $"%{filters.CompanyNameContains}%");
        }
        if (!string.IsNullOrEmpty(filters.FileDescriptionContains))
        {
            predicates.Add("FileDescription LIKE $FileDescriptionContains");
            parameters.AddWithValue("$FileDescriptionContains", $"%{filters.FileDescriptionContains}%");
        }
        if (!string.IsNullOrEmpty(filters.Sha256HashContains))
        {
            predicates.Add("Sha256Hash LIKE $Sha256HashContains");
            parameters.AddWithValue("$Sha256HashContains", $"%{filters.Sha256HashContains}%");
        }
        AddFilterIdentityPredicate(predicates, parameters, "CaseId", filters.CaseId, "$CaseId");
        AddFilterIdentityPredicate(predicates, parameters, "EvidenceSessionId", filters.EvidenceSessionId, "$EvidenceSessionId");
        AddFilterIdentityPredicate(predicates, parameters, "CaptureId", filters.CaptureId, "$CaptureId");
        AddFilterIdentityPredicate(predicates, parameters, "SourceIdentityId", filters.SourceIdentityId, "$SourceIdentityId");
        AddFilterIdentityPredicate(predicates, parameters, "HostId", filters.HostId, "$HostId");
        AddFilterIdentityPredicate(predicates, parameters, "ExecutionRootId", filters.ExecutionRootId, "$ExecutionRootId");
        if (!string.IsNullOrWhiteSpace(filters.OwnerKey))
        {
            predicates.Add($"{BuildOwnerKeyExpression("Processes")} = $OwnerKey");
            parameters.AddWithValue("$OwnerKey", filters.OwnerKey);
        }
        if (!string.IsNullOrWhiteSpace(filters.ProcessSubtreeRootKey))
        {
            predicates.Add($"""
                ProcessKey IN (
                    WITH RECURSIVE ProcessSubtree(ProcessKey) AS (
                        SELECT ProcessKey
                        FROM Processes
                        WHERE ProcessKey = $ProcessSubtreeRootKey
                        UNION
                        SELECT child.ProcessKey
                        FROM ProcessSubtree parent
                        JOIN Processes parentProcess ON parentProcess.ProcessKey = parent.ProcessKey
                        JOIN Processes child ON {BuildProcessParentMatchPredicate("child", "parentProcess")}
                        WHERE 1 = 1
                          AND child.ProcessKey <> parent.ProcessKey
                    )
                    SELECT ProcessKey FROM ProcessSubtree
                )
                """);
            parameters.AddWithValue("$ProcessSubtreeRootKey", filters.ProcessSubtreeRootKey);
        }
        if (filters.RequireModules)
        {
            predicates.Add("EXISTS (SELECT 1 FROM Modules m WHERE m.ProcessKey = Processes.ProcessKey LIMIT 1)");
        }
        if (filters.RequireHandles)
        {
            predicates.Add("EXISTS (SELECT 1 FROM Handles h WHERE h.ProcessKey = Processes.ProcessKey LIMIT 1)");
        }
        if (!string.IsNullOrEmpty(filters.RequireEventSource))
        {
            predicates.Add("EXISTS (SELECT 1 FROM ProcessEvents e WHERE e.ProcessKey = Processes.ProcessKey AND e.Source = $RequireEventSource LIMIT 1)");
            parameters.AddWithValue("$RequireEventSource", filters.RequireEventSource);
        }
        if (filters.RequireBookmarked)
        {
            predicates.Add(BuildProcessAnnotationTargetPredicate());
        }

        var includePredicateGroups = new List<List<string>>();
        var includeKeyPredicate = BuildProcessKeySetPredicate(
            filters.IncludedProcessKeys,
            include: true,
            parameters,
            "IncludeProcessKey");
        if (!string.IsNullOrEmpty(includeKeyPredicate))
        {
            includePredicateGroups.Add(new List<string> { includeKeyPredicate });
        }

        var includeScopeIndex = 0;
        foreach (var scopeGroup in filters.IncludedScopes.GroupBy(GetScopeIncludeGroupKey))
        {
            var groupPredicates = new List<string>();
            foreach (var scope in scopeGroup)
            {
                groupPredicates.Add(BuildScopePredicate(scope, parameters, $"IncludeScope{includeScopeIndex}"));
                includeScopeIndex++;
            }

            if (groupPredicates.Count > 0)
            {
                includePredicateGroups.Add(groupPredicates);
            }
        }

        foreach (var includePredicates in includePredicateGroups)
        {
            predicates.Add("(" + string.Join(" OR ", includePredicates) + ")");
        }

        if (filters.SelectedScopes.Count > 0)
        {
            var selectedScopePredicates = new List<string>();
            for (var i = 0; i < filters.SelectedScopes.Count; i++)
            {
                selectedScopePredicates.Add(BuildScopePredicate(filters.SelectedScopes[i], parameters, $"SelectedScope{i}"));
            }

            predicates.Add("(" + string.Join(" OR ", selectedScopePredicates) + ")");
        }

        if (filters.SelectedDirectChildScopes.Count > 0)
        {
            var selectedChildPredicates = new List<string>();
            for (var i = 0; i < filters.SelectedDirectChildScopes.Count; i++)
            {
                selectedChildPredicates.Add(BuildDirectChildScopePredicate(filters.SelectedDirectChildScopes[i], parameters, $"SelectedChildScope{i}"));
            }

            predicates.Add("(" + string.Join(" OR ", selectedChildPredicates) + ")");
        }

        var excludeKeyPredicate = BuildProcessKeySetPredicate(
            filters.ExcludedProcessKeys,
            include: false,
            parameters,
            "ExcludeProcessKey");
        if (!string.IsNullOrEmpty(excludeKeyPredicate))
        {
            predicates.Add(excludeKeyPredicate);
        }

        for (var i = 0; i < filters.ExcludedScopes.Count; i++)
        {
            predicates.Add("NOT (" + BuildScopePredicate(filters.ExcludedScopes[i], parameters, $"ExcludeScope{i}") + ")");
        }

        return string.Join(" AND ", predicates);
    }

    private static void AddFilterIdentityPredicate(
        List<string> predicates,
        SqliteParameterCollection parameters,
        string columnName,
        string? value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        predicates.Add($"{columnName} = {parameterName}");
        parameters.AddWithValue(parameterName, value);
    }

    private static void AddScopeIdentityPredicate(
        List<string> predicates,
        SqliteParameterCollection parameters,
        string columnName,
        string? value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var sqlParameterName = $"${parameterName}";
        predicates.Add($"{columnName} = {sqlParameterName}");
        parameters.AddWithValue(sqlParameterName, value);
    }

    internal static string BuildProcessParentMatchPredicate(string childAlias, string parentAlias)
    {
        return $"""
            (
                {childAlias}.ProcessKey <> {parentAlias}.ProcessKey
                AND (
                    (
                        {childAlias}.ParentProcessEntityId IS NOT NULL
                        AND {childAlias}.ParentProcessEntityId <> ''
                        AND {childAlias}.ParentProcessEntityId = {parentAlias}.ProcessEntityId
                    )
                    OR
                    (
                        {childAlias}.ParentProcessKey = {parentAlias}.ProcessKey
                        AND {BuildIdentityMatchPredicate(childAlias, parentAlias)}
                    )
                    OR (
                        ({childAlias}.ParentProcessKey IS NULL OR {childAlias}.ParentProcessKey = '')
                        AND {childAlias}.ParentProcessId > 0
                        AND {childAlias}.ParentProcessId = {parentAlias}.ProcessId
                        AND {BuildIdentityMatchPredicate(childAlias, parentAlias)}
                        AND (
                            {childAlias}.StartTimeUtc IS NULL
                            OR {parentAlias}.StartTimeUtc IS NULL
                            OR {childAlias}.StartTimeUtc >= {parentAlias}.StartTimeUtc
                        )
                    )
                )
            )
            """;
    }

    private static string BuildIdentityMatchPredicate(string leftAlias, string rightAlias)
    {
        return $"""
            COALESCE({leftAlias}.CaseId, '') = COALESCE({rightAlias}.CaseId, '')
            AND COALESCE({leftAlias}.EvidenceSessionId, '') = COALESCE({rightAlias}.EvidenceSessionId, '')
            AND COALESCE({leftAlias}.HostId, '') = COALESCE({rightAlias}.HostId, '')
            AND COALESCE({leftAlias}.ExecutionRootId, '') = COALESCE({rightAlias}.ExecutionRootId, '')
            """;
    }

    private static string? BuildProcessKeySetPredicate(
        IReadOnlyList<string> processKeys,
        bool include,
        SqliteParameterCollection parameters,
        string parameterPrefix)
    {
        var keys = processKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (keys.Count == 0)
        {
            return null;
        }

        var parameterNames = new List<string>(keys.Count);
        for (var i = 0; i < keys.Count; i++)
        {
            var parameterName = $"${parameterPrefix}{i}";
            parameterNames.Add(parameterName);
            parameters.AddWithValue(parameterName, keys[i]);
        }

        var op = include ? "IN" : "NOT IN";
        return $"ProcessKey {op} ({string.Join(", ", parameterNames)})";
    }

    private string BuildScopePredicate(
        ExplorerScope scope,
        SqliteParameterCollection parameters,
        string parameterPrefix)
    {
        var scopePredicates = new List<string>();

        if (scope.Status.HasValue)
        {
            var parameterName = $"${parameterPrefix}Status";
            scopePredicates.Add($"Status = {parameterName}");
            parameters.AddWithValue(parameterName, scope.Status.Value.ToString());
        }

        AddScopeIdentityPredicate(scopePredicates, parameters, "CaseId", scope.CaseId, $"{parameterPrefix}CaseId");
        AddScopeIdentityPredicate(scopePredicates, parameters, "EvidenceSessionId", scope.EvidenceSessionId, $"{parameterPrefix}EvidenceSessionId");
        AddScopeIdentityPredicate(scopePredicates, parameters, "CaptureId", scope.CaptureId, $"{parameterPrefix}CaptureId");
        AddScopeIdentityPredicate(scopePredicates, parameters, "SourceIdentityId", scope.SourceIdentityId, $"{parameterPrefix}SourceIdentityId");
        AddScopeIdentityPredicate(scopePredicates, parameters, "HostId", scope.HostId, $"{parameterPrefix}HostId");
        AddScopeIdentityPredicate(scopePredicates, parameters, "ExecutionRootId", scope.ExecutionRootId, $"{parameterPrefix}ExecutionRootId");

        if (!string.IsNullOrWhiteSpace(scope.OwnerKey))
        {
            var parameterName = $"${parameterPrefix}OwnerKey";
            scopePredicates.Add($"{BuildOwnerKeyExpression("Processes")} = {parameterName}");
            parameters.AddWithValue(parameterName, scope.OwnerKey);
        }

        if (!string.IsNullOrWhiteSpace(scope.ProcessKey))
        {
            var parameterName = $"${parameterPrefix}ProcessSubtreeRootKey";
            scopePredicates.Add($"""
                ProcessKey IN (
                    WITH RECURSIVE ProcessSubtree(ProcessKey) AS (
                        SELECT ProcessKey
                        FROM Processes
                        WHERE ProcessKey = {parameterName}
                        UNION
                        SELECT child.ProcessKey
                        FROM ProcessSubtree parent
                        JOIN Processes parentProcess ON parentProcess.ProcessKey = parent.ProcessKey
                        JOIN Processes child ON {BuildProcessParentMatchPredicate("child", "parentProcess")}
                        WHERE 1 = 1
                          AND child.ProcessKey <> parent.ProcessKey
                    )
                    SELECT ProcessKey FROM ProcessSubtree
                )
                """);
            parameters.AddWithValue(parameterName, scope.ProcessKey);
        }

        if (scope.ArtifactScope == ExplorerArtifactScope.Modules)
        {
            scopePredicates.Add("EXISTS (SELECT 1 FROM Modules m WHERE m.ProcessKey = Processes.ProcessKey LIMIT 1)");
        }

        if (scope.ArtifactScope == ExplorerArtifactScope.Handles)
        {
            scopePredicates.Add("EXISTS (SELECT 1 FROM Handles h WHERE h.ProcessKey = Processes.ProcessKey LIMIT 1)");
        }

        if (scope.RequiredPeAnalysisSourceKind.HasValue)
        {
            var parameterName = $"${parameterPrefix}PeAnalysisSourceKind";
            scopePredicates.Add($"EXISTS (SELECT 1 FROM PeAnalyses p WHERE p.ProcessKey = Processes.ProcessKey AND p.SourceKind = {parameterName} LIMIT 1)");
            parameters.AddWithValue(parameterName, scope.RequiredPeAnalysisSourceKind.Value.ToString());
        }

        if (!string.IsNullOrEmpty(scope.EventSource))
        {
            var parameterName = $"${parameterPrefix}EventSource";
            scopePredicates.Add($"EXISTS (SELECT 1 FROM ProcessEvents e WHERE e.ProcessKey = Processes.ProcessKey AND e.Source = {parameterName} LIMIT 1)");
            parameters.AddWithValue(parameterName, scope.EventSource);
        }

        if (scope.Kind == ExplorerScopeKind.Bookmarked)
        {
            scopePredicates.Add(BuildProcessAnnotationTargetPredicate());
        }

        return scopePredicates.Count == 0
            ? "1 = 1"
            : string.Join(" AND ", scopePredicates);
    }

    private static string BuildDirectChildScopePredicate(
        ExplorerScope scope,
        SqliteParameterCollection parameters,
        string parameterPrefix)
    {
        if (string.IsNullOrWhiteSpace(scope.ProcessKey))
        {
            return "1 = 0";
        }

        var parameterName = $"${parameterPrefix}ProcessKey";
        parameters.AddWithValue(parameterName, scope.ProcessKey);
        return $"""
            EXISTS (
                SELECT 1
                FROM Processes parent
                WHERE parent.ProcessKey = {parameterName}
                  AND {BuildProcessParentMatchPredicate("Processes", "parent")}
                LIMIT 1
            )
            """;
    }

    private static string GetScopeIncludeGroupKey(ExplorerScope scope)
    {
        if (scope.Status.HasValue)
        {
            return "status";
        }

        if (!string.IsNullOrWhiteSpace(scope.OwnerKey))
        {
            return "owner";
        }

        if (!string.IsNullOrWhiteSpace(scope.ProcessKey))
        {
            return "process-tree";
        }

        if (scope.ArtifactScope != ExplorerArtifactScope.None)
        {
            return "artifact";
        }

        if (scope.RequiredPeAnalysisSourceKind.HasValue)
        {
            return "pe-analysis";
        }

        if (!string.IsNullOrWhiteSpace(scope.EventSource))
        {
            return "event-source";
        }

        if (scope.Kind == ExplorerScopeKind.Bookmarked)
        {
            return "annotation";
        }

        if (!string.IsNullOrWhiteSpace(scope.CaseId) ||
            !string.IsNullOrWhiteSpace(scope.EvidenceSessionId) ||
            !string.IsNullOrWhiteSpace(scope.CaptureId) ||
            !string.IsNullOrWhiteSpace(scope.SourceIdentityId) ||
            !string.IsNullOrWhiteSpace(scope.HostId) ||
            !string.IsNullOrWhiteSpace(scope.ExecutionRootId))
        {
            return "identity";
        }

        return scope.Kind.ToString();
    }

    private string BuildProcessSourceExpression(ProcessListingFilterSet filters, SqliteConnection connection)
    {
        var canonicalSource = GetProcessSource(connection);
        var canonicalTable = GetProcessTable(connection);
        if (!ShouldIncludeUnresolvedAnnotationTargets(filters))
        {
            return canonicalSource;
        }

        var bookmarkTable = GetBookmarkTableName();
        var noteTable = GetNoteTableName();
        var noteUnion = string.IsNullOrEmpty(noteTable)
            ? string.Empty
            : $"""
               UNION ALL
               SELECT COALESCE(NULLIF(ProcessKey, ''), TargetId) AS AnnotationProcessKey,
                      ProcessId, ProcessName, Label, DisplayPath,
                      CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                      CreatedUtc, UpdatedUtc
               FROM {noteTable}
               WHERE TargetKind = 'Process'
               """;

        return $"""
            (
                SELECT ProcessKey, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                       ModuleCaptureStatus, ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError,
                       HandleCaptureStatus, HandleCount, HandleLastCapturedUtc, HandleCaptureError,
                       ParentProcessId, ParentProcessKey, ParentProcessName, ProcessName, ProcessPath,
                       CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                       CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc,
                       LastObservedUtc, LastSource, CaseId, EvidenceSessionId, CaptureId,
                       SourceIdentityId, HostId, ExecutionRootId, ProcessEntityId, ParentProcessEntityId
                FROM {canonicalSource}
                UNION ALL
                SELECT a.AnnotationProcessKey AS ProcessKey,
                       MAX(a.ProcessId) AS ProcessId,
                       '' AS ProcessGuid,
                       NULL AS StartTimeUtc,
                       NULL AS EndTimeUtc,
                       'NotFound' AS Status,
                       'NotAvailable' AS ModuleCaptureStatus,
                       0 AS ModuleCount,
                       NULL AS ModuleLastCapturedUtc,
                       'Annotation target is not present in the active snapshot.' AS ModuleCaptureError,
                       'NotAvailable' AS HandleCaptureStatus,
                       0 AS HandleCount,
                       NULL AS HandleLastCapturedUtc,
                       'Annotation target is not present in the active snapshot.' AS HandleCaptureError,
                       0 AS ParentProcessId,
                       '' AS ParentProcessKey,
                       '<unknown>' AS ParentProcessName,
                       COALESCE(NULLIF(MAX(a.ProcessName), ''), NULLIF(MAX(a.Label), ''), '<annotation target>') AS ProcessName,
                       COALESCE(NULLIF(MAX(a.DisplayPath), ''), '<annotation target unresolved>') AS ProcessPath,
                       'Annotation target is not present in the active snapshot.' AS CommandLine,
                       '<annotation>' AS UserName,
                       0 AS SessionId,
                       '<not available>' AS Architecture,
                       0.0 AS CpuUsage,
                       0 AS MemoryUsageBytes,
                       '<not available>' AS CompanyName,
                       'Annotation target is not present in the active snapshot.' AS FileDescription,
                       '<not available>' AS Sha256Hash,
                       0 AS TreeDepth,
                       COALESCE(MIN(a.CreatedUtc), '') AS FirstObservedUtc,
                       COALESCE(MAX(a.UpdatedUtc), MIN(a.CreatedUtc), '') AS LastObservedUtc,
                       'Annotation' AS LastSource,
                       MAX(a.CaseId) AS CaseId,
                       MAX(a.EvidenceSessionId) AS EvidenceSessionId,
                       MAX(a.CaptureId) AS CaptureId,
                       MAX(a.SourceIdentityId) AS SourceIdentityId,
                       MAX(a.HostId) AS HostId,
                       '' AS ExecutionRootId,
                       '' AS ProcessEntityId,
                       '' AS ParentProcessEntityId
                FROM (
                    SELECT COALESCE(NULLIF(ProcessKey, ''), TargetId) AS AnnotationProcessKey,
                           ProcessId, ProcessName, Label, DisplayPath,
                           CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                           CreatedUtc, UpdatedUtc
                    FROM {bookmarkTable}
                    WHERE TargetKind = 'Process'
                    {noteUnion}
                ) a
                WHERE a.AnnotationProcessKey IS NOT NULL
                  AND a.AnnotationProcessKey <> ''
                  AND NOT EXISTS (
                      SELECT 1
                      FROM {canonicalTable} p
                      WHERE p.ProcessKey = a.AnnotationProcessKey
                      LIMIT 1
                  )
                GROUP BY a.AnnotationProcessKey
            ) AS Processes
            """;
    }

    private bool ShouldIncludeUnresolvedAnnotationTargets(ProcessListingFilterSet filters)
    {
        if (!UsesAnnotationDatabase())
        {
            return false;
        }

        return filters.RequireBookmarked ||
               filters.IncludedScopes.Any(scope => scope.Kind == ExplorerScopeKind.Bookmarked);
    }

    private string BuildProcessAnnotationTargetPredicate()
    {
        var bookmarkTable = GetBookmarkTableName();
        var bookmarkPredicate =
            $"EXISTS (SELECT 1 FROM {bookmarkTable} b WHERE b.TargetKind = 'Process' AND (b.TargetId = Processes.ProcessKey OR b.ProcessKey = Processes.ProcessKey) LIMIT 1)";
        var noteTable = GetNoteTableName();
        if (string.IsNullOrEmpty(noteTable))
        {
            return bookmarkPredicate;
        }

        return "(" + bookmarkPredicate + " OR " +
               $"EXISTS (SELECT 1 FROM {noteTable} n WHERE n.TargetKind = 'Process' AND (n.TargetId = Processes.ProcessKey OR n.ProcessKey = Processes.ProcessKey) LIMIT 1)" +
               ")";
    }

    private bool UsesAnnotationDatabase()
        => _readContext.UsesAnnotationDatabase;

    private string GetBookmarkTableName()
        => _readContext.BookmarkTableName;

    private string? GetNoteTableName()
        => _readContext.NoteTableName;

    private static string BuildOrderByClause(
        ProcessListingSortDescriptor sort,
        bool riskSortAvailable = false)
    {
        var dir = sort.Direction == ProcessListingSortDirection.Descending ? "DESC" : "ASC";
        const string stableIdentity = "COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY";
        if (sort.Column == ProcessListingSortColumn.ProcessRisk)
        {
            return riskSortAvailable
                ? $"CASE WHEN ListingRiskSortScore IS NULL THEN 1 ELSE 0 END ASC, ListingRiskSortScore {dir}, {stableIdentity} ASC"
                : $"COALESCE(NULLIF(ExecutionRootId, ''), ProcessKey) COLLATE NOCASE ASC, TreeDepth ASC, COALESCE(StartTimeUtc, FirstObservedUtc) ASC, ProcessName COLLATE NOCASE ASC, ProcessId ASC, {stableIdentity} ASC";
        }

        if (sort.Column is ProcessListingSortColumn.Tree or ProcessListingSortColumn.Unknown)
        {
            return sort.Direction == ProcessListingSortDirection.Descending
                ? $"COALESCE(NULLIF(ExecutionRootId, ''), ProcessKey) COLLATE NOCASE DESC, TreeDepth DESC, COALESCE(StartTimeUtc, FirstObservedUtc) DESC, ProcessName COLLATE NOCASE DESC, ProcessId DESC, {stableIdentity} DESC"
                : $"COALESCE(NULLIF(ExecutionRootId, ''), ProcessKey) COLLATE NOCASE ASC, TreeDepth ASC, COALESCE(StartTimeUtc, FirstObservedUtc) ASC, ProcessName COLLATE NOCASE ASC, ProcessId ASC, {stableIdentity} ASC";
        }

        var spec = GetCursorSortSpec(sort.Column);

        return spec is not null
            ? $"{spec.Expression} {dir}, {stableIdentity} {dir}"
            : $"COALESCE(NULLIF(ExecutionRootId, ''), ProcessKey) COLLATE NOCASE ASC, TreeDepth ASC, COALESCE(StartTimeUtc, FirstObservedUtc) ASC, ProcessName COLLATE NOCASE ASC, ProcessId ASC, {stableIdentity} ASC";
    }

    private static bool SupportsCursorPaging(ProcessListingSortDescriptor sort)
        => GetCursorSortSpec(sort.Column) != null;

    private static bool ConfigureProcessRiskSort(
        SqliteConnection connection,
        ProcessListingSortDescriptor sort)
    {
        if (sort.Column != ProcessListingSortColumn.ProcessRisk ||
            !TableExists(connection, "ProcessRiskProjections") ||
            !TableExists(connection, "ProcessRiskProjectionSources"))
        {
            return false;
        }

        connection.CreateFunction<
            string?, string?, string?, string?, string?, string?, string?, bool>(
            "dfiroscope_risk_contract_current",
            (evaluationId, inputIdentityHash, mapperId, mapperVersion, aggregationVersion, policyId, policyVersion) =>
                !ProcessRiskProjectionReadPolicy.HasStaleContract(
                    mapperId,
                    mapperVersion,
                    aggregationVersion,
                    policyId,
                    policyVersion) &&
                ProcessRiskProjectionReadPolicy.HasValidEvaluationIdentity(
                    evaluationId,
                    inputIdentityHash,
                    mapperId,
                    mapperVersion,
                    aggregationVersion,
                    policyId,
                    policyVersion),
            isDeterministic: true);
        connection.CreateFunction<
            string?, long?, string?, double?, double?, string?, string?, bool>(
            "dfiroscope_risk_summary_valid",
            (projectionState, score, band, confidence, coverage, policyId, policyVersion) =>
            {
                var policy = ProcessRiskProjectionReadPolicy.GetSupportedPolicy(policyId, policyVersion);
                if (policy == null || score is < int.MinValue or > int.MaxValue)
                {
                    return false;
                }

                var normalizedScore = score.HasValue ? (int)score.Value : (int?)null;
                return Enum.TryParse<ProcessRiskProjectionState>(projectionState, out var parsedState) &&
                       Enum.IsDefined(parsedState) &&
                       Enum.TryParse<ProcessRiskBand>(band, out var parsedBand) &&
                       Enum.IsDefined(parsedBand) &&
                       confidence.HasValue &&
                       coverage.HasValue &&
                       ProcessRiskProjectionReadPolicy.IsValidSummaryValues(
                           parsedState,
                           normalizedScore,
                           parsedBand,
                           confidence.Value,
                           coverage.Value,
                           policy);
            },
            isDeterministic: true);
        connection.CreateFunction<string?, string?, long, string?, string?, string?, bool>(
            "dfiroscope_risk_source_valid",
            (policyId, policyVersion, sourceOrder, sourceKind, sourceId, availability) =>
                sourceOrder is >= int.MinValue and <= int.MaxValue &&
                ProcessRiskProjectionReadPolicy.IsValidPersistedSummarySource(
                    policyId,
                    policyVersion,
                    (int)sourceOrder,
                    sourceKind,
                    sourceId,
                    availability),
            isDeterministic: true);
        connection.CreateFunction<string?, string?, long>(
            "dfiroscope_risk_expected_source_count",
            (policyId, policyVersion) =>
                ProcessRiskProjectionReadPolicy.GetExpectedSourceCount(policyId, policyVersion),
            isDeterministic: true);
        return true;
    }

    private static string BuildProcessRiskSortSource(string processSource) =>
        $"""
        (
            SELECT Processes.*,
                   (
                       SELECT CASE
                           WHEN risk.RebuildStatus = 'Ready'
                            AND dfiroscope_risk_contract_current(
                                    risk.EvaluationId,
                                    risk.InputIdentityHash,
                                    risk.MapperId,
                                    risk.MapperVersion,
                                    risk.AggregationVersion,
                                    risk.PolicyId,
                                    risk.PolicyVersion) = 1
                            AND dfiroscope_risk_summary_valid(
                                    risk.ProjectionState,
                                    risk.Score,
                                    risk.Band,
                                    risk.Confidence,
                                    risk.Coverage,
                                    risk.PolicyId,
                                    risk.PolicyVersion) = 1
                            AND (
                                SELECT COUNT(*)
                                FROM ProcessRiskProjectionSources source
                                WHERE source.ProcessEntityId = risk.ProcessEntityId
                            ) = dfiroscope_risk_expected_source_count(risk.PolicyId, risk.PolicyVersion)
                            AND (
                                SELECT COUNT(DISTINCT source.SourceOrder)
                                FROM ProcessRiskProjectionSources source
                                WHERE source.ProcessEntityId = risk.ProcessEntityId
                            ) = dfiroscope_risk_expected_source_count(risk.PolicyId, risk.PolicyVersion)
                            AND NOT EXISTS (
                                SELECT 1
                                FROM ProcessRiskProjectionSources source
                                WHERE source.ProcessEntityId = risk.ProcessEntityId
                                  AND dfiroscope_risk_source_valid(
                                          risk.PolicyId,
                                          risk.PolicyVersion,
                                          source.SourceOrder,
                                          source.SourceKind,
                                          source.SourceId,
                                          source.Availability) = 0
                            )
                           THEN risk.Score
                           ELSE NULL
                       END
                       FROM ProcessRiskProjections risk
                       WHERE risk.ProcessEntityId = Processes.ProcessEntityId
                       LIMIT 1
                   ) AS ListingRiskSortScore
            FROM {processSource}
        ) AS Processes
        """;

    private static ProcessCursorPayload? DecodeAndValidateCursor(
        string? token,
        ProcessListingSortDescriptor sort)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        if (token.Length > 4096)
        {
            throw new InvalidOperationException("The process listing cursor exceeds the supported size.");
        }

        try
        {
            var base64 = token.Replace('-', '+').Replace('_', '/');
            base64 = base64.PadRight(base64.Length + ((4 - base64.Length % 4) % 4), '=');
            var payload = JsonSerializer.Deserialize<ProcessCursorPayload>(Convert.FromBase64String(base64));
            if (payload == null ||
                payload.Version != 1 ||
                payload.Column != sort.Column ||
                payload.Direction != sort.Direction ||
                string.IsNullOrWhiteSpace(payload.StableIdentity) ||
                GetCursorSortSpec(payload.Column)?.Kind != payload.Kind)
            {
                throw new InvalidOperationException("The process listing cursor does not match the active sort.");
            }

            return payload;
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            throw new InvalidOperationException("The process listing cursor is invalid.", ex);
        }
    }

    private static string EncodeCursor(ProcessListingSortDescriptor sort, ProcessRecord row)
    {
        var spec = GetCursorSortSpec(sort.Column) ??
            throw new InvalidOperationException($"Cursor paging is unavailable for {sort.Column}.");
        var value = GetCursorValue(sort.Column, row);
        var payload = new ProcessCursorPayload(
            1,
            sort.Column,
            sort.Direction,
            spec.Kind,
            value == null,
            spec.Kind switch
            {
                ProcessCursorValueKind.Text => Convert.ToString(value, CultureInfo.InvariantCulture),
                ProcessCursorValueKind.DateTime => GetListingCursorMetadata(row)?.Value ??
                    (value is DateTime dateTime ? FormatDate(dateTime) : null),
                _ => null
            },
            spec.Kind == ProcessCursorValueKind.Integer && value != null ? Convert.ToInt64(value, CultureInfo.InvariantCulture) : null,
            spec.Kind == ProcessCursorValueKind.Real && value != null ? Convert.ToDouble(value, CultureInfo.InvariantCulture) : null,
            spec.Kind == ProcessCursorValueKind.DateTime ? value as DateTime? : null,
            string.IsNullOrWhiteSpace(row.ProcessEntityId) ? row.ProcessKey : row.ProcessEntityId);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string BuildCursorPredicate(
        ProcessListingSortDescriptor sort,
        ProcessCursorPayload cursor,
        SqliteParameterCollection parameters)
    {
        var spec = GetCursorSortSpec(sort.Column) ??
            throw new InvalidOperationException($"Cursor paging is unavailable for {sort.Column}.");
        var isAscending = sort.Direction == ProcessListingSortDirection.Ascending;
        var comparison = isAscending ? ">" : "<";
        const string stableIdentity = "COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY";
        parameters.AddWithValue("$CursorIdentity", cursor.StableIdentity);

        if (cursor.IsNull)
        {
            return isAscending
                ? $"(({spec.Expression} IS NULL AND {stableIdentity} {comparison} $CursorIdentity COLLATE BINARY) OR {spec.Expression} IS NOT NULL)"
                : $"({spec.Expression} IS NULL AND {stableIdentity} {comparison} $CursorIdentity COLLATE BINARY)";
        }

        object value = cursor.Kind switch
        {
            ProcessCursorValueKind.Text => cursor.TextValue ?? string.Empty,
            ProcessCursorValueKind.Integer => cursor.IntegerValue ?? 0L,
            ProcessCursorValueKind.Real => cursor.RealValue ?? 0d,
            ProcessCursorValueKind.DateTime => cursor.TextValue ?? FormatDate(cursor.DateTimeValue ?? DateTime.MinValue),
            _ => throw new InvalidOperationException("The process listing cursor value kind is unsupported.")
        };
        parameters.AddWithValue("$CursorValue", value);
        var afterEqual = $"({spec.Expression} = $CursorValue AND {stableIdentity} {comparison} $CursorIdentity COLLATE BINARY)";
        return isAscending
            ? $"({spec.Expression} > $CursorValue OR {afterEqual})"
            : $"({spec.Expression} < $CursorValue OR {spec.Expression} IS NULL OR {afterEqual})";
    }

    private static ProcessCursorSortSpec? GetCursorSortSpec(ProcessListingSortColumn column)
        => column switch
        {
            ProcessListingSortColumn.ProcessName => new("ProcessName COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.ProcessId => new("ProcessId", ProcessCursorValueKind.Integer),
            ProcessListingSortColumn.ParentProcessId => new("ParentProcessId", ProcessCursorValueKind.Integer),
            ProcessListingSortColumn.ParentProcessName => new("ParentProcessName COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.ProcessPath => new("ProcessPath COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.CommandLine => new("CommandLine COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.UserName => new("UserName COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.SessionId => new("SessionId", ProcessCursorValueKind.Integer),
            ProcessListingSortColumn.Architecture => new("Architecture COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.StartTime => new("StartTimeUtc", ProcessCursorValueKind.DateTime),
            ProcessListingSortColumn.EndTime => new("EndTimeUtc", ProcessCursorValueKind.DateTime),
            ProcessListingSortColumn.Status => new("Status COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.CpuUsage => new("CpuUsage", ProcessCursorValueKind.Real),
            ProcessListingSortColumn.MemoryUsage => new("MemoryUsageBytes", ProcessCursorValueKind.Integer),
            ProcessListingSortColumn.CompanyName => new("CompanyName COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.FileDescription => new("FileDescription COLLATE NOCASE", ProcessCursorValueKind.Text),
            ProcessListingSortColumn.Sha256Hash => new("Sha256Hash COLLATE NOCASE", ProcessCursorValueKind.Text),
            _ => null
        };

    private static object? GetCursorValue(ProcessListingSortColumn column, ProcessRecord row)
        => column switch
        {
            ProcessListingSortColumn.ProcessName => row.ProcessName,
            ProcessListingSortColumn.ProcessId => row.ProcessId,
            ProcessListingSortColumn.ParentProcessId => row.ParentProcessId,
            ProcessListingSortColumn.ParentProcessName => row.ParentProcessName,
            ProcessListingSortColumn.ProcessPath => row.ProcessPath,
            ProcessListingSortColumn.CommandLine => row.CommandLine,
            ProcessListingSortColumn.UserName => row.UserName,
            ProcessListingSortColumn.SessionId => row.SessionId,
            ProcessListingSortColumn.Architecture => row.Architecture,
            ProcessListingSortColumn.StartTime => row.StartTimeUtc,
            ProcessListingSortColumn.EndTime => row.EndTimeUtc,
            ProcessListingSortColumn.Status => row.Status.ToString(),
            ProcessListingSortColumn.CpuUsage => row.CpuUsage,
            ProcessListingSortColumn.MemoryUsage => row.MemoryUsageBytes,
            ProcessListingSortColumn.CompanyName => row.CompanyName,
            ProcessListingSortColumn.FileDescription => row.FileDescription,
            ProcessListingSortColumn.Sha256Hash => row.Sha256Hash,
            _ => null
        };

    private enum ProcessCursorValueKind
    {
        Text,
        Integer,
        Real,
        DateTime
    }

    private sealed record ProcessCursorSortSpec(string Expression, ProcessCursorValueKind Kind);

    private sealed record ProcessCursorPayload(
        int Version,
        ProcessListingSortColumn Column,
        ProcessListingSortDirection Direction,
        ProcessCursorValueKind Kind,
        bool IsNull,
        string? TextValue,
        long? IntegerValue,
        double? RealValue,
        DateTime? DateTimeValue,
        string StableIdentity);

    private sealed record ListingCursorMetadata(string? Value);

    internal static ProcessRecord ReadProcess(SqliteDataReader reader)
    {
        var record = new ProcessRecord
        {
            ProcessKey = GetString(reader, 0),
            ProcessId = GetInt(reader, 1),
            ProcessGuid = GetString(reader, 2),
            StartTimeUtc = GetDateTime(reader, 3),
            EndTimeUtc = GetDateTime(reader, 4),
            Status = GetEnum(reader, 5, ProcessStatus.Running),
            ModuleCaptureStatus = GetEnum(reader, 6, ArtifactCaptureStatus.Pending),
            ModuleCount = GetInt(reader, 7),
            ModuleLastCapturedUtc = GetDateTime(reader, 8),
            ModuleCaptureError = GetString(reader, 9),
            HandleCaptureStatus = GetEnum(reader, 10, ArtifactCaptureStatus.Pending),
            HandleCount = GetInt(reader, 11),
            HandleLastCapturedUtc = GetDateTime(reader, 12),
            HandleCaptureError = GetString(reader, 13),
            ParentProcessId = GetInt(reader, 14),
            ParentProcessKey = GetString(reader, 15),
            ParentProcessName = GetString(reader, 16),
            ProcessName = GetString(reader, 17),
            ProcessPath = GetString(reader, 18),
            CommandLine = GetString(reader, 19),
            UserName = GetString(reader, 20),
            SessionId = GetInt(reader, 21),
            Architecture = GetString(reader, 22),
            CpuUsage = GetDouble(reader, 23),
            MemoryUsageBytes = GetLong(reader, 24),
            CompanyName = GetString(reader, 25),
            FileDescription = GetString(reader, 26),
            Sha256Hash = GetString(reader, 27),
            TreeDepth = GetInt(reader, 28),
            FirstObservedUtc = GetDateTime(reader, 29) ?? DateTime.UtcNow,
            LastObservedUtc = GetDateTime(reader, 30) ?? DateTime.UtcNow,
            LastSource = GetString(reader, 31)
        };
        if (reader.FieldCount >= 38)
        {
            record.CaseId = GetString(reader, 32);
            record.EvidenceSessionId = GetString(reader, 33);
            record.CaptureId = GetString(reader, 34);
            record.SourceIdentityId = GetString(reader, 35);
            record.HostId = GetString(reader, 36);
            record.ExecutionRootId = GetString(reader, 37);
        }
        if (reader.FieldCount >= 40)
        {
            record.ProcessEntityId = GetString(reader, 38);
            record.ParentProcessEntityId = GetString(reader, 39);
        }
        if (reader.FieldCount >= 41)
        {
            ListingCursorMetadataByRecord.Add(
                record,
                new ListingCursorMetadata(reader.IsDBNull(40) ? null : reader.GetString(40)));
        }

        return record;
    }

    private static ListingCursorMetadata? GetListingCursorMetadata(ProcessRecord record) =>
        ListingCursorMetadataByRecord.TryGetValue(record, out var metadata) ? metadata : null;

    private static void AddQueryPlan(
        ICollection<SqliteQueryPlanRecord> plans,
        SqliteConnection connection,
        string operation,
        string sql,
        Action<SqliteCommand>? configure = null)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"EXPLAIN QUERY PLAN {sql.Trim().TrimEnd(';')};";
            configure?.Invoke(command);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                plans.Add(new SqliteQueryPlanRecord(
                    operation,
                    GetInt(reader, 0),
                    GetInt(reader, 1),
                    GetInt(reader, 2),
                    GetString(reader, 3)));
            }
        }
        catch (Exception ex) when (ex is SqliteException or InvalidOperationException)
        {
            plans.Add(new SqliteQueryPlanRecord(
                operation,
                -1,
                -1,
                -1,
                $"query plan unavailable: {ex.Message}"));
        }
    }

    private static string BuildOwnerKeyExpression(string tableAlias)
    {
        return $"""
            CASE
                WHEN {tableAlias}.UserName IS NULL
                     OR TRIM({tableAlias}.UserName) = ''
                     OR LOWER(TRIM({tableAlias}.UserName)) IN ('<not available>', '<access denied>', '<unknown>', 'unknown', 'n/a')
                THEN 'unknown'
                ELSE LOWER(TRIM({tableAlias}.UserName))
            END
            """;
    }

    private static string GetProcessTable(SqliteConnection connection)
        => TableExists(connection, "ProcessEntities") ? "ProcessEntities" : "Processes";

    private static string GetProcessSource(SqliteConnection connection)
        => TableExists(connection, "ProcessEntities") ? "ProcessEntities AS Processes" : "Processes";

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type = 'table' AND name = $TableName;
            """;
        command.Parameters.AddWithValue("$TableName", tableName);
        return Convert.ToInt32(command.ExecuteScalar()) > 0;
    }

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static int GetInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt32(ordinal);

    private static long GetLong(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt64(ordinal);

    private static double GetDouble(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetDouble(ordinal);

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ||
               !DateTimeOffset.TryParse(
                   reader.GetString(ordinal),
                   CultureInfo.InvariantCulture,
                   DateTimeStyles.RoundtripKind,
                   out var value)
            ? null
            : value.UtcDateTime;
    }

    private static string FormatDate(DateTime value)
    {
        return value.Kind == DateTimeKind.Utc
            ? value.ToString("O", CultureInfo.InvariantCulture)
            : value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    }

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum fallback)
        where TEnum : struct
    {
        return !reader.IsDBNull(ordinal) &&
               Enum.TryParse<TEnum>(reader.GetString(ordinal), out var value)
            ? value
            : fallback;
    }
}
