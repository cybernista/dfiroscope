using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Narrow read contract for Explorer badges, evidence roots, process trees/owners,
/// and filesystem tree expansion.
/// </summary>
public interface IExplorerQueryService
{
    ExplorerScopeCounts GetExplorerScopeCounts();

    Task<ExplorerScopeCounts> GetExplorerScopeCountsAsync();

    ExplorerScopeCountReadResult GetExplorerScopeCountsWithDiagnostics();

    IReadOnlyList<EvidenceRootSummary> GetEvidenceRoots();

    Task<IReadOnlyList<EvidenceRootSummary>> GetEvidenceRootsAsync();

    IReadOnlyList<ExplorerProcessNodeSummary> GetExplorerProcessRoots(
        ExplorerScope scope,
        int maxCount = 100);

    Task<IReadOnlyList<ExplorerProcessNodeSummary>> GetExplorerProcessRootsAsync(
        ExplorerScope scope,
        int maxCount = 100);

    IReadOnlyList<ExplorerProcessNodeSummary> GetExplorerProcessChildren(
        ExplorerScope parentScope,
        int maxCount = 100);

    Task<IReadOnlyList<ExplorerProcessNodeSummary>> GetExplorerProcessChildrenAsync(
        ExplorerScope parentScope,
        int maxCount = 100);

    IReadOnlyList<ExplorerProcessOwnerSummary> GetExplorerProcessOwners(
        ExplorerScope scope,
        int maxCount = 100);

    Task<IReadOnlyList<ExplorerProcessOwnerSummary>> GetExplorerProcessOwnersAsync(
        ExplorerScope scope,
        int maxCount = 100);

    IReadOnlyList<EvidenceRootSummary> GetExplorerFilesystemRoots(int maxCount = 100);

    Task<IReadOnlyList<EvidenceRootSummary>> GetExplorerFilesystemRootsAsync(int maxCount = 100);

    IReadOnlyList<ExplorerFilesystemNodeSummary> GetExplorerFilesystemChildren(
        ExplorerScope scope,
        int maxCount = 100);

    Task<IReadOnlyList<ExplorerFilesystemNodeSummary>> GetExplorerFilesystemChildrenAsync(
        ExplorerScope scope,
        int maxCount = 100);

    IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeQueryPlans();
}

/// <summary>
/// Owns the exact correlation-state count projection shared by snapshot preparation
/// and the legacy/unprepared snapshot fallback query.
/// </summary>
internal static class ExplorerCorrelationCountSql
{
    // SQLite's single MAX aggregate returns the bare CorrelationState from the row
    // that supplied the maximum. RelationId makes the existing newest-row order unique.
    internal static string BuildCountSelectSql() => $"""
        WITH LatestInputRelations AS MATERIALIZED (
            SELECT i.rowid AS InputRowId,
                   r.CorrelationState,
                   MAX(r.UpdatedUtc || char(0) || r.RelationId) AS LatestOrder
            FROM EvidenceCorrelationInputs i
            JOIN EvidenceRelations r
              ON r.DecisionKey = {SqliteStagingQueryService.CorrelationDecisionKeySql("i")}
             AND r.Status = 'Active'
            GROUP BY i.rowid
        )
        SELECT (SELECT COUNT(*) FROM EvidenceCorrelationInputs)
                   - COUNT(*)
                   + COALESCE(SUM(CASE WHEN CorrelationState = 'Unresolved' THEN 1 ELSE 0 END), 0)
                   AS UnresolvedCount,
               COALESCE(SUM(CASE WHEN CorrelationState = 'Ambiguous' THEN 1 ELSE 0 END), 0)
                   AS AmbiguousCount
        FROM LatestInputRelations;
        """;
}

internal readonly record struct ExplorerCorrelationCounts(int Unresolved, int Ambiguous);

/// <summary>
/// Bounded process-memory acceleration for the immutable correlation tally prepared
/// with a viewer snapshot. The exact SQL remains the fallback for any unprepared path;
/// no aggregate state is written to the capture or snapshot database.
/// </summary>
internal static class ExplorerCorrelationCountCache
{
    private const int MaximumEntries = 8;
    private static readonly object Gate = new();
    private static readonly Dictionary<string, CacheEntry> Entries =
        new(StringComparer.OrdinalIgnoreCase);
    private static long _accessSequence;

    internal static bool TryGet(string databasePath, out ExplorerCorrelationCounts counts)
    {
        var key = NormalizePath(databasePath);
        lock (Gate)
        {
            if (Entries.TryGetValue(key, out var entry))
            {
                Entries[key] = entry with { LastAccess = ++_accessSequence };
                counts = entry.Counts;
                return true;
            }
        }

        counts = default;
        return false;
    }

    internal static void Rebuild(
        SqliteConnection connection,
        CancellationToken cancellationToken = default)
    {
        var key = NormalizePath(connection.DataSource);
        Remove(key);
        cancellationToken.ThrowIfCancellationRequested();

        using var command = connection.CreateCommand();
        command.CommandText = ExplorerCorrelationCountSql.BuildCountSelectSql();
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return;
        }

        var counts = new ExplorerCorrelationCounts(
            ReadInt(reader, 0),
            ReadInt(reader, 1));
        cancellationToken.ThrowIfCancellationRequested();
        lock (Gate)
        {
            if (Entries.Count >= MaximumEntries && !Entries.ContainsKey(key))
            {
                var oldest = Entries.MinBy(pair => pair.Value.LastAccess).Key;
                Entries.Remove(oldest);
            }

            Entries[key] = new CacheEntry(counts, ++_accessSequence);
        }
    }

    internal static void Remove(string databasePath)
    {
        var key = NormalizePath(databasePath);
        lock (Gate)
        {
            Entries.Remove(key);
        }
    }

    private static int ReadInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : Convert.ToInt32(reader.GetValue(ordinal));

    private static string NormalizePath(string databasePath)
        => Path.GetFullPath(databasePath);

    private sealed record CacheEntry(ExplorerCorrelationCounts Counts, long LastAccess);
}

/// <summary>
/// Focused SQLite owner for the Explorer summary/tree read family. The validated
/// <see cref="SqliteStagingQueryService"/> remains the compatibility facade.
/// </summary>
internal sealed class ExplorerQueryService : IExplorerQueryService
{
    private readonly SqliteReadQueryContext _readContext;
    private readonly SystemActivityCandidateQuery _systemActivityCandidates;

    internal ExplorerQueryService(
        SqliteReadQueryContext readContext,
        SystemActivityCandidateQuery systemActivityCandidates)
    {
        _readContext = readContext;
        _systemActivityCandidates = systemActivityCandidates;
    }

    public ExplorerScopeCounts GetExplorerScopeCounts()
    {
        return _readContext.MeasureRead(
            "GetExplorerScopeCounts",
            () => ReadExplorerScopeCounts(includeDiagnostics: false).Counts,
            "Explorer root and source counts");
    }

    public Task<ExplorerScopeCounts> GetExplorerScopeCountsAsync()
        => Task.Run(GetExplorerScopeCounts);

    public ExplorerScopeCountReadResult GetExplorerScopeCountsWithDiagnostics()
    {
        return _readContext.MeasureRead(
            "GetExplorerScopeCountsWithDiagnostics",
            () => ReadExplorerScopeCounts(includeDiagnostics: true),
            "Explorer root/source counts with bounded stage timings",
            _ => 1);
    }

    public IReadOnlyList<EvidenceRootSummary> GetEvidenceRoots()
    {
        using var connection = _readContext.OpenReadOnlyConnection();
        var roots = new Dictionary<string, EvidenceRootSummary>(StringComparer.Ordinal);
        AddRootCounts(connection, roots, GetProcessTable(connection), "ProcessCount");
        if (TableExists(connection, "ProcessObservations"))
        {
            AddRootCounts(connection, roots, "ProcessObservations", "ProcessObservationCount");
        }

        AddRootCounts(connection, roots, "ProcessEvents", "EventCount");
        AddRootCounts(connection, roots, "Modules", "ModuleCount");
        AddRootCounts(connection, roots, "Handles", "HandleCount");
        AddRootCounts(connection, roots, "NetworkCaptures", "NetworkCaptureCount");
        if (TableExists(connection, "SourceRuns"))
        {
            AddRootCounts(connection, roots, "SourceRuns", "SourceRunCount");
            foreach (var provenanceTable in new[]
            {
                GetProcessTable(connection), "ProcessStatistics", "ProcessEvents", "Modules", "Handles",
                "MemoryDumps", "PeAnalyses", "MemoryImages", "VolatilityPluginRuns", "MemoryProcesses",
                "NetworkCaptures", "ZeekNetworkArtifacts", "RawRecords", "Artifacts"
            })
            {
                if (TableExists(connection, provenanceTable) &&
                    ColumnExists(connection, provenanceTable, "SourceRunId"))
                {
                    AddRootCounts(
                        connection,
                        roots,
                        provenanceTable,
                        "MissingSourceRunLinkCount",
                        "SourceRunId IS NULL OR SourceRunId = ''");
                }
            }
        }

        AddRootCounts(
            connection,
            roots,
            "Artifacts",
            "FilesystemArtifactCount",
            "ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata')");
        return roots.Values
            .OrderBy(root => root.CaseId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(root => root.EvidenceSessionId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(root => root.CaptureId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(root => root.ExecutionRootId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public Task<IReadOnlyList<EvidenceRootSummary>> GetEvidenceRootsAsync()
        => Task.Run(GetEvidenceRoots);

    public IReadOnlyList<ExplorerProcessNodeSummary> GetExplorerProcessRoots(
        ExplorerScope scope,
        int maxCount = 100)
    {
        using var connection = _readContext.OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        var processTable = GetProcessTable(connection);
        var identityWhere = ExplorerScopeQuerySql.BuildIdentityWhereClause(
            scope,
            "p",
            command.Parameters,
            "RootIdentity");
        command.CommandText = $"""
            {BuildProcessHierarchyCtes(processTable, identityWhere)}
            SELECT p.ProcessKey, p.ProcessId, p.ProcessName, p.ProcessPath, p.Status,
                   p.ParentProcessKey, p.CaseId, p.EvidenceSessionId, p.CaptureId,
                   p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                   COALESCE(descendants.DescendantProcessCount, 0) AS DescendantProcessCount
            FROM ScopedProcesses p
            LEFT JOIN DescendantCounts descendants
                   ON descendants.AncestorNodeId = p.HierarchyNodeId
            WHERE NOT EXISTS (
                      SELECT 1
                      FROM ProcessEdges edge
                      WHERE edge.ChildNodeId = p.HierarchyNodeId
                      LIMIT 1
                  )
            ORDER BY COALESCE(p.StartTimeUtc, p.FirstObservedUtc) ASC, p.ProcessName COLLATE NOCASE ASC
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 500));

        var rows = new List<ExplorerProcessNodeSummary>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(ReadExplorerProcessNode(reader));
        }

        return rows;
    }

    public Task<IReadOnlyList<ExplorerProcessNodeSummary>> GetExplorerProcessRootsAsync(
        ExplorerScope scope,
        int maxCount = 100)
        => Task.Run(() => GetExplorerProcessRoots(scope, maxCount));

    public IReadOnlyList<ExplorerProcessNodeSummary> GetExplorerProcessChildren(
        ExplorerScope parentScope,
        int maxCount = 100)
    {
        var parentProcessKey = parentScope.ProcessKey;
        if (string.IsNullOrWhiteSpace(parentProcessKey))
        {
            return [];
        }

        using var connection = _readContext.OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        var processTable = GetProcessTable(connection);
        var identityWhere = ExplorerScopeQuerySql.BuildIdentityWhereClause(
            parentScope,
            "p",
            command.Parameters,
            "ChildIdentity");
        command.CommandText = $"""
            {BuildProcessHierarchyCtes(processTable, identityWhere)}
            SELECT p.ProcessKey, p.ProcessId, p.ProcessName, p.ProcessPath, p.Status,
                   p.ParentProcessKey, p.CaseId, p.EvidenceSessionId, p.CaptureId,
                   p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                   COALESCE(descendants.DescendantProcessCount, 0) AS DescendantProcessCount
            FROM ScopedProcesses p
            LEFT JOIN DescendantCounts descendants
                   ON descendants.AncestorNodeId = p.HierarchyNodeId
            WHERE EXISTS (
                      SELECT 1
                      FROM ScopedProcesses parent
                      JOIN ProcessEdges edge
                        ON edge.ParentNodeId = parent.HierarchyNodeId
                       AND edge.ChildNodeId = p.HierarchyNodeId
                      WHERE parent.ProcessKey = $ParentProcessKey
                      LIMIT 1
                  )
            ORDER BY COALESCE(p.StartTimeUtc, p.FirstObservedUtc) ASC, p.ProcessName COLLATE NOCASE ASC
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$ParentProcessKey", parentProcessKey);
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 500));

        var rows = new List<ExplorerProcessNodeSummary>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(ReadExplorerProcessNode(reader));
        }

        return rows;
    }

    public Task<IReadOnlyList<ExplorerProcessNodeSummary>> GetExplorerProcessChildrenAsync(
        ExplorerScope parentScope,
        int maxCount = 100)
        => Task.Run(() => GetExplorerProcessChildren(parentScope, maxCount));

    public IReadOnlyList<ExplorerProcessOwnerSummary> GetExplorerProcessOwners(
        ExplorerScope scope,
        int maxCount = 100)
    {
        using var connection = _readContext.OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        var identityWhere = ExplorerScopeQuerySql.BuildIdentityWhereClause(
            scope,
            "p",
            command.Parameters,
            "OwnerIdentity");
        command.CommandText = BuildOwnerAggregateSql(identityWhere);
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 500));

        var rows = new List<ExplorerProcessOwnerSummary>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var ownerKey = GetString(reader, 6);
            var displayName = GetString(reader, 7);
            if (string.Equals(ownerKey, "unknown", StringComparison.Ordinal))
            {
                displayName = "Unknown / unresolved owner";
            }

            rows.Add(new ExplorerProcessOwnerSummary
            {
                CaseId = GetString(reader, 0),
                EvidenceSessionId = GetString(reader, 1),
                CaptureId = GetString(reader, 2),
                SourceIdentityId = GetString(reader, 3),
                HostId = GetString(reader, 4),
                ExecutionRootId = GetString(reader, 5),
                OwnerKey = ownerKey,
                DisplayName = string.IsNullOrWhiteSpace(displayName)
                    ? "Unknown / unresolved owner"
                    : displayName,
                Domain = GetOwnerDomain(displayName),
                ProcessCount = GetInt(reader, 8)
            });
        }

        return rows;
    }

    public Task<IReadOnlyList<ExplorerProcessOwnerSummary>> GetExplorerProcessOwnersAsync(
        ExplorerScope scope,
        int maxCount = 100)
        => Task.Run(() => GetExplorerProcessOwners(scope, maxCount));

    public IReadOnlyList<EvidenceRootSummary> GetExplorerFilesystemRoots(int maxCount = 100)
    {
        using var connection = _readContext.OpenReadOnlyConnection();
        var roots = new Dictionary<string, EvidenceRootSummary>(StringComparer.Ordinal);
        AddRootCounts(
            connection,
            roots,
            "Artifacts",
            "FilesystemArtifactCount",
            "ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata')");

        return roots.Values
            .Where(root => root.FilesystemArtifactCount > 0)
            .OrderBy(root => root.CaseId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(root => root.EvidenceSessionId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(root => root.CaptureId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(root => root.SourceIdentityId, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Clamp(maxCount, 1, 500))
            .ToList();
    }

    public Task<IReadOnlyList<EvidenceRootSummary>> GetExplorerFilesystemRootsAsync(int maxCount = 100)
        => Task.Run(() => GetExplorerFilesystemRoots(maxCount));

    public IReadOnlyList<ExplorerFilesystemNodeSummary> GetExplorerFilesystemChildren(
        ExplorerScope scope,
        int maxCount = 100)
    {
        using var connection = _readContext.OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        var identityWhere = ExplorerScopeQuerySql.BuildIdentityWhereClause(
            scope,
            "a",
            command.Parameters,
            "FilesystemChildIdentity");
        var pathWhere = FilesystemQueryPath.BuildWhereClause(
            scope.FilesystemPath,
            recursive: true,
            "a",
            command.Parameters,
            "FilesystemChildPath");
        command.CommandText = $"""
            SELECT a.Path
            FROM Artifacts a
            WHERE a.ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata')
                  {identityWhere}
                  {pathWhere}
            ORDER BY a.Path COLLATE NOCASE ASC
            LIMIT $CandidateLimit;
            """;
        command.Parameters.AddWithValue("$CandidateLimit", Math.Clamp(maxCount * 200, 200, 20000));

        var paths = new List<string>();
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                var path = GetString(reader, 0);
                if (!string.IsNullOrWhiteSpace(path))
                {
                    paths.Add(path);
                }
            }
        }

        var folders = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            var childFolder = FilesystemQueryPath.GetImmediateChildFolder(path, scope.FilesystemPath);
            if (string.IsNullOrWhiteSpace(childFolder))
            {
                continue;
            }

            folders[childFolder] = folders.TryGetValue(childFolder, out var count) ? count + 1 : 1;
        }

        return folders
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Clamp(maxCount, 1, 500))
            .Select(pair => new ExplorerFilesystemNodeSummary
            {
                FolderPath = pair.Key,
                ArtifactCount = pair.Value,
                ChildFolderCount = paths.Any(path =>
                    FilesystemQueryPath.GetImmediateChildFolder(path, pair.Key) != null)
                        ? 1
                        : 0,
                CaseId = scope.CaseId ?? string.Empty,
                EvidenceSessionId = scope.EvidenceSessionId ?? string.Empty,
                CaptureId = scope.CaptureId ?? string.Empty,
                SourceIdentityId = scope.SourceIdentityId ?? string.Empty,
                HostId = scope.HostId ?? string.Empty,
                ExecutionRootId = scope.ExecutionRootId ?? string.Empty
            })
            .ToList();
    }

    public Task<IReadOnlyList<ExplorerFilesystemNodeSummary>> GetExplorerFilesystemChildrenAsync(
        ExplorerScope scope,
        int maxCount = 100)
        => Task.Run(() => GetExplorerFilesystemChildren(scope, maxCount));

    public IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeQueryPlans()
    {
        return _readContext.MeasureRead(
            "GetRepresentativeExplorerQueryPlans",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var plans = new List<SqliteQueryPlanRecord>();
                var processTable = GetProcessTable(connection);
                var processKey = ReadFirstProcessKey(connection, processTable);

                AddQueryPlan(
                    plans,
                    connection,
                    "explorer process status counts",
                    BuildProcessStatusCountSql(processTable));
                AddQueryPlan(
                    plans,
                    connection,
                    "explorer system-activity candidates",
                    SystemActivityCandidateQuery.CandidateSql,
                    command => command.Parameters.AddWithValue(
                        "$MaxCount",
                        SystemActivityCandidateQuery.MaxCandidateRows));
                AddQueryPlan(
                    plans,
                    connection,
                    "explorer event-source process counts",
                    EventProcessSourceCountSql);
                AddQueryPlan(
                    plans,
                    connection,
                    "explorer correlation-state counts",
                    BuildEvidenceCorrelationStateCountSql());
                AddQueryPlan(
                    plans,
                    connection,
                    "explorer evidence roots",
                    $"""
                    SELECT {BuildEvidenceRootKeyExpressionList("e")}, COUNT(*)
                    FROM {processTable} e
                    GROUP BY {BuildEvidenceRootRawKeyColumnList("e")};
                    """);
                AddQueryPlan(
                    plans,
                    connection,
                    "explorer process roots",
                    $"""
                    {BuildProcessHierarchyCtes(processTable, string.Empty)}
                    SELECT p.ProcessKey, COALESCE(descendants.DescendantProcessCount, 0)
                    FROM ScopedProcesses p
                    LEFT JOIN DescendantCounts descendants
                           ON descendants.AncestorNodeId = p.HierarchyNodeId
                    WHERE NOT EXISTS (
                        SELECT 1 FROM ProcessEdges edge
                        WHERE edge.ChildNodeId = p.HierarchyNodeId
                        LIMIT 1)
                    ORDER BY COALESCE(p.StartTimeUtc, p.FirstObservedUtc), p.ProcessName COLLATE NOCASE
                    LIMIT $MaxCount;
                    """,
                    command => command.Parameters.AddWithValue("$MaxCount", 100));
                AddQueryPlan(
                    plans,
                    connection,
                    "explorer process children",
                    $"""
                    {BuildProcessHierarchyCtes(processTable, string.Empty)}
                    SELECT p.ProcessKey, COALESCE(descendants.DescendantProcessCount, 0)
                    FROM ScopedProcesses p
                    LEFT JOIN DescendantCounts descendants
                           ON descendants.AncestorNodeId = p.HierarchyNodeId
                    WHERE EXISTS (
                        SELECT 1
                        FROM ScopedProcesses parent
                        JOIN ProcessEdges edge
                          ON edge.ParentNodeId = parent.HierarchyNodeId
                         AND edge.ChildNodeId = p.HierarchyNodeId
                        WHERE parent.ProcessKey = $ParentProcessKey
                        LIMIT 1)
                    ORDER BY COALESCE(p.StartTimeUtc, p.FirstObservedUtc), p.ProcessName COLLATE NOCASE
                    LIMIT $MaxCount;
                    """,
                    command =>
                    {
                        command.Parameters.AddWithValue("$ParentProcessKey", processKey);
                        command.Parameters.AddWithValue("$MaxCount", 100);
                    });
                AddQueryPlan(
                    plans,
                    connection,
                    "explorer process owners",
                    BuildOwnerAggregateSql(string.Empty),
                    command => command.Parameters.AddWithValue("$MaxCount", 100));
                AddQueryPlan(
                    plans,
                    connection,
                    "explorer filesystem children",
                    """
                    SELECT a.Path
                    FROM Artifacts a
                    WHERE a.ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata')
                    ORDER BY a.Path COLLATE NOCASE
                    LIMIT $CandidateLimit;
                    """,
                    command => command.Parameters.AddWithValue("$CandidateLimit", 20000));

                return plans;
            },
            "representative Explorer EXPLAIN QUERY PLAN reads",
            plans => plans.Count);
    }

    private ExplorerScopeCountReadResult ReadExplorerScopeCounts(bool includeDiagnostics)
    {
        var totalStopwatch = Stopwatch.StartNew();
        List<ExplorerScopeCountStageTiming>? stages = includeDiagnostics ? [] : null;
        var candidates = MeasureStage(
            stages,
            "system activity candidate query/materialization",
            _systemActivityCandidates.GetCandidates,
            rows => rows.Count);
        var systemActivitySummary = MeasureStage(
            stages,
            "system activity normalization",
            () => GetSystemActivityExplorerSummary(candidates),
            summary => summary.CountsByScope.TryGetValue(SystemActivityScopeKind.All, out var count)
                ? count
                : 0);
        using var connection = MeasureStage(
            stages,
            "open read-only count connection",
            _readContext.OpenReadOnlyConnection);
        var processTable = GetProcessTable(connection);
        var processCounts = MeasureStage(
            stages,
            "process total/status counts",
            () => CountProcessStatuses(connection, processTable),
            counts => counts.Total);
        var attachedProcessCounts = MeasureStage(
            stages,
            "module/handle distinct-process counts",
            () => CountAttachedArtifactProcesses(connection));
        var bookmarkedProcesses = MeasureStage(
            stages,
            "bookmark/note annotation counts",
            () => CountBookmarkedProcesses(connection),
            count => count);
        var artifactCounts = MeasureStage(
            stages,
            "independent artifact-table counts",
            () => CountIndependentArtifacts(connection));
        var correlationCounts = MeasureStage(
            stages,
            "correlation-state counts",
            () => CountEvidenceCorrelationStates(connection));
        var eventProcessesBySource = MeasureStage(
            stages,
            "event-source distinct-process grouping",
            () => CountEventProcessesBySource(connection),
            counts => counts.Count);
        var counts = new ExplorerScopeCounts
        {
            TotalProcesses = processCounts.Total,
            RunningProcesses = processCounts.Running,
            ExitedProcesses = processCounts.Exited,
            NotFoundProcesses = processCounts.NotFound,
            ModuleProcesses = attachedProcessCounts.Modules,
            HandleProcesses = attachedProcessCounts.Handles,
            BookmarkedProcesses = bookmarkedProcesses,
            MemoryDumpCount = artifactCounts.MemoryDumps,
            MemoryImageCount = artifactCounts.MemoryImages,
            PeAnalysisCount = artifactCounts.PeAnalyses,
            NetworkCaptureCount = artifactCounts.NetworkCaptures,
            ZeekNetworkArtifactCount = artifactCounts.ZeekArtifacts,
            FilesystemArtifactCount = artifactCounts.FilesystemArtifacts,
            UnresolvedEvidenceCount = correlationCounts.Unresolved,
            AmbiguousEvidenceCount = correlationCounts.Ambiguous,
            SystemActivityCount = systemActivitySummary.CountsByScope.TryGetValue(
                SystemActivityScopeKind.All,
                out var activityCount)
                    ? activityCount
                    : 0,
            SystemActivityAccountCount = systemActivitySummary.AccountCount,
            SystemActivityCountsByScope = systemActivitySummary.CountsByScope,
            EventProcessesBySource = eventProcessesBySource
        };
        totalStopwatch.Stop();
        return new ExplorerScopeCountReadResult(counts, stages ?? [], totalStopwatch.Elapsed);
    }

    private static T MeasureStage<T>(
        ICollection<ExplorerScopeCountStageTiming>? stages,
        string stage,
        Func<T> action,
        Func<T, int>? rowCount = null)
    {
        if (stages == null)
        {
            return action();
        }

        var stopwatch = Stopwatch.StartNew();
        var result = action();
        stopwatch.Stop();
        stages.Add(new ExplorerScopeCountStageTiming(
            stage,
            stopwatch.Elapsed,
            Math.Max(0, rowCount?.Invoke(result) ?? 0)));
        return result;
    }

    private static SystemActivityExplorerSummary GetSystemActivityExplorerSummary(
        IReadOnlyList<TelemetryEventRecord> candidates)
    {
        var activities = candidates
            .Select(SystemActivityNormalizer.TryNormalize)
            .Where(activity => activity != null)
            .Cast<SystemActivityRecord>()
            .ToList();
        return new SystemActivityExplorerSummary(
            SystemActivityNormalizer.CountByScope(activities),
            SystemActivityNormalizer.CountAccountSummaries(activities));
    }

    private static string BuildProcessStatusCountSql(string processTable) => $"""
        SELECT COUNT(*),
               COALESCE(SUM(CASE WHEN Status = 'Running' THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN Status = 'Exited' THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN Status = 'NotFound' THEN 1 ELSE 0 END), 0)
        FROM {processTable};
        """;

    private static ProcessStatusCounts CountProcessStatuses(
        SqliteConnection connection,
        string processTable)
    {
        using var command = connection.CreateCommand();
        command.CommandText = BuildProcessStatusCountSql(processTable);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new ProcessStatusCounts(
                GetInt(reader, 0),
                GetInt(reader, 1),
                GetInt(reader, 2),
                GetInt(reader, 3))
            : new ProcessStatusCounts(0, 0, 0, 0);
    }

    private static AttachedArtifactProcessCounts CountAttachedArtifactProcesses(
        SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(DISTINCT ProcessKey) FROM Modules),
                   (SELECT COUNT(DISTINCT ProcessKey) FROM Handles);
            """;
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new AttachedArtifactProcessCounts(GetInt(reader, 0), GetInt(reader, 1))
            : new AttachedArtifactProcessCounts(0, 0);
    }

    private static IndependentArtifactCounts CountIndependentArtifacts(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM MemoryDumps),
                   (SELECT COUNT(*) FROM MemoryImages),
                   (SELECT COUNT(*) FROM PeAnalyses),
                   (SELECT COUNT(*) FROM NetworkCaptures),
                   (SELECT COUNT(*) FROM ZeekNetworkArtifacts),
                   (SELECT COUNT(*) FROM Artifacts
                    WHERE ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata'));
            """;
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new IndependentArtifactCounts(
                GetInt(reader, 0),
                GetInt(reader, 1),
                GetInt(reader, 2),
                GetInt(reader, 3),
                GetInt(reader, 4),
                GetInt(reader, 5))
            : new IndependentArtifactCounts(0, 0, 0, 0, 0, 0);
    }

    private int CountBookmarkedProcesses(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        if (_readContext.UsesAnnotationDatabase)
        {
            command.CommandText = $"""
                SELECT COUNT(DISTINCT AnnotationProcessKey)
                FROM (
                    SELECT COALESCE(NULLIF(ProcessKey, ''), TargetId) AS AnnotationProcessKey
                    FROM {_readContext.BookmarkTableName}
                    WHERE TargetKind = 'Process'
                    UNION
                    SELECT COALESCE(NULLIF(ProcessKey, ''), TargetId) AS AnnotationProcessKey
                    FROM {_readContext.NoteTableName}
                    WHERE TargetKind = 'Process'
                )
                WHERE AnnotationProcessKey IS NOT NULL AND AnnotationProcessKey <> '';
                """;
        }
        else
        {
            command.CommandText = """
                SELECT COUNT(DISTINCT ProcessKey)
                FROM Bookmarks
                WHERE TargetKind = 'Process' AND ProcessKey IS NOT NULL AND ProcessKey <> '';
                """;
        }

        return Convert.ToInt32(command.ExecuteScalar());
    }

    private static int Count(SqliteConnection connection, string tableName, string? where = null)
    {
        using var command = connection.CreateCommand();
        command.CommandText = string.IsNullOrWhiteSpace(where)
            ? $"SELECT COUNT(*) FROM {tableName};"
            : $"SELECT COUNT(*) FROM {tableName} WHERE {where};";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private ExplorerCorrelationCounts CountEvidenceCorrelationStates(SqliteConnection connection)
    {
        if (!TableExists(connection, "EvidenceCorrelationInputs") ||
            !TableExists(connection, "EvidenceRelations"))
        {
            return new ExplorerCorrelationCounts(0, 0);
        }

        if (ExplorerCorrelationCountCache.TryGet(_readContext.DatabasePath, out var cached))
        {
            return cached;
        }

        using var command = connection.CreateCommand();
        command.CommandText = ExplorerCorrelationCountSql.BuildCountSelectSql();
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new ExplorerCorrelationCounts(GetInt(reader, 0), GetInt(reader, 1))
            : new ExplorerCorrelationCounts(0, 0);
    }

    private static string BuildEvidenceCorrelationStateCountSql()
        => ExplorerCorrelationCountSql.BuildCountSelectSql();

    private const string EventProcessSourceCountSql = """
        SELECT Source, COUNT(DISTINCT ProcessKey)
        FROM ProcessEvents
        GROUP BY Source;
        """;

    private static IReadOnlyDictionary<string, int> CountEventProcessesBySource(SqliteConnection connection)
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        using var command = connection.CreateCommand();
        command.CommandText = EventProcessSourceCountSql;

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var source = GetString(reader, 0);
            if (!string.IsNullOrWhiteSpace(source))
            {
                counts[source] = GetInt(reader, 1);
            }
        }

        return counts;
    }

    private static void AddRootCounts(
        SqliteConnection connection,
        Dictionary<string, EvidenceRootSummary> roots,
        string tableName,
        string countProperty,
        string? where = null)
    {
        using var command = connection.CreateCommand();
        var whereClause = string.IsNullOrWhiteSpace(where) ? string.Empty : $"WHERE {where}";
        var identityKeyExpression = BuildEvidenceRootKeyExpressionList("e");
        command.CommandText = $"""
            SELECT {identityKeyExpression}, COUNT(*)
            FROM {tableName} e
            {whereClause}
            GROUP BY {BuildEvidenceRootRawKeyColumnList("e")};
            """;

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var root = GetOrCreateRoot(
                roots,
                GetString(reader, 0),
                GetString(reader, 1),
                GetString(reader, 2),
                GetString(reader, 3),
                GetString(reader, 4),
                GetString(reader, 5));
            var count = GetInt(reader, 6);
            switch (countProperty)
            {
                case "ProcessCount":
                    root.ProcessCount += count;
                    break;
                case "ProcessObservationCount":
                    root.ProcessObservationCount += count;
                    break;
                case "EventCount":
                    root.EventCount += count;
                    break;
                case "ModuleCount":
                    root.ModuleCount += count;
                    break;
                case "HandleCount":
                    root.HandleCount += count;
                    break;
                case "NetworkCaptureCount":
                    root.NetworkCaptureCount += count;
                    break;
                case "FilesystemArtifactCount":
                    root.FilesystemArtifactCount += count;
                    break;
                case "SourceRunCount":
                    root.SourceRunCount += count;
                    break;
                case "MissingSourceRunLinkCount":
                    root.MissingSourceRunLinkCount += count;
                    break;
            }
        }
    }

    private static EvidenceRootSummary GetOrCreateRoot(
        Dictionary<string, EvidenceRootSummary> roots,
        string caseId,
        string evidenceSessionId,
        string captureId,
        string sourceIdentityId,
        string hostId,
        string executionRootId)
    {
        var key = string.Join(
            '\u001f',
            caseId,
            evidenceSessionId,
            captureId,
            sourceIdentityId,
            hostId,
            executionRootId);
        if (!roots.TryGetValue(key, out var root))
        {
            root = new EvidenceRootSummary
            {
                CaseId = caseId,
                EvidenceSessionId = evidenceSessionId,
                CaptureId = captureId,
                SourceIdentityId = sourceIdentityId,
                HostId = hostId,
                ExecutionRootId = executionRootId
            };
            roots[key] = root;
        }

        return root;
    }

    private static ExplorerProcessNodeSummary ReadExplorerProcessNode(SqliteDataReader reader)
    {
        return new ExplorerProcessNodeSummary
        {
            ProcessKey = GetString(reader, 0),
            ProcessId = GetInt(reader, 1),
            ProcessName = GetString(reader, 2),
            ProcessPath = GetString(reader, 3),
            Status = GetEnum(reader, 4, ProcessStatus.Running),
            ParentProcessKey = GetString(reader, 5),
            CaseId = GetString(reader, 6),
            EvidenceSessionId = GetString(reader, 7),
            CaptureId = GetString(reader, 8),
            SourceIdentityId = GetString(reader, 9),
            HostId = GetString(reader, 10),
            ExecutionRootId = GetString(reader, 11),
            DescendantProcessCount = GetInt(reader, 12)
        };
    }

    private static string BuildProcessHierarchyCtes(string processTable, string identityWhere)
    {
        return $"""
            WITH RECURSIVE
            ScopedProcesses AS MATERIALIZED (
                SELECT {BuildHierarchyNodeIdExpression("p")} AS HierarchyNodeId, p.*
                FROM {processTable} p
                WHERE 1 = 1
                      {identityWhere}
            ),
            ResolvedProcessParents(ChildNodeId, ParentNodeId) AS MATERIALIZED (
                SELECT child.HierarchyNodeId,
                       {BuildResolvedParentNodeExpression("child")}
                FROM ScopedProcesses child
            ),
            ProcessEdges(ParentNodeId, ChildNodeId) AS MATERIALIZED (
                SELECT ParentNodeId, ChildNodeId
                FROM ResolvedProcessParents
                WHERE ParentNodeId IS NOT NULL
                  AND ParentNodeId <> ''
                  AND ParentNodeId <> ChildNodeId
            ),
            ProcessClosure(AncestorNodeId, DescendantNodeId) AS (
                SELECT ParentNodeId, ChildNodeId
                FROM ProcessEdges
                UNION
                SELECT closure.AncestorNodeId, edge.ChildNodeId
                FROM ProcessClosure closure
                JOIN ProcessEdges edge
                  ON edge.ParentNodeId = closure.DescendantNodeId
            ),
            DescendantCounts(AncestorNodeId, DescendantProcessCount) AS MATERIALIZED (
                SELECT AncestorNodeId, COUNT(*)
                FROM ProcessClosure
                WHERE AncestorNodeId <> DescendantNodeId
                GROUP BY AncestorNodeId
            )
            """;
    }

    private static string BuildHierarchyNodeIdExpression(string tableAlias)
    {
        return $"""
            COALESCE(
                NULLIF({tableAlias}.ProcessEntityId, ''),
                COALESCE({tableAlias}.CaseId, '') || CHAR(31) ||
                COALESCE({tableAlias}.EvidenceSessionId, '') || CHAR(31) ||
                COALESCE({tableAlias}.CaptureId, '') || CHAR(31) ||
                COALESCE({tableAlias}.SourceIdentityId, '') || CHAR(31) ||
                COALESCE({tableAlias}.HostId, '') || CHAR(31) ||
                COALESCE({tableAlias}.ExecutionRootId, '') || CHAR(31) ||
                COALESCE({tableAlias}.ProcessKey, '') || CHAR(31) ||
                COALESCE(CAST({tableAlias}.ProcessId AS TEXT), '') || CHAR(31) ||
                COALESCE({tableAlias}.StartTimeUtc, '')
            )
            """;
    }

    private static string BuildResolvedParentNodeExpression(string childAlias)
    {
        return $"""
            CASE
                WHEN {childAlias}.ParentProcessKey IS NOT NULL
                     AND {childAlias}.ParentProcessKey <> ''
                THEN (
                    SELECT candidate.HierarchyNodeId
                    FROM ScopedProcesses candidate
                    WHERE candidate.HierarchyNodeId <> {childAlias}.HierarchyNodeId
                      AND candidate.ProcessKey = {childAlias}.ParentProcessKey
                      AND {BuildExplorerIdentityMatchPredicate("candidate", childAlias)}
                    ORDER BY candidate.HierarchyNodeId ASC
                    LIMIT 1
                )
                WHEN {childAlias}.ParentProcessEntityId IS NOT NULL
                     AND {childAlias}.ParentProcessEntityId <> ''
                THEN (
                    SELECT candidate.HierarchyNodeId
                    FROM ScopedProcesses candidate
                    WHERE candidate.HierarchyNodeId <> {childAlias}.HierarchyNodeId
                      AND candidate.ProcessEntityId = {childAlias}.ParentProcessEntityId
                      AND {BuildExplorerIdentityMatchPredicate("candidate", childAlias)}
                    ORDER BY candidate.HierarchyNodeId ASC
                    LIMIT 1
                )
                WHEN {childAlias}.ParentProcessId > 0
                THEN (
                    SELECT candidate.HierarchyNodeId
                    FROM ScopedProcesses candidate
                    WHERE candidate.HierarchyNodeId <> {childAlias}.HierarchyNodeId
                      AND candidate.ProcessId = {childAlias}.ParentProcessId
                      AND {BuildExplorerIdentityMatchPredicate("candidate", childAlias)}
                      AND (
                          {childAlias}.StartTimeUtc IS NULL
                          OR candidate.StartTimeUtc IS NULL
                          OR {childAlias}.StartTimeUtc >= candidate.StartTimeUtc
                      )
                    ORDER BY COALESCE(candidate.StartTimeUtc, candidate.FirstObservedUtc, '') DESC,
                             candidate.HierarchyNodeId ASC
                    LIMIT 1
                )
                ELSE NULL
            END
            """;
    }

    private static string BuildExplorerIdentityMatchPredicate(string leftAlias, string rightAlias)
    {
        return $"""
            COALESCE({leftAlias}.CaseId, '') = COALESCE({rightAlias}.CaseId, '')
            AND COALESCE({leftAlias}.EvidenceSessionId, '') = COALESCE({rightAlias}.EvidenceSessionId, '')
            AND COALESCE({leftAlias}.CaptureId, '') = COALESCE({rightAlias}.CaptureId, '')
            AND COALESCE({leftAlias}.SourceIdentityId, '') = COALESCE({rightAlias}.SourceIdentityId, '')
            AND COALESCE({leftAlias}.HostId, '') = COALESCE({rightAlias}.HostId, '')
            AND COALESCE({leftAlias}.ExecutionRootId, '') = COALESCE({rightAlias}.ExecutionRootId, '')
            """;
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

    private static string BuildOwnerAggregateSql(string identityWhere)
    {
        var identityKeyExpression = BuildEvidenceRootKeyExpressionList("p");
        var ownerKeyExpression = BuildOwnerKeyExpression("r");
        return $"""
            WITH RawOwners AS MATERIALIZED (
                SELECT COALESCE(p.CaseId, '') AS CaseId,
                       COALESCE(p.EvidenceSessionId, '') AS EvidenceSessionId,
                       COALESCE(p.CaptureId, '') AS CaptureId,
                       COALESCE(p.SourceIdentityId, '') AS SourceIdentityId,
                       COALESCE(p.HostId, '') AS HostId,
                       COALESCE(p.ExecutionRootId, '') AS ExecutionRootId,
                       p.UserName,
                       COUNT(*) AS ProcessCount
                FROM Processes p
                WHERE 1 = 1
                      {identityWhere}
                GROUP BY {BuildEvidenceRootRawKeyColumnList("p")}, p.UserName
            )
            SELECT r.CaseId, r.EvidenceSessionId, r.CaptureId, r.SourceIdentityId, r.HostId, r.ExecutionRootId,
                   {ownerKeyExpression} AS OwnerKey,
                   MIN(
                       CASE
                           WHEN {ownerKeyExpression} = 'unknown'
                           THEN 'Unknown / unresolved owner'
                           ELSE TRIM(r.UserName)
                       END
                   ) AS OwnerDisplayName,
                   SUM(r.ProcessCount) AS ProcessCount
            FROM RawOwners r
            GROUP BY r.CaseId, r.EvidenceSessionId, r.CaptureId, r.SourceIdentityId,
                     r.HostId, r.ExecutionRootId, {ownerKeyExpression}
            ORDER BY OwnerKey = 'unknown' ASC,
                     OwnerDisplayName COLLATE NOCASE ASC,
                     r.CaptureId COLLATE NOCASE ASC,
                     r.ExecutionRootId COLLATE NOCASE ASC
            LIMIT $MaxCount;
            """;
    }

    private static string BuildEvidenceRootKeyExpressionList(string tableAlias)
    {
        return $"""
            COALESCE({tableAlias}.CaseId, ''), COALESCE({tableAlias}.EvidenceSessionId, ''),
            COALESCE({tableAlias}.CaptureId, ''), COALESCE({tableAlias}.SourceIdentityId, ''),
            COALESCE({tableAlias}.HostId, ''), COALESCE({tableAlias}.ExecutionRootId, '')
            """;
    }

    private static string BuildEvidenceRootRawKeyColumnList(string tableAlias)
    {
        return $"""
            {tableAlias}.CaseId, {tableAlias}.EvidenceSessionId, {tableAlias}.CaptureId,
            {tableAlias}.SourceIdentityId, {tableAlias}.HostId, {tableAlias}.ExecutionRootId
            """;
    }

    private static string GetOwnerDomain(string displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName) ||
            string.Equals(
                displayName,
                "Unknown / unresolved owner",
                StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        var separatorIndex = displayName.IndexOf('\\');
        if (separatorIndex > 0)
        {
            return displayName[..separatorIndex];
        }

        var atIndex = displayName.IndexOf('@');
        return atIndex > 0 && atIndex < displayName.Length - 1
            ? displayName[(atIndex + 1)..]
            : string.Empty;
    }

    private static string ReadFirstProcessKey(SqliteConnection connection, string processTable)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT ProcessKey FROM {processTable} ORDER BY ProcessKey LIMIT 1;";
        return Convert.ToString(command.ExecuteScalar()) ?? string.Empty;
    }

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

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM sqlite_master
            WHERE name = $TableName
              AND type IN ('table', 'view')
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$TableName", tableName);
        return command.ExecuteScalar() != null;
    }

    private static bool ColumnExists(
        SqliteConnection connection,
        string tableName,
        string columnName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({tableName});";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (string.Equals(GetString(reader, 1), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string GetProcessTable(SqliteConnection connection)
        => TableExists(connection, "ProcessEntities") ? "ProcessEntities" : "Processes";

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static int GetInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt32(ordinal);

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum fallback)
        where TEnum : struct
        => !reader.IsDBNull(ordinal) &&
           Enum.TryParse<TEnum>(reader.GetString(ordinal), out var value)
            ? value
            : fallback;

    private sealed record SystemActivityExplorerSummary(
        IReadOnlyDictionary<SystemActivityScopeKind, int> CountsByScope,
        int AccountCount);

    private sealed record ProcessStatusCounts(int Total, int Running, int Exited, int NotFound);

    private sealed record AttachedArtifactProcessCounts(int Modules, int Handles);

    private sealed record IndependentArtifactCounts(
        int MemoryDumps,
        int MemoryImages,
        int PeAnalyses,
        int NetworkCaptures,
        int ZeekArtifacts,
        int FilesystemArtifacts);

}

/// <summary>
/// Shared narrow candidate reader used by general System Activity APIs and the
/// Explorer badge summary so the candidate SQL is defined and executed once per call.
/// </summary>
internal sealed class SystemActivityCandidateQuery
{
    internal const int MaxCandidateRows = 100000;
    private const string CandidateEventIdPredicate =
        "EventCode IN (104, 106, 140, 141, 4624, 4625, 4634, 4647, 4648, 4672, 4697, 4698, 4702, 4719, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4740, 4756, 4757, 4902, 4904, 4905, 4906, 4907, 7045, 1102)";
    private readonly SqliteReadQueryContext _readContext;

    internal SystemActivityCandidateQuery(SqliteReadQueryContext readContext)
    {
        _readContext = readContext;
    }

    internal IReadOnlyList<TelemetryEventRecord> GetCandidates()
    {
        using var connection = _readContext.OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        command.CommandText = CandidateSql;
        command.Parameters.AddWithValue("$MaxCount", MaxCandidateRows);
        return SelectedProcessEvidenceQueryService.ReadEvents(command);
    }

    internal static string CandidateSql => $"""
            SELECT SequenceId, TimestampUtc, Source, ProcessKey, ProcessId, ProcessGuid,
                   ProcessStartTimeUtc, ProcessName, ParentProcessId, EventCode, Category,
                   Action, Target, Summary, Details, RiskFlags, IsInteresting, RepeatCount,
                   RawProvider, RawLogName, RawRecordIdText, CorrelationMethod,
                   CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId
            FROM ProcessEvents
            WHERE {CandidateEventIdPredicate}
                  OR (
                      EventCode IS NULL
                      AND (
                          Source IN ('Security', 'WindowsOther', 'Sysmon')
                          OR RawLogName IN ('Security', 'System', 'Microsoft-Windows-TaskScheduler/Operational')
                          OR RawLogName LIKE '%TaskScheduler%'
                      )
                  )
            ORDER BY TimestampUtc DESC, SequenceId DESC
            LIMIT $MaxCount;
            """;
}

internal static class ExplorerScopeQuerySql
{
    internal static string BuildIdentityWhereClause(
        ExplorerScope scope,
        string tableAlias,
        SqliteParameterCollection parameters,
        string parameterPrefix)
    {
        var predicates = new List<string>();
        AddIdentityPredicate(
            predicates,
            parameters,
            tableAlias,
            "CaseId",
            scope.CaseId,
            $"{parameterPrefix}CaseId");
        AddIdentityPredicate(
            predicates,
            parameters,
            tableAlias,
            "EvidenceSessionId",
            scope.EvidenceSessionId,
            $"{parameterPrefix}EvidenceSessionId");
        AddIdentityPredicate(
            predicates,
            parameters,
            tableAlias,
            "CaptureId",
            scope.CaptureId,
            $"{parameterPrefix}CaptureId");
        AddIdentityPredicate(
            predicates,
            parameters,
            tableAlias,
            "SourceIdentityId",
            scope.SourceIdentityId,
            $"{parameterPrefix}SourceIdentityId");
        AddIdentityPredicate(
            predicates,
            parameters,
            tableAlias,
            "HostId",
            scope.HostId,
            $"{parameterPrefix}HostId");
        AddIdentityPredicate(
            predicates,
            parameters,
            tableAlias,
            "ExecutionRootId",
            scope.ExecutionRootId,
            $"{parameterPrefix}ExecutionRootId");

        return predicates.Count == 0
            ? string.Empty
            : "AND " + string.Join(" AND ", predicates);
    }

    private static void AddIdentityPredicate(
        ICollection<string> predicates,
        SqliteParameterCollection parameters,
        string tableAlias,
        string columnName,
        string? value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var sqlParameterName = $"${parameterName}";
        predicates.Add($"{tableAlias}.{columnName} = {sqlParameterName}");
        parameters.AddWithValue(sqlParameterName, value);
    }
}

internal static class FilesystemQueryPath
{
    internal static string BuildWhereClause(
        string? folderPath,
        bool recursive,
        string tableAlias,
        SqliteParameterCollection parameters,
        string parameterPrefix)
    {
        var normalizedFolderPath = Normalize(folderPath);
        if (string.IsNullOrWhiteSpace(normalizedFolderPath))
        {
            return string.Empty;
        }

        var pathParameter = $"${parameterPrefix}Path";
        parameters.AddWithValue(pathParameter, normalizedFolderPath);

        if (!recursive)
        {
            return $"AND {tableAlias}.Path = {pathParameter}";
        }

        var prefixParameter = $"${parameterPrefix}Prefix";
        parameters.AddWithValue(prefixParameter, BuildPrefix(normalizedFolderPath));
        return $"AND ({tableAlias}.Path = {pathParameter} COLLATE NOCASE OR {tableAlias}.Path LIKE {prefixParameter} COLLATE NOCASE)";
    }

    internal static string? GetImmediateChildFolder(string artifactPath, string? parentPath)
    {
        var normalizedPath = Normalize(artifactPath);
        if (string.IsNullOrWhiteSpace(normalizedPath))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(parentPath))
        {
            var root = Path.GetPathRoot(normalizedPath);
            return string.IsNullOrWhiteSpace(root) ? null : Normalize(root);
        }

        var normalizedParent = Normalize(parentPath);
        if (string.IsNullOrWhiteSpace(normalizedParent) ||
            !IsSameOrDescendant(normalizedPath, normalizedParent))
        {
            return null;
        }

        var remainder = normalizedPath[normalizedParent.Length..]
            .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.IsNullOrWhiteSpace(remainder))
        {
            return null;
        }

        var separators = new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar };
        var firstSeparator = remainder.IndexOfAny(separators);
        if (firstSeparator <= 0)
        {
            return null;
        }

        return Combine(normalizedParent, remainder[..firstSeparator]);
    }

    internal static bool MatchesImmediateArtifact(string artifactPath, string? folderPath)
    {
        var normalizedFolderPath = Normalize(folderPath);
        if (string.IsNullOrWhiteSpace(normalizedFolderPath))
        {
            return true;
        }

        var normalizedArtifactPath = Normalize(artifactPath);
        if (string.IsNullOrWhiteSpace(normalizedArtifactPath) ||
            !IsSameOrDescendant(normalizedArtifactPath, normalizedFolderPath))
        {
            return false;
        }

        if (string.Equals(
            normalizedArtifactPath,
            normalizedFolderPath,
            StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var directory = Normalize(GetDirectoryNameSafe(normalizedArtifactPath));
        return string.Equals(directory, normalizedFolderPath, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSameOrDescendant(string path, string parentPath)
    {
        return string.Equals(path, parentPath, StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(
                   BuildPrefix(parentPath).TrimEnd('%'),
                   StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var trimmed = path.Trim();
        if (trimmed.Length >= 2 &&
            char.IsLetter(trimmed[0]) &&
            trimmed[1] == ':' &&
            (trimmed.Length == 2 ||
             (trimmed.Length == 3 &&
              (trimmed[2] == Path.DirectorySeparatorChar ||
               trimmed[2] == Path.AltDirectorySeparatorChar))))
        {
            return trimmed[..2];
        }

        var separators = new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar };
        var root = Path.GetPathRoot(trimmed);
        if (!string.IsNullOrWhiteSpace(root) &&
            string.Equals(
                trimmed.TrimEnd(separators),
                root.TrimEnd(separators),
                StringComparison.OrdinalIgnoreCase))
        {
            return root.TrimEnd(separators);
        }

        try
        {
            return Path.GetFullPath(trimmed).TrimEnd(separators);
        }
        catch
        {
            return trimmed.TrimEnd(separators);
        }
    }

    private static string? GetDirectoryNameSafe(string path)
    {
        try
        {
            return Path.GetDirectoryName(path);
        }
        catch
        {
            return null;
        }
    }

    private static string BuildPrefix(string folderPath)
    {
        if (folderPath.EndsWith(Path.DirectorySeparatorChar) ||
            folderPath.EndsWith(Path.AltDirectorySeparatorChar))
        {
            return folderPath + "%";
        }

        return folderPath + Path.DirectorySeparatorChar + "%";
    }

    private static string Combine(string parent, string child)
    {
        if (parent.EndsWith(Path.DirectorySeparatorChar) ||
            parent.EndsWith(Path.AltDirectorySeparatorChar))
        {
            return parent + child;
        }

        return parent + Path.DirectorySeparatorChar + child;
    }
}
