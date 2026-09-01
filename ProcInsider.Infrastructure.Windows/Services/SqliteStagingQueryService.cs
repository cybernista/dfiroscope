using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services;

public sealed record SqliteQueryPlanRecord(
    string Operation,
    int SelectId,
    int ParentId,
    int NotUsed,
    string Detail);

public sealed class SqliteStagingQueryService
{
    private const int MaxProcessStatisticsRows = 100000;
    private const int MaxProcessDetailArtifactRows = 10000;
    private const int MaxSigmaAnalysisRecordsPerKind = 10000;
    private static readonly SigmaAnalysisEvaluator SigmaEvaluator = new();
    private readonly SqliteReadQueryContext _readContext;
    private readonly ProcessListingQueryService _processListingQueries;
    private readonly SystemActivityCandidateQuery _systemActivityCandidates;
    private readonly ExplorerQueryService _explorerQueries;
    private readonly SelectedProcessEvidenceQueryService _selectedProcessEvidenceQueries;
    private readonly ArtifactEvidenceQueryService _artifactEvidenceQueries;
    private readonly YaraEvidenceQueryService _yaraEvidenceQueries;
    private readonly YaraAnalysisQueryService _yaraAnalysisQueries;
    private readonly ReputationAttributionQueryService _reputationAttributionQueries;
    private readonly ProcessRiskProjectionQueryService _processRiskProjectionQueries;

    public CaptureCompatibilityAssessment CompatibilityAssessment { get; }
    public IProcessListingQueryService ProcessListingQueries => _processListingQueries;
    public IExplorerQueryService ExplorerQueries => _explorerQueries;
    public ISelectedProcessEvidenceQueryService SelectedProcessEvidenceQueries => _selectedProcessEvidenceQueries;
    public IArtifactEvidenceQueryService ArtifactEvidenceQueries => _artifactEvidenceQueries;
    public IYaraEvidenceQueryService YaraEvidenceQueries => _yaraEvidenceQueries;
    public IYaraAnalysisQueryService YaraAnalysisQueries => _yaraAnalysisQueries;
    public IReputationAttributionQueryService ReputationAttributionQueries =>
        _reputationAttributionQueries;
    public IProcessRiskProjectionQueryService ProcessRiskProjectionQueries => _processRiskProjectionQueries;

    public SqliteStagingQueryService(
        string databasePath,
        string? annotationDatabasePath = null,
        SqlitePerformanceProfileName performanceProfile = SqlitePerformanceProfileName.HighMemoryRead,
        CaptureOpenContext openContext = CaptureOpenContext.ViewerArchivedReadOnly,
        CaptureManifestCompatibilityMetadata? manifest = null,
        string expectedEvidenceSessionId = "")
    {
        _readContext = new SqliteReadQueryContext(
            databasePath,
            annotationDatabasePath,
            performanceProfile);
        CompatibilityAssessment = SqliteStagingStore.AssessExistingDatabase(
            _readContext.DatabasePath,
            openContext,
            manifest,
            expectedEvidenceSessionId);
        CaptureCompatibilityPolicy.EnsureAllowed(
            CompatibilityAssessment,
            CaptureOpenCapability.ReadEvidence);
        _systemActivityCandidates = new SystemActivityCandidateQuery(_readContext);
        _processListingQueries = new ProcessListingQueryService(_readContext);
        _explorerQueries = new ExplorerQueryService(_readContext, _systemActivityCandidates);
        _selectedProcessEvidenceQueries = new SelectedProcessEvidenceQueryService(_readContext);
        _artifactEvidenceQueries = new ArtifactEvidenceQueryService(_readContext);
        _yaraEvidenceQueries = new YaraEvidenceQueryService(_readContext);
        _yaraAnalysisQueries = new YaraAnalysisQueryService(_readContext);
        _reputationAttributionQueries = new ReputationAttributionQueryService(_readContext);
        _processRiskProjectionQueries = new ProcessRiskProjectionQueryService(_readContext);
    }

    public IReadOnlyList<ProcessRecord> GetProcesses(ProcessProjectionQuery query)
    {
        return MeasureRead(
            "GetProcesses",
            () =>
            {
                var processes = new List<ProcessRecord>();
                using var connection = OpenReadOnlyConnection();
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
                    WHERE $IncludeExited = 1 OR Status <> 'Exited'
                    ORDER BY CASE Status WHEN 'Running' THEN 0 WHEN 'NotFound' THEN 1 ELSE 2 END,
                             COALESCE(StartTimeUtc, FirstObservedUtc) DESC
                    LIMIT $MaxCount;
                    """.Replace("{PROCESS_SOURCE}", processSource, StringComparison.Ordinal);
                command.Parameters.AddWithValue("$IncludeExited", query.IncludeExited ? 1 : 0);
                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(query.MaxCount, 1, 100000));

                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    processes.Add(ReadProcess(reader));
                }

                return processes;
            },
            $"include_exited={query.IncludeExited}; max={query.MaxCount}",
            processes => processes.Count);
    }

    public TelemetryStoreStats GetStats()
    {
        return MeasureRead(
            "GetStats",
            () =>
            {
                using var connection = OpenReadOnlyConnection();
                var performanceStatus = SqlitePerformanceProfile.GetStatus(
                    connection,
                    _readContext.PerformanceProfile);
                var processTable = GetProcessTable(connection);
                return new TelemetryStoreStats
                {
                    ProcessCount = Count(connection, processTable),
                    ProcessObservationCount = TableExists(connection, "ProcessObservations") ? Count(connection, "ProcessObservations") : 0,
                    RunningProcessCount = Count(connection, processTable, "Status = 'Running'"),
                    ExitedProcessCount = Count(connection, processTable, "Status = 'Exited'"),
                    EventCount = Count(connection, "ProcessEvents"),
                    RuntimeEventCount = Count(connection, "ProcessEvents", "Source = 'Runtime'"),
                    EtwEventCount = Count(connection, "ProcessEvents", "Source = 'ETW'"),
                    SecurityEventCount = Count(connection, "ProcessEvents", "Source = 'Security'"),
                    PowerShellEventCount = Count(connection, "ProcessEvents", "Source = 'PowerShell'"),
                    OtherWindowsEventCount = Count(connection, "ProcessEvents", "Source = 'WindowsOther'"),
                    SysmonEventCount = Count(connection, "ProcessEvents", "Source = 'Sysmon'"),
                    ProcessMonitorEventCount = Count(connection, "ProcessEvents", "Source = 'Procmon'"),
                    ModuleObservationCount = Count(connection, "Modules"),
                    HandleObservationCount = Count(connection, "Handles"),
                    MemoryDumpCount = Count(connection, "MemoryDumps"),
                    MemoryImageCount = Count(connection, "MemoryImages"),
                    VolatilityPluginRunCount = Count(connection, "VolatilityPluginRuns"),
                    PeAnalysisCount = Count(connection, "PeAnalyses"),
                    NetworkCaptureCount = Count(connection, "NetworkCaptures"),
                    ZeekNetworkArtifactCount = Count(connection, "ZeekNetworkArtifacts"),
                    FilesystemArtifactCount = Count(connection, "Artifacts", "ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata')"),
                    StatusMessage = performanceStatus.Summary
                };
            },
            "snapshot evidence counts");
    }

    public IReadOnlyList<ProcessStatisticsRecord> GetProcessStatisticsSamples(
        string processKey = "",
        int maxCount = 100000,
        string processEntityId = "")
    {
        using var connection = OpenReadOnlyConnection();
        if (!TableExists(connection, "ProcessStatistics"))
        {
            return Array.Empty<ProcessStatisticsRecord>();
        }

        using var command = connection.CreateCommand();
        var entity = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "ProcessEntityId", "''");
        var sourceRun = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "SourceRunId", "''");
        var ingestionJob = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "IngestionJobId", "''");
        var predicate = BuildProcessAttachmentPredicate(
            connection,
            "ProcessStatistics",
            "ps",
            processEntityId,
            processKey);
        command.CommandText = $"""
            SELECT SampleId, ProcessKey, ProcessId, ProcessGuid, ProcessName, Status, ObservedUtc,
                   TotalProcessorTimeTicks, UserProcessorTimeTicks, PrivilegedProcessorTimeTicks,
                   ReadBytes, WrittenBytes, CollectionError, Source,
                   CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                   {entity}, {sourceRun}, {ingestionJob}
            FROM ProcessStatistics ps
            WHERE {predicate}
            ORDER BY ObservedUtc DESC
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$ProcessKey", processKey ?? string.Empty);
        command.Parameters.AddWithValue("$ProcessEntityId", processEntityId ?? string.Empty);
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, MaxProcessStatisticsRows));

        var samples = new List<ProcessStatisticsRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            samples.Add(ReadProcessStatistics(reader));
        }

        return samples;
    }

    public IReadOnlyList<ProcessStatisticsRecord> GetLatestProcessStatistics(int maxCount = 100000)
    {
        using var connection = OpenReadOnlyConnection();
        if (!TableExists(connection, "ProcessStatistics"))
        {
            return Array.Empty<ProcessStatisticsRecord>();
        }

        using var command = connection.CreateCommand();
        var entity = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "ProcessEntityId", "''");
        var sourceRun = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "SourceRunId", "''");
        var ingestionJob = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "IngestionJobId", "''");
        var ownership = ColumnExists(connection, "ProcessStatistics", "ProcessEntityId")
            ? "COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey)"
            : "ProcessKey";
        var qualifiedOwnership = ColumnExists(connection, "ProcessStatistics", "ProcessEntityId")
            ? "COALESCE(NULLIF(ps.ProcessEntityId, ''), ps.ProcessKey)"
            : "ps.ProcessKey";
        command.CommandText = $"""
            WITH Latest AS (
                SELECT {ownership} AS OwnershipId, MAX(ObservedUtc) AS ObservedUtc
                FROM ProcessStatistics
                GROUP BY {ownership}
            )
            SELECT ps.SampleId, ps.ProcessKey, ps.ProcessId, ps.ProcessGuid, ps.ProcessName, ps.Status, ps.ObservedUtc,
                   ps.TotalProcessorTimeTicks, ps.UserProcessorTimeTicks, ps.PrivilegedProcessorTimeTicks,
                   ps.ReadBytes, ps.WrittenBytes, ps.CollectionError, ps.Source,
                   ps.CaseId, ps.EvidenceSessionId, ps.CaptureId, ps.SourceIdentityId, ps.HostId, ps.ExecutionRootId,
                   {entity}, {sourceRun}, {ingestionJob}
            FROM ProcessStatistics ps
            INNER JOIN Latest latest
                ON latest.OwnershipId = {qualifiedOwnership}
               AND latest.ObservedUtc = ps.ObservedUtc
            ORDER BY ps.ProcessName COLLATE NOCASE, ps.ProcessId
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, MaxProcessStatisticsRows));

        var samples = new List<ProcessStatisticsRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            samples.Add(ReadProcessStatistics(reader));
        }

        return samples;
    }

    /// <summary>
    /// Returns only the latest statistics rows owned by the supplied process entity/key
    /// identities. Requests are chunked below SQLite's parameter limit so listing page
    /// materialization never loads statistics for the complete capture.
    /// </summary>
    public IReadOnlyList<ProcessStatisticsRecord> GetLatestProcessStatisticsForOwners(
        IReadOnlyCollection<string> ownershipIds,
        CancellationToken cancellationToken = default)
    {
        var owners = ownershipIds
            .Where(owner => !string.IsNullOrWhiteSpace(owner))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (owners.Length == 0)
        {
            return [];
        }

        var results = new List<ProcessStatisticsRecord>(owners.Length);
        foreach (var batch in owners.Chunk(400))
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var connection = OpenReadOnlyConnection();
            if (!TableExists(connection, "ProcessStatistics"))
            {
                return [];
            }

            using var command = connection.CreateCommand();
            var entity = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "ProcessEntityId", "''");
            var sourceRun = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "SourceRunId", "''");
            var ingestionJob = SelectOptionalColumn(connection, "ProcessStatistics", "ps", "IngestionJobId", "''");
            var hasEntityId = ColumnExists(connection, "ProcessStatistics", "ProcessEntityId");
            var ownership = hasEntityId
                ? "COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey)"
                : "ProcessKey";
            var qualifiedOwnership = hasEntityId
                ? "COALESCE(NULLIF(ps.ProcessEntityId, ''), ps.ProcessKey)"
                : "ps.ProcessKey";
            var parameters = new List<string>(batch.Length);
            for (var index = 0; index < batch.Length; index++)
            {
                var parameterName = $"$Owner{index}";
                parameters.Add(parameterName);
                command.Parameters.AddWithValue(parameterName, batch[index]);
            }

            command.CommandText = $"""
                WITH Latest AS (
                    SELECT {ownership} AS OwnershipId, MAX(ObservedUtc) AS ObservedUtc
                    FROM ProcessStatistics
                    WHERE {ownership} IN ({string.Join(", ", parameters)})
                    GROUP BY {ownership}
                )
                SELECT ps.SampleId, ps.ProcessKey, ps.ProcessId, ps.ProcessGuid, ps.ProcessName, ps.Status, ps.ObservedUtc,
                       ps.TotalProcessorTimeTicks, ps.UserProcessorTimeTicks, ps.PrivilegedProcessorTimeTicks,
                       ps.ReadBytes, ps.WrittenBytes, ps.CollectionError, ps.Source,
                       ps.CaseId, ps.EvidenceSessionId, ps.CaptureId, ps.SourceIdentityId, ps.HostId, ps.ExecutionRootId,
                       {entity}, {sourceRun}, {ingestionJob}
                FROM ProcessStatistics ps
                INNER JOIN Latest latest
                    ON latest.OwnershipId = {qualifiedOwnership}
                   AND latest.ObservedUtc = ps.ObservedUtc
                ORDER BY ps.ProcessName COLLATE NOCASE, ps.ProcessId;
                """;

            using var registration = cancellationToken.Register(command.Cancel);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                results.Add(ReadProcessStatistics(reader));
            }
        }

        return results;
    }

    public SqlitePerformanceStatus GetPerformanceStatus()
    {
        using var connection = OpenReadOnlyConnection();
        return SqlitePerformanceProfile.GetStatus(connection, _readContext.PerformanceProfile);
    }

    public AgentSqliteDatabaseDiagnostics GetDatabaseDiagnostics()
    {
        using var connection = OpenReadOnlyConnection();
        return SqlitePerformanceProfile.GetDatabaseDiagnostics(
            connection,
            _readContext.PerformanceProfile,
            _readContext.DatabasePath,
            "SnapshotDb");
    }

    public ExplorerScopeCounts GetExplorerScopeCounts()
        => _explorerQueries.GetExplorerScopeCounts();

    public Task<ExplorerScopeCounts> GetExplorerScopeCountsAsync()
        => _explorerQueries.GetExplorerScopeCountsAsync();

    public ExplorerScopeCountReadResult GetExplorerScopeCountsWithDiagnostics()
        => _explorerQueries.GetExplorerScopeCountsWithDiagnostics();

    public IReadOnlyList<EvidenceRootSummary> GetEvidenceRoots()
        => _explorerQueries.GetEvidenceRoots();

    public IReadOnlyList<SourceRunSummary> GetSourceRuns(int maxCount = 200)
    {
        using var connection = OpenReadOnlyConnection();
        if (!TableExists(connection, "SourceRuns"))
        {
            return [];
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT SourceRunId, SourceId, IngestionJobId, SourceType, DisplayName, Status,
                   StartedUtc, EndedUtc, SourcePath, Provider, Channel, ToolVersion, ParserVersion,
                   CaseId, EvidenceSessionId, CaptureId, HostId, ExecutionRootId,
                   COALESCE((SELECT ParentSourceRunId FROM SourceRunLineage l
                             WHERE l.SourceRunId = r.SourceRunId LIMIT 1), ''),
                   COALESCE((SELECT InputArtifactId FROM SourceRunLineage l
                             WHERE l.SourceRunId = r.SourceRunId LIMIT 1), '')
            FROM SourceRuns r
            ORDER BY StartedUtc DESC, SourceRunId
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 1000));
        var rows = new List<SourceRunSummary>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new SourceRunSummary
            {
                SourceRunId = GetString(reader, 0),
                SourceId = GetInt(reader, 1),
                IngestionJobId = Guid.TryParse(GetString(reader, 2), out var jobId) ? jobId : null,
                SourceType = GetString(reader, 3),
                DisplayName = GetString(reader, 4),
                Status = GetString(reader, 5),
                StartedUtc = GetDateTime(reader, 6),
                EndedUtc = GetDateTime(reader, 7),
                SourcePath = GetString(reader, 8),
                Provider = GetString(reader, 9),
                Channel = GetString(reader, 10),
                ToolVersion = GetString(reader, 11),
                ParserVersion = GetString(reader, 12),
                CaseId = GetString(reader, 13),
                EvidenceSessionId = GetString(reader, 14),
                CaptureId = GetString(reader, 15),
                HostId = GetString(reader, 16),
                ExecutionRootId = GetString(reader, 17),
                ParentSourceRunId = GetString(reader, 18),
                InputArtifactId = GetString(reader, 19)
            });
        }

        return rows;
    }

    public SourceRunDiagnostics GetSourceRunDiagnostics()
    {
        using var connection = OpenReadOnlyConnection();
        if (!TableExists(connection, "SourceRuns"))
        {
            return new SourceRunDiagnostics();
        }

        var result = new SourceRunDiagnostics();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT COUNT(*),
                       SUM(CASE WHEN SourceRunId LIKE 'legacy-srun-%' THEN 1 ELSE 0 END)
                FROM SourceRuns;
                """;
            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                result.SourceRunCount = GetInt(reader, 0);
                result.LegacySourceRunCount = GetInt(reader, 1);
            }
        }

        foreach (var table in new[]
        {
            "Processes", "ProcessEntities", "ProcessStatistics", "ProcessEvents", "Modules", "Handles", "MemoryDumps",
            "PeAnalyses", "MemoryImages", "VolatilityPluginRuns", "MemoryProcesses", "NetworkCaptures",
            "ZeekNetworkArtifacts", "RawRecords", "Artifacts"
        })
        {
            if (!TableExists(connection, table) || !ColumnExists(connection, table, "SourceRunId"))
            {
                continue;
            }

            using var missing = connection.CreateCommand();
            missing.CommandText = $"SELECT COUNT(*) FROM {table} WHERE SourceRunId IS NULL OR SourceRunId = '';";
            result.MissingEvidenceLinkCount += Convert.ToInt32(missing.ExecuteScalar());
        }

        using (var jobs = connection.CreateCommand())
        {
            jobs.CommandText = "SELECT COUNT(*) FROM IngestionJobs WHERE SourceRunId IS NULL OR SourceRunId = '';";
            result.MissingJobLinkCount = Convert.ToInt32(jobs.ExecuteScalar());
        }

        return result;
    }

    public ProcessProjectionDiagnostics GetProcessProjectionDiagnostics()
    {
        using var connection = OpenReadOnlyConnection();
        if (!TableExists(connection, "ProcessObservations")) return new ProcessProjectionDiagnostics();
        var result = new ProcessProjectionDiagnostics
        {
            ObservationCount = Count(connection, "ProcessObservations"),
            UnresolvedEntityLinkCount = Count(connection, "ProcessObservations", "ProcessEntityId IS NULL OR ProcessEntityId = ''")
        };
        using (var conflicts = connection.CreateCommand())
        {
            conflicts.CommandText = "SELECT COALESCE(SUM(CAST(Value AS INTEGER)), 0) FROM SchemaInfo WHERE Key LIKE 'ProcessProjectionConflicts.%';";
            result.ProjectionConflictCount = Convert.ToInt32(conflicts.ExecuteScalar());
        }
        using (var metadata = connection.CreateCommand())
        {
            metadata.CommandText = "SELECT Key, Value FROM SchemaInfo WHERE Key IN ('ProcessProjectionVersion','ProcessProjectionLastRebuildUtc');";
            using var reader = metadata.ExecuteReader();
            while (reader.Read())
            {
                if (GetString(reader, 0) == "ProcessProjectionVersion") result.ProjectionVersion = GetString(reader, 1);
                else result.LastRebuildUtc = GetDateTime(reader, 1);
            }
        }
        return result;
    }

    public IReadOnlyList<ProcessProjectionFieldWinner> GetProcessProjectionProvenance(string processEntityId)
    {
        using var connection = OpenReadOnlyConnection();
        if (string.IsNullOrWhiteSpace(processEntityId) || !TableExists(connection, "ProcessProjectionFields")) return [];
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT FieldName, ObservationId, SourceRunId, ValueQuality, ResolutionReason
            FROM ProcessProjectionFields
            WHERE ProcessEntityId = $ProcessEntityId
            ORDER BY FieldName
            LIMIT 64;
            """;
        command.Parameters.AddWithValue("$ProcessEntityId", processEntityId);
        var rows = new List<ProcessProjectionFieldWinner>();
        using var reader = command.ExecuteReader();
        while (reader.Read()) rows.Add(new ProcessProjectionFieldWinner(
            GetString(reader, 0), GetString(reader, 1), GetString(reader, 2), GetInt(reader, 3), GetString(reader, 4)));
        return rows;
    }

    public Task<IReadOnlyList<EvidenceRootSummary>> GetEvidenceRootsAsync()
        => _explorerQueries.GetEvidenceRootsAsync();

    public IReadOnlyList<ExplorerProcessNodeSummary> GetExplorerProcessRoots(ExplorerScope scope, int maxCount = 100)
        => _explorerQueries.GetExplorerProcessRoots(scope, maxCount);

    public Task<IReadOnlyList<ExplorerProcessNodeSummary>> GetExplorerProcessRootsAsync(ExplorerScope scope, int maxCount = 100)
        => _explorerQueries.GetExplorerProcessRootsAsync(scope, maxCount);

    public IReadOnlyList<ExplorerProcessNodeSummary> GetExplorerProcessChildren(ExplorerScope parentScope, int maxCount = 100)
        => _explorerQueries.GetExplorerProcessChildren(parentScope, maxCount);

    public Task<IReadOnlyList<ExplorerProcessNodeSummary>> GetExplorerProcessChildrenAsync(ExplorerScope parentScope, int maxCount = 100)
        => _explorerQueries.GetExplorerProcessChildrenAsync(parentScope, maxCount);

    public IReadOnlyList<ExplorerProcessOwnerSummary> GetExplorerProcessOwners(ExplorerScope scope, int maxCount = 100)
        => _explorerQueries.GetExplorerProcessOwners(scope, maxCount);

    public Task<IReadOnlyList<ExplorerProcessOwnerSummary>> GetExplorerProcessOwnersAsync(ExplorerScope scope, int maxCount = 100)
        => _explorerQueries.GetExplorerProcessOwnersAsync(scope, maxCount);

    public IReadOnlyList<EvidenceRootSummary> GetExplorerFilesystemRoots(int maxCount = 100)
        => _explorerQueries.GetExplorerFilesystemRoots(maxCount);

    public Task<IReadOnlyList<EvidenceRootSummary>> GetExplorerFilesystemRootsAsync(int maxCount = 100)
        => _explorerQueries.GetExplorerFilesystemRootsAsync(maxCount);

    public IReadOnlyList<ExplorerFilesystemNodeSummary> GetExplorerFilesystemChildren(ExplorerScope scope, int maxCount = 100)
        => _explorerQueries.GetExplorerFilesystemChildren(scope, maxCount);

    public Task<IReadOnlyList<ExplorerFilesystemNodeSummary>> GetExplorerFilesystemChildrenAsync(ExplorerScope scope, int maxCount = 100)
        => _explorerQueries.GetExplorerFilesystemChildrenAsync(scope, maxCount);

    public ProcessArtifactCounts GetArtifactCounts(string processKey, string processEntityId = "")
        => _selectedProcessEvidenceQueries.GetArtifactCounts(processKey, processEntityId);

    public ProcessSourceEventCounts GetEventCounts(string processKey, string processEntityId = "")
        => _selectedProcessEvidenceQueries.GetEventCounts(processKey, processEntityId);

    public IReadOnlyDictionary<string, ProcessSourceEventCounts> CountEventsByProcessAndSource()
        => _selectedProcessEvidenceQueries.CountEventsByProcessAndSource();

    public IReadOnlyDictionary<string, int> CountModulesByProcess(bool includeUnloaded)
        => _selectedProcessEvidenceQueries.CountModulesByProcess(includeUnloaded);

    public IReadOnlyDictionary<string, int> CountHandlesByProcess(bool includeClosed)
        => _selectedProcessEvidenceQueries.CountHandlesByProcess(includeClosed);

    public IReadOnlyList<TelemetryEventRecord> GetEventsForProcess(
        string processKey,
        string? source,
        int maxCount,
        string processEntityId = "")
        => _selectedProcessEvidenceQueries.GetEventsForProcess(
            processKey,
            source,
            maxCount,
            processEntityId);

    public IReadOnlyList<SystemActivityRecord> GetSystemActivities(SystemActivityQuery query)
    {
        if (query.MaxCount <= 0)
        {
            return Array.Empty<SystemActivityRecord>();
        }

        return _systemActivityCandidates.GetCandidates()
            .Select(SystemActivityNormalizer.TryNormalize)
            .Where(activity => activity != null)
            .Cast<SystemActivityRecord>()
            .Where(activity => SystemActivityNormalizer.MatchesQuery(activity, query))
            .OrderByDescending(activity => activity.TimestampUtc)
            .ThenByDescending(activity => activity.SourceSequenceId)
            .Take(Math.Clamp(query.MaxCount, 1, 100000))
            .ToList();
    }

    public IReadOnlyDictionary<SystemActivityScopeKind, int> GetSystemActivityScopeCounts()
    {
        var activities = _systemActivityCandidates.GetCandidates()
            .Select(SystemActivityNormalizer.TryNormalize)
            .Where(activity => activity != null)
            .Cast<SystemActivityRecord>();
        return SystemActivityNormalizer.CountByScope(activities);
    }

    public IReadOnlyList<SystemActivityAccountSummary> GetSystemActivityAccounts(
        SystemActivityQuery query,
        int maxCount = 100)
    {
        var activities = _systemActivityCandidates.GetCandidates()
            .Select(SystemActivityNormalizer.TryNormalize)
            .Where(activity => activity != null)
            .Cast<SystemActivityRecord>()
            .Where(activity => SystemActivityNormalizer.MatchesQuery(activity, query));
        return SystemActivityNormalizer.BuildAccountSummaries(activities, maxCount);
    }

    public IReadOnlyList<ModuleObservationRecord> GetModulesForProcess(
        string processKey,
        bool includeUnloaded,
        int maxCount = MaxProcessDetailArtifactRows,
        string processEntityId = "")
        => _selectedProcessEvidenceQueries.GetModulesForProcess(
            processKey,
            includeUnloaded,
            maxCount,
            processEntityId);

    public IReadOnlyList<HandleObservationRecord> GetHandlesForProcess(
        string processKey,
        bool includeClosed,
        int maxCount = MaxProcessDetailArtifactRows,
        string processEntityId = "")
        => _selectedProcessEvidenceQueries.GetHandlesForProcess(
            processKey,
            includeClosed,
            maxCount,
            processEntityId);

    public int CountProcesses(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default)
        => _processListingQueries.CountProcesses(filters, cancellationToken);

    public ProcessListingPage GetProcessPage(
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
        => _processListingQueries.GetProcessPage(query, cancellationToken);

    public Task<int> CountProcessesAsync(
        ProcessListingFilterSet filters,
        CancellationToken cancellationToken = default)
        => _processListingQueries.CountProcessesAsync(filters, cancellationToken);

    public Task<ProcessListingPage> GetProcessPageAsync(
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
        => _processListingQueries.GetProcessPageAsync(query, cancellationToken);

    /// <summary>
    /// Looks up a single process record by its exact <paramref name="processKey"/>.
    /// Returns <see cref="ProcessKeyLookupResult.IsFound"/> = <c>false</c> when
    /// the key is not present in the database.
    /// </summary>
    public ProcessKeyLookupResult GetProcessByKey(string processKey)
        => _processListingQueries.GetProcessByKey(processKey);

    /// <inheritdoc cref="GetProcessByKey"/>
    public Task<ProcessKeyLookupResult> GetProcessByKeyAsync(string processKey)
        => _processListingQueries.GetProcessByKeyAsync(processKey);

    public ProcessEntityLookupResult GetProcessByEntityId(string processEntityId)
        => _processListingQueries.GetProcessByEntityId(processEntityId);

    public Task<ProcessEntityLookupResult> GetProcessByEntityIdAsync(string processEntityId)
        => _processListingQueries.GetProcessByEntityIdAsync(processEntityId);

    public IReadOnlyList<MemoryDumpRecord> GetMemoryDumpsForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "")
        => _artifactEvidenceQueries.GetMemoryDumpsForProcess(processKey, maxCount, processEntityId);

    public Task<IReadOnlyList<MemoryDumpRecord>> GetMemoryDumpsForProcessAsync(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "")
        => _artifactEvidenceQueries.GetMemoryDumpsForProcessAsync(processKey, maxCount, processEntityId);

    public IReadOnlyList<PeAnalysisRecord> GetPeAnalysesForProcess(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "")
        => _artifactEvidenceQueries.GetPeAnalysesForProcess(processKey, maxCount, processEntityId);

    public Task<IReadOnlyList<PeAnalysisRecord>> GetPeAnalysesForProcessAsync(
        string processKey,
        int maxCount = 1000,
        string processEntityId = "")
        => _artifactEvidenceQueries.GetPeAnalysesForProcessAsync(processKey, maxCount, processEntityId);

    public IReadOnlyDictionary<string, PeAnalysisRecord> GetLatestProcessImagePeAnalysesByProcessKey()
        => _artifactEvidenceQueries.GetLatestProcessImagePeAnalysesByProcessKey();

    public IReadOnlyList<AuthenticodeVerificationRecord> GetAuthenticodeVerificationsForProcess(
        string processKey,
        int maxCount = 100,
        string processEntityId = "")
        => _artifactEvidenceQueries.GetAuthenticodeVerificationsForProcess(processKey, maxCount, processEntityId);

    public AuthenticodeVerificationRecord? GetLatestAuthenticodeVerificationForProcess(
        string processKey,
        string processEntityId = "")
        => _artifactEvidenceQueries.GetLatestAuthenticodeVerificationForProcess(processKey, processEntityId);

    public IReadOnlyList<MemoryImageRecord> GetMemoryImages(int maxCount = 1000)
        => _artifactEvidenceQueries.GetMemoryImages(maxCount);

    public Task<IReadOnlyList<MemoryImageRecord>> GetMemoryImagesAsync(int maxCount = 1000)
        => _artifactEvidenceQueries.GetMemoryImagesAsync(maxCount);

    public MemoryImageRecord? GetMemoryImageById(string imageId)
        => _artifactEvidenceQueries.GetMemoryImageById(imageId);

    public IReadOnlyList<VolatilityPluginRunRecord> GetVolatilityPluginRuns(string imageId = "", int maxCount = 1000)
        => _artifactEvidenceQueries.GetVolatilityPluginRuns(imageId, maxCount);

    public Task<IReadOnlyList<VolatilityPluginRunRecord>> GetVolatilityPluginRunsAsync(string imageId = "", int maxCount = 1000)
        => _artifactEvidenceQueries.GetVolatilityPluginRunsAsync(imageId, maxCount);

    public IReadOnlyList<MemoryProcessRecord> GetMemoryProcesses(string imageId = "", int maxCount = 5000)
        => _artifactEvidenceQueries.GetMemoryProcesses(imageId, maxCount);

    public Task<IReadOnlyList<MemoryProcessRecord>> GetMemoryProcessesAsync(string imageId = "", int maxCount = 5000)
        => _artifactEvidenceQueries.GetMemoryProcessesAsync(imageId, maxCount);

    public IReadOnlyList<EvidenceRelation> GetEvidenceRelations(EvidenceRelationQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        using var connection = OpenReadOnlyConnection();
        if (!TableExists(connection, "EvidenceRelations"))
        {
            return [];
        }

        using var command = connection.CreateCommand();
        var predicates = new List<string>();
        if (!query.IncludeSuperseded)
        {
            predicates.Add("Status = 'Active'");
        }

        if (query.ReferenceKind.HasValue && !string.IsNullOrWhiteSpace(query.ReferenceId))
        {
            predicates.Add("((FromKind = $ReferenceKind AND FromId = $ReferenceId) OR (ToKind = $ReferenceKind AND ToId = $ReferenceId))");
            command.Parameters.AddWithValue("$ReferenceKind", query.ReferenceKind.Value.ToString());
            command.Parameters.AddWithValue("$ReferenceId", query.ReferenceId);
        }

        if (!string.IsNullOrWhiteSpace(query.ProcessEntityId))
        {
            predicates.Add("((FromKind = 'ProcessEntity' AND FromId = $ProcessEntityId) OR (ToKind = 'ProcessEntity' AND ToId = $ProcessEntityId))");
            command.Parameters.AddWithValue("$ProcessEntityId", query.ProcessEntityId);
        }

        if (!string.IsNullOrWhiteSpace(query.SourceRunId))
        {
            predicates.Add("SourceRunId = $SourceRunId");
            command.Parameters.AddWithValue("$SourceRunId", query.SourceRunId);
        }

        if (query.States.Count > 0)
        {
            var stateParameters = new List<string>();
            for (var index = 0; index < query.States.Count; index++)
            {
                var parameter = $"$CorrelationState{index}";
                stateParameters.Add(parameter);
                command.Parameters.AddWithValue(parameter, query.States[index].ToString());
            }
            predicates.Add($"CorrelationState IN ({string.Join(", ", stateParameters)})");
        }

        if (query.TimelineFromUtc.HasValue)
        {
            predicates.Add("ObservedFromUtc >= $TimelineFromUtc");
            command.Parameters.AddWithValue("$TimelineFromUtc", query.TimelineFromUtc.Value.ToString("O"));
        }

        if (query.TimelineToUtc.HasValue)
        {
            predicates.Add("ObservedFromUtc <= $TimelineToUtc");
            command.Parameters.AddWithValue("$TimelineToUtc", query.TimelineToUtc.Value.ToString("O"));
        }

        var where = predicates.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", predicates)}";
        var candidateCount = ColumnExists(connection, "EvidenceRelations", "CandidateCount")
            ? "CandidateCount"
            : "0 AS CandidateCount";
        var correlationDiagnostics = ColumnExists(connection, "EvidenceRelations", "CorrelationDiagnostics")
            ? "CorrelationDiagnostics"
            : "'' AS CorrelationDiagnostics";
        command.CommandText = $"""
            SELECT RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                   CorrelationState, CorrelationMethod, Confidence, {candidateCount}, {correlationDiagnostics},
                   CaseId, EvidenceSessionId,
                   CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId,
                   IngestionJobId, RawInputId, ObservedFromUtc, ObservedToUtc, ValidFromUtc,
                   ValidToUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                   SupersededByRelationId, AnalystAnnotationId
            FROM EvidenceRelations
            {where}
            ORDER BY ObservedFromUtc DESC, RelationId
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(query.MaxCount, 1, 5000));

        var relations = new List<EvidenceRelation>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            relations.Add(ReadEvidenceRelation(reader));
        }

        return relations;
    }

    public IReadOnlyList<EvidenceRelation> GetEvidenceRelationsForProcess(string processEntityId, int maxCount = 200)
        => GetEvidenceRelations(new EvidenceRelationQuery { ProcessEntityId = processEntityId, MaxCount = maxCount });

    public IReadOnlyList<EvidenceRelation> GetEvidenceRelationsForArtifact(
        EvidenceReferenceKind kind,
        string artifactId,
        int maxCount = 200)
        => GetEvidenceRelations(new EvidenceRelationQuery
        {
            ReferenceKind = kind,
            ReferenceId = artifactId,
            MaxCount = maxCount
        });

    public IReadOnlyList<EvidenceCorrelationInput> GetEvidenceCorrelationInputs(
        EvidenceCorrelationState? state = null,
        EvidenceReferenceKind? evidenceKind = null,
        string source = "",
        int maxCount = 1000)
    {
        using var connection = OpenReadOnlyConnection();
        if (!TableExists(connection, "EvidenceCorrelationInputs") || !TableExists(connection, "EvidenceRelations"))
        {
            return [];
        }

        using var command = connection.CreateCommand();
        var predicates = new List<string>();
        if (state.HasValue)
        {
            predicates.Add("COALESCE(r.CorrelationState, 'Unresolved') = $State");
            command.Parameters.AddWithValue("$State", state.Value.ToString());
        }
        if (evidenceKind.HasValue)
        {
            predicates.Add("i.EvidenceKind = $EvidenceKind");
            command.Parameters.AddWithValue("$EvidenceKind", evidenceKind.Value.ToString());
        }
        if (!string.IsNullOrWhiteSpace(source))
        {
            predicates.Add("i.Source = $Source");
            command.Parameters.AddWithValue("$Source", source);
        }
        var where = predicates.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", predicates)}";
        command.CommandText = $"""
            SELECT i.InputId, i.EvidenceKind, i.EvidenceId, i.EvidenceType, i.Source, i.RelationType,
                   i.CaseId, i.EvidenceSessionId, i.CaptureId, i.SourceIdentityId, i.HostId,
                   i.ExecutionRootId, i.SourceRunId, i.IngestionJobId, i.RawInputId, i.ProcessId,
                   i.ProcessStartTimeUtc, i.ProcessGuid, i.ProcessName, i.ProcessPath, i.SourceNativeId,
                   i.SourceEndpoint, i.DestinationEndpoint, i.ObservedUtc, i.CreatedUtc,
                   COALESCE(r.CorrelationState, 'Unresolved'),
                   CASE WHEN r.ToKind = 'ProcessEntity' THEN COALESCE(r.ToId, '')
                        WHEN r.FromKind = 'ProcessEntity' THEN COALESCE(r.FromId, '') ELSE '' END,
                   COALESCE(r.CorrelationMethod, ''), COALESCE(r.Confidence, 0),
                   COALESCE(r.CandidateCount, 0), COALESCE(r.CorrelationDiagnostics, ''),
                   COALESCE(r.ResolverVersion, '')
            FROM EvidenceCorrelationInputs i
            LEFT JOIN EvidenceRelations r ON r.RelationId = (
                SELECT active.RelationId FROM EvidenceRelations active
                WHERE active.DecisionKey = {CorrelationDecisionKeySql("i")}
                  AND active.Status = 'Active'
                ORDER BY active.UpdatedUtc DESC, active.RelationId DESC LIMIT 1)
            {where}
            ORDER BY i.ObservedUtc DESC, i.InputId
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 5000));
        var inputs = new List<EvidenceCorrelationInput>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            inputs.Add(ReadEvidenceCorrelationInput(reader));
        }
        return inputs;
    }

    public IReadOnlyList<EvidenceCorrelationGroupSummary> GetEvidenceCorrelationGroups(
        EvidenceCorrelationState state,
        int maxCount = 100)
    {
        using var connection = OpenReadOnlyConnection();
        if (!TableExists(connection, "EvidenceCorrelationInputs") || !TableExists(connection, "EvidenceRelations"))
        {
            return [];
        }

        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT COALESCE(r.CorrelationState, 'Unresolved'), i.EvidenceKind, i.Source, COUNT(*)
            FROM EvidenceCorrelationInputs i
            LEFT JOIN EvidenceRelations r ON r.RelationId = (
                SELECT active.RelationId FROM EvidenceRelations active
                WHERE active.DecisionKey = {CorrelationDecisionKeySql("i")}
                  AND active.Status = 'Active'
                ORDER BY active.UpdatedUtc DESC, active.RelationId DESC LIMIT 1)
            WHERE COALESCE(r.CorrelationState, 'Unresolved') = $State
            GROUP BY COALESCE(r.CorrelationState, 'Unresolved'), i.EvidenceKind, i.Source
            ORDER BY COUNT(*) DESC, i.EvidenceKind, i.Source
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$State", state.ToString());
        command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 500));
        var groups = new List<EvidenceCorrelationGroupSummary>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            groups.Add(new EvidenceCorrelationGroupSummary(
                GetEnum(reader, 0, EvidenceCorrelationState.Unresolved),
                GetEnum(reader, 1, EvidenceReferenceKind.GenericArtifact),
                GetString(reader, 2),
                GetInt(reader, 3)));
        }
        return groups;
    }

    public IReadOnlyList<TelemetrySearchResult> GetEvidenceCorrelationResults(
        EvidenceCorrelationState state,
        EvidenceReferenceKind? evidenceKind = null,
        string source = "",
        int maxCount = 1000)
        => GetEvidenceCorrelationInputs(state, evidenceKind, source, maxCount)
            .Select(input => new TelemetrySearchResult
            {
                Kind = "Correlation",
                RecordKey = input.InputId,
                ProcessEntityId = input.CurrentProcessEntityId,
                TimestampUtc = input.ObservedUtc,
                ProcessId = input.ProcessId,
                ProcessName = string.IsNullOrWhiteSpace(input.ProcessName) ? "<unknown>" : input.ProcessName,
                Title = $"{input.CurrentState}: {input.EvidenceKind} {input.EvidenceType}".Trim(),
                Subtitle = input.CorrelationDiagnostics,
                MatchedField = "Correlation state",
                MatchedValue = input.CurrentState.ToString(),
                Source = input.Source,
                EvidenceKind = input.EvidenceKind.ToString(),
                CorrelationState = input.CurrentState,
                CorrelationMethod = input.CurrentMethod,
                CorrelationCandidateCount = input.CandidateCount,
                CorrelationDiagnostics = input.CorrelationDiagnostics,
                ResolverVersion = input.ResolverVersion
            })
            .ToList();

    internal static string CorrelationDecisionKeySql(string alias)
        => $"CASE {alias}.EvidenceKind " +
           $"WHEN 'Event' THEN 'event:' || {alias}.EvidenceId || ':process' " +
           $"WHEN 'MemoryProcess' THEN 'memory-process:' || {alias}.EvidenceId || ':process' " +
           $"WHEN 'NetworkFlow' THEN 'zeek:' || {alias}.EvidenceId || ':process' " +
           $"ELSE 'correlation:' || {alias}.EvidenceKind || ':' || {alias}.EvidenceId || ':process' END";

    public IReadOnlyDictionary<int, List<ProcessRecord>> GetProcessPidLookup()
    {
        using var connection = OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ProcessKey, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                   ModuleCaptureStatus, ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError,
                   HandleCaptureStatus, HandleCount, HandleLastCapturedUtc, HandleCaptureError,
                   ParentProcessId, ParentProcessKey, ParentProcessName, ProcessName, ProcessPath,
                   CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                   CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc,
                   LastObservedUtc, LastSource, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId
            FROM Processes
            WHERE ProcessId > 0;
            """;
        var lookup = new Dictionary<int, List<ProcessRecord>>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var process = ReadProcess(reader);
            if (!lookup.TryGetValue(process.ProcessId, out var bucket))
            {
                bucket = [];
                lookup[process.ProcessId] = bucket;
            }

            bucket.Add(process);
        }

        return lookup;
    }

    public IReadOnlyList<NetworkCaptureRecord> GetNetworkCaptures(int maxCount = 1000)
        => _artifactEvidenceQueries.GetNetworkCaptures(maxCount);

    public Task<IReadOnlyList<NetworkCaptureRecord>> GetNetworkCapturesAsync(int maxCount = 1000)
        => _artifactEvidenceQueries.GetNetworkCapturesAsync(maxCount);

    public NetworkCaptureRecord? GetNetworkCaptureById(string captureId)
        => _artifactEvidenceQueries.GetNetworkCaptureById(captureId);

    public IReadOnlyList<ZeekNetworkRecord> GetZeekNetworkArtifacts(int maxCount = 1000)
        => _artifactEvidenceQueries.GetZeekNetworkArtifacts(maxCount);

    public Task<IReadOnlyList<ZeekNetworkRecord>> GetZeekNetworkArtifactsAsync(int maxCount = 1000)
        => _artifactEvidenceQueries.GetZeekNetworkArtifactsAsync(maxCount);

    public IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(int maxCount = 1000)
        => _artifactEvidenceQueries.GetFilesystemArtifacts(maxCount);

    public IReadOnlyList<FilesystemArtifactRecord> GetFilesystemArtifacts(
        ExplorerScope? scope,
        bool includeDescendants,
        int maxCount = 1000)
        => _artifactEvidenceQueries.GetFilesystemArtifacts(scope, includeDescendants, maxCount);

    public Task<IReadOnlyList<FilesystemArtifactRecord>> GetFilesystemArtifactsAsync(int maxCount = 1000)
        => _artifactEvidenceQueries.GetFilesystemArtifactsAsync(maxCount);

    public Task<IReadOnlyList<FilesystemArtifactRecord>> GetFilesystemArtifactsAsync(
        ExplorerScope? scope,
        bool includeDescendants,
        int maxCount = 1000)
        => _artifactEvidenceQueries.GetFilesystemArtifactsAsync(scope, includeDescendants, maxCount);

    public ZeekProcessCorrelation ResolveZeekProcessCorrelation(ZeekNetworkRecord artifact)
        => _artifactEvidenceQueries.ResolveZeekProcessCorrelation(artifact);

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
        => _processListingQueries.GetProcessRowIndex(processKey, query, cancellationToken);

    /// <inheritdoc cref="GetProcessRowIndex"/>
    public Task<int> GetProcessRowIndexAsync(
        string processKey,
        ProcessListingQuery query,
        CancellationToken cancellationToken = default)
        => _processListingQueries.GetProcessRowIndexAsync(processKey, query, cancellationToken);

    public IReadOnlyList<TelemetrySearchResult> Search(TelemetrySearchQuery query)
    {
        if (query.MaxResults <= 0 || query.AdvancedExpression == null)
        {
            return Array.Empty<TelemetrySearchResult>();
        }

        return MeasureRead<IReadOnlyList<TelemetrySearchResult>>(
            "Search",
            () =>
            {
        using var connection = OpenReadOnlyConnection();
        using var command = connection.CreateCommand();
        var predicates = new List<string>();
        var kinds = GetIncludedSearchKinds(query).ToList();
        if (kinds.Count == 0)
        {
            return Array.Empty<TelemetrySearchResult>();
        }

        var kindParameters = new List<string>();
        for (var i = 0; i < kinds.Count; i++)
        {
            var parameterName = $"$Kind{i}";
            kindParameters.Add(parameterName);
            command.Parameters.AddWithValue(parameterName, kinds[i]);
        }

        predicates.Add($"Kind IN ({string.Join(", ", kindParameters)})");
        if (query.IncludeCorrelationEvidence)
        {
            predicates.Add("(Kind <> 'CorrelationEvidence' OR StatusText IN ('Unresolved', 'Ambiguous'))");
        }
        var compiler = new SearchSqlCompiler(command.Parameters);
        predicates.Add(compiler.BuildPredicate(query.AdvancedExpression));
        var hasEvidenceRelations = TableExists(connection, "EvidenceRelations");
        var relationJoin = hasEvidenceRelations
            ? """
              LEFT JOIN EvidenceRelations r ON m.Kind = 'Event' AND r.RelationId = (
                  SELECT active.RelationId FROM EvidenceRelations active
                  WHERE active.DecisionKey = 'event:' || m.RecordKey || ':process'
                    AND active.Status = 'Active'
                  ORDER BY active.UpdatedUtc DESC, active.RelationId DESC LIMIT 1)
              LEFT JOIN EvidenceRelations attachment ON m.Kind IN ('Event', 'Module', 'Handle')
                  AND attachment.RelationId = (
                      SELECT active.RelationId FROM EvidenceRelations active
                      WHERE active.Status = 'Active'
                        AND ((active.FromKind = m.Kind AND active.FromId = m.RecordKey AND active.ToKind = 'ProcessEntity')
                          OR (active.ToKind = m.Kind AND active.ToId = m.RecordKey AND active.FromKind = 'ProcessEntity'))
                      ORDER BY CASE WHEN active.ResolverVersion = 'process-attached-v1' THEN 0 ELSE 1 END,
                               active.UpdatedUtc DESC, active.RelationId DESC LIMIT 1)
              """
            : string.Empty;
        var processEntityExpression = hasEvidenceRelations
            ? "CASE WHEN m.Kind = 'Process' THEN m.RecordKey WHEN m.Kind = 'Event' AND r.ToKind = 'ProcessEntity' THEN COALESCE(r.ToId, '') WHEN m.Kind = 'Event' AND r.FromKind = 'ProcessEntity' THEN COALESCE(r.FromId, '') WHEN attachment.ToKind = 'ProcessEntity' THEN COALESCE(attachment.ToId, '') WHEN attachment.FromKind = 'ProcessEntity' THEN COALESCE(attachment.FromId, '') ELSE '' END"
            : "CASE WHEN m.Kind = 'Process' THEN m.RecordKey ELSE '' END";
        var eventStateExpression = hasEvidenceRelations
            ? "CASE WHEN m.Kind = 'Event' THEN COALESCE(r.CorrelationState, CASE WHEN COALESCE(m.ProcessKey, '') <> '' THEN 'Asserted' ELSE 'Unresolved' END) ELSE '' END"
            : "CASE WHEN m.Kind = 'Event' THEN CASE WHEN COALESCE(m.ProcessKey, '') <> '' THEN 'Asserted' ELSE 'Unresolved' END ELSE '' END";
        var eventMethodExpression = hasEvidenceRelations
            ? "CASE WHEN m.Kind = 'Event' THEN COALESCE(r.CorrelationMethod, '') ELSE '' END"
            : "''";
        var eventCandidateExpression = hasEvidenceRelations && ColumnExists(connection, "EvidenceRelations", "CandidateCount")
            ? "CASE WHEN m.Kind = 'Event' THEN COALESCE(r.CandidateCount, 0) ELSE 0 END"
            : "0";
        var eventDiagnosticsExpression = hasEvidenceRelations && ColumnExists(connection, "EvidenceRelations", "CorrelationDiagnostics")
            ? "CASE WHEN m.Kind = 'Event' THEN COALESCE(r.CorrelationDiagnostics, '') ELSE '' END"
            : "''";
        var eventResolverExpression = hasEvidenceRelations
            ? "CASE WHEN m.Kind = 'Event' THEN COALESCE(r.ResolverVersion, '') ELSE '' END"
            : "''";
        command.CommandText = $"""
            WITH matches AS (
                SELECT Kind, ProcessKey, ProcessId, ProcessName, TimestampUtc, Source,
                       Title, Subtitle, RecordKey, StatusText, SummaryText, CategoryText,
                       ActionText, EventCodeText
                FROM SearchIndex
                WHERE {string.Join(" AND ", predicates)}
                ORDER BY COALESCE(TimestampUtc, '') DESC
                LIMIT $MaxResults
            )
            SELECT m.Kind, m.ProcessKey, m.ProcessId, m.ProcessName, m.TimestampUtc, m.Source,
                   m.Title, m.Subtitle, m.RecordKey, m.StatusText, m.SummaryText, m.CategoryText,
                   m.ActionText, m.EventCodeText, {processEntityExpression}, {eventStateExpression},
                   {eventMethodExpression}, {eventCandidateExpression}, {eventDiagnosticsExpression},
                   {eventResolverExpression}
            FROM matches m
            {relationJoin}
            ORDER BY COALESCE(m.TimestampUtc, '') DESC;
            """;
        command.Parameters.AddWithValue("$MaxResults", Math.Clamp(query.MaxResults, 1, 10000));

        var results = new List<TelemetrySearchResult>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var kind = GetString(reader, 0);
            var recordKey = GetString(reader, 8);
            var isCorrelation = string.Equals(kind, "CorrelationEvidence", StringComparison.OrdinalIgnoreCase);
            var isEvent = string.Equals(kind, "Event", StringComparison.OrdinalIgnoreCase);
            var correlationStateText = isCorrelation ? GetString(reader, 9) : isEvent ? GetString(reader, 15) : string.Empty;
            results.Add(new TelemetrySearchResult
            {
                Kind = isCorrelation ? "Correlation" : kind,
                RecordKey = recordKey,
                ProcessEntityId = GetString(reader, 14),
                ProcessKey = GetString(reader, 1),
                ProcessId = GetInt(reader, 2),
                ProcessName = string.IsNullOrWhiteSpace(GetString(reader, 3)) ? "<unknown>" : GetString(reader, 3),
                TimestampUtc = GetDateTime(reader, 4),
                Source = GetString(reader, 5),
                Title = GetString(reader, 6),
                Subtitle = GetString(reader, 7),
                MatchedField = string.IsNullOrWhiteSpace(query.AdvancedExpression.Field)
                    ? "SQLite FTS"
                    : query.AdvancedExpression.Field,
                MatchedValue = query.Text,
                EvidenceKind = isCorrelation ? GetString(reader, 11) : kind,
                CorrelationState = Enum.TryParse<EvidenceCorrelationState>(correlationStateText, out var state)
                    ? state
                    : null,
                CorrelationDiagnostics = isCorrelation ? GetString(reader, 7) : isEvent ? GetString(reader, 18) : string.Empty,
                CorrelationMethod = isCorrelation ? GetString(reader, 10) : isEvent ? GetString(reader, 16) : string.Empty,
                CorrelationCandidateCount = isCorrelation && int.TryParse(GetString(reader, 13), out var candidateCount)
                    ? candidateCount
                    : isEvent ? GetInt(reader, 17) : 0,
                ResolverVersion = isCorrelation ? GetString(reader, 12) : isEvent ? GetString(reader, 19) : string.Empty
            });
        }

        return results;
            },
            $"max_results={query.MaxResults}; scope={query.ScopeMode}",
            results => results.Count);
    }

    public Task<IReadOnlyList<TelemetrySearchResult>> SearchAsync(TelemetrySearchQuery query)
        => Task.Run(() => Search(query));

    public IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeReadQueryPlans()
    {
        return MeasureRead(
            "GetRepresentativeReadQueryPlans",
            () =>
            {
                using var connection = OpenReadOnlyConnection();
                var plans = new List<SqliteQueryPlanRecord>();
                plans.AddRange(_processListingQueries.GetRepresentativeQueryPlans());
                plans.AddRange(_explorerQueries.GetRepresentativeQueryPlans());
                plans.AddRange(_selectedProcessEvidenceQueries.GetRepresentativeQueryPlans());
                plans.AddRange(_artifactEvidenceQueries.GetRepresentativeQueryPlans());

                AddQueryPlan(
                    plans,
                    connection,
                    "keyword search",
                    """
                    SELECT Kind, RecordKey
                    FROM SearchIndex
                    WHERE SearchIndex MATCH $Text
                    LIMIT $MaxResults;
                    """,
                    command =>
                    {
                        command.Parameters.AddWithValue("$Text", "powershell");
                        command.Parameters.AddWithValue("$MaxResults", 250);
                    });

                return plans;
            },
            "representative EXPLAIN QUERY PLAN snapshot reads",
            plans => plans.Count);
    }

    public SigmaRunResult RunSigmaRulesWithDiagnostics(IReadOnlyList<SigmaRule> rules, int maxFindings)
    {
        return SigmaEvaluator.RunWithDiagnostics(CreateSigmaEvaluationInput(), rules, maxFindings);
    }

    public SigmaEvaluationInput CreateSigmaEvaluationInput()
        => CreateEvaluationInput(MaxSigmaAnalysisRecordsPerKind, MaxSigmaAnalysisRecordsPerKind);

    public IReadOnlyList<ProcessObservation> GetProcessObservations(int maxCount = 10000)
    {
        if (maxCount <= 0)
        {
            return Array.Empty<ProcessObservation>();
        }

        using var connection = OpenReadOnlyConnection();
        return ReadAllProcessObservations(connection, Math.Clamp(maxCount, 1, 10000));
    }

    public SigmaEvaluationInput CreateSnapshotAnalysisInput()
        => CreateEvaluationInput(int.MaxValue, MaxSigmaAnalysisRecordsPerKind);

    private SigmaEvaluationInput CreateEvaluationInput(int coreMaxCount, int independentArtifactMaxCount)
    {
        using var connection = OpenReadOnlyConnection();
        return new SigmaEvaluationInput
        {
            Processes = ReadAllProcesses(connection, coreMaxCount),
            ProcessObservations = ReadAllProcessObservations(connection, coreMaxCount),
            Events = ReadAllEvents(connection, coreMaxCount),
            Modules = ReadAllModules(connection, coreMaxCount),
            Handles = ReadAllHandles(connection, coreMaxCount),
            NetworkCaptures = GetNetworkCaptures(independentArtifactMaxCount),
            ZeekNetworkArtifacts = GetZeekNetworkArtifacts(independentArtifactMaxCount),
            FilesystemArtifacts = GetFilesystemArtifacts(independentArtifactMaxCount),
            MemoryImages = GetMemoryImages(independentArtifactMaxCount),
            VolatilityPluginRuns = GetVolatilityPluginRuns(maxCount: independentArtifactMaxCount),
            MemoryProcesses = GetMemoryProcesses(maxCount: independentArtifactMaxCount)
        };
    }

    private static IReadOnlyList<ProcessObservation> ReadAllProcessObservations(
        SqliteConnection connection,
        int maxCount)
    {
        if (!TableExists(connection, "ProcessObservations") ||
            !ColumnExists(connection, "ProcessObservations", "AdapterId") ||
            !ColumnExists(connection, "ProcessObservations", "ObservationKind"))
        {
            return Array.Empty<ProcessObservation>();
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ProcessEntityId, ObservationId, AdapterId, ObservationKind, SourceRunId,
                   IngestionJobId, RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc,
                   ValidToUtc, StatusAssertion, CorrelationMethod, CorrelationConfidence,
                   ParserVersion, FieldStatesJson, MetadataJson, PayloadJson
            FROM ProcessObservations
            ORDER BY ObservedUtc DESC, ObservationId DESC
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", maxCount);
        var rows = new List<ProcessObservation>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var entityId = GetString(reader, 0);
            ProcessRecord fields;
            Dictionary<string, ProcessObservationValueState> fieldStates;
            try
            {
                fields = JsonSerializer.Deserialize<ProcessRecord>(GetString(reader, 17)) ??
                         new ProcessRecord { ProcessEntityId = entityId };
                fieldStates = JsonSerializer.Deserialize<Dictionary<string, ProcessObservationValueState>>(
                                  GetString(reader, 15)) ??
                              new Dictionary<string, ProcessObservationValueState>(StringComparer.Ordinal);
            }
            catch (JsonException)
            {
                fields = new ProcessRecord { ProcessEntityId = entityId };
                fieldStates = new Dictionary<string, ProcessObservationValueState>(StringComparer.Ordinal);
            }

            rows.Add(new ProcessObservation
            {
                ProcessEntityId = entityId,
                ObservationId = GetString(reader, 1),
                AdapterId = GetString(reader, 2),
                ObservationKind = GetEnum(reader, 3, (ProcessObservationKind)(-1)),
                SourceRunId = GetString(reader, 4),
                IngestionJobId = Guid.TryParse(GetString(reader, 5), out var jobId) ? jobId : null,
                RawRecordId = GetString(reader, 6),
                SourceNativeAlias = GetString(reader, 7),
                ObservedUtc = GetDateTime(reader, 8) ?? DateTime.MinValue,
                ValidFromUtc = GetDateTime(reader, 9),
                ValidToUtc = GetDateTime(reader, 10),
                StatusAssertion = GetEnum(reader, 11, (ProcessStatus)(-1)),
                CorrelationMethod = GetEnum(reader, 12, (ProcessCorrelationMethod)(-1)),
                CorrelationConfidence = GetDouble(reader, 13),
                ParserVersion = GetString(reader, 14),
                FieldStates = fieldStates,
                MetadataJson = GetString(reader, 16),
                Fields = fields
            });
        }

        return rows;
    }

    private static IEnumerable<string> GetIncludedSearchKinds(TelemetrySearchQuery query)
    {
        if (query.IncludeProcesses)
        {
            yield return "Process";
        }

        if (query.IncludeEvents)
        {
            yield return "Event";
            yield return "NetworkCapture";
            yield return "Zeek";
            yield return "FilesystemArtifact";
            yield return "MemoryImage";
            yield return "VolatilityRun";
            yield return "MemoryProcess";
        }

        if (query.IncludeModules)
        {
            yield return "Module";
        }

        if (query.IncludeHandles)
        {
            yield return "Handle";
        }

        if (query.IncludeCorrelationEvidence)
        {
            yield return "CorrelationEvidence";
        }
    }

    private static EvidenceRelation ReadEvidenceRelation(SqliteDataReader reader)
    {
        return new EvidenceRelation
        {
            RelationId = GetString(reader, 0),
            DecisionKey = GetString(reader, 1),
            FromKind = GetEnum(reader, 2, EvidenceReferenceKind.GenericArtifact),
            FromId = GetString(reader, 3),
            ToKind = GetEnum(reader, 4, EvidenceReferenceKind.GenericArtifact),
            ToId = GetString(reader, 5),
            RelationType = GetEnum(reader, 6, EvidenceRelationType.CorrelatesWith),
            State = GetEnum(reader, 7, EvidenceCorrelationState.Unresolved),
            CorrelationMethod = GetString(reader, 8),
            Confidence = reader.IsDBNull(9) ? 0d : reader.GetDouble(9),
            CandidateCount = GetInt(reader, 10),
            CorrelationDiagnostics = GetString(reader, 11),
            CaseId = GetString(reader, 12),
            EvidenceSessionId = GetString(reader, 13),
            CaptureId = GetString(reader, 14),
            SourceIdentityId = GetString(reader, 15),
            HostId = GetString(reader, 16),
            ExecutionRootId = GetString(reader, 17),
            SourceRunId = GetString(reader, 18),
            IngestionJobId = GetString(reader, 19),
            RawInputId = GetString(reader, 20),
            ObservedFromUtc = GetDateTime(reader, 21) ?? DateTime.MinValue,
            ObservedToUtc = GetDateTime(reader, 22),
            ValidFromUtc = GetDateTime(reader, 23),
            ValidToUtc = GetDateTime(reader, 24),
            ResolverName = GetString(reader, 25),
            ResolverVersion = GetString(reader, 26),
            CreatedUtc = GetDateTime(reader, 27) ?? DateTime.MinValue,
            UpdatedUtc = GetDateTime(reader, 28) ?? DateTime.MinValue,
            Status = GetEnum(reader, 29, EvidenceRelationStatus.Active),
            SupersededByRelationId = GetString(reader, 30),
            AnalystAnnotationId = GetString(reader, 31)
        };
    }

    private static EvidenceCorrelationInput ReadEvidenceCorrelationInput(SqliteDataReader reader)
        => new()
        {
            InputId = GetString(reader, 0),
            EvidenceKind = GetEnum(reader, 1, EvidenceReferenceKind.GenericArtifact),
            EvidenceId = GetString(reader, 2),
            EvidenceType = GetString(reader, 3),
            Source = GetString(reader, 4),
            RelationType = GetEnum(reader, 5, EvidenceRelationType.CorrelatesWith),
            CaseId = GetString(reader, 6),
            EvidenceSessionId = GetString(reader, 7),
            CaptureId = GetString(reader, 8),
            SourceIdentityId = GetString(reader, 9),
            HostId = GetString(reader, 10),
            ExecutionRootId = GetString(reader, 11),
            SourceRunId = GetString(reader, 12),
            IngestionJobId = GetString(reader, 13),
            RawInputId = GetString(reader, 14),
            ProcessId = GetInt(reader, 15),
            ProcessStartTimeUtc = GetDateTime(reader, 16),
            ProcessGuid = GetString(reader, 17),
            ProcessName = GetString(reader, 18),
            ProcessPath = GetString(reader, 19),
            SourceNativeId = GetString(reader, 20),
            SourceEndpoint = GetString(reader, 21),
            DestinationEndpoint = GetString(reader, 22),
            ObservedUtc = GetDateTime(reader, 23) ?? DateTime.MinValue,
            CreatedUtc = GetDateTime(reader, 24) ?? DateTime.MinValue,
            CurrentState = GetEnum(reader, 25, EvidenceCorrelationState.Unresolved),
            CurrentProcessEntityId = GetString(reader, 26),
            CurrentMethod = GetString(reader, 27),
            CurrentConfidence = reader.IsDBNull(28) ? 0d : reader.GetDouble(28),
            CandidateCount = GetInt(reader, 29),
            CorrelationDiagnostics = GetString(reader, 30),
            ResolverVersion = GetString(reader, 31)
        };

    private static IReadOnlyList<ProcessRecord> ReadAllProcesses(SqliteConnection connection, int maxCount)
    {
        using var command = connection.CreateCommand();
        var entity = SelectOptionalColumn(connection, "Processes", "p", "ProcessEntityId", "''");
        var parentEntity = SelectOptionalColumn(connection, "Processes", "p", "ParentProcessEntityId", "''");
        command.CommandText = $"""
            SELECT ProcessKey, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                   ModuleCaptureStatus, ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError,
                   HandleCaptureStatus, HandleCount, HandleLastCapturedUtc, HandleCaptureError,
                   ParentProcessId, ParentProcessKey, ParentProcessName, ProcessName, ProcessPath,
                   CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                   CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc,
                   LastObservedUtc, LastSource, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, {entity}, {parentEntity}
            FROM Processes p
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Max(maxCount, 1));
        var processes = new List<ProcessRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            processes.Add(ReadProcess(reader));
        }

        return processes;
    }

    private static IReadOnlyList<TelemetryEventRecord> ReadAllEvents(SqliteConnection connection, int maxCount)
    {
        using var command = connection.CreateCommand();
        var entity = SelectOptionalColumn(connection, "ProcessEvents", "e", "ProcessEntityId", "''");
        var sourceRun = SelectOptionalColumn(connection, "ProcessEvents", "e", "SourceRunId", "''");
        var ingestionJob = SelectOptionalColumn(connection, "ProcessEvents", "e", "IngestionJobId", "''");
        var compatibilityState = ColumnExists(connection, "ProcessEvents", "ProcessEntityId")
            ? "CASE WHEN e.ProcessEntityId <> '' THEN 'Asserted' ELSE 'Unresolved' END"
            : "'Unresolved'";
        if (!TableExists(connection, "EvidenceRelations"))
        {
            command.CommandText = $"""
                SELECT e.SequenceId, e.TimestampUtc, e.Source, e.ProcessKey, e.ProcessId, e.ProcessGuid,
                       e.ProcessStartTimeUtc, e.ProcessName, e.ParentProcessId, e.EventCode, e.Category,
                       e.Action, e.Target, e.Summary, e.Details, e.RiskFlags, e.IsInteresting, e.RepeatCount,
                       e.RawProvider, e.RawLogName, e.RawRecordIdText, e.CorrelationMethod,
                       e.CaseId, e.EvidenceSessionId, e.CaptureId, e.SourceIdentityId, e.HostId, e.ExecutionRootId,
                       {entity}, {compatibilityState},
                       e.CorrelationMethod, 0, '', {sourceRun}, {ingestionJob}
                FROM ProcessEvents e
                ORDER BY e.SequenceId
                LIMIT $MaxCount;
                """;
            command.Parameters.AddWithValue("$MaxCount", Math.Max(maxCount, 1));
            return SelectedProcessEvidenceQueryService.ReadEvents(command);
        }

        var candidateCount = ColumnExists(connection, "EvidenceRelations", "CandidateCount")
            ? "COALESCE(r.CandidateCount, 0)"
            : "0";
        var diagnostics = ColumnExists(connection, "EvidenceRelations", "CorrelationDiagnostics")
            ? "COALESCE(r.CorrelationDiagnostics, '')"
            : "''";
        command.CommandText = $"""
            SELECT e.SequenceId, e.TimestampUtc, e.Source, e.ProcessKey, e.ProcessId, e.ProcessGuid,
                   e.ProcessStartTimeUtc, e.ProcessName, e.ParentProcessId, e.EventCode, e.Category,
                   e.Action, e.Target, e.Summary, e.Details, e.RiskFlags, e.IsInteresting, e.RepeatCount,
                   e.RawProvider, e.RawLogName, e.RawRecordIdText, e.CorrelationMethod,
                   e.CaseId, e.EvidenceSessionId, e.CaptureId, e.SourceIdentityId, e.HostId, e.ExecutionRootId,
                   COALESCE(NULLIF(e.ProcessEntityId, ''), CASE WHEN r.ToKind = 'ProcessEntity' THEN r.ToId ELSE '' END),
                   COALESCE(r.CorrelationState, CASE WHEN COALESCE(e.ProcessEntityId, '') <> '' THEN 'Asserted' ELSE 'Unresolved' END),
                   COALESCE(NULLIF(r.CorrelationMethod, ''), e.CorrelationMethod),
                   {candidateCount}, {diagnostics}, {sourceRun}, {ingestionJob}
            FROM ProcessEvents e
            LEFT JOIN EvidenceRelations r ON r.RelationId = (
                SELECT active.RelationId FROM EvidenceRelations active
                WHERE active.DecisionKey = 'event:' || e.SequenceId || ':process'
                  AND active.Status = 'Active'
                ORDER BY active.UpdatedUtc DESC, active.RelationId DESC LIMIT 1)
            ORDER BY e.SequenceId
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Max(maxCount, 1));
        return SelectedProcessEvidenceQueryService.ReadEvents(command);
    }

    private static IReadOnlyList<ModuleObservationRecord> ReadAllModules(SqliteConnection connection, int maxCount)
    {
        using var command = connection.CreateCommand();
        var entity = SelectOptionalColumn(connection, "Modules", "m", "ProcessEntityId", "''");
        var sourceRun = SelectOptionalColumn(connection, "Modules", "m", "SourceRunId", "''");
        var ingestionJob = SelectOptionalColumn(connection, "Modules", "m", "IngestionJobId", "''");
        command.CommandText = $"""
            SELECT m.SequenceId, m.ProcessKey, m.ProcessId, m.ProcessGuid, m.ModuleKey, m.ModuleName,
                   m.FullPath, m.BaseAddress, m.ModuleMemorySize, m.FileVersion, m.CompanyName,
                   m.Description, m.Sha256Hash, m.FirstSeenUtc, m.LastSeenUtc, m.UnloadedUtc,
                   m.State, m.Sources, m.LastSource, m.CaseId, m.EvidenceSessionId, m.CaptureId,
                   m.SourceIdentityId, m.HostId, m.ExecutionRootId, {entity}, {sourceRun}, {ingestionJob}
            FROM Modules m
            ORDER BY m.SequenceId
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Max(maxCount, 1));
        return SelectedProcessEvidenceQueryService.ReadModules(command);
    }

    private static IReadOnlyList<HandleObservationRecord> ReadAllHandles(SqliteConnection connection, int maxCount)
    {
        using var command = connection.CreateCommand();
        var entity = SelectOptionalColumn(connection, "Handles", "h", "ProcessEntityId", "''");
        var sourceRun = SelectOptionalColumn(connection, "Handles", "h", "SourceRunId", "''");
        var ingestionJob = SelectOptionalColumn(connection, "Handles", "h", "IngestionJobId", "''");
        command.CommandText = $"""
            SELECT h.SequenceId, h.ProcessKey, h.ProcessId, h.HandleKey, h.HandleValue, h.HandleValueNumeric,
                   h.ObjectType, h.ObjectName, h.GrantedAccess, h.GrantedAccessValue, h.HandleAttributes,
                   h.HandleAttributesValue, h.ObjectAddress, h.FirstSeenUtc, h.LastSeenUtc, h.ClosedUtc,
                   h.State, h.LastSource, h.CaseId, h.EvidenceSessionId, h.CaptureId,
                   h.SourceIdentityId, h.HostId, h.ExecutionRootId, {entity}, {sourceRun}, {ingestionJob}
            FROM Handles h
            ORDER BY h.SequenceId
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$MaxCount", Math.Max(maxCount, 1));
        return SelectedProcessEvidenceQueryService.ReadHandles(command);
    }

    private sealed class SearchSqlCompiler
    {
        private readonly SqliteParameterCollection _parameters;
        private int _nextParameterIndex;

        public SearchSqlCompiler(SqliteParameterCollection parameters)
        {
            _parameters = parameters;
        }

        public string BuildPredicate(AdvancedSearchExpression expression)
        {
            return expression.Kind switch
            {
                AdvancedSearchExpressionKind.Term => BuildTermPredicate(expression),
                AdvancedSearchExpressionKind.Not => $"NOT ({BuildPredicate(expression.Children[0])})",
                AdvancedSearchExpressionKind.And => $"({BuildPredicate(expression.Children[0])} AND {BuildPredicate(expression.Children[1])})",
                AdvancedSearchExpressionKind.Or => $"({BuildPredicate(expression.Children[0])} OR {BuildPredicate(expression.Children[1])})",
                _ => throw new InvalidOperationException($"Unsupported search expression kind '{expression.Kind}'.")
            };
        }

        private string BuildTermPredicate(AdvancedSearchExpression term)
        {
            var value = term.Value.Trim();
            if (string.IsNullOrWhiteSpace(value))
            {
                return "0 = 1";
            }

            var field = NormalizeSearchField(term.Field);
            if (field is "kind" or "type")
            {
                var parameterName = AddParameter(value);
                return $"Kind = {parameterName}";
            }

            if (field is "source")
            {
                var parameterName = AddParameter($"%{value}%");
                return $"Source LIKE {parameterName}";
            }

            if (field is "pid")
            {
                if (!int.TryParse(value, out var processId))
                {
                    return "0 = 1";
                }

                var parameterName = AddParameter(processId.ToString());
                return $"ProcessId = {parameterName}";
            }

            var matchExpression = BuildFtsMatchExpression(value, ResolveFtsColumn(field));
            var matchParameterName = AddParameter(matchExpression);
            return $"rowid IN (SELECT rowid FROM SearchIndex WHERE SearchIndex MATCH {matchParameterName})";
        }

        private string AddParameter(object value)
        {
            var parameterName = $"$Search{_nextParameterIndex++}";
            _parameters.AddWithValue(parameterName, value);
            return parameterName;
        }

        private static string BuildFtsMatchExpression(string value, string? column)
        {
            var escapedValue = value.Replace("\"", "\"\"");
            return string.IsNullOrWhiteSpace(column)
                ? $"\"{escapedValue}\""
                : $"{column}:\"{escapedValue}\"";
        }

        private static string? ResolveFtsColumn(string field)
        {
            return field switch
            {
                "" => null,
                "status" or "state" => "StatusText",
                "process" or "processname" or "name" => "ProcessNameText",
                "path" => "PathText",
                "commandline" or "cmd" => "CommandLineText",
                "user" => "UserText",
                "company" => "CompanyText",
                "description" => "DescriptionText",
                "hash" or "sha256" => "Sha256Text",
                "parent" => "ParentText",
                "target" => "TargetText",
                "summary" => "SummaryText",
                "details" => "DetailsText",
                "risk" => "RiskFlagsText",
                "eventcode" => "EventCodeText",
                "action" => "ActionText",
                "category" => "CategoryText",
                "processguid" or "guid" => "ProcessGuidText",
                "module" => "ModuleNameText",
                "version" => "FileVersionText",
                "baseaddress" => "BaseAddressText",
                "objecttype" => "ObjectTypeText",
                "objectname" => "ObjectNameText",
                "access" => "GrantedAccessText",
                "handle" => "HandleText",
                _ => throw new InvalidOperationException($"Unsupported search field '{field}'.")
            };
        }

        private static string NormalizeSearchField(string value)
        {
            return new string(value.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        }
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

    private SqliteConnection OpenReadOnlyConnection()
        => _readContext.OpenReadOnlyConnection();

    private T MeasureRead<T>(
        string operation,
        Func<T> action,
        string detail = "",
        Func<T, long>? rowCountSelector = null)
        => _readContext.MeasureRead(operation, action, detail, rowCountSelector);

    private bool UsesAnnotationDatabase()
        => _readContext.UsesAnnotationDatabase;

    private string GetBookmarkTableName()
        => _readContext.BookmarkTableName;

    private string? GetNoteTableName()
        => _readContext.NoteTableName;

    private static int Count(SqliteConnection connection, string tableName, string? where = null)
    {
        using var command = connection.CreateCommand();
        command.CommandText = string.IsNullOrWhiteSpace(where)
            ? $"SELECT COUNT(*) FROM {tableName};"
            : $"SELECT COUNT(*) FROM {tableName} WHERE {where};";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private static ProcessRecord ReadProcess(SqliteDataReader reader)
        => ProcessListingQueryService.ReadProcess(reader);

    private static ProcessStatisticsRecord ReadProcessStatistics(SqliteDataReader reader)
    {
        var record = new ProcessStatisticsRecord
        {
            SampleId = GetString(reader, 0),
            ProcessKey = GetString(reader, 1),
            ProcessId = GetInt(reader, 2),
            ProcessGuid = GetString(reader, 3),
            ProcessName = GetString(reader, 4),
            Status = GetEnum(reader, 5, ProcessStatus.Running),
            ObservedUtc = GetDateTime(reader, 6) ?? DateTime.UtcNow,
            TotalProcessorTimeTicks = GetNullableLong(reader, 7),
            UserProcessorTimeTicks = GetNullableLong(reader, 8),
            PrivilegedProcessorTimeTicks = GetNullableLong(reader, 9),
            ReadBytes = GetNullableLong(reader, 10),
            WrittenBytes = GetNullableLong(reader, 11),
            CollectionError = GetString(reader, 12),
            Source = GetString(reader, 13)
        };
        if (reader.FieldCount >= 20)
        {
            record.CaseId = GetString(reader, 14);
            record.EvidenceSessionId = GetString(reader, 15);
            record.CaptureId = GetString(reader, 16);
            record.SourceIdentityId = GetString(reader, 17);
            record.HostId = GetString(reader, 18);
            record.ExecutionRootId = GetString(reader, 19);
        }
        if (reader.FieldCount >= 23)
        {
            record.ProcessEntityId = GetString(reader, 20);
            record.SourceRunId = GetString(reader, 21);
            record.IngestionJobId = GetString(reader, 22);
        }

        return record;
    }

    private static string GetString(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);
    }

    private static int GetInt(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? 0 : reader.GetInt32(ordinal);
    }

    private static int? GetNullableInt(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    }

    private static long GetLong(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? 0 : reader.GetInt64(ordinal);
    }

    private static long? GetNullableLong(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);
    }

    private static double GetDouble(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? 0 : reader.GetDouble(ordinal);
    }

    private static bool GetBool(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return false;
        }

        if (reader.GetFieldType(ordinal) == typeof(string))
        {
            var value = GetString(reader, ordinal);
            return value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("T", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("1", StringComparison.OrdinalIgnoreCase);
        }

        return reader.GetInt64(ordinal) != 0;
    }

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) || !DateTimeOffset.TryParse(reader.GetString(ordinal), out var value)
            ? null
            : value.UtcDateTime;
    }

    private static string FormatDate(DateTime value)
    {
        return value.Kind == DateTimeKind.Utc
            ? value.ToString("O")
            : value.ToUniversalTime().ToString("O");
    }

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum fallback)
        where TEnum : struct
    {
        return !reader.IsDBNull(ordinal) && Enum.TryParse<TEnum>(reader.GetString(ordinal), out var value)
            ? value
            : fallback;
    }

    private static string SelectOptionalColumn(
        SqliteConnection connection,
        string tableName,
        string alias,
        string columnName,
        string fallbackExpression)
    {
        return ColumnExists(connection, tableName, columnName)
            ? $"{alias}.{columnName}"
            : $"{fallbackExpression} AS {columnName}";
    }

    private static bool ColumnExists(SqliteConnection connection, string tableName, string columnName)
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

    private static string BuildProcessAttachmentPredicate(
        SqliteConnection connection,
        string tableName,
        string alias,
        string processEntityId,
        string processKey)
    {
        return !string.IsNullOrWhiteSpace(processEntityId) && ColumnExists(connection, tableName, "ProcessEntityId")
            ? $"{alias}.ProcessEntityId = $ProcessEntityId"
            : !string.IsNullOrWhiteSpace(processKey)
                ? $"{alias}.ProcessKey = $ProcessKey"
                : "1 = 0";
    }

    private static string GetOptionalString(SqliteDataReader reader, string columnName)
    {
        for (var index = 0; index < reader.FieldCount; index++)
        {
            if (string.Equals(reader.GetName(index), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return GetString(reader, index);
            }
        }

        return string.Empty;
    }

    private static string GetProcessTable(SqliteConnection connection)
        => TableExists(connection, "ProcessEntities") ? "ProcessEntities" : "Processes";

    private static string GetProcessSource(SqliteConnection connection)
        => TableExists(connection, "ProcessEntities") ? "ProcessEntities AS Processes" : "Processes";

    public readonly record struct ZeekProcessCorrelation(
        string ProcessKey,
        int ProcessId,
        string ProcessName,
        string Method,
        double Confidence);
}
