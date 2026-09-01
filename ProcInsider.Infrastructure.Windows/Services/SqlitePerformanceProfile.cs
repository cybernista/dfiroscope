using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Diagnostics;
using Microsoft.Data.Sqlite;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services;

public enum SqlitePerformanceProfileName
{
    Conservative = 0,
    HighMemoryRead = 1,
    BrowserAnalysis = 2
}

internal enum SqliteWalCheckpointMode
{
    Passive,
    Truncate
}

public sealed record SqlitePerformanceStatus(
    SqlitePerformanceProfileName Profile,
    int CacheSizePages,
    int TempStore,
    long MmapSizeBytes,
    string JournalMode,
    int WalAutoCheckpointPages,
    int LiveIndexCount,
    int AnalysisIndexCount,
    string Summary);

public sealed record SqliteAnalysisIndexGroup(string Name, IReadOnlyList<string> Statements);

public static class SqlitePerformanceProfile
{
    public const string LiveIndexMigrationId = "011_v3_sqlite_live_indexes";
    public const string AnalysisIndexMigrationId = "012_v3_sqlite_analysis_indexes";

    private static readonly string[] LiveIndexSql =
    [
        "CREATE INDEX IF NOT EXISTS IX_Processes_ProcessId ON Processes(ProcessId);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_Status ON Processes(Status);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_StartTimeUtc ON Processes(StartTimeUtc);",
        "CREATE INDEX IF NOT EXISTS IX_Modules_ProcessKey ON Modules(ProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_Handles_ProcessKey ON Handles(ProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_PeAnalyses_ProcessKey ON PeAnalyses(ProcessKey);"
    ];

    private static readonly string[] SnapshotBrowsingIndexSql =
    [
        "CREATE INDEX IF NOT EXISTS IX_Processes_ProcessName ON Processes(ProcessName);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_EndTimeUtc ON Processes(EndTimeUtc);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_ModuleCount ON Processes(ModuleCount);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_HandleCount ON Processes(HandleCount);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_ModuleCaptureStatus ON Processes(ModuleCaptureStatus);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_HandleCaptureStatus ON Processes(HandleCaptureStatus);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_ParentProcessId ON Processes(ParentProcessId);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_ParentProcessKey ON Processes(ParentProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_ParentProcessName ON Processes(ParentProcessName);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_ProcessPath ON Processes(ProcessPath);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_UserName ON Processes(UserName);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_ExplorerOwner ON Processes(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId, UserName);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_EvidenceRoot ON ProcessEntities(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessObservations_EvidenceRoot ON ProcessObservations(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEvents_EvidenceRoot ON ProcessEvents(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId);",
        "CREATE INDEX IF NOT EXISTS IX_Modules_EvidenceRoot ON Modules(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId);",
        "CREATE INDEX IF NOT EXISTS IX_Handles_EvidenceRoot ON Handles(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_SessionId ON Processes(SessionId);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_Architecture ON Processes(Architecture);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_CompanyName ON Processes(CompanyName);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_FileDescription ON Processes(FileDescription);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_Sha256Hash ON Processes(Sha256Hash);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_ProcessNameCursor ON ProcessEntities(ProcessName COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_ProcessIdCursor ON ProcessEntities(ProcessId, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_ParentProcessIdCursor ON ProcessEntities(ParentProcessId, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_ParentProcessNameCursor ON ProcessEntities(ParentProcessName COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_ProcessPathCursor ON ProcessEntities(ProcessPath COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_CommandLineCursor ON ProcessEntities(CommandLine COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_UserNameCursor ON ProcessEntities(UserName COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_SessionIdCursor ON ProcessEntities(SessionId, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_ArchitectureCursor ON ProcessEntities(Architecture COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_StartTimeCursor ON ProcessEntities(StartTimeUtc, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_EndTimeCursor ON ProcessEntities(EndTimeUtc, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_StatusCursor ON ProcessEntities(Status COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_CpuUsageCursor ON ProcessEntities(CpuUsage, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_MemoryUsageCursor ON ProcessEntities(MemoryUsageBytes, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_CompanyNameCursor ON ProcessEntities(CompanyName COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_FileDescriptionCursor ON ProcessEntities(FileDescription COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEntities_Sha256HashCursor ON ProcessEntities(Sha256Hash COLLATE NOCASE, COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey) COLLATE BINARY);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessStatistics_ProcessKeyObserved ON ProcessStatistics(ProcessKey, ObservedUtc);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessStatistics_OwnerObserved ON ProcessStatistics(COALESCE(NULLIF(ProcessEntityId, ''), ProcessKey), ObservedUtc);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessStatistics_ObservedUtc ON ProcessStatistics(ObservedUtc);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessStatistics_CaseSessionCapture ON ProcessStatistics(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEvents_ProcessKey ON ProcessEvents(ProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEvents_TimestampUtc ON ProcessEvents(TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEvents_Source ON ProcessEvents(Source);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEvents_ExplorerActivityCandidate ON ProcessEvents(EventCode, TimestampUtc DESC, SequenceId DESC);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEvents_ExplorerSourceProcess ON ProcessEvents(Source, ProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_EvidenceRelations_ExplorerActiveDecision ON EvidenceRelations(DecisionKey, Status, UpdatedUtc DESC, RelationId DESC, CorrelationState);",
        "CREATE INDEX IF NOT EXISTS IX_Modules_ModuleName ON Modules(ModuleName);",
        "CREATE INDEX IF NOT EXISTS IX_Modules_FullPath ON Modules(FullPath);",
        "CREATE INDEX IF NOT EXISTS IX_Handles_ObjectType ON Handles(ObjectType);",
        "CREATE INDEX IF NOT EXISTS IX_Handles_ObjectName ON Handles(ObjectName);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryDumps_ProcessKey ON MemoryDumps(ProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryDumps_Status ON MemoryDumps(Status);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryDumps_RequestedUtc ON MemoryDumps(RequestedUtc);",
        "CREATE INDEX IF NOT EXISTS IX_PeAnalyses_SourceArtifact ON PeAnalyses(SourceKind, SourceArtifactId);",
        "CREATE INDEX IF NOT EXISTS IX_PeAnalyses_AnalyzedUtc ON PeAnalyses(AnalyzedUtc);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryImages_Status ON MemoryImages(Status);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryImages_ImportedUtc ON MemoryImages(ImportedUtc);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryImages_Sha256Hash ON MemoryImages(Sha256Hash);",
        "CREATE INDEX IF NOT EXISTS IX_VolatilityPluginRuns_ImageId ON VolatilityPluginRuns(ImageId);",
        "CREATE INDEX IF NOT EXISTS IX_VolatilityPluginRuns_Status ON VolatilityPluginRuns(Status);",
        "CREATE INDEX IF NOT EXISTS IX_VolatilityPluginRuns_PluginName ON VolatilityPluginRuns(PluginName);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryProcesses_ImageId ON MemoryProcesses(ImageId);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryProcesses_ProcessId ON MemoryProcesses(ProcessId);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryProcesses_ProcessKey ON MemoryProcesses(ProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryProcesses_CorrelationState ON MemoryProcesses(CorrelationState);",
        "CREATE INDEX IF NOT EXISTS IX_NetworkCaptures_Status ON NetworkCaptures(Status);",
        "CREATE INDEX IF NOT EXISTS IX_NetworkCaptures_RequestedUtc ON NetworkCaptures(RequestedUtc);",
        "CREATE INDEX IF NOT EXISTS IX_NetworkCaptures_JobId ON NetworkCaptures(JobId);",
        "CREATE INDEX IF NOT EXISTS IX_ZeekNetworkArtifacts_CaptureId ON ZeekNetworkArtifacts(CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_ZeekNetworkArtifacts_ProcessKey ON ZeekNetworkArtifacts(ProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_ZeekNetworkArtifacts_TimestampUtc ON ZeekNetworkArtifacts(TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IX_ZeekNetworkArtifacts_Endpoint ON ZeekNetworkArtifacts(DestinationIp, DestinationPort);",
        "CREATE INDEX IF NOT EXISTS IX_ZeekNetworkArtifacts_DnsQuery ON ZeekNetworkArtifacts(DnsQuery);",
        "CREATE INDEX IF NOT EXISTS IX_Artifacts_Type ON Artifacts(ArtifactType);",
        "CREATE INDEX IF NOT EXISTS IX_Artifacts_Path ON Artifacts(Path);",
        "CREATE INDEX IF NOT EXISTS IX_Artifacts_TimestampUtc ON Artifacts(TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IX_Bookmarks_ProcessKey ON Bookmarks(ProcessKey);",
        "CREATE INDEX IF NOT EXISTS IX_Bookmarks_Target ON Bookmarks(TargetKind, TargetId);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_CaseSessionCapture ON Processes(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_Processes_ExecutionRoot ON Processes(ExecutionRootId);",
        "CREATE INDEX IF NOT EXISTS IX_ProcessEvents_CaseSessionCapture ON ProcessEvents(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_Modules_CaseSessionCapture ON Modules(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_Handles_CaseSessionCapture ON Handles(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryDumps_CaseSessionCapture ON MemoryDumps(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_PeAnalyses_CaseSessionCapture ON PeAnalyses(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryImages_CaseSessionCapture ON MemoryImages(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_VolatilityPluginRuns_CaseSessionCapture ON VolatilityPluginRuns(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_MemoryProcesses_CaseSessionCapture ON MemoryProcesses(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_NetworkCaptures_CaseSessionCapture ON NetworkCaptures(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_ZeekNetworkArtifacts_CaseSessionCapture ON ZeekNetworkArtifacts(CaseId, EvidenceSessionId, CaptureId);",
        "CREATE INDEX IF NOT EXISTS IX_Artifacts_CaseSessionCapture ON Artifacts(CaseId, EvidenceSessionId, CaptureId);"
    ];

    private static readonly string[] SnapshotAnalysisIndexSql =
    [
        "CREATE INDEX IF NOT EXISTS IXA_Processes_IdentityStatusStart ON Processes(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId, Status, StartTimeUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Processes_IdentityUserStart ON Processes(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, UserName, StartTimeUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Processes_IdentityHashPath ON Processes(CaseId, EvidenceSessionId, CaptureId, Sha256Hash, ProcessPath);",
        "CREATE INDEX IF NOT EXISTS IXA_Processes_ParentIdentityStart ON Processes(ParentProcessKey, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId, StartTimeUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_ProcessEvents_ProcessSourceTime ON ProcessEvents(ProcessKey, Source, TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_ProcessEvents_IdentitySourceTime ON ProcessEvents(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId, Source, TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_ProcessEvents_ProviderEventTime ON ProcessEvents(RawProvider, RawLogName, EventCode, TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Modules_ProcessStateSeen ON Modules(ProcessKey, State, LastSeenUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Modules_IdentityPath ON Modules(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, FullPath);",
        "CREATE INDEX IF NOT EXISTS IXA_Modules_HashName ON Modules(Sha256Hash, ModuleName);",
        "CREATE INDEX IF NOT EXISTS IXA_Handles_ProcessStateSeen ON Handles(ProcessKey, State, LastSeenUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Handles_IdentityTypeName ON Handles(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, ObjectType, ObjectName);",
        "CREATE INDEX IF NOT EXISTS IXA_MemoryDumps_ProcessRequested ON MemoryDumps(ProcessKey, RequestedUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_PeAnalyses_ProcessKindTime ON PeAnalyses(ProcessKey, SourceKind, AnalyzedUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_NetworkCaptures_IdentityRequested ON NetworkCaptures(CaseId, EvidenceSessionId, SourceIdentityId, RequestedUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Zeek_CaptureTime ON ZeekNetworkArtifacts(CaptureId, TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Zeek_DnsTime ON ZeekNetworkArtifacts(DnsQuery, TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Zeek_ProcessTime ON ZeekNetworkArtifacts(ProcessKey, TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_Artifacts_IdentityTypePath ON Artifacts(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, ArtifactType, Path);",
        "CREATE INDEX IF NOT EXISTS IXA_Artifacts_ProcessTypeTime ON Artifacts(ProcessKey, ArtifactType, TimestampUtc);",
        "CREATE INDEX IF NOT EXISTS IXA_RawRecords_PayloadHash ON RawRecords(PayloadHash);",
        "CREATE INDEX IF NOT EXISTS IXA_ArtifactProperties_NameValue ON ArtifactProperties(Name, Value);"
    ];

    private static readonly string[] AnalysisIndexSql =
        SnapshotBrowsingIndexSql.Concat(SnapshotAnalysisIndexSql).ToArray();

    public static IReadOnlyList<SqliteAnalysisIndexGroup> AnalysisIndexGroups { get; } =
    [
        new("Capture compatibility", LiveIndexSql),
        new("Snapshot browsing", SnapshotBrowsingIndexSql),
        new("Forensic analysis", SnapshotAnalysisIndexSql)
    ];

    public static SqliteConnection OpenConnection(
        string databasePath,
        SqliteOpenMode mode,
        SqlitePerformanceProfileName profile = SqlitePerformanceProfileName.Conservative)
    {
        databasePath = Path.GetFullPath(databasePath);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = mode,
            Pooling = false
        }.ToString());
        connection.Open();
        Apply(connection, profile, mode);
        return connection;
    }

    public static void Apply(SqliteConnection connection, SqlitePerformanceProfileName profile, SqliteOpenMode mode)
    {
        Execute(connection, "PRAGMA busy_timeout=5000;");
        Execute(connection, "PRAGMA foreign_keys=ON;");
        if (mode != SqliteOpenMode.ReadOnly)
        {
            Execute(connection, "PRAGMA wal_autocheckpoint=0;");
        }

        switch (profile)
        {
            case SqlitePerformanceProfileName.HighMemoryRead:
                Execute(connection, "PRAGMA cache_size=-131072;");
                Execute(connection, "PRAGMA temp_store=MEMORY;");
                Execute(connection, "PRAGMA mmap_size=268435456;");
                break;
            case SqlitePerformanceProfileName.BrowserAnalysis:
                Execute(connection, "PRAGMA cache_size=-65536;");
                Execute(connection, "PRAGMA temp_store=MEMORY;");
                Execute(connection, "PRAGMA mmap_size=134217728;");
                break;
            default:
                Execute(connection, "PRAGMA cache_size=-8192;");
                Execute(connection, "PRAGMA temp_store=DEFAULT;");
                Execute(connection, "PRAGMA mmap_size=0;");
                break;
        }
    }

    public static void EnsureLiveIndexes(SqliteConnection connection)
        => ExecuteBatch(connection, LiveIndexSql);

    public static void EnsureAnalysisIndexes(SqliteConnection connection)
    {
        foreach (var group in AnalysisIndexGroups)
        {
            EnsureAnalysisIndexGroup(connection, group);
        }
    }

    public static void EnsureAnalysisIndexGroup(
        SqliteConnection connection,
        SqliteAnalysisIndexGroup group,
        CancellationToken cancellationToken = default)
    {
        var isSnapshotBrowsing = string.Equals(
            group.Name,
            "Snapshot browsing",
            StringComparison.Ordinal);
        if (isSnapshotBrowsing)
        {
            ExplorerCorrelationCountCache.Remove(connection.DataSource);
        }

        ExecuteBatch(connection, group.Statements, cancellationToken);
        if (isSnapshotBrowsing &&
            SchemaTableExists(connection, "EvidenceCorrelationInputs") &&
            SchemaTableExists(connection, "EvidenceRelations"))
        {
            ExplorerCorrelationCountCache.Rebuild(connection, cancellationToken);
        }
    }

    public static void DropNonLiveIndexes(SqliteConnection connection)
    {
        ExplorerCorrelationCountCache.Remove(connection.DataSource);
        var liveIndexNames = LiveIndexSql
            .Select(ExtractIndexName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var snapshotIndexNames = AnalysisIndexSql
            .Select(ExtractIndexName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var indexName in snapshotIndexNames)
        {
            if (liveIndexNames.Contains(indexName))
            {
                continue;
            }

            Execute(connection, $"DROP INDEX IF EXISTS {indexName};");
        }
    }

    public static void RecordIndexMigration(SqliteConnection connection, string migrationId, string description)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT OR IGNORE INTO SchemaMigrations(MigrationId, AppliedUtc, Description)
            VALUES($MigrationId, $AppliedUtc, $Description);
            """;
        command.Parameters.AddWithValue("$MigrationId", migrationId);
        command.Parameters.AddWithValue("$AppliedUtc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$Description", description);
        command.ExecuteNonQuery();
    }

    public static SqlitePerformanceStatus GetStatus(SqliteConnection connection, SqlitePerformanceProfileName profile)
    {
        var cacheSize = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA cache_size;"), CultureInfo.InvariantCulture);
        var tempStore = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA temp_store;"), CultureInfo.InvariantCulture);
        var mmapSize = Convert.ToInt64(ExecuteScalar(connection, "PRAGMA mmap_size;"), CultureInfo.InvariantCulture);
        var journalMode = Convert.ToString(ExecuteScalar(connection, "PRAGMA journal_mode;"), CultureInfo.InvariantCulture) ?? "unknown";
        var walAutoCheckpoint = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA wal_autocheckpoint;"), CultureInfo.InvariantCulture);
        var liveIndexCount = CountIndexes(connection, LiveIndexSql);
        var analysisIndexCount = CountIndexes(connection, AnalysisIndexSql);
        var summary = $"SQLite profile {profile}; cache_size {cacheSize}; temp_store {tempStore}; mmap {FormatBytes(mmapSize)}; wal_autocheckpoint {walAutoCheckpoint}; indexes capture {liveIndexCount}/{LiveIndexSql.Length}, snapshot {analysisIndexCount}/{AnalysisIndexSql.Length}.";
        return new SqlitePerformanceStatus(profile, cacheSize, tempStore, mmapSize, journalMode, walAutoCheckpoint, liveIndexCount, analysisIndexCount, summary);
    }

    public static AgentSqliteDatabaseDiagnostics GetDatabaseDiagnostics(
        SqliteConnection connection,
        SqlitePerformanceProfileName profile,
        string databasePath,
        string role)
    {
        databasePath = string.IsNullOrWhiteSpace(databasePath)
            ? TryGetMainDatabasePath(connection)
            : Path.GetFullPath(databasePath);

        try
        {
            var cacheSize = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA cache_size;"), CultureInfo.InvariantCulture);
            var tempStore = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA temp_store;"), CultureInfo.InvariantCulture);
            var mmapSize = Convert.ToInt64(ExecuteScalar(connection, "PRAGMA mmap_size;"), CultureInfo.InvariantCulture);
            var journalMode = Convert.ToString(ExecuteScalar(connection, "PRAGMA journal_mode;"), CultureInfo.InvariantCulture) ?? "unknown";
            var synchronous = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA synchronous;"), CultureInfo.InvariantCulture);
            var busyTimeout = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA busy_timeout;"), CultureInfo.InvariantCulture);
            var walAutoCheckpoint = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA wal_autocheckpoint;"), CultureInfo.InvariantCulture);
            var pageSize = Convert.ToInt32(ExecuteScalar(connection, "PRAGMA page_size;"), CultureInfo.InvariantCulture);
            var pageCount = Convert.ToInt64(ExecuteScalar(connection, "PRAGMA page_count;"), CultureInfo.InvariantCulture);
            var freelistCount = Convert.ToInt64(ExecuteScalar(connection, "PRAGMA freelist_count;"), CultureInfo.InvariantCulture);
            var liveIndexCount = CountIndexes(connection, LiveIndexSql);
            var analysisIndexCount = CountIndexes(connection, AnalysisIndexSql);
            var databaseSize = GetFileSize(databasePath);
            var walSize = GetFileSize($"{databasePath}-wal");
            var summary =
                $"SQLite {role}: profile {profile}, journal {journalMode}, synchronous {FormatSynchronous(synchronous)}, " +
                $"busy {busyTimeout} ms, wal_autocheckpoint {walAutoCheckpoint}, db {FormatBytes(databaseSize)}, wal {FormatBytes(walSize)}, " +
                $"indexes capture {liveIndexCount}/{LiveIndexSql.Length}, snapshot {analysisIndexCount}/{AnalysisIndexSql.Length}.";

            return new AgentSqliteDatabaseDiagnostics
            {
                CapturedAtUtc = DateTime.UtcNow,
                Role = role,
                DatabasePath = databasePath,
                DiagnosticsLogPath = SqliteDiagnosticsLogger.GetLogPath(databasePath),
                Profile = profile.ToString(),
                JournalMode = journalMode,
                SynchronousMode = FormatSynchronous(synchronous),
                BusyTimeoutMilliseconds = busyTimeout,
                WalAutoCheckpointPages = walAutoCheckpoint,
                CacheSizePages = cacheSize,
                TempStore = tempStore,
                MmapSizeBytes = mmapSize,
                DatabaseSizeBytes = databaseSize,
                WalSizeBytes = walSize,
                PageSizeBytes = pageSize,
                PageCount = pageCount,
                FreelistCount = freelistCount,
                LiveIndexCount = liveIndexCount,
                LiveIndexExpectedCount = LiveIndexSql.Length,
                AnalysisIndexCount = analysisIndexCount,
                AnalysisIndexExpectedCount = AnalysisIndexSql.Length,
                Summary = summary
            };
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new AgentSqliteDatabaseDiagnostics
            {
                CapturedAtUtc = DateTime.UtcNow,
                Role = role,
                DatabasePath = databasePath,
                DiagnosticsLogPath = SqliteDiagnosticsLogger.GetLogPath(databasePath),
                Profile = profile.ToString(),
                Error = ex.Message,
                Summary = $"SQLite {role}: diagnostics unavailable: {ex.Message}"
            };
        }
    }

    internal static AgentSqliteCheckpointDiagnostics RunWalCheckpoint(
        SqliteConnection connection,
        SqliteWalCheckpointMode mode)
    {
        var normalizedMode = mode switch
        {
            SqliteWalCheckpointMode.Passive => "PASSIVE",
            SqliteWalCheckpointMode.Truncate => "TRUNCATE",
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unsupported WAL checkpoint mode.")
        };

        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"PRAGMA wal_checkpoint({normalizedMode});";
            using var reader = command.ExecuteReader();
            var busy = 0;
            var log = 0;
            var checkpointed = 0;
            if (reader.Read())
            {
                busy = reader.IsDBNull(0) ? 0 : reader.GetInt32(0);
                log = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
                checkpointed = reader.IsDBNull(2) ? 0 : reader.GetInt32(2);
            }

            stopwatch.Stop();
            var summary = $"checkpoint {normalizedMode.ToLowerInvariant()}: busy {busy}, log {log}, checkpointed {checkpointed}, {stopwatch.Elapsed.TotalMilliseconds:F1} ms.";
            return new AgentSqliteCheckpointDiagnostics
            {
                CheckedAtUtc = DateTime.UtcNow,
                Mode = normalizedMode,
                Succeeded = true,
                BusyFrameCount = busy,
                LogFrameCount = log,
                CheckpointedFrameCount = checkpointed,
                DurationMilliseconds = stopwatch.Elapsed.TotalMilliseconds,
                Summary = summary
            };
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            stopwatch.Stop();
            return new AgentSqliteCheckpointDiagnostics
            {
                CheckedAtUtc = DateTime.UtcNow,
                Mode = normalizedMode,
                Succeeded = false,
                DurationMilliseconds = stopwatch.Elapsed.TotalMilliseconds,
                Error = ex.Message,
                Summary = $"checkpoint {normalizedMode.ToLowerInvariant()} failed after {stopwatch.Elapsed.TotalMilliseconds:F1} ms: {ex.Message}"
            };
        }
    }

    private static int CountIndexes(SqliteConnection connection, IReadOnlyList<string> indexSql)
    {
        var names = indexSql
            .Select(ExtractIndexName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .ToArray();
        if (names.Length == 0)
        {
            return 0;
        }

        using var command = connection.CreateCommand();
        var parameters = new List<string>(names.Length);
        for (var i = 0; i < names.Length; i++)
        {
            var parameterName = $"$IndexName{i}";
            parameters.Add(parameterName);
            command.Parameters.AddWithValue(parameterName, names[i]);
        }

        command.CommandText = $"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ({string.Join(", ", parameters)});";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string ExtractIndexName(string sql)
    {
        const string marker = "IF NOT EXISTS ";
        var start = sql.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return string.Empty;
        }

        start += marker.Length;
        var end = sql.IndexOf(' ', start);
        return end > start ? sql[start..end].Trim() : string.Empty;
    }

    private static void ExecuteBatch(
        SqliteConnection connection,
        IEnumerable<string> statements,
        CancellationToken cancellationToken = default)
    {
        foreach (var statement in statements)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Execute(connection, statement);
        }
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static object? ExecuteScalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static bool SchemaTableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $Name LIMIT 1;";
        command.Parameters.AddWithValue("$Name", tableName);
        return command.ExecuteScalar() != null;
    }

    private static string TryGetMainDatabasePath(SqliteConnection connection)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA database_list;";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var name = reader.GetString(1);
                if (string.Equals(name, "main", StringComparison.OrdinalIgnoreCase))
                {
                    return Path.GetFullPath(reader.GetString(2));
                }
            }
        }
        catch (Exception)
        {
        }

        return string.Empty;
    }

    private static long GetFileSize(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return 0;
        }

        try
        {
            return File.Exists(path) ? new FileInfo(path).Length : 0;
        }
        catch (Exception)
        {
            return 0;
        }
    }

    private static string FormatSynchronous(int synchronous)
    {
        return synchronous switch
        {
            0 => "OFF",
            1 => "NORMAL",
            2 => "FULL",
            3 => "EXTRA",
            _ => synchronous.ToString(CultureInfo.InvariantCulture)
        };
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:F1} {units[unit]}";
    }
}
