using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Analysis;
using ProcInsider.Models.Infrastructure;

namespace ProcInsider.Services;

public enum SqliteAnalysisIndexBuildStageState
{
    Started,
    Completed
}

public sealed record SqliteAnalysisIndexBuildProgress(
    int CompletedGroups,
    int TotalGroups,
    string GroupName,
    bool IsSearchIndex,
    SqliteAnalysisIndexBuildStageState StageState = SqliteAnalysisIndexBuildStageState.Completed,
    double StageElapsedMilliseconds = 0,
    long StageAllocatedBytes = 0,
    double TotalElapsedMilliseconds = 0,
    long TotalAllocatedBytes = 0);

public sealed class SqliteStagingStore : IDisposable
{
    private const string AuthoritativeLiveDatabaseFileName = "procinsider-live.sqlite3";
    private readonly object _lock = new();
    private readonly string _databasePath;
    private readonly string _expectedEvidenceSessionId;
    private readonly ProcessEvidenceWriteService _processEvidenceWriter;
    private readonly EventEvidenceWriteService _eventEvidenceWriter;
    private readonly ModuleHandleEvidenceWriteService _moduleHandleEvidenceWriter;
    private readonly DumpPeEvidenceWriteService _dumpPeEvidenceWriter;
    private readonly NetworkEvidenceWriteService _networkEvidenceWriter;
    private readonly FilesystemEvidenceWriteService _filesystemEvidenceWriter;
    private readonly SystemMemoryEvidenceWriteService _systemMemoryEvidenceWriter;
    private readonly YaraAnalysisPersistenceService _yaraAnalysisPersistence;
    private readonly ReputationAttributionPersistenceService _reputationAttributionPersistence;
    private ISqliteAnalysisIndexMaintenanceService _analysisIndexMaintenance;
    private ISqliteProcessRiskProjectionMaintenanceService _processRiskProjectionMaintenance;
    private SqliteConnection? _connection;
    private SqliteTransaction? _activeTransaction;
    private Guid _infrastructureOutboxOwnerId;
    private Guid _infrastructureOutboxWriterInstanceId;
    private Guid _activeInfrastructureOutboxOwnerId;
    private EvidenceIdentity? _defaultEvidenceIdentity;
    private CaptureOpenContext? _openContext;
    private CaptureArtifactKind _artifactKind = CaptureArtifactKind.Unknown;

    public SqliteStagingStore(string databasePath, string expectedEvidenceSessionId = "")
    {
        _databasePath = databasePath;
        _expectedEvidenceSessionId = expectedEvidenceSessionId?.Trim() ?? string.Empty;
        _analysisIndexMaintenance = new UnavailableSqliteAnalysisIndexMaintenanceService();
        _processRiskProjectionMaintenance = new UnavailableSqliteProcessRiskProjectionMaintenanceService();
        var writeContext = new SqliteWriteTransactionContext(this);
        _processEvidenceWriter = new ProcessEvidenceWriteService(writeContext);
        _eventEvidenceWriter = new EventEvidenceWriteService(writeContext);
        _moduleHandleEvidenceWriter = new ModuleHandleEvidenceWriteService(writeContext);
        _dumpPeEvidenceWriter = new DumpPeEvidenceWriteService(writeContext);
        _networkEvidenceWriter = new NetworkEvidenceWriteService(writeContext);
        _filesystemEvidenceWriter = new FilesystemEvidenceWriteService(writeContext);
        _systemMemoryEvidenceWriter = new SystemMemoryEvidenceWriteService(writeContext);
        _yaraAnalysisPersistence = new YaraAnalysisPersistenceService(writeContext);
        _reputationAttributionPersistence =
            new ReputationAttributionPersistenceService(writeContext);
    }

    public string DatabasePath => _databasePath;

    public void EnableInfrastructureEvidenceOutbox(Guid ownerId, Guid writerInstanceId)
    {
        if (ownerId == Guid.Empty || writerInstanceId == Guid.Empty)
        {
            throw new ArgumentException("Exact outbox-owner and writer identities are required.");
        }

        lock (_lock)
        {
            EnsureOpenRole(CaptureOpenContext.AgentWritableLive, CaptureArtifactKind.LiveAuthoritativeDatabase);
            if (!HasSchemaMigration("032_infrastructure_evidence_outbox") ||
                !TableExists(Connection, "InfrastructureEvidenceOutbox"))
            {
                throw new InvalidOperationException("The transactional evidence outbox migration is unavailable.");
            }

            if (_infrastructureOutboxOwnerId != Guid.Empty &&
                (_infrastructureOutboxOwnerId != ownerId ||
                 _infrastructureOutboxWriterInstanceId != writerInstanceId))
            {
                throw new InvalidOperationException("A different transactional evidence outbox owner is already active.");
            }

            _infrastructureOutboxOwnerId = ownerId;
            _infrastructureOutboxWriterInstanceId = writerInstanceId;
        }
    }

    public InfrastructureEvidenceOutboxEntry? ExecuteAgentWriterTransaction(
        Guid ownerId,
        InfrastructureEvidenceOutboxCommit? outboxCommit,
        Action<SqliteStagingStore> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (_lock)
        {
            EnsureOpenRole(CaptureOpenContext.AgentWritableLive, CaptureArtifactKind.LiveAuthoritativeDatabase);
            if (_activeTransaction != null)
            {
                throw new InvalidOperationException("An Agent writer transaction cannot nest another outer transaction.");
            }
            if (_infrastructureOutboxOwnerId == Guid.Empty || ownerId != _infrastructureOutboxOwnerId)
            {
                throw new InvalidOperationException("The transactional evidence outbox owner is unavailable or stale.");
            }
            if (outboxCommit != null)
            {
                ValidateOutboxCommit(outboxCommit);
                if (outboxCommit.WriterInstanceId != _infrastructureOutboxWriterInstanceId)
                {
                    throw new InvalidDataException("The outbox commit belongs to a different serialized writer.");
                }
            }

            using var transaction = Connection.BeginTransaction();
            _activeTransaction = transaction;
            _activeInfrastructureOutboxOwnerId = ownerId;
            try
            {
                action(this);
                var entry = outboxCommit == null ? null : InsertInfrastructureOutbox(outboxCommit);
                transaction.Commit();
                return entry;
            }
            finally
            {
                _activeInfrastructureOutboxOwnerId = Guid.Empty;
                _activeTransaction = null;
            }
        }
    }

    public IReadOnlyList<InfrastructureEvidenceOutboxEntry> ListInfrastructureEvidenceOutbox(
        InfrastructureEvidenceOutboxState state,
        int maxCount = InfrastructureEvidenceOutboxPolicy.MaxPageSize)
    {
        maxCount = InfrastructureEvidenceOutboxPolicy.NormalizePageSize(maxCount);
        lock (_lock)
        {
            EnsureInfrastructureOutboxReadable();
            using var command = CreateCommand("""
                SELECT Sequence, SchemaVersion, OutboxId, WriterInstanceId, WriterCommitGeneration,
                       OperationName, ApproximateRowCount, CommittedAtUtc, State, BatchId,
                       ManifestSha256, PackageSha256, AcknowledgementOutcome, ServerCommitId,
                       ServerReceiptTimeUtc, StateChangedAtUtc, RetryCount, LastErrorCode
                FROM InfrastructureEvidenceOutbox
                WHERE State = $State
                ORDER BY Sequence
                LIMIT $MaxCount;
                """);
            Add(command, "$State", state.ToString());
            Add(command, "$MaxCount", maxCount);
            using var reader = command.ExecuteReader();
            var entries = new List<InfrastructureEvidenceOutboxEntry>();
            while (reader.Read())
            {
                entries.Add(ReadInfrastructureOutbox(reader));
            }
            return entries;
        }
    }

    public InfrastructureEvidenceOutboxEntry? GetInfrastructureEvidenceOutboxByBatchId(string batchId)
    {
        if (!InfrastructureEvidenceBatchCodec.IsIdentifier(batchId))
        {
            throw new InvalidDataException("The evidence outbox batch identity is invalid.");
        }

        lock (_lock)
        {
            EnsureInfrastructureOutboxReadable();
            using var command = CreateCommand("""
                SELECT Sequence, SchemaVersion, OutboxId, WriterInstanceId, WriterCommitGeneration,
                       OperationName, ApproximateRowCount, CommittedAtUtc, State, BatchId,
                       ManifestSha256, PackageSha256, AcknowledgementOutcome, ServerCommitId,
                       ServerReceiptTimeUtc, StateChangedAtUtc, RetryCount, LastErrorCode
                FROM InfrastructureEvidenceOutbox
                WHERE BatchId = $BatchId
                LIMIT 2;
                """);
            Add(command, "$BatchId", batchId);
            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }
            var entry = ReadInfrastructureOutbox(reader);
            if (reader.Read())
            {
                throw new InvalidDataException("More than one outbox row claims the evidence batch identity.");
            }
            return entry;
        }
    }

    public bool CanCheckpointAuthoritativeLiveDatabase
    {
        get
        {
            lock (_lock)
            {
                return _openContext == CaptureOpenContext.AgentWritableLive &&
                       _artifactKind == CaptureArtifactKind.LiveAuthoritativeDatabase;
            }
        }
    }

    internal IProcessEvidenceWriteService ProcessEvidenceWriter => _processEvidenceWriter;

    internal IEventEvidenceWriteService EventEvidenceWriter => _eventEvidenceWriter;

    internal IModuleHandleEvidenceWriteService ModuleHandleEvidenceWriter => _moduleHandleEvidenceWriter;

    internal IDumpPeEvidenceWriteService DumpPeEvidenceWriter => _dumpPeEvidenceWriter;

    internal INetworkEvidenceWriteService NetworkEvidenceWriter => _networkEvidenceWriter;

    internal IFilesystemEvidenceWriteService FilesystemEvidenceWriter => _filesystemEvidenceWriter;

    internal ISystemMemoryEvidenceWriteService SystemMemoryEvidenceWriter => _systemMemoryEvidenceWriter;

    internal ISqliteAnalysisIndexMaintenanceService AnalysisIndexMaintenance => _analysisIndexMaintenance;

    internal ISqliteProcessRiskProjectionMaintenanceService ProcessRiskProjectionMaintenance =>
        _processRiskProjectionMaintenance;

    internal void AttachAnalysisIndexMaintenance(ISqliteAnalysisIndexMaintenanceService maintenance)
    {
        ArgumentNullException.ThrowIfNull(maintenance);
        lock (_lock)
        {
            if (_analysisIndexMaintenance is not UnavailableSqliteAnalysisIndexMaintenanceService)
            {
                throw new InvalidOperationException(
                    "Analysis-index maintenance is already attached to this SQLite store.");
            }

            _analysisIndexMaintenance = maintenance;
        }
    }

    internal void AttachProcessRiskProjectionMaintenance(
        ISqliteProcessRiskProjectionMaintenanceService maintenance)
    {
        ArgumentNullException.ThrowIfNull(maintenance);
        lock (_lock)
        {
            if (_processRiskProjectionMaintenance is not UnavailableSqliteProcessRiskProjectionMaintenanceService)
            {
                throw new InvalidOperationException(
                    "Process-risk projection maintenance is already attached to this SQLite store.");
            }

            _processRiskProjectionMaintenance = maintenance;
        }
    }

    public static CaptureCompatibilityAssessment ValidateExistingDatabase(
        string databasePath,
        CaptureOpenContext context = CaptureOpenContext.ViewerArchivedReadOnly,
        CaptureManifestCompatibilityMetadata? manifest = null,
        string expectedEvidenceSessionId = "")
    {
        var assessment = AssessExistingDatabase(
            databasePath,
            context,
            manifest,
            expectedEvidenceSessionId);
        if (context == CaptureOpenContext.AgentWritableLive)
        {
            if (!assessment.Allows(CaptureOpenCapability.WritePrimaryEvidence) &&
                !assessment.Allows(CaptureOpenCapability.MigratePrimaryEvidence))
            {
                CaptureCompatibilityPolicy.EnsureAllowed(
                    assessment,
                    CaptureOpenCapability.WritePrimaryEvidence);
            }

            return assessment;
        }

        var requiredCapability = context switch
        {
            CaptureOpenContext.ViewerLiveSourceReadOnly => CaptureOpenCapability.ReadEvidence,
            CaptureOpenContext.ViewerLiveSnapshot => CaptureOpenCapability.ReadEvidence,
            CaptureOpenContext.ViewerArchivedReadOnly => CaptureOpenCapability.ReadEvidence,
            CaptureOpenContext.ArchivedAnalysisMaintenance => CaptureOpenCapability.MaintainAnalysisState,
            _ => CaptureOpenCapability.InspectMetadata
        };
        CaptureCompatibilityPolicy.EnsureAllowed(assessment, requiredCapability);
        return assessment;
    }

    public static CaptureCompatibilityAssessment AssessExistingDatabase(
        string databasePath,
        CaptureOpenContext context,
        CaptureManifestCompatibilityMetadata? manifest = null,
        string expectedEvidenceSessionId = "",
        CaptureArtifactKind? artifactKind = null)
        => AssessExistingDatabaseCore(
            databasePath,
            context,
            manifest,
            expectedEvidenceSessionId,
            artifactKind,
            preserveTransientSqliteFailure: false);

    internal static CaptureCompatibilityAssessment AssessExistingDatabaseForLiveSnapshot(
        string databasePath,
        CaptureManifestCompatibilityMetadata? manifest,
        string expectedEvidenceSessionId)
        => AssessExistingDatabaseCore(
            databasePath,
            CaptureOpenContext.ViewerLiveSourceReadOnly,
            manifest,
            expectedEvidenceSessionId,
            CaptureArtifactKind.LiveAuthoritativeDatabase,
            preserveTransientSqliteFailure: true);

    private static CaptureCompatibilityAssessment AssessExistingDatabaseCore(
        string databasePath,
        CaptureOpenContext context,
        CaptureManifestCompatibilityMetadata? manifest,
        string expectedEvidenceSessionId,
        CaptureArtifactKind? artifactKind,
        bool preserveTransientSqliteFailure)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            throw new ArgumentException("SQLite database path is required.", nameof(databasePath));
        }

        databasePath = Path.GetFullPath(databasePath);
        if (!File.Exists(databasePath))
        {
            throw new FileNotFoundException("The SQLite staging database does not exist.", databasePath);
        }

        try
        {
            using var connection = SqlitePerformanceProfile.OpenConnection(
                databasePath,
                SqliteOpenMode.ReadOnly,
                SqlitePerformanceProfileName.Conservative);
            var requiredTables = new[]
            {
                "SchemaInfo",
                "SchemaMigrations",
                "Processes",
                "ProcessEvents",
                "Modules",
                "Handles",
                "Sources"
            };
            var hasRequiredSchema = requiredTables.All(tableName => TableExists(connection, tableName));
            var formatText = TableExists(connection, "SchemaInfo")
                ? ReadSchemaInfo(connection, "EvidenceFormatVersion") ??
                  ReadSchemaInfo(connection, "SchemaVersion")
                : null;
            int? formatVersion = null;
            if (!string.IsNullOrWhiteSpace(formatText))
            {
                formatVersion = int.TryParse(
                    formatText,
                    System.Globalization.NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out var parsed)
                    ? parsed
                    : 0;
            }

            var evidenceSessionId = TableExists(connection, "SchemaInfo")
                ? ReadSchemaInfo(connection, "EvidenceSessionId") ?? string.Empty
                : string.Empty;
            var migrations = ReadAppliedMigrations(connection);
            return CaptureCompatibilityPolicy.Assess(new CaptureCompatibilityInput
            {
                Context = context,
                ArtifactKind = artifactKind ?? GetArtifactKind(context),
                Manifest = manifest,
                Evidence = new CaptureEvidenceCompatibilityMetadata(
                    formatVersion,
                    evidenceSessionId,
                    hasRequiredSchema,
                    migrations),
                ExpectedEvidenceSessionId = expectedEvidenceSessionId?.Trim() ?? string.Empty
            });
        }
        catch (SqliteException ex) when (
            preserveTransientSqliteFailure &&
            ex.SqliteErrorCode is 5 or 6)
        {
            throw;
        }
        catch (Exception ex) when (ex is SqliteException or InvalidDataException or IOException)
        {
            return CaptureCompatibilityPolicy.Assess(new CaptureCompatibilityInput
            {
                Context = context,
                ArtifactKind = artifactKind ?? GetArtifactKind(context),
                Manifest = manifest,
                ExpectedEvidenceSessionId = expectedEvidenceSessionId?.Trim() ?? string.Empty,
                InspectionFailure = ex.Message
            });
        }
    }

    internal static IReadOnlyList<AppliedCaptureMigration> ReadAppliedMigrations(string databasePath)
    {
        using var connection = SqlitePerformanceProfile.OpenConnection(
            databasePath,
            SqliteOpenMode.ReadOnly,
            SqlitePerformanceProfileName.Conservative);
        return ReadAppliedMigrations(connection);
    }

    internal static bool MigrationLedgerUpgradeRequired(string databasePath)
    {
        using var connection = SqlitePerformanceProfile.OpenConnection(
            databasePath,
            SqliteOpenMode.ReadOnly,
            SqlitePerformanceProfileName.Conservative);
        if (!TableExists(connection, "SchemaMigrations"))
        {
            return true;
        }

        return new[]
        {
            "Sequence", "DefinitionHash", "SourceEvidenceFormatVersion",
            "TargetEvidenceFormatVersion", "MigrationKind", "AppliedByRelease",
            "ExclusiveOwnershipRequired", "ResultCode"
        }.Any(columnName => !ColumnExists(connection, "SchemaMigrations", columnName));
    }

    private static IReadOnlyList<AppliedCaptureMigration> ReadAppliedMigrations(SqliteConnection connection)
    {
        if (!TableExists(connection, "SchemaMigrations"))
        {
            return Array.Empty<AppliedCaptureMigration>();
        }

        var hasSequence = ColumnExists(connection, "SchemaMigrations", "Sequence");
        var hasDefinitionHash = ColumnExists(connection, "SchemaMigrations", "DefinitionHash");
        var hasAppliedByRelease = ColumnExists(connection, "SchemaMigrations", "AppliedByRelease");
        var migrations = new List<AppliedCaptureMigration>();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT MigrationId,
                   Description,
                   {(hasDefinitionHash ? "COALESCE(DefinitionHash, '')" : "''")},
                   {(hasSequence ? "Sequence" : "NULL")},
                   AppliedUtc,
                   rowid,
                   {(hasAppliedByRelease ? "COALESCE(AppliedByRelease, '')" : "''")}
            FROM SchemaMigrations
            ORDER BY rowid;
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            migrations.Add(new AppliedCaptureMigration(
                reader.IsDBNull(0) ? string.Empty : reader.GetString(0),
                reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetInt32(3),
                reader.IsDBNull(4) || !DateTime.TryParse(
                    reader.GetString(4),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind,
                    out var appliedUtc)
                    ? null
                    : appliedUtc,
                reader.IsDBNull(5) ? 0 : reader.GetInt64(5),
                reader.IsDBNull(6) ? string.Empty : reader.GetString(6)));
        }

        return migrations;
    }

    public void Initialize()
    {
        lock (_lock)
        {
            var isFresh = !File.Exists(_databasePath) || new FileInfo(_databasePath).Length == 0;
            if (!isFresh)
            {
                var existingAssessment = AssessExistingDatabase(
                    _databasePath,
                    CaptureOpenContext.AgentWritableLive,
                    expectedEvidenceSessionId: _expectedEvidenceSessionId);
                CaptureCompatibilityPolicy.EnsureAllowed(
                    existingAssessment,
                    CaptureOpenCapability.WritePrimaryEvidence);
            }

            OpenForAgentOwnedMigration();
            if (isFresh)
            {
                foreach (var step in SqliteEvidenceMigrationCatalog.Steps.Where(
                             step => step.Definition.Kind == CaptureMigrationKind.PrimaryEvidence ||
                                     !string.Equals(
                                         step.Definition.MigrationId,
                                         SqlitePerformanceProfile.AnalysisIndexMigrationId,
                                         StringComparison.Ordinal)))
                {
                    ExecuteCatalogMigrationStep(
                        step,
                        typeof(SqliteStagingStore).Assembly.GetName().Version?.ToString() ?? "development-bootstrap",
                        CancellationToken.None);
                }

                FinalizeAgentOwnedDatabaseOpen();
            }
            else
            {
                _defaultEvidenceIdentity = LoadDefaultEvidenceIdentity();
            }

            var assessment = AssessExistingDatabase(
                _databasePath,
                CaptureOpenContext.AgentWritableLive,
                expectedEvidenceSessionId: _expectedEvidenceSessionId);
            CaptureCompatibilityPolicy.EnsureAllowed(
                assessment,
                CaptureOpenCapability.WritePrimaryEvidence);
        }
    }

    internal void OpenForAgentOwnedMigration()
    {
        lock (_lock)
        {
            if (_connection != null)
            {
                EnsureOpenRole(
                    CaptureOpenContext.AgentWritableLive,
                    CaptureArtifactKind.LiveAuthoritativeDatabase);
                return;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(_databasePath) ?? AppContext.BaseDirectory);
            _connection = SqlitePerformanceProfile.OpenConnection(
                _databasePath,
                SqliteOpenMode.ReadWriteCreate,
                SqlitePerformanceProfileName.Conservative);
            _analysisIndexMaintenance.Disable();
            ExecuteNonQuery("PRAGMA journal_mode=WAL;");
            ExecuteNonQuery("PRAGMA synchronous=NORMAL;");
            SetOpenRole(
                CaptureOpenContext.AgentWritableLive,
                CaptureArtifactKind.LiveAuthoritativeDatabase);
        }
    }

    internal void OpenCurrentAgentOwnedDatabase()
    {
        lock (_lock)
        {
            OpenForAgentOwnedMigration();
            _defaultEvidenceIdentity = LoadDefaultEvidenceIdentity();
        }
    }

    internal void FinalizeAgentOwnedDatabaseOpen()
    {
        lock (_lock)
        {
            SqlitePerformanceProfile.EnsureLiveIndexes(Connection);
            SqlitePerformanceProfile.DropNonLiveIndexes(Connection);
            UpsertSchemaInfo(
                "ApplicationVersion",
                typeof(SqliteStagingStore).Assembly.GetName().Version?.ToString() ?? "unknown");
            UpsertSchemaInfo("LastOpenedUtc", FormatDate(DateTime.UtcNow));
            UpsertSchemaInfo("DefaultSqlitePerformanceProfile", SqlitePerformanceProfileName.Conservative.ToString());
            UpsertSchemaInfo("SearchIndexMaintenance", "Deferred");
            UpsertDefaultIdentitySchemaInfo();
            _defaultEvidenceIdentity = LoadDefaultEvidenceIdentity();
        }
    }

    internal void ExecuteCatalogMigrationStep(
        SqliteEvidenceMigrationStep step,
        string appliedByRelease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(step);
        lock (_lock)
        {
            if (_activeTransaction != null)
            {
                throw new InvalidOperationException("A catalogued migration cannot start inside another SQLite transaction.");
            }

            using var transaction = Connection.BeginTransaction();
            _activeTransaction = transaction;
            try
            {
                var context = new SqliteEvidenceMigrationExecutionContext(this, cancellationToken);
                step.Execute(context);
                EnsureMigrationLedgerSchema();
                RecordSchemaMigration(step.Definition, appliedByRelease);
                cancellationToken.ThrowIfCancellationRequested();
                transaction.Commit();
            }
            finally
            {
                _activeTransaction = null;
            }
        }
    }

    internal void UpgradeMigrationLedger(string appliedByRelease)
    {
        ExecuteInWriteTransaction(() =>
        {
            EnsureMigrationLedgerSchema();
            foreach (var definition in CaptureCompatibilityPolicy.Migrations)
            {
                using var command = CreateCommand("""
                    UPDATE SchemaMigrations
                    SET Sequence = COALESCE(Sequence, $Sequence),
                        DefinitionHash = COALESCE(NULLIF(DefinitionHash, ''), $DefinitionHash),
                        SourceEvidenceFormatVersion = COALESCE(SourceEvidenceFormatVersion, $SourceEvidenceFormatVersion),
                        TargetEvidenceFormatVersion = COALESCE(TargetEvidenceFormatVersion, $TargetEvidenceFormatVersion),
                        MigrationKind = COALESCE(NULLIF(MigrationKind, ''), $MigrationKind),
                        AppliedByRelease = COALESCE(NULLIF(AppliedByRelease, ''), $LegacyRelease),
                        ExclusiveOwnershipRequired = COALESCE(ExclusiveOwnershipRequired, $ExclusiveOwnershipRequired),
                        ResultCode = COALESCE(NULLIF(ResultCode, ''), 'migration.completed')
                    WHERE MigrationId = $MigrationId;
                    """);
                Add(command, "$Sequence", definition.Sequence);
                Add(command, "$DefinitionHash", definition.DefinitionHash);
                Add(command, "$SourceEvidenceFormatVersion", definition.SourceEvidenceFormatVersion);
                Add(command, "$TargetEvidenceFormatVersion", definition.TargetEvidenceFormatVersion);
                Add(command, "$MigrationKind", definition.Kind.ToString());
                Add(command, "$LegacyRelease", string.IsNullOrWhiteSpace(appliedByRelease)
                    ? "legacy-unrecorded"
                    : $"legacy-before-{appliedByRelease}");
                Add(command, "$ExclusiveOwnershipRequired", definition.RequiresExclusiveLiveDatabaseOwnership ? 1 : 0);
                Add(command, "$MigrationId", definition.MigrationId);
                command.ExecuteNonQuery();
            }
        });
    }

    private void ApplyRebuildableCatalogMigrationIfNeeded(string migrationId)
    {
        if (HasSchemaMigration(migrationId))
        {
            return;
        }

        var step = SqliteEvidenceMigrationCatalog.GetStep(migrationId);
        if (step.Definition.Kind != CaptureMigrationKind.RebuildableAnalysisState)
        {
            throw new InvalidOperationException(
                $"Archived analysis maintenance cannot execute primary migration {migrationId}.");
        }

        var appliedIds = ReadAppliedMigrations(Connection)
            .Select(migration => migration.MigrationId)
            .ToHashSet(StringComparer.Ordinal);
        var missingPrerequisites = step.Definition.PrerequisiteMigrationIds
            .Where(prerequisiteId => !appliedIds.Contains(prerequisiteId))
            .ToArray();
        if (missingPrerequisites.Length > 0)
        {
            throw new InvalidDataException(
                $"migration.analysis.prerequisite-missing: {migrationId} requires " +
                $"{string.Join(", ", missingPrerequisites)}.");
        }

        ExecuteCatalogMigrationStep(
            step,
            "archived-analysis-maintenance",
            CancellationToken.None);
    }

    public void OpenExistingForViewerSnapshot()
    {
        OpenExistingForAnalysisMaintenance("SnapshotDb", "Snapshot");
        lock (_lock)
        {
            ApplySupportedRebuildableAnalysisMigrations();
        }
    }

    public void OpenExistingForArchivedAnalysisMaintenance()
    {
        OpenExistingForAnalysisMaintenance("ArchivedDirectDb", "ArchivedDirect");
        lock (_lock)
        {
            if (TableExists(Connection, "EvidenceRelations"))
            {
                ApplyRebuildableCatalogMigrationIfNeeded("021_evidence_recorrelation");
            }

            ApplySupportedRebuildableAnalysisMigrations();
        }
    }

    private void ApplySupportedRebuildableAnalysisMigrations()
    {
        if (HasSchemaMigration("025_authenticode_verification"))
        {
            ApplyRebuildableCatalogMigrationIfNeeded("026_process_risk_projection");
        }

        if (HasSchemaMigration("026_process_risk_projection"))
        {
            ApplyRebuildableCatalogMigrationIfNeeded("027_sigma_risk_inputs");
        }

        if (HasSchemaMigration("027_sigma_risk_inputs"))
        {
            ApplyRebuildableCatalogMigrationIfNeeded("028_baseline_risk_inputs");
        }

        if (HasSchemaMigration("028_baseline_risk_inputs"))
        {
            ApplyRebuildableCatalogMigrationIfNeeded("029_yara_analysis_results");
        }

        if (HasSchemaMigration("029_yara_analysis_results"))
        {
            ApplyRebuildableCatalogMigrationIfNeeded("030_yara_risk_inputs");
        }

        if (HasSchemaMigration("030_yara_risk_inputs"))
        {
            ApplyRebuildableCatalogMigrationIfNeeded("031_reputation_attributions");
        }
    }

    private void OpenExistingForAnalysisMaintenance(string databaseRole, string maintenanceMode)
    {
        lock (_lock)
        {
            var context = string.Equals(databaseRole, "ArchivedDirectDb", StringComparison.Ordinal)
                ? CaptureOpenContext.ArchivedAnalysisMaintenance
                : CaptureOpenContext.ViewerLiveSnapshot;
            ValidateExistingDatabase(
                _databasePath,
                context,
                expectedEvidenceSessionId: _expectedEvidenceSessionId);
            _connection = SqlitePerformanceProfile.OpenConnection(
                _databasePath,
                SqliteOpenMode.ReadWrite,
                SqlitePerformanceProfileName.HighMemoryRead);
            _analysisIndexMaintenance.Enable(databaseRole, maintenanceMode);
            ExecuteNonQuery("PRAGMA journal_mode=WAL;");
            ExecuteNonQuery("PRAGMA synchronous=NORMAL;");
            _defaultEvidenceIdentity = LoadDefaultEvidenceIdentity();
            SetOpenRole(context, GetArtifactKind(context));
        }
    }

    private static string? ReadSchemaInfo(SqliteConnection connection, string key)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Value FROM SchemaInfo WHERE Key = $Key LIMIT 1;";
        command.Parameters.AddWithValue("$Key", key);
        return Convert.ToString(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static CaptureArtifactKind GetArtifactKind(CaptureOpenContext context)
        => context switch
        {
            CaptureOpenContext.AgentWritableLive or CaptureOpenContext.ViewerLiveSourceReadOnly =>
                CaptureArtifactKind.LiveAuthoritativeDatabase,
            CaptureOpenContext.ViewerLiveSnapshot => CaptureArtifactKind.ViewerSnapshotCopy,
            CaptureOpenContext.ViewerArchivedReadOnly or CaptureOpenContext.ArchivedAnalysisMaintenance =>
                CaptureArtifactKind.ArchivedSealedPackage,
            _ => CaptureArtifactKind.Unknown
        };

    public SqlitePerformanceStatus GetPerformanceStatus(SqlitePerformanceProfileName profile = SqlitePerformanceProfileName.Conservative)
    {
        lock (_lock)
        {
            return SqlitePerformanceProfile.GetStatus(Connection, profile);
        }
    }

    public AgentSqliteDatabaseDiagnostics GetDatabaseDiagnostics(
        SqlitePerformanceProfileName profile = SqlitePerformanceProfileName.Conservative,
        string role = "LiveDb")
    {
        lock (_lock)
        {
            return SqlitePerformanceProfile.GetDatabaseDiagnostics(Connection, profile, _databasePath, role);
        }
    }

    public AgentSqliteCheckpointDiagnostics CheckpointAuthoritativeLiveWalFromAgentWriter()
    {
        lock (_lock)
        {
            EnsureOpenRole(
                CaptureOpenContext.AgentWritableLive,
                CaptureArtifactKind.LiveAuthoritativeDatabase);
            return SqlitePerformanceProfile.RunWalCheckpoint(
                Connection,
                SqliteWalCheckpointMode.Passive);
        }
    }

    public AgentSqliteCheckpointDiagnostics CheckpointViewerSnapshotWalForReplacement(
        string authoritativeLiveDatabasePath)
    {
        if (string.IsNullOrWhiteSpace(authoritativeLiveDatabasePath))
        {
            throw new ArgumentException(
                "The authoritative live database path is required for snapshot checkpoint fencing.",
                nameof(authoritativeLiveDatabasePath));
        }

        lock (_lock)
        {
            EnsureOpenRole(
                CaptureOpenContext.ViewerLiveSnapshot,
                CaptureArtifactKind.ViewerSnapshotCopy);
            var livePath = Path.GetFullPath(authoritativeLiveDatabasePath);
            if (string.Equals(Path.GetFullPath(_databasePath), livePath, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    Path.GetFileName(_databasePath),
                    AuthoritativeLiveDatabaseFileName,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "A viewer snapshot checkpoint cannot target the authoritative live evidence database.");
            }

            return SqlitePerformanceProfile.RunWalCheckpoint(
                Connection,
                SqliteWalCheckpointMode.Truncate);
        }
    }

    private void SetOpenRole(CaptureOpenContext context, CaptureArtifactKind artifactKind)
    {
        if (_openContext.HasValue &&
            (_openContext.Value != context || _artifactKind != artifactKind))
        {
            throw new InvalidOperationException(
                $"SQLite store role is already {_openContext.Value}/{_artifactKind} and cannot become {context}/{artifactKind}.");
        }

        _openContext = context;
        _artifactKind = artifactKind;
    }

    private void EnsureOpenRole(CaptureOpenContext context, CaptureArtifactKind artifactKind)
    {
        if (_openContext != context || _artifactKind != artifactKind)
        {
            throw new InvalidOperationException(
                $"SQLite checkpoint rejected for store role {_openContext?.ToString() ?? "Unopened"}/{_artifactKind}; " +
                $"required role is {context}/{artifactKind}.");
        }
    }

    public void EnsureAnalysisIndexes()
        => EnsureAnalysisIndexes(progress: null, CancellationToken.None);

    public void EnsureAnalysisIndexes(
        IProgress<SqliteAnalysisIndexBuildProgress>? progress,
        CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            _analysisIndexMaintenance.EnsureAnalysisIndexes(progress, cancellationToken);
        }
    }

    public ProcessRiskProjectionRebuildResult RebuildProcessRiskProjections(
        IProgress<ProcessRiskProjectionRebuildProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            return _processRiskProjectionMaintenance.Rebuild(progress, cancellationToken);
        }
    }

    public ProcessRiskProjectionRebuildResult ReplaceSigmaRiskEvidenceAndRebuild(
        IReadOnlyList<LocalProcessSigmaEvidence> evidence,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        lock (_lock)
        {
            return _processRiskProjectionMaintenance.ReplaceSigmaEvidenceAndRebuild(
                evidence,
                progress,
                cancellationToken);
        }
    }

    public ProcessRiskProjectionRebuildResult ReplaceBaselineRiskEvidenceAndRebuild(
        IReadOnlyList<LocalProcessBaselineComparisonEvidence> evidence,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        lock (_lock)
        {
            return _processRiskProjectionMaintenance.ReplaceBaselineEvidenceAndRebuild(
                evidence,
                progress,
                cancellationToken);
        }
    }

    public ProcessRiskProjectionRebuildResult ReplaceYaraRiskAttributionsAndRebuild(
        IReadOnlyList<YaraProcessAttributionResult> attributions,
        IProgress<ProcessRiskProjectionRebuildProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attributions);
        lock (_lock)
        {
            return _processRiskProjectionMaintenance.ReplaceYaraAttributionsAndRebuild(
                attributions,
                progress,
                cancellationToken);
        }
    }

    public YaraAnalysisPersistenceResult PersistYaraAnalysis(
        YaraAnalysisPersistenceRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return _yaraAnalysisPersistence.Persist(request, cancellationToken);
    }

    public ReputationAttributionPersistenceResult PersistReputationAttribution(
        ReputationProcessAttributionResult attribution,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attribution);
        return _reputationAttributionPersistence.Persist(attribution, cancellationToken);
    }

    public void UpsertProcess(ProcessRecord process)
        => _processEvidenceWriter.UpsertProcess(process);

    public void UpsertProcesses(IEnumerable<ProcessRecord> processes)
        => _processEvidenceWriter.UpsertProcesses(processes);

    public void UpsertProcessStatistic(ProcessStatisticsRecord sample)
        => _processEvidenceWriter.UpsertProcessStatistic(sample);

    public void UpsertProcessStatistics(IEnumerable<ProcessStatisticsRecord> samples)
        => _processEvidenceWriter.UpsertProcessStatistics(samples);

    public void UpsertProcessBatch(
        IEnumerable<ProcessRecord> processes,
        IEnumerable<ProcessStatisticsRecord> samples)
        => _processEvidenceWriter.UpsertProcessBatch(processes, samples);

    internal void UpsertLegacyBookmark(SqliteLegacyBookmarkWrite bookmark)
    {
        lock (_lock)
        {
            using var command = CreateCommand("""
                INSERT INTO Bookmarks (
                    BookmarkId, TargetKind, TargetId, ProcessKey, ProcessId, ProcessName,
                    Label, Notes, Tags, CreatedUtc, UpdatedUtc)
                VALUES (
                    $BookmarkId, $TargetKind, $TargetId, $ProcessKey, $ProcessId, $ProcessName,
                    $Label, $Notes, $Tags, $CreatedUtc, $UpdatedUtc)
                ON CONFLICT(TargetKind, TargetId) DO UPDATE SET
                    ProcessKey = excluded.ProcessKey,
                    ProcessId = excluded.ProcessId,
                    ProcessName = excluded.ProcessName,
                    Label = excluded.Label,
                    Notes = excluded.Notes,
                    Tags = excluded.Tags,
                    UpdatedUtc = excluded.UpdatedUtc;
                """);
            Add(command, "$BookmarkId", string.IsNullOrWhiteSpace(bookmark.BookmarkId) ? Guid.NewGuid().ToString("N") : bookmark.BookmarkId);
            Add(command, "$TargetKind", bookmark.TargetKind);
            Add(command, "$TargetId", bookmark.TargetId);
            Add(command, "$ProcessKey", bookmark.ProcessKey);
            Add(command, "$ProcessId", bookmark.ProcessId);
            Add(command, "$ProcessName", bookmark.ProcessName);
            Add(command, "$Label", bookmark.Label);
            Add(command, "$Notes", bookmark.Notes);
            Add(command, "$Tags", bookmark.Tags);
            Add(command, "$CreatedUtc", bookmark.CreatedUtc == default ? DateTime.UtcNow : bookmark.CreatedUtc);
            Add(command, "$UpdatedUtc", bookmark.UpdatedUtc == default ? DateTime.UtcNow : bookmark.UpdatedUtc);
            command.ExecuteNonQuery();
        }
    }

    public void DeleteBookmark(string targetKind, string targetId)
    {
        lock (_lock)
        {
            using var command = CreateCommand("""
                DELETE FROM Bookmarks
                WHERE TargetKind = $TargetKind AND TargetId = $TargetId;
                """);
            Add(command, "$TargetKind", targetKind);
            Add(command, "$TargetId", targetId);
            command.ExecuteNonQuery();
        }
    }

    public bool IsBookmarked(string targetKind, string targetId)
    {
        lock (_lock)
        {
            using var command = CreateCommand("""
                SELECT 1
                FROM Bookmarks
                WHERE TargetKind = $TargetKind AND TargetId = $TargetId
                LIMIT 1;
                """);
            Add(command, "$TargetKind", targetKind);
            Add(command, "$TargetId", targetId);
            return command.ExecuteScalar() != null;
        }
    }

    public void AddEvent(TelemetryEventRecord processEvent)
        => _eventEvidenceWriter.AddEvent(processEvent);

    public void AddEvents(IEnumerable<TelemetryEventRecord> events)
        => _eventEvidenceWriter.AddEvents(events);

    public void UpsertEvidenceRelation(EvidenceRelation relation)
    {
        ArgumentNullException.ThrowIfNull(relation);
        if (string.IsNullOrWhiteSpace(relation.RelationId) ||
            string.IsNullOrWhiteSpace(relation.DecisionKey) ||
            string.IsNullOrWhiteSpace(relation.FromId))
        {
            throw new ArgumentException("Relation id, decision key, and source reference are required.", nameof(relation));
        }

        if (relation.State is not (EvidenceCorrelationState.Unresolved or EvidenceCorrelationState.Ambiguous) &&
            string.IsNullOrWhiteSpace(relation.ToId))
        {
            throw new ArgumentException("Only unresolved or ambiguous relations may omit a target reference.", nameof(relation));
        }

        lock (_lock)
        {
            var nowUtc = relation.UpdatedUtc == default ? DateTime.UtcNow : relation.UpdatedUtc;
            if (relation.CreatedUtc == default)
            {
                relation.CreatedUtc = nowUtc;
            }

            if (relation.ObservedFromUtc == default)
            {
                relation.ObservedFromUtc = nowUtc;
            }

            using (var supersede = CreateCommand("""
                UPDATE EvidenceRelations
                SET Status = 'Superseded', SupersededByRelationId = $RelationId, UpdatedUtc = $UpdatedUtc
                WHERE DecisionKey = $DecisionKey
                  AND RelationId <> $RelationId
                  AND Status = 'Active';
                """))
            {
                Add(supersede, "$RelationId", relation.RelationId);
                Add(supersede, "$DecisionKey", relation.DecisionKey);
                Add(supersede, "$UpdatedUtc", nowUtc);
                supersede.ExecuteNonQuery();
            }

            using var command = CreateCommand("""
                INSERT INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                    CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId,
                    IngestionJobId, RawInputId, ObservedFromUtc, ObservedToUtc, ValidFromUtc,
                    ValidToUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                    SupersededByRelationId, AnalystAnnotationId)
                VALUES (
                    $RelationId, $DecisionKey, $FromKind, $FromId, $ToKind, $ToId, $RelationType,
                    $CorrelationState, $CorrelationMethod, $Confidence, $CandidateCount, $CorrelationDiagnostics,
                    $CaseId, $EvidenceSessionId,
                    $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId, $SourceRunId,
                    $IngestionJobId, $RawInputId, $ObservedFromUtc, $ObservedToUtc, $ValidFromUtc,
                    $ValidToUtc, $ResolverName, $ResolverVersion, $CreatedUtc, $UpdatedUtc, $Status,
                    $SupersededByRelationId, $AnalystAnnotationId)
                ON CONFLICT(RelationId) DO UPDATE SET
                    CorrelationState = excluded.CorrelationState,
                    CorrelationMethod = excluded.CorrelationMethod,
                    Confidence = excluded.Confidence,
                    CandidateCount = excluded.CandidateCount,
                    CorrelationDiagnostics = excluded.CorrelationDiagnostics,
                    ObservedToUtc = excluded.ObservedToUtc,
                    ValidToUtc = excluded.ValidToUtc,
                    UpdatedUtc = excluded.UpdatedUtc,
                    Status = excluded.Status,
                    SupersededByRelationId = excluded.SupersededByRelationId,
                    AnalystAnnotationId = excluded.AnalystAnnotationId;
                """);
            Add(command, "$RelationId", relation.RelationId);
            Add(command, "$DecisionKey", relation.DecisionKey);
            Add(command, "$FromKind", relation.FromKind.ToString());
            Add(command, "$FromId", relation.FromId);
            Add(command, "$ToKind", relation.ToKind.ToString());
            Add(command, "$ToId", relation.ToId);
            Add(command, "$RelationType", relation.RelationType.ToString());
            Add(command, "$CorrelationState", relation.State.ToString());
            Add(command, "$CorrelationMethod", relation.CorrelationMethod);
            Add(command, "$Confidence", Math.Clamp(relation.Confidence, 0d, 1d));
            Add(command, "$CandidateCount", Math.Max(0, relation.CandidateCount));
            Add(command, "$CorrelationDiagnostics", relation.CorrelationDiagnostics);
            Add(command, "$CaseId", relation.CaseId);
            Add(command, "$EvidenceSessionId", relation.EvidenceSessionId);
            Add(command, "$CaptureId", relation.CaptureId);
            Add(command, "$SourceIdentityId", relation.SourceIdentityId);
            Add(command, "$HostId", relation.HostId);
            Add(command, "$ExecutionRootId", relation.ExecutionRootId);
            Add(command, "$SourceRunId", string.IsNullOrWhiteSpace(relation.SourceRunId) ? null : relation.SourceRunId);
            Add(command, "$IngestionJobId", relation.IngestionJobId);
            Add(command, "$RawInputId", relation.RawInputId);
            Add(command, "$ObservedFromUtc", relation.ObservedFromUtc);
            Add(command, "$ObservedToUtc", relation.ObservedToUtc);
            Add(command, "$ValidFromUtc", relation.ValidFromUtc);
            Add(command, "$ValidToUtc", relation.ValidToUtc);
            Add(command, "$ResolverName", relation.ResolverName);
            Add(command, "$ResolverVersion", relation.ResolverVersion);
            Add(command, "$CreatedUtc", relation.CreatedUtc);
            Add(command, "$UpdatedUtc", nowUtc);
            Add(command, "$Status", relation.Status.ToString());
            Add(command, "$SupersededByRelationId", relation.SupersededByRelationId);
            Add(command, "$AnalystAnnotationId", relation.AnalystAnnotationId);
            command.ExecuteNonQuery();
        }
    }

    public void UpsertEvidenceRelations(IEnumerable<EvidenceRelation> relations)
    {
        ArgumentNullException.ThrowIfNull(relations);
        var snapshot = relations.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        ExecuteInWriteTransaction(() =>
        {
            foreach (var relation in snapshot)
            {
                UpsertEvidenceRelation(relation);
            }
        });
    }

    public void UpsertEvidenceCorrelationInput(EvidenceCorrelationInput input, bool resolveNow = true)
    {
        ArgumentNullException.ThrowIfNull(input);
        ExecuteInWriteTransaction(() =>
        {
            UpsertEvidenceCorrelationInputCore(input);
            if (resolveNow)
            {
                ResolveCorrelationInputCore(input, DateTime.UtcNow);
            }
        });
    }

    public EvidenceReCorrelationResult ReCorrelateEvidence(
        EvidenceReCorrelationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        EvidenceReCorrelationResult? result = null;
        ExecuteInWriteTransaction(() => result = ReCorrelateEvidenceCore(request, cancellationToken));
        return result!;
    }

    private void UpsertEvidenceCorrelationInputCore(EvidenceCorrelationInput input)
    {
        if (string.IsNullOrWhiteSpace(input.EvidenceId))
        {
            throw new ArgumentException("Correlation evidence id is required.", nameof(input));
        }

        if (string.IsNullOrWhiteSpace(input.InputId))
        {
            input.InputId = $"{input.EvidenceKind}:{input.EvidenceId}".ToLowerInvariant();
        }

        if (input.ObservedUtc == default)
        {
            input.ObservedUtc = DateTime.UtcNow;
        }

        if (input.CreatedUtc == default)
        {
            input.CreatedUtc = DateTime.UtcNow;
        }

        using var command = CreateCommand("""
            INSERT OR IGNORE INTO EvidenceCorrelationInputs (
                InputId, EvidenceKind, EvidenceId, EvidenceType, Source, RelationType,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ProcessId, ProcessStartTimeUtc,
                ProcessGuid, ProcessName, ProcessPath, SourceNativeId, SourceEndpoint,
                DestinationEndpoint, ObservedUtc, CreatedUtc)
            VALUES (
                $InputId, $EvidenceKind, $EvidenceId, $EvidenceType, $Source, $RelationType,
                $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceRunId, $IngestionJobId, $RawInputId, $ProcessId, $ProcessStartTimeUtc,
                $ProcessGuid, $ProcessName, $ProcessPath, $SourceNativeId, $SourceEndpoint,
                $DestinationEndpoint, $ObservedUtc, $CreatedUtc);
            """);
        Add(command, "$InputId", input.InputId);
        Add(command, "$EvidenceKind", input.EvidenceKind.ToString());
        Add(command, "$EvidenceId", input.EvidenceId);
        Add(command, "$EvidenceType", input.EvidenceType);
        Add(command, "$Source", input.Source);
        Add(command, "$RelationType", input.RelationType.ToString());
        Add(command, "$CaseId", input.CaseId);
        Add(command, "$EvidenceSessionId", input.EvidenceSessionId);
        Add(command, "$CaptureId", input.CaptureId);
        Add(command, "$SourceIdentityId", input.SourceIdentityId);
        Add(command, "$HostId", input.HostId);
        Add(command, "$ExecutionRootId", input.ExecutionRootId);
        Add(command, "$SourceRunId", string.IsNullOrWhiteSpace(input.SourceRunId) ? null : input.SourceRunId);
        Add(command, "$IngestionJobId", input.IngestionJobId);
        Add(command, "$RawInputId", input.RawInputId);
        Add(command, "$ProcessId", input.ProcessId);
        Add(command, "$ProcessStartTimeUtc", input.ProcessStartTimeUtc);
        Add(command, "$ProcessGuid", input.ProcessGuid);
        Add(command, "$ProcessName", input.ProcessName);
        Add(command, "$ProcessPath", input.ProcessPath);
        Add(command, "$SourceNativeId", input.SourceNativeId);
        Add(command, "$SourceEndpoint", input.SourceEndpoint);
        Add(command, "$DestinationEndpoint", input.DestinationEndpoint);
        Add(command, "$ObservedUtc", input.ObservedUtc);
        Add(command, "$CreatedUtc", input.CreatedUtc);
        command.ExecuteNonQuery();
    }

    private EvidenceReCorrelationResult ReCorrelateEvidenceCore(
        EvidenceReCorrelationRequest request,
        CancellationToken cancellationToken)
    {
        var maxCount = Math.Clamp(request.MaxCount, 1, 1000);
        var inputs = ReadEvidenceCorrelationInputsCore(request, maxCount + 1);
        var reachedLimit = inputs.Count > maxCount;
        if (reachedLimit)
        {
            inputs = inputs.Take(maxCount).ToList();
        }

        var changed = 0;
        var unchanged = 0;
        var exact = 0;
        var inferred = 0;
        var ambiguous = 0;
        var unresolved = 0;
        foreach (var input in inputs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var wasChanged = ResolveCorrelationInputCore(input, DateTime.UtcNow);
            if (wasChanged) changed++; else unchanged++;
            switch (ReadActiveCorrelationState(input.DecisionKey))
            {
                case EvidenceCorrelationState.Exact:
                case EvidenceCorrelationState.Asserted:
                case EvidenceCorrelationState.Confirmed:
                    exact++;
                    break;
                case EvidenceCorrelationState.Inferred:
                    inferred++;
                    break;
                case EvidenceCorrelationState.Ambiguous:
                    ambiguous++;
                    break;
                default:
                    unresolved++;
                    break;
            }
        }

        return new EvidenceReCorrelationResult(
            inputs.Count,
            changed,
            unchanged,
            exact,
            inferred,
            ambiguous,
            unresolved,
            reachedLimit,
            EvidenceReCorrelationService.Version);
    }

    private bool ResolveCorrelationInputCore(EvidenceCorrelationInput input, DateTime resolvedUtc)
    {
        var active = ReadActiveEvidenceRelation(input.DecisionKey);
        if (active != null &&
            !string.Equals(active.ResolverName, EvidenceReCorrelationService.ResolverName, StringComparison.Ordinal) &&
            (EvidenceRelationService.IsCanonicalProcessLink(active.State) ||
             !string.IsNullOrWhiteSpace(active.AnalystAnnotationId)))
        {
            return false;
        }

        var candidates = ReadProcessCorrelationCandidates(input);
        var resolution = new EvidenceReCorrelationService().Resolve(input, candidates, resolvedUtc);
        if (active != null && AreEquivalentDecisions(active, resolution.Decision))
        {
            return false;
        }

        UpsertEvidenceRelation(resolution.Decision);
        _analysisIndexMaintenance.UpsertCorrelation(input, resolution.Decision);
        return true;
    }

    private List<EvidenceCorrelationInput> ReadEvidenceCorrelationInputsCore(
        EvidenceReCorrelationRequest request,
        int maxCount)
    {
        using var command = CreateCommand(string.Empty);
        var predicates = new List<string>();
        if (!request.IncludeAlreadyResolved)
        {
            predicates.Add("COALESCE(r.CorrelationState, 'Unresolved') IN ('Unresolved', 'Ambiguous')");
        }
        if (request.State.HasValue)
        {
            predicates.Add("COALESCE(r.CorrelationState, 'Unresolved') = $State");
            Add(command, "$State", request.State.Value.ToString());
        }
        if (request.EvidenceKind.HasValue)
        {
            predicates.Add("i.EvidenceKind = $EvidenceKind");
            Add(command, "$EvidenceKind", request.EvidenceKind.Value.ToString());
        }
        AddOptionalCorrelationPredicate(predicates, command, "i.Source", "$Source", request.Source);
        AddOptionalCorrelationPredicate(predicates, command, "i.CaseId", "$CaseId", request.CaseId);
        AddOptionalCorrelationPredicate(predicates, command, "i.EvidenceSessionId", "$EvidenceSessionId", request.EvidenceSessionId);
        AddOptionalCorrelationPredicate(predicates, command, "i.HostId", "$HostId", request.HostId);
        AddOptionalCorrelationPredicate(predicates, command, "i.ExecutionRootId", "$ExecutionRootId", request.ExecutionRootId);
        if (request.ProcessId.HasValue)
        {
            predicates.Add("i.ProcessId = $ProcessId");
            Add(command, "$ProcessId", request.ProcessId.Value);
        }
        AddOptionalCorrelationPredicate(predicates, command, "i.ProcessGuid", "$ProcessGuid", request.ProcessGuid);
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
                WHERE active.DecisionKey = CASE i.EvidenceKind
                    WHEN 'Event' THEN 'event:' || i.EvidenceId || ':process'
                    WHEN 'MemoryProcess' THEN 'memory-process:' || i.EvidenceId || ':process'
                    WHEN 'NetworkFlow' THEN 'zeek:' || i.EvidenceId || ':process'
                    ELSE 'correlation:' || i.EvidenceKind || ':' || i.EvidenceId || ':process'
                END AND active.Status = 'Active'
                ORDER BY active.UpdatedUtc DESC, active.RelationId DESC LIMIT 1)
            {where}
            ORDER BY i.ObservedUtc, i.InputId
            LIMIT $MaxCount;
            """;
        Add(command, "$MaxCount", Math.Clamp(maxCount, 1, 1001));
        var result = new List<EvidenceCorrelationInput>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            result.Add(ReadEvidenceCorrelationInput(reader));
        }
        return result;
    }

    private static void AddOptionalCorrelationPredicate(
        ICollection<string> predicates,
        SqliteCommand command,
        string column,
        string parameter,
        string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        predicates.Add($"{column} = {parameter}");
        Add(command, parameter, value);
    }

    private List<ProcessCorrelationCandidate> ReadProcessCorrelationCandidates(EvidenceCorrelationInput input)
    {
        var processPath = IsUsableProcessText(input.ProcessPath) ? input.ProcessPath : string.Empty;
        var processName = IsUsableProcessText(input.ProcessName) ? input.ProcessName : string.Empty;
        if (input.ProcessId <= 0 && string.IsNullOrWhiteSpace(input.ProcessGuid) &&
            string.IsNullOrWhiteSpace(input.SourceNativeId) && string.IsNullOrWhiteSpace(processPath) &&
            string.IsNullOrWhiteSpace(processName))
        {
            return [];
        }

        using var command = CreateCommand("""
            SELECT ProcessEntityId, ProcessKey, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc,
                   ProcessName, ProcessPath, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                   HostId, ExecutionRootId
            FROM ProcessEntities pe
            WHERE (($ProcessId > 0 AND pe.ProcessId = $ProcessId)
               OR ($ProcessGuid <> '' AND (pe.ProcessGuid = $ProcessGuid OR EXISTS (
                    SELECT 1 FROM ProcessAliases a WHERE a.ProcessEntityId = pe.ProcessEntityId AND a.AliasValue = $ProcessGuid)))
               OR ($SourceNativeId <> '' AND (pe.ProcessKey = $SourceNativeId OR EXISTS (
                    SELECT 1 FROM ProcessAliases a WHERE a.ProcessEntityId = pe.ProcessEntityId AND a.AliasValue = $SourceNativeId)))
               OR ($ProcessPath <> '' AND pe.ProcessPath = $ProcessPath COLLATE NOCASE)
               OR ($ProcessName <> '' AND pe.ProcessName = $ProcessName COLLATE NOCASE))
              AND ($CaseId = '' OR COALESCE(pe.CaseId, '') = '' OR pe.CaseId = $CaseId)
              AND ($EvidenceSessionId = '' OR COALESCE(pe.EvidenceSessionId, '') = '' OR pe.EvidenceSessionId = $EvidenceSessionId)
              AND ($HostId = '' OR COALESCE(pe.HostId, '') = '' OR pe.HostId = $HostId)
              AND ($ExecutionRootId = '' OR COALESCE(pe.ExecutionRootId, '') = '' OR pe.ExecutionRootId = $ExecutionRootId)
            ORDER BY pe.ProcessEntityId
            LIMIT 200;
            """);
        Add(command, "$ProcessId", input.ProcessId);
        Add(command, "$ProcessGuid", input.ProcessGuid);
        Add(command, "$SourceNativeId", input.SourceNativeId);
        Add(command, "$ProcessPath", processPath);
        Add(command, "$ProcessName", processName);
        Add(command, "$CaseId", input.CaseId);
        Add(command, "$EvidenceSessionId", input.EvidenceSessionId);
        Add(command, "$HostId", input.HostId);
        Add(command, "$ExecutionRootId", input.ExecutionRootId);
        var candidates = new List<ProcessCorrelationCandidate>();
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                candidates.Add(new ProcessCorrelationCandidate
                {
                    ProcessEntityId = GetString(reader, 0),
                    ProcessKey = GetString(reader, 1),
                    ProcessId = GetInt(reader, 2),
                    ProcessGuid = GetString(reader, 3),
                    StartTimeUtc = GetDateTime(reader, 4),
                    EndTimeUtc = GetDateTime(reader, 5),
                    ProcessName = GetString(reader, 6),
                    ProcessPath = GetString(reader, 7),
                    Identity = new EvidenceIdentity
                    {
                        CaseId = GetString(reader, 8),
                        EvidenceSessionId = GetString(reader, 9),
                        CaptureId = GetString(reader, 10),
                        SourceIdentityId = GetString(reader, 11),
                        HostId = GetString(reader, 12),
                        ExecutionRootId = GetString(reader, 13)
                    }
                });
            }
        }

        for (var index = 0; index < candidates.Count; index++)
        {
            var candidate = candidates[index];
            using var aliases = CreateCommand("""
                SELECT AliasKind, AliasValue, CaseId, EvidenceSessionId, HostId, ExecutionRootId, SourceIdentityId
                FROM ProcessAliases WHERE ProcessEntityId = $ProcessEntityId ORDER BY ProcessAliasId;
                """);
            Add(aliases, "$ProcessEntityId", candidate.ProcessEntityId);
            var values = new List<ProcessAlias>();
            using var aliasReader = aliases.ExecuteReader();
            while (aliasReader.Read())
            {
                values.Add(new ProcessAlias
                {
                    ProcessEntityId = candidate.ProcessEntityId,
                    Kind = GetEnum(aliasReader, 0, ProcessAliasKind.Unknown),
                    Value = GetString(aliasReader, 1),
                    CaseId = GetString(aliasReader, 2),
                    EvidenceSessionId = GetString(aliasReader, 3),
                    HostId = GetString(aliasReader, 4),
                    ExecutionRootId = GetString(aliasReader, 5),
                    SourceIdentityId = GetString(aliasReader, 6)
                });
            }
            candidates[index] = candidate with { Aliases = values };
        }
        return candidates;
    }

    private EvidenceRelation? ReadActiveEvidenceRelation(string decisionKey)
    {
        using var command = CreateCommand("""
            SELECT RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                   CorrelationState, CorrelationMethod, Confidence, CandidateCount,
                   CorrelationDiagnostics, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                   HostId, ExecutionRootId, SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc,
                   ObservedToUtc, ValidFromUtc, ValidToUtc, ResolverName, ResolverVersion, CreatedUtc,
                   UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId
            FROM EvidenceRelations WHERE DecisionKey = $DecisionKey AND Status = 'Active'
            ORDER BY UpdatedUtc DESC, RelationId DESC LIMIT 1;
            """);
        Add(command, "$DecisionKey", decisionKey);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadEvidenceRelationForCorrelation(reader) : null;
    }

    private EvidenceCorrelationState ReadActiveCorrelationState(string decisionKey)
        => ReadActiveEvidenceRelation(decisionKey)?.State ?? EvidenceCorrelationState.Unresolved;

    private static bool AreEquivalentDecisions(EvidenceRelation left, EvidenceRelation right)
        => string.Equals(left.RelationId, right.RelationId, StringComparison.Ordinal) &&
           left.State == right.State &&
           string.Equals(left.ToId, right.ToId, StringComparison.Ordinal) &&
           string.Equals(left.CorrelationMethod, right.CorrelationMethod, StringComparison.Ordinal) &&
           string.Equals(left.ResolverVersion, right.ResolverVersion, StringComparison.Ordinal) &&
           left.CandidateCount == right.CandidateCount &&
           string.Equals(left.CorrelationDiagnostics, right.CorrelationDiagnostics, StringComparison.Ordinal);

    private void EnsureInitialCorrelationDecisionCore(EvidenceCorrelationInput input)
    {
        if (ReadActiveEvidenceRelation(input.DecisionKey) != null)
        {
            return;
        }

        var unresolved = new EvidenceReCorrelationService().Resolve(input, [], input.CreatedUtc).Decision;
        UpsertEvidenceRelation(unresolved);
        _analysisIndexMaintenance.UpsertCorrelation(input, unresolved);
    }

    private void ApplyPersistedCorrelationProvenance(
        EvidenceCorrelationInput input,
        string table,
        string keyColumn,
        object keyValue)
    {
        using var command = CreateCommand($"SELECT SourceRunId, IngestionJobId FROM {table} WHERE {keyColumn} = $Key LIMIT 1;");
        Add(command, "$Key", keyValue);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return;
        }

        input.SourceRunId = GetString(reader, 0);
        input.IngestionJobId = GetString(reader, 1);
    }

    private ProcessEvidenceAttachmentResolution PrepareProcessAttachedEvidence(
        IHasProcessEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        int processId,
        string processGuid,
        DateTime? processStartTimeUtc,
        string processName,
        DateTime observedUtc)
    {
        ApplyCurrentWriterProvenance(evidence);
        var identity = new EvidenceIdentity
        {
            CaseId = evidence.CaseId,
            EvidenceSessionId = evidence.EvidenceSessionId,
            CaptureId = evidence.CaptureId,
            SourceIdentityId = evidence.SourceIdentityId,
            HostId = evidence.HostId,
            ExecutionRootId = evidence.ExecutionRootId
        };

        if (!string.IsNullOrWhiteSpace(evidence.ProcessEntityId))
        {
            EnsureCompatibleProcessEntity(evidence.ProcessEntityId, identity);
            return new ProcessEvidenceAttachmentResolution(
                EvidenceCorrelationState.Asserted,
                "ProvidedProcessEntityId",
                1.0,
                1,
                "The producer supplied a scoped ProcessEntityId that matched the evidence scope.");
        }

        var input = new EvidenceCorrelationInput
        {
            InputId = $"attachment:{evidenceKind}:{evidenceId}",
            EvidenceKind = evidenceKind,
            EvidenceId = evidenceId,
            EvidenceType = evidenceKind.ToString(),
            RelationType = EvidenceRelationType.OwnedBy,
            CaseId = identity.CaseId,
            EvidenceSessionId = identity.EvidenceSessionId,
            CaptureId = identity.CaptureId,
            SourceIdentityId = identity.SourceIdentityId,
            HostId = identity.HostId,
            ExecutionRootId = identity.ExecutionRootId,
            SourceRunId = evidence.SourceRunId,
            IngestionJobId = evidence.IngestionJobId,
            ProcessId = processId,
            ProcessStartTimeUtc = processStartTimeUtc,
            ProcessGuid = processGuid ?? string.Empty,
            ProcessName = processName ?? string.Empty,
            SourceNativeId = evidence.ProcessKey,
            ObservedUtc = observedUtc == default ? DateTime.UtcNow : observedUtc,
            CreatedUtc = observedUtc == default ? DateTime.UtcNow : observedUtc
        };
        var resolved = new EvidenceReCorrelationService().Resolve(
            input,
            ReadProcessCorrelationCandidates(input),
            DateTime.UtcNow).Decision;
        if (EvidenceRelationService.IsCanonicalProcessLink(resolved.State))
        {
            evidence.ProcessEntityId = resolved.ToId;
        }

        return new ProcessEvidenceAttachmentResolution(
            resolved.State,
            resolved.CorrelationMethod,
            resolved.Confidence,
            resolved.CandidateCount,
            resolved.CorrelationDiagnostics);
    }

    private void ApplyCurrentWriterProvenance(IHasSourceRunEvidenceLink evidence)
    {
        using var command = CreateCommand("SELECT SourceRunId, IngestionJobId FROM WriterProvenanceContext WHERE SingletonId = 1 LIMIT 1;");
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return;
        }

        var sourceRunId = GetString(reader, 0);
        var ingestionJobId = GetString(reader, 1);
        if (!string.IsNullOrWhiteSpace(evidence.SourceRunId) &&
            !string.Equals(evidence.SourceRunId, sourceRunId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Process-attached evidence cannot cross the active source-run boundary.");
        }

        if (!string.IsNullOrWhiteSpace(evidence.IngestionJobId) &&
            !string.Equals(evidence.IngestionJobId, ingestionJobId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Process-attached evidence cannot cross the active ingestion-job boundary.");
        }

        evidence.SourceRunId = sourceRunId;
        evidence.IngestionJobId = ingestionJobId;
    }

    private void PersistIndependentArtifactSourceRunRelation(
        IHasSourceRunEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        DateTime observedUtc,
        string rawInputId)
    {
        if (string.IsNullOrWhiteSpace(evidence.SourceRunId) || string.IsNullOrWhiteSpace(evidenceId))
        {
            return;
        }

        var relation = new EvidenceRelationService().CreateDecision(
            new EvidenceReference(evidenceKind, evidenceId),
            new EvidenceReference(EvidenceReferenceKind.SourceRun, evidence.SourceRunId),
            EvidenceRelationType.DerivedFrom,
            EvidenceCorrelationState.Exact,
            "ExactWriterSourceRun",
            1.0,
            new EvidenceIdentity
            {
                CaseId = evidence.CaseId,
                EvidenceSessionId = evidence.EvidenceSessionId,
                CaptureId = evidence.CaptureId,
                SourceIdentityId = evidence.SourceIdentityId,
                HostId = evidence.HostId,
                ExecutionRootId = evidence.ExecutionRootId
            },
            "IndependentArtifactWriter",
            decisionKey: $"source-run:{evidenceKind}:{evidenceId}:{evidence.SourceRunId}",
            observedUtc: observedUtc == default ? DateTime.UtcNow : observedUtc,
            sourceRunId: evidence.SourceRunId,
            ingestionJobId: evidence.IngestionJobId,
            rawInputId: rawInputId,
            resolverVersion: "independent-artifact-v1");
        UpsertEvidenceRelation(relation);
    }

    private void EnsureCompatibleProcessEntity(string processEntityId, EvidenceIdentity evidenceIdentity)
    {
        using var command = CreateCommand("""
            SELECT CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId
            FROM ProcessEntities
            WHERE ProcessEntityId = $ProcessEntityId
            LIMIT 1;
            """);
        Add(command, "$ProcessEntityId", processEntityId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            throw new InvalidOperationException($"Process-attached evidence references unknown entity '{processEntityId}'.");
        }

        EvidenceRelationService.EnsureCompatibleScopes(
            evidenceIdentity,
            new EvidenceIdentity
            {
                CaseId = GetString(reader, 0),
                EvidenceSessionId = GetString(reader, 1),
                CaptureId = GetString(reader, 2),
                SourceIdentityId = GetString(reader, 3),
                HostId = GetString(reader, 4),
                ExecutionRootId = GetString(reader, 5)
            });
    }

    private void PersistProcessAttachedRelation(
        IHasProcessEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        EvidenceRelationType relationType,
        ProcessEvidenceAttachmentResolution resolution,
        DateTime observedUtc,
        DateTime? observedToUtc = null,
        string rawInputId = "",
        string observationDiscriminator = "",
        bool processIsSource = false)
    {
        if (string.IsNullOrWhiteSpace(evidenceId))
        {
            return;
        }

        var sourceRun = string.IsNullOrWhiteSpace(evidence.SourceRunId) ? "legacy" : evidence.SourceRunId;
        var discriminator = string.IsNullOrWhiteSpace(observationDiscriminator)
            ? observedUtc.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture)
            : observationDiscriminator;
        var decisionKey = $"attachment:{evidenceKind}:{evidenceId}:{sourceRun}:{discriminator}:process";
        var evidenceReference = new EvidenceReference(evidenceKind, evidenceId);
        var processReference = new EvidenceReference(EvidenceReferenceKind.ProcessEntity, evidence.ProcessEntityId);
        var relation = new EvidenceRelationService().CreateDecision(
            processIsSource ? processReference : evidenceReference,
            processIsSource ? evidenceReference : processReference,
            relationType,
            string.IsNullOrWhiteSpace(evidence.ProcessEntityId) ? resolution.State :
                EvidenceRelationService.IsCanonicalProcessLink(resolution.State)
                    ? resolution.State
                    : EvidenceCorrelationState.Asserted,
            resolution.Method,
            string.IsNullOrWhiteSpace(evidence.ProcessEntityId) ? resolution.Confidence : Math.Max(resolution.Confidence, 0.99),
            new EvidenceIdentity
            {
                CaseId = evidence.CaseId,
                EvidenceSessionId = evidence.EvidenceSessionId,
                CaptureId = evidence.CaptureId,
                SourceIdentityId = evidence.SourceIdentityId,
                HostId = evidence.HostId,
                ExecutionRootId = evidence.ExecutionRootId
            },
            "ProcessAttachedEvidenceWriter",
            decisionKey,
            observedUtc,
            evidence.SourceRunId,
            evidence.IngestionJobId,
            rawInputId,
            resolverVersion: "process-attached-v1",
            candidateCount: resolution.CandidateCount,
            correlationDiagnostics: resolution.Diagnostics);
        relation.ObservedToUtc = observedToUtc;
        UpsertEvidenceRelation(relation);
    }

    private static object? EmptyToNull(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    private static bool IsUsableProcessText(string value)
        => !string.IsNullOrWhiteSpace(value) &&
           value is not "<unknown>" and not "<not available>" and not "Access denied";

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
            CurrentConfidence = GetDouble(reader, 28),
            CandidateCount = GetInt(reader, 29),
            CorrelationDiagnostics = GetString(reader, 30),
            ResolverVersion = GetString(reader, 31)
        };

    private static EvidenceRelation ReadEvidenceRelationForCorrelation(SqliteDataReader reader)
        => new()
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
            Confidence = GetDouble(reader, 9),
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

    public void UpsertModule(ModuleObservationRecord module)
        => _moduleHandleEvidenceWriter.UpsertModule(module);

    public void UpsertHandle(HandleObservationRecord handle)
        => _moduleHandleEvidenceWriter.UpsertHandle(handle);

    public void UpsertModules(IEnumerable<ModuleObservationRecord> modules)
        => _moduleHandleEvidenceWriter.UpsertModules(modules);

    public void UpsertHandles(IEnumerable<HandleObservationRecord> handles)
        => _moduleHandleEvidenceWriter.UpsertHandles(handles);

    public void UpsertModuleSnapshot(
        string processKey,
        IEnumerable<ModuleObservationRecord> modules,
        DateTime observedUtc,
        string source)
        => _moduleHandleEvidenceWriter.UpsertModuleSnapshot(processKey, modules, observedUtc, source);

    public void UpsertModuleSnapshotBatch(
        string processKey,
        IEnumerable<ModuleObservationRecord> modules,
        DateTime observedUtc,
        string source)
        => _moduleHandleEvidenceWriter.UpsertModuleSnapshotBatch(processKey, modules, observedUtc, source);

    public int CloseStaleModulesForSnapshot(
        string processKey,
        IReadOnlySet<string> seenKeys,
        DateTime observedUtc,
        string source,
        int maxRows)
        => _moduleHandleEvidenceWriter.CloseStaleModulesForSnapshot(
            processKey,
            seenKeys,
            observedUtc,
            source,
            maxRows);

    public void UpsertHandleSnapshot(
        string processKey,
        IEnumerable<HandleObservationRecord> handles,
        DateTime observedUtc,
        string source)
        => _moduleHandleEvidenceWriter.UpsertHandleSnapshot(processKey, handles, observedUtc, source);

    public void UpsertHandleSnapshotBatch(
        string processKey,
        IEnumerable<HandleObservationRecord> handles,
        DateTime observedUtc,
        string source)
        => _moduleHandleEvidenceWriter.UpsertHandleSnapshotBatch(processKey, handles, observedUtc, source);

    public int CloseStaleHandlesForSnapshot(
        string processKey,
        IReadOnlySet<string> seenKeys,
        DateTime observedUtc,
        string source,
        int maxRows)
        => _moduleHandleEvidenceWriter.CloseStaleHandlesForSnapshot(
            processKey,
            seenKeys,
            observedUtc,
            source,
            maxRows);

    public void UpsertMemoryDump(MemoryDumpRecord memoryDump)
        => _dumpPeEvidenceWriter.UpsertMemoryDump(memoryDump);

    public void UpsertPeAnalysis(PeAnalysisRecord analysis)
        => _dumpPeEvidenceWriter.UpsertPeAnalysis(analysis);

    public void UpsertMemoryImage(MemoryImageRecord image)
        => _systemMemoryEvidenceWriter.UpsertMemoryImage(image);

    public void UpsertVolatilityPluginRun(VolatilityPluginRunRecord run)
        => _systemMemoryEvidenceWriter.UpsertVolatilityPluginRun(run);

    public void UpsertMemoryProcess(MemoryProcessRecord process)
        => _systemMemoryEvidenceWriter.UpsertMemoryProcess(process);

    public void UpsertNetworkCapture(NetworkCaptureRecord capture)
        => _networkEvidenceWriter.UpsertNetworkCapture(capture);

    public void UpsertZeekNetworkArtifact(ZeekNetworkRecord artifact)
        => _networkEvidenceWriter.UpsertZeekNetworkArtifact(artifact);

    public void UpsertFilesystemArtifact(FilesystemArtifactRecord artifact)
        => _filesystemEvidenceWriter.UpsertFilesystemArtifact(artifact);

    public void UpsertMemoryDumps(IEnumerable<MemoryDumpRecord> memoryDumps)
        => _dumpPeEvidenceWriter.UpsertMemoryDumps(memoryDumps);

    public void UpsertPeAnalyses(IEnumerable<PeAnalysisRecord> analyses)
        => _dumpPeEvidenceWriter.UpsertPeAnalyses(analyses);

    public void InsertAuthenticodeVerification(AuthenticodeVerificationRecord verification)
        => _dumpPeEvidenceWriter.InsertAuthenticodeVerification(verification);

    public void InsertAuthenticodeVerifications(IEnumerable<AuthenticodeVerificationRecord> verifications)
        => _dumpPeEvidenceWriter.InsertAuthenticodeVerifications(verifications);

    public void UpsertMemoryImages(IEnumerable<MemoryImageRecord> memoryImages)
        => _systemMemoryEvidenceWriter.UpsertMemoryImages(memoryImages);

    public void UpsertVolatilityPluginRuns(IEnumerable<VolatilityPluginRunRecord> pluginRuns)
        => _systemMemoryEvidenceWriter.UpsertVolatilityPluginRuns(pluginRuns);

    public void UpsertMemoryProcesses(IEnumerable<MemoryProcessRecord> processes)
        => _systemMemoryEvidenceWriter.UpsertMemoryProcesses(processes);

    public void UpsertNetworkCaptures(IEnumerable<NetworkCaptureRecord> networkCaptures)
        => _networkEvidenceWriter.UpsertNetworkCaptures(networkCaptures);

    public void UpsertZeekNetworkArtifacts(IEnumerable<ZeekNetworkRecord> artifacts)
        => _networkEvidenceWriter.UpsertZeekNetworkArtifacts(artifacts);

    public void UpsertFilesystemArtifacts(IEnumerable<FilesystemArtifactRecord> artifacts)
        => _filesystemEvidenceWriter.UpsertFilesystemArtifacts(artifacts);

    public void ReplaceWithSnapshot(IEvidenceStoreSnapshot snapshot)
    {
        lock (_lock)
        {
            using var transaction = Connection.BeginTransaction();
            _activeTransaction = transaction;
            try
            {
                ClearTables(preserveSourceCatalog: true);
                foreach (var process in snapshot.Processes)
                {
                    UpsertProcess(process);
                }

                foreach (var processEvent in snapshot.Events)
                {
                    AddEvent(processEvent);
                }

                foreach (var module in snapshot.Modules)
                {
                    UpsertModule(module);
                }

                foreach (var handle in snapshot.Handles)
                {
                    UpsertHandle(handle);
                }

                foreach (var memoryDump in snapshot.MemoryDumps)
                {
                    UpsertMemoryDump(memoryDump);
                }

                foreach (var analysis in snapshot.PeAnalyses)
                {
                    UpsertPeAnalysis(analysis);
                }

                foreach (var capture in snapshot.NetworkCaptures)
                {
                    UpsertNetworkCapture(capture);
                }

                foreach (var artifact in snapshot.ZeekNetworkArtifacts)
                {
                    UpsertZeekNetworkArtifact(artifact);
                }

                foreach (var artifact in snapshot.FilesystemArtifacts)
                {
                    UpsertFilesystemArtifact(artifact);
                }

                foreach (var image in snapshot.MemoryImages)
                {
                    UpsertMemoryImage(image);
                }

                foreach (var run in snapshot.VolatilityPluginRuns)
                {
                    UpsertVolatilityPluginRun(run);
                }

                foreach (var process in snapshot.MemoryProcesses)
                {
                    UpsertMemoryProcess(process);
                }

                transaction.Commit();
            }
            finally
            {
                _activeTransaction = null;
            }
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            using var transaction = Connection.BeginTransaction();
            _activeTransaction = transaction;
            try
            {
                ClearTables();
                transaction.Commit();
            }
            finally
            {
                _activeTransaction = null;
            }
        }
    }

    public int EnsureSource(
        string sourceType,
        string displayName,
        string? path = null,
        string? provider = null,
        string? channel = null,
        bool isLive = false,
        string status = "Active",
        string? metadataJson = null,
        EvidenceIdentity? identity = null)
    {
        if (string.IsNullOrWhiteSpace(sourceType))
        {
            throw new ArgumentException("Source type is required.", nameof(sourceType));
        }

        if (string.IsNullOrWhiteSpace(displayName))
        {
            throw new ArgumentException("Display name is required.", nameof(displayName));
        }

        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var resolvedIdentity = ResolveEvidenceIdentity(
                IdentityCarrier.FromIdentity(identity),
                sourceType,
                displayName);
            using (var insert = CreateCommand("""
                INSERT INTO Sources(
                    SourceIdentityId, CaseId, EvidenceSessionId, CaptureId, HostId, ExecutionRootId,
                    SourceType, DisplayName, Path, Provider, Channel, IsLive, Status,
                    StartTimeUtc, CreatedUtc, UpdatedUtc, MetadataJson)
                VALUES(
                    $SourceIdentityId, $CaseId, $EvidenceSessionId, $CaptureId, $HostId, $ExecutionRootId,
                    $SourceType, $DisplayName, $Path, $Provider, $Channel, $IsLive, $Status,
                    $StartTimeUtc, $CreatedUtc, $UpdatedUtc, $MetadataJson)
                ON CONFLICT(SourceType, DisplayName) DO UPDATE SET
                    SourceIdentityId = excluded.SourceIdentityId,
                    CaseId = excluded.CaseId,
                    EvidenceSessionId = excluded.EvidenceSessionId,
                    CaptureId = excluded.CaptureId,
                    HostId = excluded.HostId,
                    ExecutionRootId = excluded.ExecutionRootId,
                    Path = COALESCE(excluded.Path, Sources.Path),
                    Provider = COALESCE(excluded.Provider, Sources.Provider),
                    Channel = COALESCE(excluded.Channel, Sources.Channel),
                    IsLive = excluded.IsLive,
                    Status = excluded.Status,
                    StartTimeUtc = excluded.StartTimeUtc,
                    EndTimeUtc = NULL,
                    UpdatedUtc = excluded.UpdatedUtc,
                    MetadataJson = COALESCE(excluded.MetadataJson, Sources.MetadataJson);
                """))
            {
                AddEvidenceIdentityParameters(insert, resolvedIdentity);
                Add(insert, "$SourceType", sourceType);
                Add(insert, "$DisplayName", displayName);
                Add(insert, "$Path", path);
                Add(insert, "$Provider", provider);
                Add(insert, "$Channel", channel);
                Add(insert, "$IsLive", isLive ? 1 : 0);
                Add(insert, "$Status", status);
                Add(insert, "$StartTimeUtc", now);
                Add(insert, "$CreatedUtc", now);
                Add(insert, "$UpdatedUtc", now);
                Add(insert, "$MetadataJson", metadataJson);
                insert.ExecuteNonQuery();
            }

            using var select = CreateCommand("SELECT SourceId FROM Sources WHERE SourceType = $SourceType AND DisplayName = $DisplayName;");
            Add(select, "$SourceType", sourceType);
            Add(select, "$DisplayName", displayName);
            return Convert.ToInt32(select.ExecuteScalar());
        }
    }

    public SourceRunRegistration CreateSourceRun(SourceRunDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (string.IsNullOrWhiteSpace(descriptor.SourceRunId))
        {
            throw new ArgumentException("Source run ID is required.", nameof(descriptor));
        }

        var suppliedIdentity = new EvidenceIdentity
        {
            CaseId = descriptor.CaseId,
            EvidenceSessionId = descriptor.EvidenceSessionId,
            CaptureId = descriptor.CaptureId,
            SourceIdentityId = descriptor.SourceIdentityId,
            HostId = descriptor.HostId,
            ExecutionRootId = descriptor.ExecutionRootId
        };
        var sourceId = EnsureSource(
            descriptor.SourceType,
            descriptor.DisplayName,
            string.IsNullOrWhiteSpace(descriptor.SourcePath) ? null : descriptor.SourcePath,
            string.IsNullOrWhiteSpace(descriptor.Provider) ? null : descriptor.Provider,
            string.IsNullOrWhiteSpace(descriptor.Channel) ? null : descriptor.Channel,
            descriptor.IsLive,
            "Active",
            identity: suppliedIdentity);

        lock (_lock)
        {
            var identity = ResolveEvidenceIdentity(
                IdentityCarrier.FromIdentity(suppliedIdentity),
                descriptor.SourceType,
                descriptor.DisplayName);
            var now = DateTime.UtcNow;
            using (var command = CreateCommand("""
                INSERT OR IGNORE INTO SourceRuns(
                    SourceRunId, SourceId, IngestionJobId, CaseId, EvidenceSessionId, CaptureId,
                    SourceIdentityId, HostId, ExecutionRootId, SourceType, DisplayName, SourcePath,
                    Provider, Channel, ConfigurationHash, IsLive, Status, StartedUtc, ToolVersion,
                    ParserVersion, MetadataJson, CreatedUtc, UpdatedUtc)
                VALUES(
                    $SourceRunId, $SourceId, $IngestionJobId, $CaseId, $EvidenceSessionId, $CaptureId,
                    $SourceIdentityId, $HostId, $ExecutionRootId, $SourceType, $DisplayName, $SourcePath,
                    $Provider, $Channel, $ConfigurationHash, $IsLive, 'Active', $StartedUtc, $ToolVersion,
                    $ParserVersion, $MetadataJson, $CreatedUtc, $UpdatedUtc);
                """))
            {
                Add(command, "$SourceRunId", descriptor.SourceRunId);
                Add(command, "$SourceId", sourceId);
                Add(command, "$IngestionJobId", descriptor.IngestionJobId?.ToString("D"));
                AddEvidenceIdentityParameters(command, identity);
                Add(command, "$SourceType", descriptor.SourceType);
                Add(command, "$DisplayName", descriptor.DisplayName);
                Add(command, "$SourcePath", descriptor.SourcePath);
                Add(command, "$Provider", descriptor.Provider);
                Add(command, "$Channel", descriptor.Channel);
                Add(command, "$ConfigurationHash", descriptor.ConfigurationHash);
                Add(command, "$IsLive", descriptor.IsLive ? 1 : 0);
                Add(command, "$StartedUtc", descriptor.StartedUtc == default ? now : descriptor.StartedUtc);
                Add(command, "$ToolVersion", descriptor.ToolVersion);
                Add(command, "$ParserVersion", descriptor.ParserVersion);
                Add(command, "$MetadataJson", SanitizeSourceRunMetadata(descriptor.MetadataJson));
                Add(command, "$CreatedUtc", now);
                Add(command, "$UpdatedUtc", now);
                command.ExecuteNonQuery();
            }

            if (!string.IsNullOrWhiteSpace(descriptor.ParentSourceRunId) ||
                !string.IsNullOrWhiteSpace(descriptor.InputArtifactId) ||
                !string.IsNullOrWhiteSpace(descriptor.InputPath) ||
                !string.IsNullOrWhiteSpace(descriptor.InputHash))
            {
                using var lineage = CreateCommand("""
                    INSERT OR IGNORE INTO SourceRunLineage(
                        SourceRunId, ParentSourceRunId, InputArtifactId, InputPath, InputHash, RelationType, CreatedUtc)
                    VALUES($SourceRunId, $ParentSourceRunId, $InputArtifactId, $InputPath, $InputHash, 'DerivedFrom', $CreatedUtc);
                    """);
                Add(lineage, "$SourceRunId", descriptor.SourceRunId);
                Add(lineage, "$ParentSourceRunId", string.IsNullOrWhiteSpace(descriptor.ParentSourceRunId) ? null : descriptor.ParentSourceRunId);
                Add(lineage, "$InputArtifactId", string.IsNullOrWhiteSpace(descriptor.InputArtifactId) ? null : descriptor.InputArtifactId);
                Add(lineage, "$InputPath", string.IsNullOrWhiteSpace(descriptor.InputPath) ? null : descriptor.InputPath);
                Add(lineage, "$InputHash", string.IsNullOrWhiteSpace(descriptor.InputHash) ? null : descriptor.InputHash);
                Add(lineage, "$CreatedUtc", now);
                lineage.ExecuteNonQuery();
            }

            return new SourceRunRegistration(sourceId, descriptor.SourceRunId);
        }
    }

    public void CreateIngestionJob(
        Guid jobId,
        int? sourceId,
        string sourceRunId,
        JobKind jobKind,
        string parametersJson,
        string progressMessage = "Queued")
    {
        lock (_lock)
        {
            using var command = CreateCommand("""
                INSERT INTO IngestionJobs(
                    JobId, SourceId, SourceRunId, CaseId, EvidenceSessionId, CaptureId, HostId, ExecutionRootId,
                    JobType, Status, ProgressCurrent, ProgressTotal, ProgressMessage, CreatedUtc, ParametersJson)
                VALUES(
                    $JobId, $SourceId, $SourceRunId,
                    (SELECT CaseId FROM SourceRuns WHERE SourceRunId = $SourceRunId),
                    (SELECT EvidenceSessionId FROM SourceRuns WHERE SourceRunId = $SourceRunId),
                    (SELECT CaptureId FROM SourceRuns WHERE SourceRunId = $SourceRunId),
                    (SELECT HostId FROM SourceRuns WHERE SourceRunId = $SourceRunId),
                    (SELECT ExecutionRootId FROM SourceRuns WHERE SourceRunId = $SourceRunId),
                    $JobType, $Status, 0, -1, $ProgressMessage, $CreatedUtc, $ParametersJson);
                """);
            Add(command, "$JobId", jobId.ToString("D"));
            Add(command, "$SourceId", sourceId);
            Add(command, "$SourceRunId", sourceRunId);
            Add(command, "$JobType", jobKind.ToString());
            Add(command, "$Status", JobState.Queued.ToString());
            Add(command, "$ProgressMessage", progressMessage);
            Add(command, "$CreatedUtc", DateTime.UtcNow);
            Add(command, "$ParametersJson", parametersJson);
            command.ExecuteNonQuery();
        }
    }

    public void UpdateIngestionJob(
        Guid jobId,
        JobState state,
        long progressCurrent,
        long progressTotal,
        string? progressMessage,
        string? errorMessage = null)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var terminal = IsTerminalJobState(state);
            using var command = CreateCommand("""
                UPDATE IngestionJobs
                SET Status = $Status,
                    ProgressCurrent = $ProgressCurrent,
                    ProgressTotal = $ProgressTotal,
                    ProgressMessage = $ProgressMessage,
                    StartedUtc = CASE
                        WHEN $Status = 'Running' AND StartedUtc IS NULL THEN $Now
                        ELSE StartedUtc
                    END,
                    CompletedUtc = CASE
                        WHEN $IsTerminal = 1 THEN $Now
                        ELSE CompletedUtc
                    END,
                    ErrorMessage = $ErrorMessage
                WHERE JobId = $JobId;
                """);
            Add(command, "$JobId", jobId.ToString("D"));
            Add(command, "$Status", state.ToString());
            Add(command, "$ProgressCurrent", progressCurrent);
            Add(command, "$ProgressTotal", progressTotal);
            Add(command, "$ProgressMessage", progressMessage);
            Add(command, "$Now", now);
            Add(command, "$IsTerminal", terminal ? 1 : 0);
            Add(command, "$ErrorMessage", string.IsNullOrWhiteSpace(errorMessage) ? null : errorMessage);
            command.ExecuteNonQuery();
        }
    }

    public void UpdateSourceStatus(int sourceId, string status, DateTime? endTimeUtc = null, string? metadataJson = null)
    {
        lock (_lock)
        {
            using var command = CreateCommand("""
                UPDATE Sources
                SET Status = $Status,
                    EndTimeUtc = COALESCE($EndTimeUtc, EndTimeUtc),
                    UpdatedUtc = $UpdatedUtc,
                    MetadataJson = COALESCE($MetadataJson, MetadataJson)
                WHERE SourceId = $SourceId;
                """);
            Add(command, "$SourceId", sourceId);
            Add(command, "$Status", status);
            Add(command, "$EndTimeUtc", endTimeUtc);
            Add(command, "$UpdatedUtc", DateTime.UtcNow);
            Add(command, "$MetadataJson", metadataJson);
            command.ExecuteNonQuery();
        }
    }

    public long GetNextEventSequenceId()
    {
        lock (_lock)
        {
            using var command = CreateCommand("SELECT COALESCE(MAX(SequenceId), 0) + 1 FROM ProcessEvents;");
            return Convert.ToInt64(command.ExecuteScalar());
        }
    }

    public long GetNextModuleSequenceId()
    {
        lock (_lock)
        {
            using var command = CreateCommand("SELECT COALESCE(MAX(SequenceId), 0) + 1 FROM Modules;");
            return Convert.ToInt64(command.ExecuteScalar());
        }
    }

    public long GetNextHandleSequenceId()
    {
        lock (_lock)
        {
            using var command = CreateCommand("SELECT COALESCE(MAX(SequenceId), 0) + 1 FROM Handles;");
            return Convert.ToInt64(command.ExecuteScalar());
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _connection?.Dispose();
            _connection = null;
            _openContext = null;
            _artifactKind = CaptureArtifactKind.Unknown;
        }
    }

    private SqliteConnection Connection => _connection ?? throw new InvalidOperationException("SQLite staging store has not been initialized.");

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
            if (string.Equals(
                    reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                    columnName,
                    StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private void EnsureCanonicalSchemaObjects()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS SchemaInfo (
                Key TEXT PRIMARY KEY,
                Value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS SchemaMigrations (
                MigrationId TEXT PRIMARY KEY,
                AppliedUtc TEXT NOT NULL,
                Description TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS Sources (
                SourceId INTEGER PRIMARY KEY AUTOINCREMENT,
                SourceIdentityId TEXT,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceType TEXT NOT NULL,
                DisplayName TEXT NOT NULL,
                Path TEXT,
                Provider TEXT,
                Channel TEXT,
                StartTimeUtc TEXT,
                EndTimeUtc TEXT,
                IsLive INTEGER NOT NULL DEFAULT 0,
                Status TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL,
                UpdatedUtc TEXT NOT NULL,
                MetadataJson TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS IX_Sources_Type_DisplayName ON Sources(SourceType, DisplayName);
            CREATE TABLE IF NOT EXISTS SourceRuns (
                SourceRunId TEXT PRIMARY KEY,
                SourceId INTEGER NOT NULL,
                IngestionJobId TEXT,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceType TEXT NOT NULL,
                DisplayName TEXT NOT NULL,
                SourcePath TEXT,
                Provider TEXT,
                Channel TEXT,
                ConfigurationHash TEXT,
                IsLive INTEGER NOT NULL DEFAULT 0,
                Status TEXT NOT NULL,
                StartedUtc TEXT NOT NULL,
                EndedUtc TEXT,
                ToolVersion TEXT,
                ParserVersion TEXT,
                MetadataJson TEXT NOT NULL DEFAULT '{}',
                CreatedUtc TEXT NOT NULL,
                UpdatedUtc TEXT NOT NULL,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS SourceRunLineage (
                SourceRunId TEXT NOT NULL,
                ParentSourceRunId TEXT,
                InputArtifactId TEXT,
                InputPath TEXT,
                InputHash TEXT,
                RelationType TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL,
                PRIMARY KEY(SourceRunId, RelationType, ParentSourceRunId, InputArtifactId, InputPath, InputHash),
                FOREIGN KEY(SourceRunId) REFERENCES SourceRuns(SourceRunId),
                FOREIGN KEY(ParentSourceRunId) REFERENCES SourceRuns(SourceRunId)
            );
            CREATE TABLE IF NOT EXISTS WriterProvenanceContext (
                SingletonId INTEGER PRIMARY KEY CHECK(SingletonId = 1),
                SourceRunId TEXT NOT NULL,
                IngestionJobId TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS IngestionJobs (
                JobId TEXT PRIMARY KEY,
                SourceId INTEGER,
                SourceRunId TEXT,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                JobType TEXT NOT NULL,
                Status TEXT NOT NULL,
                ProgressCurrent INTEGER NOT NULL DEFAULT 0,
                ProgressTotal INTEGER NOT NULL DEFAULT 0,
                ProgressMessage TEXT,
                CreatedUtc TEXT NOT NULL,
                StartedUtc TEXT,
                CompletedUtc TEXT,
                ErrorMessage TEXT,
                ParametersJson TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS Processes (
                ProcessKey TEXT PRIMARY KEY,
                ProcessEntityId TEXT,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                ArtifactId TEXT,
                SourceId INTEGER,
                ProcessId INTEGER NOT NULL,
                ProcessGuid TEXT,
                StartTimeUtc TEXT,
                EndTimeUtc TEXT,
                Status TEXT NOT NULL,
                ParentProcessId INTEGER,
                ParentProcessKey TEXT,
                ParentProcessEntityId TEXT,
                ParentProcessName TEXT,
                ProcessName TEXT,
                ProcessPath TEXT,
                CommandLine TEXT,
                UserName TEXT,
                SessionId INTEGER,
                Architecture TEXT,
                CpuUsage REAL,
                MemoryUsageBytes INTEGER,
                CompanyName TEXT,
                FileDescription TEXT,
                Sha256Hash TEXT,
                TreeDepth INTEGER,
                FirstObservedUtc TEXT,
                LastObservedUtc TEXT,
                LastSource TEXT,
                ModuleCaptureStatus TEXT,
                ModuleCount INTEGER NOT NULL DEFAULT 0,
                ModuleLastCapturedUtc TEXT,
                ModuleCaptureError TEXT,
                HandleCaptureStatus TEXT,
                HandleCount INTEGER NOT NULL DEFAULT 0,
                HandleLastCapturedUtc TEXT,
                HandleCaptureError TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS ProcessEntities (
                ProcessEntityId TEXT PRIMARY KEY,
                ProcessKey TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                ArtifactId TEXT,
                SourceId INTEGER,
                ProcessId INTEGER NOT NULL,
                ProcessGuid TEXT,
                StartTimeUtc TEXT,
                EndTimeUtc TEXT,
                Status TEXT NOT NULL,
                ParentProcessId INTEGER,
                ParentProcessKey TEXT,
                ParentProcessEntityId TEXT,
                ParentProcessName TEXT,
                ProcessName TEXT,
                ProcessPath TEXT,
                CommandLine TEXT,
                UserName TEXT,
                SessionId INTEGER,
                Architecture TEXT,
                CpuUsage REAL,
                MemoryUsageBytes INTEGER,
                CompanyName TEXT,
                FileDescription TEXT,
                Sha256Hash TEXT,
                TreeDepth INTEGER,
                FirstObservedUtc TEXT,
                LastObservedUtc TEXT,
                LastSource TEXT,
                ModuleCaptureStatus TEXT,
                ModuleCount INTEGER NOT NULL DEFAULT 0,
                ModuleLastCapturedUtc TEXT,
                ModuleCaptureError TEXT,
                HandleCaptureStatus TEXT,
                HandleCount INTEGER NOT NULL DEFAULT 0,
                HandleLastCapturedUtc TEXT,
                HandleCaptureError TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS IX_ProcessEntities_ExactNaturalIdentity
                ON ProcessEntities(CaseId, EvidenceSessionId, HostId, ExecutionRootId, ProcessId, StartTimeUtc)
                WHERE StartTimeUtc IS NOT NULL AND StartTimeUtc <> '';
            CREATE INDEX IF NOT EXISTS IX_ProcessEntities_LegacyKey ON ProcessEntities(ProcessKey);
            CREATE INDEX IF NOT EXISTS IX_ProcessEntities_Parent ON ProcessEntities(ParentProcessEntityId);
            CREATE TABLE IF NOT EXISTS ProcessAliases (
                ProcessAliasId INTEGER PRIMARY KEY AUTOINCREMENT,
                ProcessEntityId TEXT NOT NULL,
                AliasKind TEXT NOT NULL,
                AliasValue TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceIdentityId TEXT,
                CreatedUtc TEXT NOT NULL,
                UNIQUE(ProcessEntityId, AliasKind, AliasValue, SourceIdentityId),
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessEntities(ProcessEntityId)
            );
            CREATE INDEX IF NOT EXISTS IX_ProcessAliases_ScopedLookup
                ON ProcessAliases(CaseId, EvidenceSessionId, HostId, ExecutionRootId, AliasKind, AliasValue);
            CREATE TABLE IF NOT EXISTS ProcessObservations (
                ObservationId TEXT PRIMARY KEY,
                AdapterId TEXT NOT NULL DEFAULT '',
                ObservationKind TEXT NOT NULL DEFAULT 'LegacyCompatibility',
                ProcessEntityId TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceRunId TEXT,
                IngestionJobId TEXT,
                RawRecordId TEXT,
                SourceNativeAlias TEXT NOT NULL,
                ObservedUtc TEXT NOT NULL,
                ValidFromUtc TEXT,
                ValidToUtc TEXT,
                StatusAssertion TEXT NOT NULL,
                CorrelationMethod TEXT NOT NULL,
                CorrelationConfidence REAL NOT NULL,
                ParserVersion TEXT,
                FieldStatesJson TEXT NOT NULL DEFAULT '{}',
                MetadataJson TEXT NOT NULL DEFAULT '{}',
                PayloadJson TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL,
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessEntities(ProcessEntityId),
                FOREIGN KEY(SourceRunId) REFERENCES SourceRuns(SourceRunId)
            );
            CREATE INDEX IF NOT EXISTS IX_ProcessObservations_EntityObserved
                ON ProcessObservations(ProcessEntityId, ObservedUtc, ObservationId);
            CREATE INDEX IF NOT EXISTS IX_ProcessObservations_SourceRun
                ON ProcessObservations(SourceRunId, ObservationId);
            CREATE TABLE IF NOT EXISTS ProcessProjectionFields (
                ProcessEntityId TEXT NOT NULL,
                FieldName TEXT NOT NULL,
                ObservationId TEXT NOT NULL,
                SourceRunId TEXT,
                ValueQuality INTEGER NOT NULL,
                ResolutionReason TEXT NOT NULL,
                ProjectionVersion TEXT NOT NULL,
                UpdatedUtc TEXT NOT NULL,
                PRIMARY KEY(ProcessEntityId, FieldName),
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessEntities(ProcessEntityId),
                FOREIGN KEY(ObservationId) REFERENCES ProcessObservations(ObservationId)
            );
            CREATE INDEX IF NOT EXISTS IX_ProcessProjectionFields_Observation
                ON ProcessProjectionFields(ObservationId);
            CREATE TABLE IF NOT EXISTS ProcessStatistics (
                SampleId TEXT PRIMARY KEY,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                ProcessKey TEXT NOT NULL,
                ProcessId INTEGER NOT NULL,
                ProcessGuid TEXT,
                ProcessName TEXT,
                Status TEXT NOT NULL,
                ObservedUtc TEXT NOT NULL,
                TotalProcessorTimeTicks INTEGER,
                UserProcessorTimeTicks INTEGER,
                PrivilegedProcessorTimeTicks INTEGER,
                ReadBytes INTEGER,
                WrittenBytes INTEGER,
                CollectionError TEXT,
                Source TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS ProcessEvents (
                SequenceId INTEGER PRIMARY KEY,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                ArtifactId TEXT,
                SourceId INTEGER,
                RawRecordId INTEGER,
                TimestampUtc TEXT NOT NULL,
                Source TEXT,
                ProcessKey TEXT,
                ProcessId INTEGER,
                ProcessGuid TEXT,
                ProcessStartTimeUtc TEXT,
                ProcessName TEXT,
                ParentProcessId INTEGER,
                EventCode INTEGER,
                Category TEXT,
                Action TEXT,
                Target TEXT,
                Summary TEXT,
                Details TEXT,
                RiskFlags TEXT,
                IsInteresting INTEGER,
                RepeatCount INTEGER,
                RawProvider TEXT,
                RawLogName TEXT,
                RawRecordIdText TEXT,
                CorrelationMethod TEXT,
                DedupKey TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS Modules (
                SequenceId INTEGER,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                ArtifactId TEXT,
                SourceId INTEGER,
                ProcessKey TEXT NOT NULL,
                ProcessId INTEGER,
                ProcessGuid TEXT,
                ModuleKey TEXT PRIMARY KEY,
                ModuleName TEXT,
                FullPath TEXT,
                BaseAddress TEXT,
                ModuleMemorySize INTEGER,
                FileVersion TEXT,
                CompanyName TEXT,
                Description TEXT,
                Sha256Hash TEXT,
                FirstSeenUtc TEXT,
                LastSeenUtc TEXT,
                UnloadedUtc TEXT,
                State TEXT,
                Sources TEXT,
                LastSource TEXT,
                DedupKey TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS Handles (
                SequenceId INTEGER,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                ArtifactId TEXT,
                SourceId INTEGER,
                ProcessKey TEXT NOT NULL,
                ProcessId INTEGER,
                HandleKey TEXT PRIMARY KEY,
                HandleValue TEXT,
                HandleValueNumeric INTEGER,
                ObjectType TEXT,
                ObjectName TEXT,
                GrantedAccess TEXT,
                GrantedAccessValue INTEGER,
                HandleAttributes TEXT,
                HandleAttributesValue INTEGER,
                ObjectAddress TEXT,
                FirstSeenUtc TEXT,
                LastSeenUtc TEXT,
                ClosedUtc TEXT,
                State TEXT,
                LastSource TEXT,
                DedupKey TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS MemoryDumps (
                DumpId TEXT PRIMARY KEY,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                JobId TEXT,
                ProcessKey TEXT NOT NULL,
                ProcessId INTEGER,
                ProcessGuid TEXT,
                ProcessName TEXT,
                DumpKind TEXT NOT NULL,
                Status TEXT NOT NULL,
                RequestedUtc TEXT NOT NULL,
                CompletedUtc TEXT,
                OutputDirectory TEXT,
                FilePath TEXT,
                FileSizeBytes INTEGER NOT NULL DEFAULT 0,
                Sha256Hash TEXT,
                ToolName TEXT,
                ErrorMessage TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS PeAnalyses (
                AnalysisId TEXT PRIMARY KEY,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                ProcessKey TEXT NOT NULL,
                ProcessId INTEGER,
                ProcessGuid TEXT,
                ProcessName TEXT,
                SourceKind TEXT NOT NULL,
                SourceArtifactId TEXT,
                FilePath TEXT,
                Status TEXT NOT NULL,
                AnalyzedUtc TEXT NOT NULL,
                FileSizeBytes INTEGER NOT NULL DEFAULT 0,
                FileLastWriteUtc TEXT,
                Sha256Hash TEXT,
                Md5Hash TEXT,
                Machine TEXT,
                Subsystem TEXT,
                PeKind TEXT,
                LinkerTimestampUtc TEXT,
                EntryPoint TEXT,
                ImageBase TEXT,
                SectionCount INTEGER NOT NULL DEFAULT 0,
                ImportCount INTEGER NOT NULL DEFAULT 0,
                ExportCount INTEGER NOT NULL DEFAULT 0,
                PrintableStringCount INTEGER NOT NULL DEFAULT 0,
                StringAnalysisStatus TEXT NOT NULL DEFAULT 'Completed',
                SectionsJson TEXT,
                ImportsJson TEXT,
                ExportsJson TEXT,
                VersionInfoJson TEXT,
                StringSummaryJson TEXT,
                ErrorMessage TEXT,
                PerformanceJson TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS MemoryImages (
                ImageId TEXT PRIMARY KEY,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                JobId TEXT,
                Status TEXT NOT NULL,
                ImportedUtc TEXT NOT NULL,
                SourcePath TEXT,
                FilePath TEXT,
                DisplayName TEXT,
                ImageFormat TEXT,
                FileSizeBytes INTEGER NOT NULL DEFAULT 0,
                Sha256Hash TEXT,
                HostName TEXT,
                OsBuild TEXT,
                AcquisitionTool TEXT,
                AcquisitionToolVersion TEXT,
                AcquisitionCommandLine TEXT,
                PrivilegeState TEXT,
                ErrorMessage TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS VolatilityPluginRuns (
                RunId TEXT PRIMARY KEY,
                ImageId TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                JobId TEXT,
                PluginName TEXT NOT NULL,
                Status TEXT NOT NULL,
                RequestedUtc TEXT NOT NULL,
                StartedUtc TEXT,
                CompletedUtc TEXT,
                VolatilityPath TEXT,
                VolatilityVersion TEXT,
                CommandLine TEXT,
                OutputDirectory TEXT,
                StdoutPath TEXT,
                StderrPath TEXT,
                RawOutputHash TEXT,
                SymbolsPath TEXT,
                ProfileOrLayer TEXT,
                NormalizedRowCount INTEGER NOT NULL DEFAULT 0,
                ErrorMessage TEXT,
                FOREIGN KEY(ImageId) REFERENCES MemoryImages(ImageId),
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS MemoryProcesses (
                ArtifactId TEXT PRIMARY KEY,
                ImageId TEXT NOT NULL,
                PluginRunId TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                PluginName TEXT,
                EvidenceKind TEXT,
                RowNumber INTEGER NOT NULL DEFAULT 0,
                ObjectOffset TEXT,
                ProcessId INTEGER NOT NULL DEFAULT 0,
                ParentProcessId INTEGER NOT NULL DEFAULT 0,
                ProcessName TEXT,
                ImagePath TEXT,
                CommandLine TEXT,
                CreateTimeUtc TEXT,
                ExitTimeUtc TEXT,
                SessionId INTEGER NOT NULL DEFAULT 0,
                ThreadCount INTEGER NOT NULL DEFAULT 0,
                HandleCount INTEGER NOT NULL DEFAULT 0,
                Wow64 TEXT,
                ProcessKey TEXT,
                CorrelationState TEXT,
                CorrelationMethod TEXT,
                CorrelationConfidence REAL NOT NULL DEFAULT 0,
                RawRowHash TEXT,
                RawJson TEXT,
                FOREIGN KEY(ImageId) REFERENCES MemoryImages(ImageId),
                FOREIGN KEY(PluginRunId) REFERENCES VolatilityPluginRuns(RunId),
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS NetworkCaptures (
                CaptureId TEXT PRIMARY KEY,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                JobId TEXT,
                SegmentIndex INTEGER NOT NULL DEFAULT 1,
                Status TEXT NOT NULL,
                RequestedUtc TEXT NOT NULL,
                StartedUtc TEXT,
                CompletedUtc TEXT,
                OutputDirectory TEXT,
                EtlFilePath TEXT,
                FilePath TEXT,
                FileSizeBytes INTEGER NOT NULL DEFAULT 0,
                Sha256Hash TEXT,
                ToolName TEXT,
                CaptureSource TEXT,
                FilterDescription TEXT,
                ErrorMessage TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS ZeekNetworkArtifacts (
                ArtifactId TEXT PRIMARY KEY,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                CaptureId TEXT,
                JobId TEXT,
                Status TEXT NOT NULL,
                TimestampUtc TEXT NOT NULL,
                LogType TEXT,
                ZeekUid TEXT,
                SourceIp TEXT,
                SourcePort INTEGER NOT NULL DEFAULT 0,
                DestinationIp TEXT,
                DestinationPort INTEGER NOT NULL DEFAULT 0,
                Protocol TEXT,
                Service TEXT,
                DnsQuery TEXT,
                HttpMethod TEXT,
                HttpHost TEXT,
                HttpUri TEXT,
                DurationSeconds REAL NOT NULL DEFAULT 0,
                OrigBytes INTEGER NOT NULL DEFAULT 0,
                RespBytes INTEGER NOT NULL DEFAULT 0,
                OrigPackets INTEGER NOT NULL DEFAULT 0,
                RespPackets INTEGER NOT NULL DEFAULT 0,
                OrigIpBytes INTEGER NOT NULL DEFAULT 0,
                RespIpBytes INTEGER NOT NULL DEFAULT 0,
                ConnectionState TEXT,
                History TEXT,
                ServerName TEXT,
                ClientProtocol TEXT,
                TlsVersion TEXT,
                TlsCipher TEXT,
                TlsEstablished INTEGER NOT NULL DEFAULT 0,
                WeirdName TEXT,
                WeirdAdditional TEXT,
                Summary TEXT,
                ProcessKey TEXT,
                ProcessId INTEGER NOT NULL DEFAULT 0,
                ProcessName TEXT,
                CorrelationMethod TEXT,
                CorrelationConfidence REAL NOT NULL DEFAULT 0,
                RawLogPath TEXT,
                RawLineNumber INTEGER NOT NULL DEFAULT 0,
                RawLineHash TEXT,
                RawText TEXT,
                ErrorMessage TEXT,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS RawRecords (
                RawRecordId INTEGER PRIMARY KEY AUTOINCREMENT,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                ExternalRecordId TEXT,
                TimestampUtc TEXT,
                RecordType TEXT,
                PayloadJson TEXT,
                PayloadText TEXT,
                PayloadHash TEXT,
                CreatedUtc TEXT NOT NULL,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE TABLE IF NOT EXISTS Artifacts (
                ArtifactId TEXT PRIMARY KEY,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                ArtifactType TEXT NOT NULL,
                SourceId INTEGER,
                TimestampUtc TEXT,
                Name TEXT,
                Path TEXT,
                Summary TEXT,
                Hash TEXT,
                ProcessKey TEXT,
                ParentArtifactId TEXT,
                CreatedUtc TEXT NOT NULL,
                UpdatedUtc TEXT NOT NULL,
                RawRecordId INTEGER,
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId),
                FOREIGN KEY(RawRecordId) REFERENCES RawRecords(RawRecordId)
            );
            CREATE TABLE IF NOT EXISTS ArtifactProperties (
                ArtifactId TEXT NOT NULL,
                Name TEXT NOT NULL,
                Value TEXT,
                ValueType TEXT NOT NULL,
                PRIMARY KEY(ArtifactId, Name),
                FOREIGN KEY(ArtifactId) REFERENCES Artifacts(ArtifactId)
            );
            CREATE TABLE IF NOT EXISTS ArtifactRelations (
                FromArtifactId TEXT NOT NULL,
                ToArtifactId TEXT NOT NULL,
                RelationType TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL,
                PRIMARY KEY(FromArtifactId, ToArtifactId, RelationType)
            );
            CREATE TABLE IF NOT EXISTS EvidenceRelations (
                RelationId TEXT PRIMARY KEY,
                DecisionKey TEXT NOT NULL,
                FromKind TEXT NOT NULL,
                FromId TEXT NOT NULL,
                ToKind TEXT NOT NULL,
                ToId TEXT NOT NULL,
                RelationType TEXT NOT NULL,
                CorrelationState TEXT NOT NULL,
                CorrelationMethod TEXT,
                Confidence REAL NOT NULL,
                CandidateCount INTEGER NOT NULL DEFAULT 0,
                CorrelationDiagnostics TEXT,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceRunId TEXT,
                IngestionJobId TEXT,
                RawInputId TEXT,
                ObservedFromUtc TEXT NOT NULL,
                ObservedToUtc TEXT,
                ValidFromUtc TEXT,
                ValidToUtc TEXT,
                ResolverName TEXT NOT NULL,
                ResolverVersion TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL,
                UpdatedUtc TEXT NOT NULL,
                Status TEXT NOT NULL,
                SupersededByRelationId TEXT,
                AnalystAnnotationId TEXT,
                FOREIGN KEY(SourceRunId) REFERENCES SourceRuns(SourceRunId)
            );
            CREATE INDEX IF NOT EXISTS IX_EvidenceRelations_From
                ON EvidenceRelations(FromKind, FromId, Status, ObservedFromUtc DESC);
            CREATE INDEX IF NOT EXISTS IX_EvidenceRelations_To
                ON EvidenceRelations(ToKind, ToId, Status, ObservedFromUtc DESC);
            CREATE INDEX IF NOT EXISTS IX_EvidenceRelations_Decision
                ON EvidenceRelations(DecisionKey, Status, ResolverVersion);
            CREATE INDEX IF NOT EXISTS IX_EvidenceRelations_SourceRun
                ON EvidenceRelations(SourceRunId, ObservedFromUtc DESC);
            CREATE INDEX IF NOT EXISTS IX_EvidenceRelations_Timeline
                ON EvidenceRelations(ObservedFromUtc DESC, RelationId);
            CREATE TABLE IF NOT EXISTS EvidenceCorrelationInputs (
                InputId TEXT PRIMARY KEY,
                EvidenceKind TEXT NOT NULL,
                EvidenceId TEXT NOT NULL,
                EvidenceType TEXT,
                Source TEXT,
                RelationType TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceRunId TEXT,
                IngestionJobId TEXT,
                RawInputId TEXT,
                ProcessId INTEGER,
                ProcessStartTimeUtc TEXT,
                ProcessGuid TEXT,
                ProcessName TEXT,
                ProcessPath TEXT,
                SourceNativeId TEXT,
                SourceEndpoint TEXT,
                DestinationEndpoint TEXT,
                ObservedUtc TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL,
                UNIQUE(EvidenceKind, EvidenceId)
            );
            CREATE INDEX IF NOT EXISTS IX_EvidenceCorrelationInputs_Process
                ON EvidenceCorrelationInputs(ProcessId, ProcessGuid, ObservedUtc, InputId);
            CREATE INDEX IF NOT EXISTS IX_EvidenceCorrelationInputs_Scope
                ON EvidenceCorrelationInputs(CaseId, EvidenceSessionId, HostId, ExecutionRootId, ObservedUtc, InputId);
            CREATE INDEX IF NOT EXISTS IX_EvidenceCorrelationInputs_Group
                ON EvidenceCorrelationInputs(EvidenceKind, Source, ObservedUtc, InputId);
            CREATE TABLE IF NOT EXISTS Bookmarks (
                BookmarkId TEXT PRIMARY KEY,
                TargetKind TEXT NOT NULL,
                TargetId TEXT NOT NULL,
                ProcessKey TEXT,
                ProcessId INTEGER,
                ProcessName TEXT,
                Label TEXT,
                Notes TEXT,
                Tags TEXT,
                CreatedUtc TEXT NOT NULL,
                UpdatedUtc TEXT NOT NULL,
                UNIQUE(TargetKind, TargetId)
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS SearchIndex USING fts5(
                Kind UNINDEXED,
                RecordKey UNINDEXED,
                ProcessKey UNINDEXED,
                ProcessId UNINDEXED,
                ProcessName UNINDEXED,
                TimestampUtc UNINDEXED,
                Source UNINDEXED,
                Title UNINDEXED,
                Subtitle UNINDEXED,
                StatusText,
                ProcessNameText,
                PathText,
                CommandLineText,
                UserText,
                CompanyText,
                DescriptionText,
                Sha256Text,
                ParentText,
                TargetText,
                SummaryText,
                DetailsText,
                RiskFlagsText,
                EventCodeText,
                ActionText,
                CategoryText,
                ProcessGuidText,
                ModuleNameText,
                FileVersionText,
                BaseAddressText,
                ObjectTypeText,
                ObjectNameText,
                GrantedAccessText,
                HandleText,
                SearchText,
                tokenize='unicode61'
            );
            """);
    }

    internal void ApplyCatalogMigration(
        string migrationId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(migrationId, "021_evidence_recorrelation", StringComparison.Ordinal))
        {
            EnsureCanonicalSchemaObjects();
        }

        switch (migrationId)
        {
            case "001_initial_sqlite_staging":
                InitializeCurrentSchemaInfo();
                break;
            case "002_phase3c_listing_indexes":
            case "011_v3_sqlite_live_indexes":
                SqlitePerformanceProfile.EnsureLiveIndexes(Connection);
                break;
            case "003_phase5f_bookmarks":
            case "004_phase6b_search_index":
            case "005_phase6d_memory_dumps":
            case "006_phase6f_pe_analysis":
            case "007_phase6g_network_captures":
            case "008_phase6h_zeek_artifacts":
            case "009_phase6i_filesystem_artifacts":
            case "012_v3_memory_volatility":
            case "012_v3_sqlite_analysis_indexes":
                break;
            case "010_v2_evidence_identity":
                EnsureEvidenceIdentityColumns();
                UpsertDefaultIdentitySchemaInfo();
                BackfillEvidenceIdentityColumns();
                break;
            case "013_v3_zeek_flow_context":
                EnsureZeekNetworkArtifactContextColumns();
                break;
            case "014_pe_file_freshness":
                EnsureColumn("PeAnalyses", "FileLastWriteUtc", "TEXT");
                break;
            case "015_pe_string_analysis_state":
                EnsureColumn("PeAnalyses", "StringAnalysisStatus", "TEXT NOT NULL DEFAULT 'Completed'");
                break;
            case "016_pe_analysis_performance":
                EnsureColumn("PeAnalyses", "PerformanceJson", "TEXT NOT NULL DEFAULT '{}'");
                break;
            case "017_process_entity_identity":
                EnsureProcessIdentityColumns();
                BackfillProcessEntityIdentity();
                EnsureProcessEntityLinkTriggers();
                break;
            case "018_source_run_provenance":
                EnsureSourceRunProvenanceSchema();
                BackfillSourceRunProvenance();
                EnsureSourceRunProvenanceTriggers();
                break;
            case "019_process_observations_projection":
                EnsureProcessIdentityColumns();
                EnsureSourceRunProvenanceSchema();
                _processEvidenceWriter.BackfillProcessObservations();
                UpsertSchemaInfo("ProcessProjectionVersion", ProcessProjectionPolicy.Version);
                UpsertSchemaInfo("ProcessProjectionLastRebuildUtc", FormatDate(DateTime.UtcNow));
                EnsureProcessEntityLinkTriggers();
                break;
            case "020_evidence_relations":
                BackfillEvidenceRelations();
                EnsureEvidenceRelationTriggers();
                break;
            case "021_evidence_recorrelation":
                EnsureEvidenceCorrelationSchema();
                BackfillEvidenceCorrelationInputs();
                break;
            case "022_process_source_pipeline":
                EnsureColumn("ProcessObservations", "AdapterId", "TEXT NOT NULL DEFAULT ''");
                EnsureColumn("ProcessObservations", "ObservationKind", "TEXT NOT NULL DEFAULT 'LegacyCompatibility'");
                break;
            case "023_process_attached_evidence":
                EnsureProcessAttachedEvidenceSchema();
                BackfillProcessAttachedEvidenceRelations();
                break;
            case "024_independent_artifact_lineage":
                EnsureIndependentArtifactLineageSchema();
                BackfillIndependentArtifactLineage();
                break;
            case "025_authenticode_verification":
                EnsureAuthenticodeVerificationSchema();
                break;
            case "026_process_risk_projection":
                EnsureProcessRiskProjectionSchema();
                break;
            case "027_sigma_risk_inputs":
                EnsureSigmaRiskInputSchema();
                break;
            case "028_baseline_risk_inputs":
                EnsureBaselineRiskInputSchema();
                break;
            case "029_yara_analysis_results":
                EnsureYaraAnalysisSchema();
                break;
            case "030_yara_risk_inputs":
                EnsureYaraRiskInputSchema();
                break;
            case "031_reputation_attributions":
                EnsureReputationAttributionSchema();
                break;
            case "032_infrastructure_evidence_outbox":
                EnsureInfrastructureEvidenceOutboxSchema();
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(migrationId),
                    migrationId,
                    "Unknown SQLite evidence migration ID.");
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private void EnsureInfrastructureEvidenceOutboxSchema()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS InfrastructureEvidenceOutbox (
                Sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                SchemaVersion INTEGER NOT NULL,
                OutboxId TEXT NOT NULL UNIQUE,
                WriterInstanceId TEXT NOT NULL,
                WriterCommitGeneration INTEGER NOT NULL,
                OperationName TEXT NOT NULL,
                ApproximateRowCount INTEGER NOT NULL,
                CommittedAtUtc TEXT NOT NULL,
                State TEXT NOT NULL,
                BatchId TEXT NOT NULL DEFAULT '',
                ManifestSha256 TEXT NOT NULL DEFAULT '',
                PackageSha256 TEXT NOT NULL DEFAULT '',
                AcknowledgementOutcome TEXT NOT NULL DEFAULT 'Unknown',
                ServerCommitId TEXT NOT NULL DEFAULT '',
                ServerReceiptTimeUtc TEXT,
                StateChangedAtUtc TEXT NOT NULL,
                RetryCount INTEGER NOT NULL DEFAULT 0,
                LastErrorCode TEXT NOT NULL DEFAULT '',
                UNIQUE(WriterInstanceId, WriterCommitGeneration),
                CHECK(SchemaVersion = 1),
                CHECK(WriterCommitGeneration > 0),
                CHECK(ApproximateRowCount >= 0),
                CHECK(RetryCount >= 0),
                CHECK(State IN ('Pending', 'Spooled', 'AcknowledgedCleanupPending', 'Completed', 'Quarantined'))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS IX_InfrastructureEvidenceOutbox_BatchId
                ON InfrastructureEvidenceOutbox(BatchId)
                WHERE BatchId <> '';
            CREATE INDEX IF NOT EXISTS IX_InfrastructureEvidenceOutbox_StateSequence
                ON InfrastructureEvidenceOutbox(State, Sequence);
            """);
    }

    public InfrastructureEvidenceOutboxEntry BindInfrastructureEvidenceOutboxPackage(
        InfrastructureEvidenceOutboxPackageBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ValidatePackageBinding(binding);
        lock (_lock)
        {
            EnsureInfrastructureOutboxTransitionContext();
            var current = GetInfrastructureOutbox(binding.OutboxId)
                ?? throw new InvalidDataException("The evidence outbox entry does not exist.");
            if (current.State == InfrastructureEvidenceOutboxState.Spooled &&
                ExactPackageBinding(current, binding))
            {
                return current;
            }
            if (current.State != InfrastructureEvidenceOutboxState.Pending)
            {
                throw new InvalidDataException("The evidence outbox package binding would regress or replace durable state.");
            }

            using var command = CreateCommand("""
                UPDATE InfrastructureEvidenceOutbox
                SET State = $State,
                    BatchId = $BatchId,
                    ManifestSha256 = $ManifestSha256,
                    PackageSha256 = $PackageSha256,
                    StateChangedAtUtc = $StateChangedAtUtc,
                    LastErrorCode = ''
                WHERE OutboxId = $OutboxId AND State = 'Pending';
                """);
            Add(command, "$State", InfrastructureEvidenceOutboxState.Spooled.ToString());
            Add(command, "$BatchId", binding.BatchId);
            Add(command, "$ManifestSha256", binding.ManifestSha256);
            Add(command, "$PackageSha256", binding.PackageSha256);
            Add(command, "$StateChangedAtUtc", binding.BoundAtUtc);
            Add(command, "$OutboxId", binding.OutboxId.ToString("N"));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new InvalidDataException("The evidence outbox package binding lost its expected pending state.");
            }
            return GetInfrastructureOutbox(binding.OutboxId)!;
        }
    }

    public InfrastructureEvidenceOutboxEntry RecordInfrastructureEvidenceOutboxAcknowledgement(
        InfrastructureEvidenceOutboxAcknowledgement acknowledgement)
    {
        ArgumentNullException.ThrowIfNull(acknowledgement);
        ValidateOutboxAcknowledgement(acknowledgement);
        lock (_lock)
        {
            EnsureInfrastructureOutboxTransitionContext();
            var current = GetInfrastructureOutbox(acknowledgement.OutboxId)
                ?? throw new InvalidDataException("The evidence outbox entry does not exist.");
            if (current.State is InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending or
                InfrastructureEvidenceOutboxState.Completed)
            {
                if (ExactAcknowledgement(current, acknowledgement))
                {
                    return current;
                }
                throw new InvalidDataException("The evidence outbox acknowledgement conflicts with the durable receipt.");
            }
            if (current.State != InfrastructureEvidenceOutboxState.Spooled ||
                !ExactPackageBinding(current, acknowledgement))
            {
                throw new InvalidDataException("The evidence outbox acknowledgement does not match one spooled package.");
            }

            using var command = CreateCommand("""
                UPDATE InfrastructureEvidenceOutbox
                SET State = $State,
                    AcknowledgementOutcome = $AcknowledgementOutcome,
                    ServerCommitId = $ServerCommitId,
                    ServerReceiptTimeUtc = $ServerReceiptTimeUtc,
                    StateChangedAtUtc = $StateChangedAtUtc,
                    LastErrorCode = ''
                WHERE OutboxId = $OutboxId AND State = 'Spooled';
                """);
            Add(command, "$State", InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending.ToString());
            Add(command, "$AcknowledgementOutcome", acknowledgement.Outcome.ToString());
            Add(command, "$ServerCommitId", acknowledgement.ServerCommitId);
            Add(command, "$ServerReceiptTimeUtc", acknowledgement.ServerReceiptTimeUtc);
            Add(command, "$StateChangedAtUtc", acknowledgement.RecordedAtUtc);
            Add(command, "$OutboxId", acknowledgement.OutboxId.ToString("N"));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new InvalidDataException("The evidence outbox acknowledgement lost its expected spooled state.");
            }
            return GetInfrastructureOutbox(acknowledgement.OutboxId)!;
        }
    }

    public InfrastructureEvidenceOutboxEntry CompleteInfrastructureEvidenceOutboxCleanup(
        Guid outboxId,
        DateTime completedAtUtc)
    {
        if (outboxId == Guid.Empty)
        {
            throw new ArgumentException("The evidence outbox identity is required.", nameof(outboxId));
        }
        InfrastructureEvidenceOutboxPolicy.RequireUtc(completedAtUtc, nameof(completedAtUtc));
        lock (_lock)
        {
            EnsureInfrastructureOutboxTransitionContext();
            var current = GetInfrastructureOutbox(outboxId)
                ?? throw new InvalidDataException("The evidence outbox entry does not exist.");
            if (current.State == InfrastructureEvidenceOutboxState.Completed)
            {
                return current;
            }
            if (current.State != InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending)
            {
                throw new InvalidDataException("Evidence outbox cleanup cannot complete before durable acknowledgement.");
            }

            using var command = CreateCommand("""
                UPDATE InfrastructureEvidenceOutbox
                SET State = 'Completed', StateChangedAtUtc = $StateChangedAtUtc, LastErrorCode = ''
                WHERE OutboxId = $OutboxId AND State = 'AcknowledgedCleanupPending';
                """);
            Add(command, "$StateChangedAtUtc", completedAtUtc);
            Add(command, "$OutboxId", outboxId.ToString("N"));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new InvalidDataException("The evidence outbox cleanup lost its acknowledged state.");
            }
            return GetInfrastructureOutbox(outboxId)!;
        }
    }

    public InfrastructureEvidenceOutboxEntry QuarantineInfrastructureEvidenceOutbox(
        Guid outboxId,
        string errorCode,
        DateTime quarantinedAtUtc)
    {
        if (outboxId == Guid.Empty)
        {
            throw new ArgumentException("The evidence outbox identity is required.", nameof(outboxId));
        }
        errorCode = InfrastructureEvidenceOutboxPolicy.NormalizeErrorCode(errorCode);
        if (errorCode.Length == 0)
        {
            throw new InvalidDataException("A quarantine error code is required.");
        }
        InfrastructureEvidenceOutboxPolicy.RequireUtc(quarantinedAtUtc, nameof(quarantinedAtUtc));
        lock (_lock)
        {
            EnsureInfrastructureOutboxTransitionContext();
            var current = GetInfrastructureOutbox(outboxId)
                ?? throw new InvalidDataException("The evidence outbox entry does not exist.");
            if (current.State == InfrastructureEvidenceOutboxState.Quarantined &&
                string.Equals(current.LastErrorCode, errorCode, StringComparison.Ordinal))
            {
                return current;
            }
            if (current.State is InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending or
                InfrastructureEvidenceOutboxState.Completed)
            {
                throw new InvalidDataException("A durably acknowledged outbox entry cannot be quarantined.");
            }

            using var command = CreateCommand("""
                UPDATE InfrastructureEvidenceOutbox
                SET State = 'Quarantined',
                    StateChangedAtUtc = $StateChangedAtUtc,
                    RetryCount = RetryCount + 1,
                    LastErrorCode = $LastErrorCode
                WHERE OutboxId = $OutboxId AND State IN ('Pending', 'Spooled');
                """);
            Add(command, "$StateChangedAtUtc", quarantinedAtUtc);
            Add(command, "$LastErrorCode", errorCode);
            Add(command, "$OutboxId", outboxId.ToString("N"));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new InvalidDataException("The evidence outbox quarantine lost its expected state.");
            }
            return GetInfrastructureOutbox(outboxId)!;
        }
    }

    private InfrastructureEvidenceOutboxEntry InsertInfrastructureOutbox(InfrastructureEvidenceOutboxCommit commit)
    {
        using var command = CreateCommand("""
            INSERT INTO InfrastructureEvidenceOutbox(
                SchemaVersion, OutboxId, WriterInstanceId, WriterCommitGeneration,
                OperationName, ApproximateRowCount, CommittedAtUtc, State, StateChangedAtUtc)
            VALUES(
                $SchemaVersion, $OutboxId, $WriterInstanceId, $WriterCommitGeneration,
                $OperationName, $ApproximateRowCount, $CommittedAtUtc, 'Pending', $CommittedAtUtc);
            """);
        Add(command, "$SchemaVersion", InfrastructureEvidenceOutboxPolicy.CurrentSchemaVersion);
        Add(command, "$OutboxId", commit.OutboxId.ToString("N"));
        Add(command, "$WriterInstanceId", commit.WriterInstanceId.ToString("N"));
        Add(command, "$WriterCommitGeneration", commit.WriterCommitGeneration);
        Add(command, "$OperationName", commit.OperationName);
        Add(command, "$ApproximateRowCount", commit.ApproximateRowCount);
        Add(command, "$CommittedAtUtc", commit.CommittedAtUtc);
        if (command.ExecuteNonQuery() != 1)
        {
            throw new InvalidDataException("The evidence outbox commit could not be recorded.");
        }
        return GetInfrastructureOutbox(commit.OutboxId)!;
    }

    private InfrastructureEvidenceOutboxEntry? GetInfrastructureOutbox(Guid outboxId)
    {
        using var command = CreateCommand("""
            SELECT Sequence, SchemaVersion, OutboxId, WriterInstanceId, WriterCommitGeneration,
                   OperationName, ApproximateRowCount, CommittedAtUtc, State, BatchId,
                   ManifestSha256, PackageSha256, AcknowledgementOutcome, ServerCommitId,
                   ServerReceiptTimeUtc, StateChangedAtUtc, RetryCount, LastErrorCode
            FROM InfrastructureEvidenceOutbox
            WHERE OutboxId = $OutboxId;
            """);
        Add(command, "$OutboxId", outboxId.ToString("N"));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadInfrastructureOutbox(reader) : null;
    }

    private static InfrastructureEvidenceOutboxEntry ReadInfrastructureOutbox(SqliteDataReader reader)
    {
        if (!Guid.TryParseExact(reader.GetString(2), "N", out var outboxId) ||
            !Guid.TryParseExact(reader.GetString(3), "N", out var writerInstanceId) ||
            !DateTime.TryParse(reader.GetString(7), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out var committedAtUtc) || committedAtUtc.Kind != DateTimeKind.Utc ||
            !Enum.TryParse<InfrastructureEvidenceOutboxState>(reader.GetString(8), out var state) ||
            !Enum.TryParse<InfrastructureEvidenceTransferOutcome>(reader.GetString(12), out var outcome) ||
            !DateTime.TryParse(reader.GetString(15), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out var stateChangedAtUtc) || stateChangedAtUtc.Kind != DateTimeKind.Utc)
        {
            throw new InvalidDataException("The durable evidence outbox row is malformed.");
        }

        DateTime? serverReceiptTimeUtc = null;
        if (!reader.IsDBNull(14))
        {
            if (!DateTime.TryParse(reader.GetString(14), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                    out var parsedReceipt) || parsedReceipt.Kind != DateTimeKind.Utc)
            {
                throw new InvalidDataException("The durable evidence outbox receipt time is malformed.");
            }
            serverReceiptTimeUtc = parsedReceipt;
        }

        var entry = new InfrastructureEvidenceOutboxEntry
        {
            Sequence = reader.GetInt64(0),
            SchemaVersion = reader.GetInt32(1),
            OutboxId = outboxId,
            WriterInstanceId = writerInstanceId,
            WriterCommitGeneration = reader.GetInt64(4),
            OperationName = reader.GetString(5),
            ApproximateRowCount = reader.GetInt64(6),
            CommittedAtUtc = committedAtUtc,
            State = state,
            BatchId = reader.GetString(9),
            ManifestSha256 = reader.GetString(10),
            PackageSha256 = reader.GetString(11),
            AcknowledgementOutcome = outcome,
            ServerCommitId = reader.GetString(13),
            ServerReceiptTimeUtc = serverReceiptTimeUtc,
            StateChangedAtUtc = stateChangedAtUtc,
            RetryCount = reader.GetInt32(16),
            LastErrorCode = reader.GetString(17)
        };
        ValidateReadInfrastructureOutbox(entry);
        return entry;
    }

    private static void ValidateReadInfrastructureOutbox(InfrastructureEvidenceOutboxEntry entry)
    {
        if (entry.SchemaVersion != InfrastructureEvidenceOutboxPolicy.CurrentSchemaVersion ||
            entry.Sequence <= 0 || entry.OutboxId == Guid.Empty || entry.WriterInstanceId == Guid.Empty ||
            entry.WriterCommitGeneration <= 0 || entry.ApproximateRowCount < 0 ||
            entry.RetryCount is < 0 or > InfrastructureEvidenceOutboxPolicy.MaxRetryCount ||
            !Enum.IsDefined(entry.State) || !Enum.IsDefined(entry.AcknowledgementOutcome) ||
            !string.Equals(
                InfrastructureEvidenceOutboxPolicy.NormalizeOperationName(entry.OperationName),
                entry.OperationName,
                StringComparison.Ordinal) ||
            !string.Equals(
                InfrastructureEvidenceOutboxPolicy.NormalizeErrorCode(entry.LastErrorCode),
                entry.LastErrorCode,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("The durable evidence outbox row violates its schema bounds.");
        }

        var hasPackage = InfrastructureEvidenceBatchCodec.IsIdentifier(entry.BatchId) &&
                         InfrastructureEvidenceBatchCodec.IsSha256(entry.ManifestSha256) &&
                         InfrastructureEvidenceBatchCodec.IsSha256(entry.PackageSha256);
        var hasNoPackage = entry.BatchId.Length == 0 && entry.ManifestSha256.Length == 0 &&
                           entry.PackageSha256.Length == 0;
        var hasAcknowledgement = (entry.AcknowledgementOutcome is
                                      InfrastructureEvidenceTransferOutcome.Committed or
                                      InfrastructureEvidenceTransferOutcome.DuplicateCommitted) &&
                                 InfrastructureEvidenceBatchCodec.IsIdentifier(entry.ServerCommitId) &&
                                 entry.ServerReceiptTimeUtc != null;
        var hasNoAcknowledgement = entry.AcknowledgementOutcome == InfrastructureEvidenceTransferOutcome.Unknown &&
                                   entry.ServerCommitId.Length == 0 && entry.ServerReceiptTimeUtc == null;

        var validState = entry.State switch
        {
            InfrastructureEvidenceOutboxState.Pending =>
                hasNoPackage && hasNoAcknowledgement && entry.RetryCount == 0 && entry.LastErrorCode.Length == 0,
            InfrastructureEvidenceOutboxState.Spooled =>
                hasPackage && hasNoAcknowledgement && entry.RetryCount == 0 && entry.LastErrorCode.Length == 0,
            InfrastructureEvidenceOutboxState.AcknowledgedCleanupPending or
                InfrastructureEvidenceOutboxState.Completed =>
                hasPackage && hasAcknowledgement && entry.LastErrorCode.Length == 0,
            InfrastructureEvidenceOutboxState.Quarantined =>
                (hasPackage || hasNoPackage) && hasNoAcknowledgement && entry.RetryCount > 0 &&
                entry.LastErrorCode.Length > 0,
            _ => false
        };
        if (!validState)
        {
            throw new InvalidDataException("The durable evidence outbox row has an inconsistent state payload.");
        }
    }

    private void EnsureInfrastructureOutboxReadable()
    {
        EnsureOpenRole(CaptureOpenContext.AgentWritableLive, CaptureArtifactKind.LiveAuthoritativeDatabase);
        if (_infrastructureOutboxOwnerId == Guid.Empty || !TableExists(Connection, "InfrastructureEvidenceOutbox"))
        {
            throw new InvalidOperationException("The transactional evidence outbox is not active.");
        }
    }

    private void EnsureInfrastructureOutboxTransitionContext()
    {
        EnsureInfrastructureOutboxReadable();
        if (_activeTransaction == null || _activeInfrastructureOutboxOwnerId != _infrastructureOutboxOwnerId)
        {
            throw new InvalidOperationException("Evidence outbox state changes must cross the serialized Agent writer transaction.");
        }
    }

    private static void ValidateOutboxCommit(InfrastructureEvidenceOutboxCommit commit)
    {
        if (commit.OutboxId == Guid.Empty || commit.WriterInstanceId == Guid.Empty ||
            commit.WriterCommitGeneration <= 0 || commit.ApproximateRowCount < 0)
        {
            throw new InvalidDataException("The transactional evidence outbox commit identity is invalid.");
        }
        _ = InfrastructureEvidenceOutboxPolicy.NormalizeOperationName(commit.OperationName);
        InfrastructureEvidenceOutboxPolicy.RequireUtc(commit.CommittedAtUtc, nameof(commit.CommittedAtUtc));
    }

    private static void ValidatePackageBinding(InfrastructureEvidenceOutboxPackageBinding binding)
    {
        if (binding.OutboxId == Guid.Empty ||
            !InfrastructureEvidenceBatchCodec.IsIdentifier(binding.BatchId) ||
            !InfrastructureEvidenceBatchCodec.IsSha256(binding.ManifestSha256) ||
            !InfrastructureEvidenceBatchCodec.IsSha256(binding.PackageSha256))
        {
            throw new InvalidDataException("The evidence outbox package binding is invalid.");
        }
        InfrastructureEvidenceOutboxPolicy.RequireUtc(binding.BoundAtUtc, nameof(binding.BoundAtUtc));
    }

    private static void ValidateOutboxAcknowledgement(InfrastructureEvidenceOutboxAcknowledgement acknowledgement)
    {
        if (acknowledgement.OutboxId == Guid.Empty ||
            !InfrastructureEvidenceBatchCodec.IsIdentifier(acknowledgement.BatchId) ||
            !InfrastructureEvidenceBatchCodec.IsSha256(acknowledgement.ManifestSha256) ||
            !InfrastructureEvidenceBatchCodec.IsSha256(acknowledgement.PackageSha256) ||
            acknowledgement.Outcome is not (InfrastructureEvidenceTransferOutcome.Committed or
                InfrastructureEvidenceTransferOutcome.DuplicateCommitted) ||
            !InfrastructureEvidenceBatchCodec.IsIdentifier(acknowledgement.ServerCommitId))
        {
            throw new InvalidDataException("The evidence outbox Server acknowledgement is invalid.");
        }
        InfrastructureEvidenceOutboxPolicy.RequireUtc(
            acknowledgement.ServerReceiptTimeUtc,
            nameof(acknowledgement.ServerReceiptTimeUtc));
        InfrastructureEvidenceOutboxPolicy.RequireUtc(acknowledgement.RecordedAtUtc, nameof(acknowledgement.RecordedAtUtc));
    }

    private static bool ExactPackageBinding(
        InfrastructureEvidenceOutboxEntry current,
        InfrastructureEvidenceOutboxPackageBinding binding)
        => current.OutboxId == binding.OutboxId &&
           string.Equals(current.BatchId, binding.BatchId, StringComparison.Ordinal) &&
           string.Equals(current.ManifestSha256, binding.ManifestSha256, StringComparison.Ordinal) &&
           string.Equals(current.PackageSha256, binding.PackageSha256, StringComparison.Ordinal);

    private static bool ExactPackageBinding(
        InfrastructureEvidenceOutboxEntry current,
        InfrastructureEvidenceOutboxAcknowledgement acknowledgement)
        => current.OutboxId == acknowledgement.OutboxId &&
           string.Equals(current.BatchId, acknowledgement.BatchId, StringComparison.Ordinal) &&
           string.Equals(current.ManifestSha256, acknowledgement.ManifestSha256, StringComparison.Ordinal) &&
           string.Equals(current.PackageSha256, acknowledgement.PackageSha256, StringComparison.Ordinal);

    private static bool ExactAcknowledgement(
        InfrastructureEvidenceOutboxEntry current,
        InfrastructureEvidenceOutboxAcknowledgement acknowledgement)
        => ExactPackageBinding(current, acknowledgement) &&
           current.AcknowledgementOutcome == acknowledgement.Outcome &&
           string.Equals(current.ServerCommitId, acknowledgement.ServerCommitId, StringComparison.Ordinal) &&
           current.ServerReceiptTimeUtc == acknowledgement.ServerReceiptTimeUtc;

    private void InitializeCurrentSchemaInfo()
    {
        var evidenceFormatVersion = CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion
            .ToString(CultureInfo.InvariantCulture);
        UpsertSchemaInfo("SchemaVersion", evidenceFormatVersion);
        UpsertSchemaInfo("EvidenceFormatVersion", evidenceFormatVersion);
        UpsertSchemaInfo("ApplicationVersion", typeof(SqliteStagingStore).Assembly.GetName().Version?.ToString() ?? "unknown");
        UpsertSchemaInfo("LastOpenedUtc", FormatDate(DateTime.UtcNow));
        UpsertSchemaInfo("DefaultSqlitePerformanceProfile", SqlitePerformanceProfileName.Conservative.ToString());
        UpsertSchemaInfo("SearchIndexMaintenance", "Deferred");
        UpsertDefaultIdentitySchemaInfo();

        using var command = CreateCommand("""
            INSERT OR IGNORE INTO SchemaInfo(Key, Value) VALUES('CreatedUtc', $CreatedUtc);
            INSERT OR IGNORE INTO SchemaInfo(Key, Value) VALUES('CaseId', $CaseId);
            """);
        Add(command, "$CreatedUtc", DateTime.UtcNow);
        Add(command, "$CaseId", Guid.NewGuid().ToString("N"));
        command.ExecuteNonQuery();
        UpsertDefaultIdentitySchemaInfo();
    }

    private void EnsureEvidenceCorrelationSchema()
    {
        EnsureColumn("EvidenceRelations", "CandidateCount", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn("EvidenceRelations", "CorrelationDiagnostics", "TEXT");
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS EvidenceCorrelationInputs (
                InputId TEXT PRIMARY KEY,
                EvidenceKind TEXT NOT NULL,
                EvidenceId TEXT NOT NULL,
                EvidenceType TEXT,
                Source TEXT,
                RelationType TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceRunId TEXT,
                IngestionJobId TEXT,
                RawInputId TEXT,
                ProcessId INTEGER,
                ProcessStartTimeUtc TEXT,
                ProcessGuid TEXT,
                ProcessName TEXT,
                ProcessPath TEXT,
                SourceNativeId TEXT,
                SourceEndpoint TEXT,
                DestinationEndpoint TEXT,
                ObservedUtc TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL,
                UNIQUE(EvidenceKind, EvidenceId)
            );
            CREATE INDEX IF NOT EXISTS IX_EvidenceCorrelationInputs_Process
                ON EvidenceCorrelationInputs(ProcessId, ProcessGuid, ObservedUtc, InputId);
            CREATE INDEX IF NOT EXISTS IX_EvidenceCorrelationInputs_Scope
                ON EvidenceCorrelationInputs(CaseId, EvidenceSessionId, HostId, ExecutionRootId, ObservedUtc, InputId);
            CREATE INDEX IF NOT EXISTS IX_EvidenceCorrelationInputs_Group
                ON EvidenceCorrelationInputs(EvidenceKind, Source, ObservedUtc, InputId);
            """);
    }

    private void BackfillEvidenceCorrelationInputs()
    {
        ExecuteNonQuery("""
            INSERT OR IGNORE INTO EvidenceCorrelationInputs (
                InputId, EvidenceKind, EvidenceId, EvidenceType, Source, RelationType,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ProcessId, ProcessStartTimeUtc,
                ProcessGuid, ProcessName, ProcessPath, SourceNativeId, SourceEndpoint,
                DestinationEndpoint, ObservedUtc, CreatedUtc)
            SELECT 'event:' || SequenceId, 'Event', CAST(SequenceId AS TEXT), Category, Source, 'ObservedProcess',
                   CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                   SourceRunId, IngestionJobId, COALESCE(RawRecordIdText, ''), ProcessId,
                   ProcessStartTimeUtc, ProcessGuid, ProcessName,
                   CASE WHEN Action = 'ProcessStart' THEN Target ELSE '' END, ProcessKey, '', '',
                   TimestampUtc, TimestampUtc
            FROM ProcessEvents;

            INSERT OR IGNORE INTO EvidenceCorrelationInputs (
                InputId, EvidenceKind, EvidenceId, EvidenceType, Source, RelationType,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ProcessId, ProcessStartTimeUtc,
                ProcessGuid, ProcessName, ProcessPath, SourceNativeId, SourceEndpoint,
                DestinationEndpoint, ObservedUtc, CreatedUtc)
            SELECT 'memory-process:' || mp.ArtifactId, 'MemoryProcess', mp.ArtifactId, mp.EvidenceKind,
                   COALESCE(NULLIF(s.DisplayName, ''), NULLIF(s.SourceType, ''), 'AgentVolatility'), 'CorrelatesWith',
                   mp.CaseId, mp.EvidenceSessionId, mp.CaptureId, mp.SourceIdentityId, mp.HostId, mp.ExecutionRootId,
                   mp.SourceRunId, mp.IngestionJobId, COALESCE(mp.RawRowHash, ''), mp.ProcessId, mp.CreateTimeUtc,
                   '', mp.ProcessName, mp.ImagePath, mp.ProcessKey, '', '',
                   COALESCE(mp.CreateTimeUtc, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP
            FROM MemoryProcesses mp
            LEFT JOIN Sources s ON s.SourceId = mp.SourceId;

            INSERT OR IGNORE INTO EvidenceCorrelationInputs (
                InputId, EvidenceKind, EvidenceId, EvidenceType, Source, RelationType,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ProcessId, ProcessStartTimeUtc,
                ProcessGuid, ProcessName, ProcessPath, SourceNativeId, SourceEndpoint,
                DestinationEndpoint, ObservedUtc, CreatedUtc)
            SELECT 'zeek:' || z.ArtifactId, 'NetworkFlow', z.ArtifactId, z.LogType,
                   COALESCE(NULLIF(s.DisplayName, ''), NULLIF(s.SourceType, ''), 'AgentZeek'), 'CorrelatesWith',
                   z.CaseId, z.EvidenceSessionId, z.CaptureId, z.SourceIdentityId, z.HostId, z.ExecutionRootId,
                   z.SourceRunId, z.IngestionJobId, COALESCE(z.RawLineHash, ''), z.ProcessId, NULL,
                   '', z.ProcessName, '', z.ProcessKey,
                   z.SourceIp || CASE WHEN z.SourcePort > 0 THEN ':' || z.SourcePort ELSE '' END,
                   z.DestinationIp || CASE WHEN z.DestinationPort > 0 THEN ':' || z.DestinationPort ELSE '' END,
                   z.TimestampUtc, z.TimestampUtc
            FROM ZeekNetworkArtifacts z
            LEFT JOIN Sources s ON s.SourceId = z.SourceId;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName,
                ResolverVersion, CreatedUtc, UpdatedUtc, Status, SupersededByRelationId,
                AnalystAnnotationId)
            SELECT 'correlation:unresolved:' || i.InputId,
                   CASE i.EvidenceKind
                       WHEN 'Event' THEN 'event:' || i.EvidenceId || ':process'
                       WHEN 'MemoryProcess' THEN 'memory-process:' || i.EvidenceId || ':process'
                       WHEN 'NetworkFlow' THEN 'zeek:' || i.EvidenceId || ':process'
                       ELSE 'correlation:' || i.EvidenceKind || ':' || i.EvidenceId || ':process'
                   END,
                   i.EvidenceKind, i.EvidenceId, 'ProcessEntity', '', i.RelationType,
                   'Unresolved', 'PendingDeterministicCorrelation', 0.0, 0,
                   'No active source assertion exists; bounded deterministic correlation has not found a scoped candidate.',
                   i.CaseId, i.EvidenceSessionId, i.CaptureId, i.SourceIdentityId, i.HostId,
                   i.ExecutionRootId, i.SourceRunId, i.IngestionJobId, i.RawInputId, i.ObservedUtc,
                   'DeterministicProcessCorrelation', 'process-correlation-v1', i.CreatedUtc,
                   i.CreatedUtc, 'Active', '', ''
            FROM EvidenceCorrelationInputs i
            WHERE NOT EXISTS (
                SELECT 1 FROM EvidenceRelations r
                WHERE r.DecisionKey = CASE i.EvidenceKind
                    WHEN 'Event' THEN 'event:' || i.EvidenceId || ':process'
                    WHEN 'MemoryProcess' THEN 'memory-process:' || i.EvidenceId || ':process'
                    WHEN 'NetworkFlow' THEN 'zeek:' || i.EvidenceId || ':process'
                    ELSE 'correlation:' || i.EvidenceKind || ':' || i.EvidenceId || ':process'
                END AND r.Status = 'Active');
            """);
    }

    private void BackfillEvidenceRelations()
    {
        ExecuteNonQuery("""
            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:event:' || e.SequenceId,
                   'event:' || e.SequenceId || ':process',
                   'ProcessEntity', e.ProcessEntityId, 'Event', CAST(e.SequenceId AS TEXT), 'ObservedProcess',
                   'Asserted', COALESCE(NULLIF(e.CorrelationMethod, ''), 'LegacyProcessKey'), 1.0,
                   e.CaseId, e.EvidenceSessionId, e.CaptureId, e.SourceIdentityId, e.HostId, e.ExecutionRootId,
                   e.SourceRunId, e.IngestionJobId, COALESCE(e.RawRecordIdText, ''), e.TimestampUtc,
                   'LegacyRelationMigration', 'evidence-relation-v1', e.TimestampUtc, e.TimestampUtc,
                   'Active', '', ''
            FROM ProcessEvents e
            WHERE COALESCE(e.ProcessEntityId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawInputId, ObservedFromUtc, ObservedToUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:module:' || m.ModuleKey,
                   'module:' || m.ModuleKey || ':process',
                   'ProcessEntity', m.ProcessEntityId, 'Module', m.ModuleKey, 'Loaded',
                   'Asserted', COALESCE(NULLIF(m.LastSource, ''), 'ModuleObservation'), 1.0,
                   m.CaseId, m.EvidenceSessionId, m.CaptureId, m.SourceIdentityId, m.HostId, m.ExecutionRootId,
                   m.SourceRunId, m.IngestionJobId, '', COALESCE(m.FirstSeenUtc, m.LastSeenUtc), m.UnloadedUtc,
                   'LegacyRelationMigration', 'evidence-relation-v1', COALESCE(m.FirstSeenUtc, m.LastSeenUtc),
                   COALESCE(m.LastSeenUtc, m.FirstSeenUtc), 'Active', '', ''
            FROM Modules m
            WHERE COALESCE(m.ProcessEntityId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawInputId, ObservedFromUtc, ObservedToUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:handle:' || h.HandleKey,
                   'handle:' || h.HandleKey || ':process',
                   'ProcessEntity', h.ProcessEntityId, 'Handle', h.HandleKey, 'Opened',
                   'Asserted', COALESCE(NULLIF(h.LastSource, ''), 'HandleObservation'), 1.0,
                   h.CaseId, h.EvidenceSessionId, h.CaptureId, h.SourceIdentityId, h.HostId, h.ExecutionRootId,
                   h.SourceRunId, h.IngestionJobId, '', COALESCE(h.FirstSeenUtc, h.LastSeenUtc), h.ClosedUtc,
                   'LegacyRelationMigration', 'evidence-relation-v1', COALESCE(h.FirstSeenUtc, h.LastSeenUtc),
                   COALESCE(h.LastSeenUtc, h.FirstSeenUtc), 'Active', '', ''
            FROM Handles h
            WHERE COALESCE(h.ProcessEntityId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:zeek-capture:' || z.ArtifactId,
                   'zeek:' || z.ArtifactId || ':capture',
                   'Capture', z.CaptureId, 'NetworkFlow', z.ArtifactId, 'ExtractedFrom',
                   'Asserted', 'ZeekAnalysis', 1.0,
                   z.CaseId, z.EvidenceSessionId, z.CaptureId, z.SourceIdentityId, z.HostId, z.ExecutionRootId,
                   z.SourceRunId, z.IngestionJobId, COALESCE(z.RawLineHash, ''), z.TimestampUtc,
                   'LegacyRelationMigration', 'evidence-relation-v1', z.TimestampUtc, z.TimestampUtc,
                   'Active', '', ''
            FROM ZeekNetworkArtifacts z
            WHERE COALESCE(z.CaptureId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:zeek-process:' || z.ArtifactId || ':' || COALESCE(z.ProcessEntityId, 'unresolved'),
                   'zeek:' || z.ArtifactId || ':process',
                   'NetworkFlow', z.ArtifactId, 'ProcessEntity', COALESCE(z.ProcessEntityId, ''), 'CorrelatesWith',
                   CASE
                       WHEN COALESCE(z.ProcessEntityId, '') = '' THEN 'Unresolved'
                       WHEN z.CorrelationConfidence >= 0.95 THEN 'Exact'
                       WHEN z.CorrelationConfidence >= 0.50 THEN 'Inferred'
                       ELSE 'Ambiguous'
                   END,
                   COALESCE(NULLIF(z.CorrelationMethod, ''), 'Unresolved'),
                   MIN(1.0, MAX(0.0, COALESCE(z.CorrelationConfidence, 0.0))),
                   z.CaseId, z.EvidenceSessionId, z.CaptureId, z.SourceIdentityId, z.HostId, z.ExecutionRootId,
                   z.SourceRunId, z.IngestionJobId, COALESCE(z.RawLineHash, ''), z.TimestampUtc,
                   'LegacyRelationMigration', 'evidence-relation-v1', z.TimestampUtc, z.TimestampUtc,
                   'Active', '', ''
            FROM ZeekNetworkArtifacts z;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:memory-run:' || v.RunId,
                   'memory-run:' || v.RunId || ':image',
                   'MemoryImage', v.ImageId, 'VolatilityPluginRun', v.RunId, 'DerivedFrom',
                   'Asserted', 'VolatilityPluginInput', 1.0,
                   v.CaseId, v.EvidenceSessionId, v.CaptureId, v.SourceIdentityId, v.HostId, v.ExecutionRootId,
                   v.SourceRunId, v.IngestionJobId, '', v.RequestedUtc,
                   'LegacyRelationMigration', 'evidence-relation-v1', v.RequestedUtc, COALESCE(v.CompletedUtc, v.RequestedUtc),
                   'Active', '', ''
            FROM VolatilityPluginRuns v
            WHERE COALESCE(v.ImageId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:memory-process-run:' || p.ArtifactId,
                   'memory-process:' || p.ArtifactId || ':run',
                   'VolatilityPluginRun', p.PluginRunId, 'MemoryProcess', p.ArtifactId, 'DerivedFrom',
                   'Asserted', 'VolatilityNormalization', 1.0,
                   p.CaseId, p.EvidenceSessionId, p.CaptureId, p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                   p.SourceRunId, p.IngestionJobId, COALESCE(p.RawRowHash, ''), COALESCE(p.CreateTimeUtc, CURRENT_TIMESTAMP),
                   'LegacyRelationMigration', 'evidence-relation-v1', COALESCE(p.CreateTimeUtc, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP,
                   'Active', '', ''
            FROM MemoryProcesses p
            WHERE COALESCE(p.PluginRunId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:memory-process:' || p.ArtifactId || ':' || COALESCE(p.ProcessEntityId, 'unresolved'),
                   'memory-process:' || p.ArtifactId || ':process',
                   'MemoryProcess', p.ArtifactId, 'ProcessEntity', COALESCE(p.ProcessEntityId, ''), 'CorrelatesWith',
                   CASE
                       WHEN COALESCE(p.ProcessEntityId, '') = '' OR p.CorrelationState IN ('Unknown', 'MemoryOnly') THEN 'Unresolved'
                       WHEN p.CorrelationState = 'Weak' THEN 'Ambiguous'
                       WHEN p.CorrelationConfidence >= 0.95 THEN 'Exact'
                       ELSE 'Inferred'
                   END,
                   COALESCE(NULLIF(p.CorrelationMethod, ''), 'Unresolved'),
                   MIN(1.0, MAX(0.0, COALESCE(p.CorrelationConfidence, 0.0))),
                   p.CaseId, p.EvidenceSessionId, p.CaptureId, p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                   p.SourceRunId, p.IngestionJobId, COALESCE(p.RawRowHash, ''), COALESCE(p.CreateTimeUtc, CURRENT_TIMESTAMP),
                   'LegacyRelationMigration', 'evidence-relation-v1', COALESCE(p.CreateTimeUtc, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP,
                   'Active', '', ''
            FROM MemoryProcesses p;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, ObservedFromUtc,
                ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:artifact:' || ar.FromArtifactId || ':' || ar.ToArtifactId || ':' || ar.RelationType,
                   'artifact:' || ar.FromArtifactId || ':' || ar.RelationType,
                   'GenericArtifact', ar.FromArtifactId, 'GenericArtifact', ar.ToArtifactId,
                   CASE ar.RelationType
                       WHEN 'Parent' THEN 'DerivedFrom'
                       WHEN 'DerivedFrom' THEN 'DerivedFrom'
                       ELSE 'CorrelatesWith'
                   END,
                   'Asserted', 'LegacyArtifactRelations', 1.0, ar.CreatedUtc,
                   'LegacyRelationMigration', 'evidence-relation-v1', ar.CreatedUtc, ar.CreatedUtc,
                   'Active', '', ''
            FROM ArtifactRelations ar;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'legacy:pe:' || p.AnalysisId || ':' || p.SourceArtifactId,
                   'pe:' || p.AnalysisId || ':input',
                   'FileArtifact', p.SourceArtifactId, 'PeAnalysis', p.AnalysisId, 'DerivedFrom',
                   'Asserted', p.SourceKind, 1.0,
                   p.CaseId, p.EvidenceSessionId, p.CaptureId, p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                   p.SourceRunId, p.IngestionJobId, p.AnalyzedUtc,
                   'LegacyRelationMigration', 'evidence-relation-v1', p.AnalyzedUtc, p.AnalyzedUtc,
                   'Active', '', ''
            FROM PeAnalyses p
            WHERE COALESCE(p.SourceArtifactId, '') <> '';
            """);
    }

    private void EnsureEvidenceRelationTriggers()
    {
        ExecuteNonQuery("""
            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_ProcessEvent_Insert
            AFTER INSERT ON ProcessEvents
            WHEN COALESCE(NEW.ProcessEntityId, '') <> ''
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES (
                    'legacy:event:' || NEW.SequenceId, 'event:' || NEW.SequenceId || ':process',
                    'ProcessEntity', NEW.ProcessEntityId, 'Event', CAST(NEW.SequenceId AS TEXT), 'ObservedProcess',
                    'Asserted', COALESCE(NULLIF(NEW.CorrelationMethod, ''), 'SourceAssertion'), 1.0,
                    NEW.CaseId, NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId,
                    NEW.ExecutionRootId, NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.RawRecordIdText, ''),
                    NEW.TimestampUtc, 'SourceAssertionProjection', 'evidence-relation-v1', NEW.TimestampUtc,
                    NEW.TimestampUtc, 'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_Module_Insert
            AFTER INSERT ON Modules
            WHEN COALESCE(NEW.ProcessEntityId, '') <> ''
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    ObservedFromUtc, ObservedToUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES (
                    'legacy:module:' || NEW.ModuleKey, 'module:' || NEW.ModuleKey || ':process',
                    'ProcessEntity', NEW.ProcessEntityId, 'Module', NEW.ModuleKey, 'Loaded', 'Asserted',
                    COALESCE(NULLIF(NEW.LastSource, ''), 'ModuleObservation'), 1.0,
                    NEW.CaseId, NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId,
                    NEW.ExecutionRootId, NEW.SourceRunId, NEW.IngestionJobId,
                    COALESCE(NEW.FirstSeenUtc, NEW.LastSeenUtc), NEW.UnloadedUtc,
                    'SourceAssertionProjection', 'evidence-relation-v1', COALESCE(NEW.FirstSeenUtc, NEW.LastSeenUtc),
                    COALESCE(NEW.LastSeenUtc, NEW.FirstSeenUtc), 'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_Handle_Insert
            AFTER INSERT ON Handles
            WHEN COALESCE(NEW.ProcessEntityId, '') <> ''
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    ObservedFromUtc, ObservedToUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES (
                    'legacy:handle:' || NEW.HandleKey, 'handle:' || NEW.HandleKey || ':process',
                    'ProcessEntity', NEW.ProcessEntityId, 'Handle', NEW.HandleKey, 'Opened', 'Asserted',
                    COALESCE(NULLIF(NEW.LastSource, ''), 'HandleObservation'), 1.0,
                    NEW.CaseId, NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId,
                    NEW.ExecutionRootId, NEW.SourceRunId, NEW.IngestionJobId,
                    COALESCE(NEW.FirstSeenUtc, NEW.LastSeenUtc), NEW.ClosedUtc,
                    'SourceAssertionProjection', 'evidence-relation-v1', COALESCE(NEW.FirstSeenUtc, NEW.LastSeenUtc),
                    COALESCE(NEW.LastSeenUtc, NEW.FirstSeenUtc), 'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_Zeek_Insert
            AFTER INSERT ON ZeekNetworkArtifacts
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                SELECT 'legacy:zeek-capture:' || NEW.ArtifactId, 'zeek:' || NEW.ArtifactId || ':capture',
                    'Capture', NEW.CaptureId, 'NetworkFlow', NEW.ArtifactId, 'ExtractedFrom', 'Asserted',
                    'ZeekAnalysis', 1.0, NEW.CaseId, NEW.EvidenceSessionId, NEW.CaptureId,
                    NEW.SourceIdentityId, NEW.HostId, NEW.ExecutionRootId, NEW.SourceRunId,
                    NEW.IngestionJobId, COALESCE(NEW.RawLineHash, ''), NEW.TimestampUtc,
                    'ZeekCorrelationProjection', 'evidence-relation-v1', NEW.TimestampUtc, NEW.TimestampUtc,
                    'Active', '', '' WHERE COALESCE(NEW.CaptureId, '') <> '';

                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES ('legacy:zeek-process:' || NEW.ArtifactId || ':' || COALESCE(NEW.ProcessEntityId, 'unresolved'),
                    'zeek:' || NEW.ArtifactId || ':process', 'NetworkFlow', NEW.ArtifactId,
                    'ProcessEntity', COALESCE(NEW.ProcessEntityId, ''), 'CorrelatesWith',
                    CASE WHEN COALESCE(NEW.ProcessEntityId, '') = '' THEN 'Unresolved'
                         WHEN NEW.CorrelationConfidence >= 0.95 THEN 'Exact'
                         WHEN NEW.CorrelationConfidence >= 0.50 THEN 'Inferred' ELSE 'Ambiguous' END,
                    COALESCE(NULLIF(NEW.CorrelationMethod, ''), 'Unresolved'),
                    MIN(1.0, MAX(0.0, COALESCE(NEW.CorrelationConfidence, 0.0))),
                    NEW.CaseId, NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId,
                    NEW.ExecutionRootId, NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.RawLineHash, ''),
                    NEW.TimestampUtc, 'ZeekCorrelationProjection', 'evidence-relation-v1', NEW.TimestampUtc,
                    NEW.TimestampUtc, 'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_VolatilityRun_Insert
            AFTER INSERT ON VolatilityPluginRuns
            WHEN COALESCE(NEW.ImageId, '') <> ''
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                    SupersededByRelationId, AnalystAnnotationId)
                VALUES ('legacy:memory-run:' || NEW.RunId, 'memory-run:' || NEW.RunId || ':image',
                    'MemoryImage', NEW.ImageId, 'VolatilityPluginRun', NEW.RunId, 'DerivedFrom',
                    'Asserted', 'VolatilityPluginInput', 1.0, NEW.CaseId, NEW.EvidenceSessionId,
                    NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId, NEW.ExecutionRootId, NEW.SourceRunId,
                    NEW.IngestionJobId, NEW.RequestedUtc, 'VolatilityDerivationProjection',
                    'evidence-relation-v1', NEW.RequestedUtc, COALESCE(NEW.CompletedUtc, NEW.RequestedUtc),
                    'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_MemoryProcess_Insert
            AFTER INSERT ON MemoryProcesses
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                SELECT 'legacy:memory-process-run:' || NEW.ArtifactId,
                    'memory-process:' || NEW.ArtifactId || ':run', 'VolatilityPluginRun', NEW.PluginRunId,
                    'MemoryProcess', NEW.ArtifactId, 'DerivedFrom', 'Asserted', 'VolatilityNormalization', 1.0,
                    NEW.CaseId, NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId,
                    NEW.ExecutionRootId, NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.RawRowHash, ''),
                    COALESCE(NEW.CreateTimeUtc, CURRENT_TIMESTAMP), 'VolatilityDerivationProjection',
                    'evidence-relation-v1', COALESCE(NEW.CreateTimeUtc, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP,
                    'Active', '', '' WHERE COALESCE(NEW.PluginRunId, '') <> '';

                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES ('legacy:memory-process:' || NEW.ArtifactId || ':' || COALESCE(NEW.ProcessEntityId, 'unresolved'),
                    'memory-process:' || NEW.ArtifactId || ':process', 'MemoryProcess', NEW.ArtifactId,
                    'ProcessEntity', COALESCE(NEW.ProcessEntityId, ''), 'CorrelatesWith',
                    CASE WHEN COALESCE(NEW.ProcessEntityId, '') = '' OR NEW.CorrelationState IN ('Unknown', 'MemoryOnly') THEN 'Unresolved'
                         WHEN NEW.CorrelationState = 'Weak' THEN 'Ambiguous'
                         WHEN NEW.CorrelationConfidence >= 0.95 THEN 'Exact' ELSE 'Inferred' END,
                    COALESCE(NULLIF(NEW.CorrelationMethod, ''), 'Unresolved'),
                    MIN(1.0, MAX(0.0, COALESCE(NEW.CorrelationConfidence, 0.0))),
                    NEW.CaseId, NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId,
                    NEW.ExecutionRootId, NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.RawRowHash, ''),
                    COALESCE(NEW.CreateTimeUtc, CURRENT_TIMESTAMP), 'VolatilityCorrelationProjection',
                    'evidence-relation-v1', COALESCE(NEW.CreateTimeUtc, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP,
                    'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_ProcessEvent_EntityUpdate
            AFTER UPDATE OF ProcessEntityId ON ProcessEvents
            WHEN COALESCE(NEW.ProcessEntityId, '') <> ''
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES ('legacy:event:' || NEW.SequenceId, 'event:' || NEW.SequenceId || ':process',
                    'ProcessEntity', NEW.ProcessEntityId, 'Event', CAST(NEW.SequenceId AS TEXT), 'ObservedProcess',
                    'Asserted', COALESCE(NULLIF(NEW.CorrelationMethod, ''), 'SourceAssertion'), 1.0,
                    NEW.CaseId, NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId,
                    NEW.ExecutionRootId, NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.RawRecordIdText, ''),
                    NEW.TimestampUtc, 'SourceAssertionProjection', 'evidence-relation-v1', NEW.TimestampUtc,
                    NEW.TimestampUtc, 'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_Module_EntityUpdate
            AFTER UPDATE OF ProcessEntityId ON Modules
            WHEN COALESCE(NEW.ProcessEntityId, '') <> ''
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    ObservedFromUtc, ObservedToUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES ('legacy:module:' || NEW.ModuleKey, 'module:' || NEW.ModuleKey || ':process',
                    'ProcessEntity', NEW.ProcessEntityId, 'Module', NEW.ModuleKey, 'Loaded', 'Asserted',
                    COALESCE(NULLIF(NEW.LastSource, ''), 'ModuleObservation'), 1.0, NEW.CaseId,
                    NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId, NEW.ExecutionRootId,
                    NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.FirstSeenUtc, NEW.LastSeenUtc), NEW.UnloadedUtc,
                    'SourceAssertionProjection', 'evidence-relation-v1', COALESCE(NEW.FirstSeenUtc, NEW.LastSeenUtc),
                    COALESCE(NEW.LastSeenUtc, NEW.FirstSeenUtc), 'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_Handle_EntityUpdate
            AFTER UPDATE OF ProcessEntityId ON Handles
            WHEN COALESCE(NEW.ProcessEntityId, '') <> ''
            BEGIN
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    ObservedFromUtc, ObservedToUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES ('legacy:handle:' || NEW.HandleKey, 'handle:' || NEW.HandleKey || ':process',
                    'ProcessEntity', NEW.ProcessEntityId, 'Handle', NEW.HandleKey, 'Opened', 'Asserted',
                    COALESCE(NULLIF(NEW.LastSource, ''), 'HandleObservation'), 1.0, NEW.CaseId,
                    NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId, NEW.ExecutionRootId,
                    NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.FirstSeenUtc, NEW.LastSeenUtc), NEW.ClosedUtc,
                    'SourceAssertionProjection', 'evidence-relation-v1', COALESCE(NEW.FirstSeenUtc, NEW.LastSeenUtc),
                    COALESCE(NEW.LastSeenUtc, NEW.FirstSeenUtc), 'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_Zeek_EntityUpdate
            AFTER UPDATE OF ProcessEntityId ON ZeekNetworkArtifacts
            BEGIN
                UPDATE EvidenceRelations
                SET Status = 'Superseded', UpdatedUtc = NEW.TimestampUtc
                WHERE DecisionKey = 'zeek:' || NEW.ArtifactId || ':process' AND Status = 'Active';
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES ('legacy:zeek-process:' || NEW.ArtifactId || ':' || COALESCE(NEW.ProcessEntityId, 'unresolved'),
                    'zeek:' || NEW.ArtifactId || ':process', 'NetworkFlow', NEW.ArtifactId,
                    'ProcessEntity', COALESCE(NEW.ProcessEntityId, ''), 'CorrelatesWith',
                    CASE WHEN COALESCE(NEW.ProcessEntityId, '') = '' THEN 'Unresolved'
                         WHEN NEW.CorrelationConfidence >= 0.95 THEN 'Exact'
                         WHEN NEW.CorrelationConfidence >= 0.50 THEN 'Inferred' ELSE 'Ambiguous' END,
                    COALESCE(NULLIF(NEW.CorrelationMethod, ''), 'Unresolved'),
                    MIN(1.0, MAX(0.0, COALESCE(NEW.CorrelationConfidence, 0.0))), NEW.CaseId,
                    NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId, NEW.ExecutionRootId,
                    NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.RawLineHash, ''), NEW.TimestampUtc,
                    'ZeekCorrelationProjection', 'evidence-relation-v1', NEW.TimestampUtc, NEW.TimestampUtc,
                    'Active', '', '');
            END;

            CREATE TRIGGER IF NOT EXISTS TR_EvidenceRelation_MemoryProcess_EntityUpdate
            AFTER UPDATE OF ProcessEntityId ON MemoryProcesses
            BEGIN
                UPDATE EvidenceRelations
                SET Status = 'Superseded', UpdatedUtc = CURRENT_TIMESTAMP
                WHERE DecisionKey = 'memory-process:' || NEW.ArtifactId || ':process' AND Status = 'Active';
                INSERT OR REPLACE INTO EvidenceRelations (
                    RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                    CorrelationState, CorrelationMethod, Confidence, CaseId, EvidenceSessionId,
                    CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                    RawInputId, ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc,
                    Status, SupersededByRelationId, AnalystAnnotationId)
                VALUES ('legacy:memory-process:' || NEW.ArtifactId || ':' || COALESCE(NEW.ProcessEntityId, 'unresolved'),
                    'memory-process:' || NEW.ArtifactId || ':process', 'MemoryProcess', NEW.ArtifactId,
                    'ProcessEntity', COALESCE(NEW.ProcessEntityId, ''), 'CorrelatesWith',
                    CASE WHEN COALESCE(NEW.ProcessEntityId, '') = '' OR NEW.CorrelationState IN ('Unknown', 'MemoryOnly') THEN 'Unresolved'
                         WHEN NEW.CorrelationState = 'Weak' THEN 'Ambiguous'
                         WHEN NEW.CorrelationConfidence >= 0.95 THEN 'Exact' ELSE 'Inferred' END,
                    COALESCE(NULLIF(NEW.CorrelationMethod, ''), 'Unresolved'),
                    MIN(1.0, MAX(0.0, COALESCE(NEW.CorrelationConfidence, 0.0))), NEW.CaseId,
                    NEW.EvidenceSessionId, NEW.CaptureId, NEW.SourceIdentityId, NEW.HostId, NEW.ExecutionRootId,
                    NEW.SourceRunId, NEW.IngestionJobId, COALESCE(NEW.RawRowHash, ''),
                    COALESCE(NEW.CreateTimeUtc, CURRENT_TIMESTAMP), 'VolatilityCorrelationProjection',
                    'evidence-relation-v1', COALESCE(NEW.CreateTimeUtc, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP,
                    'Active', '', '');
            END;
            """);
    }

    private bool HasSchemaMigration(string migrationId)
    {
        using var command = CreateCommand("""
            SELECT 1
            FROM SchemaMigrations
            WHERE MigrationId = $MigrationId
            LIMIT 1;
            """);
        Add(command, "$MigrationId", migrationId);
        return command.ExecuteScalar() != null;
    }

    private void EnsureMigrationLedgerSchema()
    {
        EnsureColumn("SchemaMigrations", "Sequence", "INTEGER");
        EnsureColumn("SchemaMigrations", "DefinitionHash", "TEXT");
        EnsureColumn("SchemaMigrations", "SourceEvidenceFormatVersion", "INTEGER");
        EnsureColumn("SchemaMigrations", "TargetEvidenceFormatVersion", "INTEGER");
        EnsureColumn("SchemaMigrations", "MigrationKind", "TEXT");
        EnsureColumn("SchemaMigrations", "AppliedByRelease", "TEXT");
        EnsureColumn("SchemaMigrations", "ExclusiveOwnershipRequired", "INTEGER");
        EnsureColumn("SchemaMigrations", "ResultCode", "TEXT");
    }

    private void RecordSchemaMigration(
        CaptureMigrationDefinition definition,
        string appliedByRelease)
    {
        using var command = CreateCommand("""
            INSERT INTO SchemaMigrations(
                MigrationId, AppliedUtc, Description, Sequence, DefinitionHash,
                SourceEvidenceFormatVersion, TargetEvidenceFormatVersion, MigrationKind,
                AppliedByRelease, ExclusiveOwnershipRequired, ResultCode)
            VALUES(
                $MigrationId, $AppliedUtc, $Description, $Sequence, $DefinitionHash,
                $SourceEvidenceFormatVersion, $TargetEvidenceFormatVersion, $MigrationKind,
                $AppliedByRelease, $ExclusiveOwnershipRequired, 'migration.completed');
            """);
        Add(command, "$MigrationId", definition.MigrationId);
        Add(command, "$AppliedUtc", DateTime.UtcNow);
        Add(command, "$Description", definition.Description);
        Add(command, "$Sequence", definition.Sequence);
        Add(command, "$DefinitionHash", definition.DefinitionHash);
        Add(command, "$SourceEvidenceFormatVersion", definition.SourceEvidenceFormatVersion);
        Add(command, "$TargetEvidenceFormatVersion", definition.TargetEvidenceFormatVersion);
        Add(command, "$MigrationKind", definition.Kind.ToString());
        Add(command, "$AppliedByRelease", appliedByRelease);
        Add(command, "$ExclusiveOwnershipRequired", definition.RequiresExclusiveLiveDatabaseOwnership ? 1 : 0);
        command.ExecuteNonQuery();
    }

    private void EnsureEvidenceIdentityColumns()
    {
        foreach (var table in new[]
        {
            "Sources",
            "Processes",
            "ProcessStatistics",
            "ProcessEvents",
            "Modules",
            "Handles",
            "MemoryDumps",
            "PeAnalyses",
            "MemoryImages",
            "VolatilityPluginRuns",
            "MemoryProcesses",
            "NetworkCaptures",
            "ZeekNetworkArtifacts",
            "RawRecords",
            "Artifacts"
        })
        {
            EnsureColumn(table, "CaseId", "TEXT");
            EnsureColumn(table, "EvidenceSessionId", "TEXT");
            if (table != "NetworkCaptures" && table != "ZeekNetworkArtifacts")
            {
                EnsureColumn(table, "CaptureId", "TEXT");
            }

            EnsureColumn(table, "SourceIdentityId", "TEXT");
            EnsureColumn(table, "HostId", "TEXT");
            EnsureColumn(table, "ExecutionRootId", "TEXT");
        }
    }

    private void EnsureZeekNetworkArtifactContextColumns()
    {
        EnsureColumn("ZeekNetworkArtifacts", "DurationSeconds", "REAL NOT NULL DEFAULT 0");
        EnsureColumn("ZeekNetworkArtifacts", "OrigPackets", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn("ZeekNetworkArtifacts", "RespPackets", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn("ZeekNetworkArtifacts", "OrigIpBytes", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn("ZeekNetworkArtifacts", "RespIpBytes", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn("ZeekNetworkArtifacts", "ConnectionState", "TEXT");
        EnsureColumn("ZeekNetworkArtifacts", "History", "TEXT");
        EnsureColumn("ZeekNetworkArtifacts", "ServerName", "TEXT");
        EnsureColumn("ZeekNetworkArtifacts", "ClientProtocol", "TEXT");
        EnsureColumn("ZeekNetworkArtifacts", "TlsVersion", "TEXT");
        EnsureColumn("ZeekNetworkArtifacts", "TlsCipher", "TEXT");
        EnsureColumn("ZeekNetworkArtifacts", "TlsEstablished", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn("ZeekNetworkArtifacts", "WeirdName", "TEXT");
        EnsureColumn("ZeekNetworkArtifacts", "WeirdAdditional", "TEXT");
    }

    private void EnsureColumn(string tableName, string columnName, string sqlType)
    {
        if (ColumnExists(tableName, columnName))
        {
            return;
        }

        ExecuteNonQuery($"ALTER TABLE {tableName} ADD COLUMN {columnName} {sqlType};");
    }

    private bool ColumnExists(string tableName, string columnName)
    {
        using var command = CreateCommand($"PRAGMA table_info({tableName});");
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

    private void UpsertDefaultIdentitySchemaInfo()
    {
        var sessionId = DeriveSessionId();
        using var command = CreateCommand("""
            INSERT OR IGNORE INTO SchemaInfo(Key, Value) VALUES('EvidenceSessionId', $EvidenceSessionId);
            INSERT OR IGNORE INTO SchemaInfo(Key, Value) VALUES('DefaultCaptureId', $DefaultCaptureId);
            INSERT OR IGNORE INTO SchemaInfo(Key, Value) VALUES('HostId', $HostId);
            INSERT OR IGNORE INTO SchemaInfo(Key, Value) VALUES('DefaultExecutionRootId', $DefaultExecutionRootId);
            """);
        Add(command, "$EvidenceSessionId", sessionId);
        Add(command, "$DefaultCaptureId", $"{sessionId}-capture-0001");
        Add(command, "$HostId", Environment.MachineName);
        Add(command, "$DefaultExecutionRootId", $"{sessionId}-execution-0001");
        command.ExecuteNonQuery();
    }

    private void BackfillEvidenceIdentityColumns()
    {
        var identity = LoadDefaultEvidenceIdentity();
        foreach (var table in new[]
        {
            "Sources",
            "Processes",
            "ProcessStatistics",
            "ProcessEvents",
            "Modules",
            "Handles",
            "MemoryDumps",
            "PeAnalyses",
            "MemoryImages",
            "VolatilityPluginRuns",
            "MemoryProcesses",
            "RawRecords",
            "Artifacts"
        })
        {
            BackfillIdentityTable(table, identity, includeCapture: true);
        }

        BackfillIdentityTable("NetworkCaptures", identity, includeCapture: false);
        BackfillIdentityTable("ZeekNetworkArtifacts", identity, includeCapture: false);
    }

    private void BackfillIdentityTable(string tableName, EvidenceIdentity identity, bool includeCapture)
    {
        var captureAssignment = includeCapture
            ? "CaptureId = COALESCE(NULLIF(CaptureId, ''), $CaptureId),"
            : string.Empty;
        using var command = CreateCommand($"""
            UPDATE {tableName}
            SET CaseId = COALESCE(NULLIF(CaseId, ''), $CaseId),
                EvidenceSessionId = COALESCE(NULLIF(EvidenceSessionId, ''), $EvidenceSessionId),
                {captureAssignment}
                SourceIdentityId = COALESCE(NULLIF(SourceIdentityId, ''), $SourceIdentityId),
                HostId = COALESCE(NULLIF(HostId, ''), $HostId),
                ExecutionRootId = COALESCE(NULLIF(ExecutionRootId, ''), $ExecutionRootId)
            WHERE CaseId IS NULL OR CaseId = ''
               OR EvidenceSessionId IS NULL OR EvidenceSessionId = ''
               OR SourceIdentityId IS NULL OR SourceIdentityId = ''
               OR HostId IS NULL OR HostId = ''
               OR ExecutionRootId IS NULL OR ExecutionRootId = ''
               {GetCaptureBackfillPredicate(includeCapture)};
            """);
        AddEvidenceIdentityParameters(command, identity);
        command.ExecuteNonQuery();
    }

    private static string GetCaptureBackfillPredicate(bool includeCapture)
        => includeCapture
            ? "OR CaptureId IS NULL OR CaptureId = ''"
            : string.Empty;

    private EvidenceIdentity LoadDefaultEvidenceIdentity()
    {
        var sessionId = GetSchemaInfo("EvidenceSessionId");
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            sessionId = DeriveSessionId();
        }

        return new EvidenceIdentity
        {
            CaseId = GetSchemaInfo("CaseId"),
            EvidenceSessionId = sessionId,
            CaptureId = GetSchemaInfo("DefaultCaptureId"),
            HostId = GetSchemaInfo("HostId"),
            ExecutionRootId = GetSchemaInfo("DefaultExecutionRootId")
        };
    }

    private string GetSchemaInfo(string key)
    {
        using var command = CreateCommand("SELECT Value FROM SchemaInfo WHERE Key = $Key LIMIT 1;");
        Add(command, "$Key", key);
        return Convert.ToString(command.ExecuteScalar(), CultureInfo.InvariantCulture) ?? string.Empty;
    }

    private string DeriveSessionId()
    {
        var directory = Path.GetFileName(Path.GetDirectoryName(_databasePath));
        return string.IsNullOrWhiteSpace(directory)
            ? Path.GetFileNameWithoutExtension(_databasePath)
            : directory;
    }

    private EvidenceIdentity ResolveEvidenceIdentity(IHasEvidenceIdentity record, string sourceType, string displayName)
    {
        var defaults = _defaultEvidenceIdentity ?? LoadDefaultEvidenceIdentity();
        var sourceIdentityId = string.IsNullOrWhiteSpace(record.SourceIdentityId)
            ? BuildSourceIdentityId(sourceType, displayName)
            : record.SourceIdentityId;
        var captureId = string.IsNullOrWhiteSpace(record.CaptureId)
            ? defaults.CaptureId
            : record.CaptureId;
        return new EvidenceIdentity
        {
            CaseId = PreferIdentityValue(record.CaseId, defaults.CaseId),
            EvidenceSessionId = PreferIdentityValue(record.EvidenceSessionId, defaults.EvidenceSessionId),
            CaptureId = captureId,
            SourceIdentityId = sourceIdentityId,
            HostId = PreferIdentityValue(record.HostId, defaults.HostId),
            ExecutionRootId = PreferIdentityValue(record.ExecutionRootId, defaults.ExecutionRootId)
        };
    }

    private static string PreferIdentityValue(string value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static string BuildSourceIdentityId(string sourceType, string displayName)
        => string.IsNullOrWhiteSpace(displayName)
            ? string.Empty
            : $"{sourceType}:{displayName.Trim()}";

    private static void ApplyEvidenceIdentity(IHasEvidenceIdentity record, EvidenceIdentity identity)
    {
        record.CaseId = identity.CaseId;
        record.EvidenceSessionId = identity.EvidenceSessionId;
        record.CaptureId = identity.CaptureId;
        record.SourceIdentityId = identity.SourceIdentityId;
        record.HostId = identity.HostId;
        record.ExecutionRootId = identity.ExecutionRootId;
    }

    private static void AddEvidenceIdentityParameters(SqliteCommand command, EvidenceIdentity identity)
    {
        Add(command, "$CaseId", identity.CaseId);
        Add(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Add(command, "$CaptureId", identity.CaptureId);
        Add(command, "$SourceIdentityId", identity.SourceIdentityId);
        Add(command, "$HostId", identity.HostId);
        Add(command, "$ExecutionRootId", identity.ExecutionRootId);
    }

    public void UpdateSourceRunStatus(
        string sourceRunId,
        string status,
        DateTime? endTimeUtc = null,
        string? metadataJson = null)
    {
        lock (_lock)
        {
            using var command = CreateCommand("""
                UPDATE SourceRuns
                SET Status = $Status,
                    EndedUtc = COALESCE($EndedUtc, EndedUtc),
                    UpdatedUtc = $UpdatedUtc,
                    MetadataJson = COALESCE($MetadataJson, MetadataJson)
                WHERE SourceRunId = $SourceRunId;
                """);
            Add(command, "$SourceRunId", sourceRunId);
            Add(command, "$Status", status);
            Add(command, "$EndedUtc", endTimeUtc);
            Add(command, "$UpdatedUtc", DateTime.UtcNow);
            Add(command, "$MetadataJson", metadataJson is null ? null : SanitizeSourceRunMetadata(metadataJson));
            command.ExecuteNonQuery();
        }
    }

    private void EnsureAuthenticodeVerificationSchema()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS AuthenticodeVerifications (
                VerificationId TEXT PRIMARY KEY,
                AnalysisId TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT,
                CaptureId TEXT,
                SourceIdentityId TEXT,
                HostId TEXT,
                ExecutionRootId TEXT,
                SourceId INTEGER,
                ProcessEntityId TEXT,
                SourceRunId TEXT,
                IngestionJobId TEXT,
                ProcessKey TEXT NOT NULL,
                ProcessId INTEGER NOT NULL DEFAULT 0,
                ProcessGuid TEXT,
                ProcessName TEXT,
                FilePath TEXT,
                Sha256Hash TEXT,
                SignatureKind TEXT NOT NULL CHECK(SignatureKind IN ('Unknown', 'None', 'Embedded', 'Catalog')),
                VerificationStatus TEXT NOT NULL CHECK(VerificationStatus IN (
                    'Unknown', 'Valid', 'Unsigned', 'Invalid', 'Untrusted', 'Expired', 'Revoked',
                    'RevocationUnavailable', 'AccessDenied', 'FileMissing', 'Unsupported', 'Error')),
                SignerSubject TEXT,
                Publisher TEXT,
                CertificateThumbprint TEXT,
                Issuer TEXT,
                HasTimestamp INTEGER NOT NULL DEFAULT 0 CHECK(HasTimestamp IN (0, 1)),
                TimestampSubject TEXT,
                TimestampUtc TEXT,
                VerificationPolicy TEXT NOT NULL,
                VerificationTimeUtc TEXT NOT NULL,
                RevocationMode TEXT NOT NULL CHECK(RevocationMode IN ('Unknown', 'None', 'OfflineCacheOnly', 'Online')),
                RevocationStatus TEXT NOT NULL CHECK(RevocationStatus IN ('Unknown', 'NotChecked', 'Good', 'Revoked', 'Unavailable')),
                NativeStatusCode TEXT,
                DiagnosticCode TEXT,
                DiagnosticText TEXT,
                FOREIGN KEY(AnalysisId) REFERENCES PeAnalyses(AnalysisId),
                FOREIGN KEY(SourceId) REFERENCES Sources(SourceId)
            );
            CREATE INDEX IF NOT EXISTS IX_AuthenticodeVerifications_EntityVerified
                ON AuthenticodeVerifications(ProcessEntityId, VerificationTimeUtc DESC, VerificationId DESC);
            CREATE INDEX IF NOT EXISTS IX_AuthenticodeVerifications_ProcessKeyVerified
                ON AuthenticodeVerifications(ProcessKey, VerificationTimeUtc DESC, VerificationId DESC);
            CREATE INDEX IF NOT EXISTS IX_AuthenticodeVerifications_AnalysisVerified
                ON AuthenticodeVerifications(AnalysisId, VerificationTimeUtc DESC, VerificationId DESC);
            CREATE INDEX IF NOT EXISTS IX_AuthenticodeVerifications_HashVerified
                ON AuthenticodeVerifications(Sha256Hash, VerificationTimeUtc DESC, VerificationId DESC);
            CREATE INDEX IF NOT EXISTS IX_AuthenticodeVerifications_SourceRun
                ON AuthenticodeVerifications(SourceRunId);
            CREATE INDEX IF NOT EXISTS IX_AuthenticodeVerifications_IngestionJob
                ON AuthenticodeVerifications(IngestionJobId);

            CREATE TRIGGER IF NOT EXISTS TR_AuthenticodeVerifications_SourceRun_Insert
            AFTER INSERT ON AuthenticodeVerifications
            WHEN NEW.SourceRunId IS NULL OR NEW.SourceRunId = ''
            BEGIN
                UPDATE AuthenticodeVerifications
                SET SourceRunId = (SELECT SourceRunId FROM WriterProvenanceContext WHERE SingletonId = 1),
                    IngestionJobId = (SELECT IngestionJobId FROM WriterProvenanceContext WHERE SingletonId = 1)
                WHERE rowid = NEW.rowid
                  AND EXISTS(SELECT 1 FROM WriterProvenanceContext WHERE SingletonId = 1);
            END;

            CREATE TRIGGER IF NOT EXISTS TR_AuthenticodeVerifications_ResolveProcessEntity
            AFTER INSERT ON AuthenticodeVerifications
            WHEN (NEW.ProcessEntityId IS NULL OR NEW.ProcessEntityId = '')
                 AND NEW.ProcessKey IS NOT NULL AND NEW.ProcessKey <> ''
            BEGIN
                UPDATE AuthenticodeVerifications
                SET ProcessEntityId = (
                    SELECT MIN(alias.ProcessEntityId)
                    FROM ProcessAliases alias
                    WHERE alias.AliasKind = 'LegacyProcessKey'
                      AND alias.AliasValue = NEW.ProcessKey
                      AND COALESCE(alias.CaseId, '') = COALESCE(NEW.CaseId, '')
                      AND COALESCE(alias.EvidenceSessionId, '') = COALESCE(NEW.EvidenceSessionId, '')
                      AND COALESCE(alias.HostId, '') = COALESCE(NEW.HostId, '')
                      AND COALESCE(alias.ExecutionRootId, '') = COALESCE(NEW.ExecutionRootId, '')
                    HAVING COUNT(DISTINCT alias.ProcessEntityId) = 1)
                WHERE rowid = NEW.rowid;
            END;
            """);
    }

    private void EnsureProcessRiskProjectionSchema()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS ProcessRiskProjections (
                ProcessEntityId TEXT PRIMARY KEY,
                ProcessKey TEXT NOT NULL,
                CaseId TEXT,
                EvidenceSessionId TEXT NOT NULL,
                CaptureId TEXT,
                SourceIdentityId TEXT NOT NULL,
                HostId TEXT NOT NULL,
                ExecutionRootId TEXT NOT NULL,
                RebuildStatus TEXT NOT NULL CHECK(RebuildStatus IN ('Ready', 'Failed')),
                Diagnostic TEXT NOT NULL,
                ProjectionState TEXT NOT NULL CHECK(ProjectionState IN ('Unknown', 'Complete', 'Partial')),
                Score INTEGER CHECK(Score IS NULL OR (Score >= 0 AND Score <= 100)),
                Band TEXT NOT NULL CHECK(Band IN ('Unknown', 'Minimal', 'Low', 'Medium', 'High', 'Critical')),
                Confidence REAL NOT NULL CHECK(Confidence >= 0 AND Confidence <= 1),
                Coverage REAL NOT NULL CHECK(Coverage >= 0 AND Coverage <= 1),
                PolicyId TEXT NOT NULL,
                PolicyVersion TEXT NOT NULL,
                MapperId TEXT NOT NULL,
                MapperVersion TEXT NOT NULL,
                AggregationVersion TEXT NOT NULL,
                EvaluationId TEXT NOT NULL,
                InputIdentityHash TEXT NOT NULL,
                ProjectedUtc TEXT NOT NULL,
                ObservationId TEXT NOT NULL,
                PeAnalysisId TEXT,
                AuthenticodeVerificationId TEXT,
                ProjectionJson TEXT NOT NULL,
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessEntities(ProcessEntityId),
                FOREIGN KEY(ObservationId) REFERENCES ProcessObservations(ObservationId),
                FOREIGN KEY(PeAnalysisId) REFERENCES PeAnalyses(AnalysisId),
                FOREIGN KEY(AuthenticodeVerificationId) REFERENCES AuthenticodeVerifications(VerificationId)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS IX_ProcessRiskProjections_ProcessKeyEntity
                ON ProcessRiskProjections(ProcessKey, ProcessEntityId);
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskProjections_Score
                ON ProcessRiskProjections(Score DESC, ProcessEntityId);

            CREATE TABLE IF NOT EXISTS ProcessRiskProjectionSources (
                ProcessEntityId TEXT NOT NULL,
                SourceOrder INTEGER NOT NULL,
                SourceKind TEXT NOT NULL,
                SourceId TEXT NOT NULL,
                Availability TEXT NOT NULL,
                ConfidenceWeight INTEGER NOT NULL,
                Confidence REAL NOT NULL,
                FindingCount INTEGER NOT NULL,
                SignalCount INTEGER NOT NULL,
                Diagnostic TEXT NOT NULL,
                PRIMARY KEY(ProcessEntityId, SourceId),
                UNIQUE(ProcessEntityId, SourceOrder),
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessRiskProjections(ProcessEntityId) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskProjectionSources_Availability
                ON ProcessRiskProjectionSources(Availability, ProcessEntityId);

            CREATE TABLE IF NOT EXISTS ProcessRiskProjectionContributors (
                ProcessEntityId TEXT NOT NULL,
                ContributorOrder INTEGER NOT NULL,
                SourceKind TEXT NOT NULL,
                SourceId TEXT NOT NULL,
                FindingId TEXT NOT NULL,
                SignalId TEXT NOT NULL,
                InputSnapshotId TEXT NOT NULL,
                ScoreDelta INTEGER NOT NULL,
                Severity TEXT NOT NULL,
                Confidence REAL NOT NULL,
                EvidenceReferencesJson TEXT NOT NULL,
                ContributionJson TEXT NOT NULL,
                PRIMARY KEY(ProcessEntityId, ContributorOrder),
                UNIQUE(ProcessEntityId, SignalId),
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessRiskProjections(ProcessEntityId) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskProjectionContributors_Finding
                ON ProcessRiskProjectionContributors(FindingId, ProcessEntityId);
            """);
    }

    private void EnsureSigmaRiskInputSchema()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS ProcessRiskSigmaInputs (
                GenerationId TEXT NOT NULL,
                ProcessEntityId TEXT NOT NULL,
                MatchId TEXT NOT NULL,
                RuleId TEXT NOT NULL,
                RuleVersion TEXT NOT NULL,
                MatchContentHashSha256 TEXT NOT NULL,
                MatchedUtc TEXT NOT NULL,
                EvidenceJson TEXT NOT NULL,
                PRIMARY KEY(ProcessEntityId, MatchId),
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessEntities(ProcessEntityId)
            );
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskSigmaInputs_Generation
                ON ProcessRiskSigmaInputs(GenerationId, ProcessEntityId, MatchedUtc, MatchId);
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskSigmaInputs_Rule
                ON ProcessRiskSigmaInputs(RuleId, RuleVersion, ProcessEntityId);
            """);
    }

    private void EnsureBaselineRiskInputSchema()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS ProcessRiskBaselineInputs (
                GenerationId TEXT NOT NULL,
                ProcessEntityId TEXT NOT NULL,
                FindingId TEXT NOT NULL,
                ComparisonId TEXT NOT NULL,
                ComparisonVersion TEXT NOT NULL,
                BaselineId TEXT NOT NULL,
                BaselineSnapshotHashSha256 TEXT NOT NULL,
                CurrentSnapshotHashSha256 TEXT NOT NULL,
                StableKeyHashSha256 TEXT NOT NULL,
                BaselineFingerprintSha256 TEXT NOT NULL,
                CurrentFingerprintSha256 TEXT NOT NULL,
                ArtifactKind TEXT NOT NULL,
                Verdict TEXT NOT NULL,
                PolicyRuleId TEXT NOT NULL,
                ComparedUtc TEXT NOT NULL,
                EvidenceJson TEXT NOT NULL,
                PRIMARY KEY(ProcessEntityId, FindingId),
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessEntities(ProcessEntityId)
            );
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskBaselineInputs_Generation
                ON ProcessRiskBaselineInputs(
                    GenerationId, ProcessEntityId, ComparedUtc, FindingId);
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskBaselineInputs_Comparison
                ON ProcessRiskBaselineInputs(
                    ComparisonId, ComparisonVersion, BaselineId, ProcessEntityId);
            """);
    }

    private void EnsureYaraRiskInputSchema()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS ProcessRiskYaraInputs (
                GenerationId TEXT NOT NULL,
                ProcessEntityId TEXT NOT NULL PRIMARY KEY,
                ScanId TEXT NOT NULL UNIQUE,
                PolicyId TEXT NOT NULL,
                PolicyVersion TEXT NOT NULL,
                ReviewerId TEXT NOT NULL,
                ReviewPolicyId TEXT NOT NULL,
                ReviewPolicyVersion TEXT NOT NULL,
                ReviewedUtc TEXT NOT NULL,
                RulesetId TEXT NOT NULL,
                RulesetVersion TEXT NOT NULL,
                RulesetHashSha256 TEXT NOT NULL,
                TargetKind INTEGER NOT NULL,
                TargetReferenceKind INTEGER NOT NULL,
                TargetReferenceId TEXT NOT NULL,
                SourceRunId TEXT NOT NULL,
                RelationId TEXT NOT NULL,
                Availability INTEGER NOT NULL,
                CompletedUtc TEXT NOT NULL,
                ScanPayloadHashSha256 TEXT NOT NULL,
                AttributionPayloadHashSha256 TEXT NOT NULL,
                AttributionJson TEXT NOT NULL,
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessEntities(ProcessEntityId),
                FOREIGN KEY(ScanId) REFERENCES YaraAnalysisScans(ScanId),
                FOREIGN KEY(RelationId) REFERENCES EvidenceRelations(RelationId)
            );
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskYaraInputs_Generation
                ON ProcessRiskYaraInputs(GenerationId, ProcessEntityId, CompletedUtc, ScanId);
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskYaraInputs_Policy
                ON ProcessRiskYaraInputs(
                    PolicyId, PolicyVersion, ReviewPolicyId, ReviewPolicyVersion,
                    RulesetId, RulesetVersion);
            CREATE INDEX IF NOT EXISTS IX_ProcessRiskYaraInputs_Target
                ON ProcessRiskYaraInputs(
                    TargetReferenceKind, TargetReferenceId, SourceRunId, RelationId);
            """);
    }

    private void EnsureReputationAttributionSchema()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS ReputationAttributions (
                AttributionHashSha256 TEXT PRIMARY KEY,
                ProcessEntityId TEXT NOT NULL,
                ProcessKey TEXT NOT NULL,
                SourceKind INTEGER NOT NULL,
                ProviderId TEXT NOT NULL,
                ProviderVersion TEXT NOT NULL,
                DatasetId TEXT NOT NULL,
                DatasetVersion TEXT NOT NULL,
                QueryMode INTEGER NOT NULL,
                IndicatorSha256 TEXT NOT NULL,
                SourceRunId TEXT NOT NULL,
                SourceEvidenceKind INTEGER NOT NULL,
                SourceEvidenceId TEXT NOT NULL,
                RelationId TEXT,
                Availability INTEGER NOT NULL,
                RecordFound INTEGER NOT NULL,
                AnalyzedCount INTEGER NOT NULL,
                PositiveCount INTEGER NOT NULL,
                SuspiciousCount INTEGER NOT NULL,
                UndetectedCount INTEGER NOT NULL,
                RetrievedUtc TEXT NOT NULL,
                CompletedUtc TEXT NOT NULL,
                ReceiptHashSha256 TEXT NOT NULL,
                CacheDecisionHashSha256 TEXT NOT NULL,
                PayloadHashSha256 TEXT NOT NULL,
                AttributionJson TEXT NOT NULL,
                FOREIGN KEY(ProcessEntityId) REFERENCES ProcessEntities(ProcessEntityId),
                FOREIGN KEY(SourceRunId) REFERENCES SourceRuns(SourceRunId),
                FOREIGN KEY(RelationId) REFERENCES EvidenceRelations(RelationId)
            );
            CREATE INDEX IF NOT EXISTS IX_ReputationAttributions_ProcessCompleted
                ON ReputationAttributions(
                    ProcessEntityId, CompletedUtc DESC, AttributionHashSha256);
            CREATE INDEX IF NOT EXISTS IX_ReputationAttributions_ProviderDatasetIndicator
                ON ReputationAttributions(
                    ProviderId, ProviderVersion, DatasetId, DatasetVersion,
                    IndicatorSha256, CompletedUtc DESC);
            CREATE INDEX IF NOT EXISTS IX_ReputationAttributions_Source
                ON ReputationAttributions(
                    SourceEvidenceKind, SourceEvidenceId, SourceRunId, RelationId);
            """);
    }

    private void EnsureYaraAnalysisSchema()
    {
        ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS YaraAnalysisScans (
                ScanId TEXT PRIMARY KEY,
                RequestId TEXT NOT NULL UNIQUE,
                ResultSchemaVersion INTEGER NOT NULL,
                Availability INTEGER NOT NULL,
                CaseId TEXT NOT NULL,
                EvidenceSessionId TEXT NOT NULL,
                CaptureId TEXT NOT NULL,
                SourceIdentityId TEXT NOT NULL,
                HostId TEXT NOT NULL,
                ExecutionRootId TEXT NOT NULL,
                SourceRunId TEXT NOT NULL,
                TargetKind INTEGER NOT NULL,
                EvidenceReferenceKind INTEGER NOT NULL,
                EvidenceReferenceId TEXT NOT NULL,
                TargetOffsetBytes INTEGER NOT NULL,
                TargetLengthBytes INTEGER NOT NULL,
                TargetContentHashSha256 TEXT NOT NULL,
                AdmissionProfileId TEXT NOT NULL,
                AdmissionProfileVersion TEXT NOT NULL,
                ScannerId TEXT NOT NULL,
                ScannerVersion TEXT NOT NULL,
                ScannerArtifactHashSha256 TEXT NOT NULL,
                ScannerAdapterProtocolVersion INTEGER NOT NULL,
                RulesetId TEXT NOT NULL,
                RulesetVersion TEXT NOT NULL,
                RulesetHashSha256 TEXT NOT NULL,
                RulesetManifestHashSha256 TEXT NOT NULL,
                RequestedUtc TEXT NOT NULL,
                CompletedUtc TEXT NOT NULL,
                IsTruncated INTEGER NOT NULL,
                Diagnostic TEXT NOT NULL,
                PayloadHashSha256 TEXT NOT NULL,
                UNIQUE(ScanId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                       HostId, ExecutionRootId, SourceRunId),
                FOREIGN KEY(SourceRunId) REFERENCES SourceRuns(SourceRunId)
            );
            CREATE INDEX IF NOT EXISTS IX_YaraAnalysisScans_EvidenceScope
                ON YaraAnalysisScans(
                    CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                    ExecutionRootId, SourceRunId, TargetKind, EvidenceReferenceKind,
                    EvidenceReferenceId, CompletedUtc, ScanId);

            CREATE TABLE IF NOT EXISTS YaraAnalysisMatches (
                ScanId TEXT NOT NULL,
                MatchId TEXT NOT NULL,
                MatchOrder INTEGER NOT NULL,
                CaseId TEXT NOT NULL,
                EvidenceSessionId TEXT NOT NULL,
                CaptureId TEXT NOT NULL,
                SourceIdentityId TEXT NOT NULL,
                HostId TEXT NOT NULL,
                ExecutionRootId TEXT NOT NULL,
                SourceRunId TEXT NOT NULL,
                RuleNamespace TEXT NOT NULL,
                RuleId TEXT NOT NULL,
                PRIMARY KEY(ScanId, MatchId),
                UNIQUE(ScanId, MatchOrder),
                UNIQUE(ScanId, MatchId, CaseId, EvidenceSessionId, CaptureId,
                       SourceIdentityId, HostId, ExecutionRootId, SourceRunId),
                FOREIGN KEY(ScanId, CaseId, EvidenceSessionId, CaptureId,
                            SourceIdentityId, HostId, ExecutionRootId, SourceRunId)
                    REFERENCES YaraAnalysisScans(
                        ScanId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                        HostId, ExecutionRootId, SourceRunId) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS YaraAnalysisTags (
                ScanId TEXT NOT NULL,
                MatchId TEXT NOT NULL,
                TagOrder INTEGER NOT NULL,
                Tag TEXT NOT NULL,
                CaseId TEXT NOT NULL,
                EvidenceSessionId TEXT NOT NULL,
                CaptureId TEXT NOT NULL,
                SourceIdentityId TEXT NOT NULL,
                HostId TEXT NOT NULL,
                ExecutionRootId TEXT NOT NULL,
                SourceRunId TEXT NOT NULL,
                PRIMARY KEY(ScanId, MatchId, Tag),
                UNIQUE(ScanId, MatchId, TagOrder),
                FOREIGN KEY(ScanId, MatchId, CaseId, EvidenceSessionId, CaptureId,
                            SourceIdentityId, HostId, ExecutionRootId, SourceRunId)
                    REFERENCES YaraAnalysisMatches(
                        ScanId, MatchId, CaseId, EvidenceSessionId, CaptureId,
                        SourceIdentityId, HostId, ExecutionRootId, SourceRunId)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS YaraAnalysisMetadata (
                ScanId TEXT NOT NULL,
                MatchId TEXT NOT NULL,
                MetadataOrder INTEGER NOT NULL,
                MetadataKey TEXT NOT NULL,
                MetadataValue TEXT NOT NULL,
                CaseId TEXT NOT NULL,
                EvidenceSessionId TEXT NOT NULL,
                CaptureId TEXT NOT NULL,
                SourceIdentityId TEXT NOT NULL,
                HostId TEXT NOT NULL,
                ExecutionRootId TEXT NOT NULL,
                SourceRunId TEXT NOT NULL,
                PRIMARY KEY(ScanId, MatchId, MetadataKey),
                UNIQUE(ScanId, MatchId, MetadataOrder),
                FOREIGN KEY(ScanId, MatchId, CaseId, EvidenceSessionId, CaptureId,
                            SourceIdentityId, HostId, ExecutionRootId, SourceRunId)
                    REFERENCES YaraAnalysisMatches(
                        ScanId, MatchId, CaseId, EvidenceSessionId, CaptureId,
                        SourceIdentityId, HostId, ExecutionRootId, SourceRunId)
                    ON DELETE CASCADE
            );
            """);
    }

    public T ExecuteWithSourceRunProvenance<T>(EvidenceWriteProvenance provenance, Func<T> action)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        ArgumentNullException.ThrowIfNull(action);
        lock (_lock)
        {
            using (var set = CreateCommand("""
                INSERT OR REPLACE INTO WriterProvenanceContext(SingletonId, SourceRunId, IngestionJobId)
                VALUES(1, $SourceRunId, $IngestionJobId);
                """))
            {
                Add(set, "$SourceRunId", provenance.SourceRunId);
                Add(set, "$IngestionJobId", provenance.IngestionJobId.ToString("D"));
                set.ExecuteNonQuery();
            }

            try
            {
                return action();
            }
            finally
            {
                ExecuteNonQuery("DELETE FROM WriterProvenanceContext WHERE SingletonId = 1;");
            }
        }
    }

    public void ExecuteWithSourceRunProvenance(EvidenceWriteProvenance provenance, Action action)
        => ExecuteWithSourceRunProvenance(provenance, () => { action(); return true; });

    public ProcessObservationWriteResult AppendProcessObservationBatch(
        IEnumerable<ProcessObservation> observations,
        IEnumerable<ProcessAlias> aliases,
        IEnumerable<ProcessStatisticsRecord>? statistics = null)
        => _processEvidenceWriter.AppendProcessObservationBatch(observations, aliases, statistics);

    public void RebuildProcessProjection()
        => _processEvidenceWriter.RebuildProcessProjection();

    public void BackfillMissingProcessObservationsAndRebuild()
        => _processEvidenceWriter.BackfillMissingProcessObservationsAndRebuild();

    private void EnsureProcessIdentityColumns()
    {
        EnsureColumn("Processes", "ProcessEntityId", "TEXT");
        EnsureColumn("Processes", "ParentProcessEntityId", "TEXT");
        foreach (var table in new[]
        {
            "ProcessStatistics",
            "ProcessEvents",
            "Modules",
            "Handles",
            "MemoryDumps",
            "PeAnalyses",
            "MemoryProcesses",
            "ZeekNetworkArtifacts",
            "Artifacts"
        })
        {
            EnsureColumn(table, "ProcessEntityId", "TEXT");
        }
    }

    private void EnsureProcessAttachedEvidenceSchema()
    {
        EnsureProcessIdentityColumns();
        EnsureSourceRunProvenanceSchema();
        foreach (var table in new[]
                 {
                     "ProcessStatistics", "ProcessEvents", "Modules", "Handles", "MemoryDumps", "PeAnalyses"
                 })
        {
            BackfillProcessEntityLinks(table);
        }

        ExecuteNonQuery("""
            CREATE INDEX IF NOT EXISTS IX_ProcessStatistics_EntityObserved
                ON ProcessStatistics(ProcessEntityId, ObservedUtc DESC, SampleId);
            CREATE INDEX IF NOT EXISTS IX_ProcessEvents_EntityTimestamp
                ON ProcessEvents(ProcessEntityId, TimestampUtc DESC, SequenceId DESC);
            CREATE INDEX IF NOT EXISTS IX_Modules_EntityState
                ON Modules(ProcessEntityId, State, ModuleName, ModuleKey);
            CREATE INDEX IF NOT EXISTS IX_Handles_EntityState
                ON Handles(ProcessEntityId, State, ObjectType, HandleKey);
            CREATE INDEX IF NOT EXISTS IX_MemoryDumps_EntityRequested
                ON MemoryDumps(ProcessEntityId, RequestedUtc DESC, DumpId);
            CREATE INDEX IF NOT EXISTS IX_PeAnalyses_EntityAnalyzed
                ON PeAnalyses(ProcessEntityId, AnalyzedUtc DESC, AnalysisId);

            DROP TRIGGER IF EXISTS TR_EvidenceRelation_Module_Insert;
            DROP TRIGGER IF EXISTS TR_EvidenceRelation_Module_EntityUpdate;
            DROP TRIGGER IF EXISTS TR_EvidenceRelation_Handle_Insert;
            DROP TRIGGER IF EXISTS TR_EvidenceRelation_Handle_EntityUpdate;
            """);
    }

    private void BackfillProcessAttachedEvidenceRelations()
    {
        ExecuteNonQuery("""
            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'attachment:statistic:' || s.SampleId || ':' || COALESCE(NULLIF(s.SourceRunId, ''), 'legacy'),
                   'attachment:statistic:' || s.SampleId || ':' || COALESCE(NULLIF(s.SourceRunId, ''), 'legacy'),
                   'ProcessStatistic', s.SampleId, 'ProcessEntity', COALESCE(s.ProcessEntityId, ''), 'OwnedBy',
                   CASE WHEN COALESCE(s.ProcessEntityId, '') = '' THEN 'Unresolved' ELSE 'Asserted' END,
                   CASE WHEN COALESCE(s.ProcessEntityId, '') = '' THEN 'NoExactProcessEntity' ELSE 'LegacyExactProcessLink' END,
                   CASE WHEN COALESCE(s.ProcessEntityId, '') = '' THEN 0.0 ELSE 1.0 END,
                   CASE WHEN COALESCE(s.ProcessEntityId, '') = '' THEN 0 ELSE 1 END,
                   CASE WHEN COALESCE(s.ProcessEntityId, '') = '' THEN 'Legacy sample retained without a unique scoped process entity.' ELSE 'Legacy sample linked by the unique scoped compatibility alias.' END,
                   s.CaseId, s.EvidenceSessionId, s.CaptureId, s.SourceIdentityId, s.HostId, s.ExecutionRootId,
                   s.SourceRunId, s.IngestionJobId, s.SampleId, s.ObservedUtc,
                   'ProcessAttachedEvidenceMigration', 'process-attached-v1', s.ObservedUtc, s.ObservedUtc,
                   'Active', '', ''
            FROM ProcessStatistics s;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'attachment:event:' || e.SequenceId || ':' || COALESCE(NULLIF(e.SourceRunId, ''), 'legacy'),
                   'attachment:event:' || e.SequenceId || ':' || COALESCE(NULLIF(e.SourceRunId, ''), 'legacy'),
                   'Event', CAST(e.SequenceId AS TEXT), 'ProcessEntity', COALESCE(e.ProcessEntityId, ''), 'OwnedBy',
                   CASE WHEN COALESCE(e.ProcessEntityId, '') = '' THEN 'Unresolved' ELSE 'Asserted' END,
                   CASE WHEN COALESCE(e.ProcessEntityId, '') = '' THEN 'NoExactProcessEntity' ELSE COALESCE(NULLIF(e.CorrelationMethod, ''), 'LegacyExactProcessLink') END,
                   CASE WHEN COALESCE(e.ProcessEntityId, '') = '' THEN 0.0 ELSE 1.0 END,
                   CASE WHEN COALESCE(e.ProcessEntityId, '') = '' THEN 0 ELSE 1 END,
                   CASE WHEN COALESCE(e.ProcessEntityId, '') = '' THEN 'Event retained without a unique scoped process entity.' ELSE 'Event linked to its scoped process entity.' END,
                   e.CaseId, e.EvidenceSessionId, e.CaptureId, e.SourceIdentityId, e.HostId, e.ExecutionRootId,
                   e.SourceRunId, e.IngestionJobId, COALESCE(e.RawRecordIdText, ''), e.TimestampUtc,
                   'ProcessAttachedEvidenceMigration', 'process-attached-v1', e.TimestampUtc, e.TimestampUtc,
                   'Active', '', ''
            FROM ProcessEvents e;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ObservedToUtc,
                ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                SupersededByRelationId, AnalystAnnotationId)
            SELECT 'attachment:module:' || m.ModuleKey || ':' || COALESCE(NULLIF(m.SourceRunId, ''), 'legacy') || ':' || COALESCE(m.LastSeenUtc, ''),
                   'attachment:module:' || m.ModuleKey || ':' || COALESCE(NULLIF(m.SourceRunId, ''), 'legacy') || ':' || COALESCE(m.LastSeenUtc, ''),
                   'ProcessEntity', COALESCE(m.ProcessEntityId, ''), 'Module', m.ModuleKey, 'Loaded',
                   CASE WHEN COALESCE(m.ProcessEntityId, '') = '' THEN 'Unresolved' ELSE 'Asserted' END,
                   CASE WHEN COALESCE(m.ProcessEntityId, '') = '' THEN 'NoExactProcessEntity' ELSE 'LegacyExactProcessLink' END,
                   CASE WHEN COALESCE(m.ProcessEntityId, '') = '' THEN 0.0 ELSE 1.0 END,
                   CASE WHEN COALESCE(m.ProcessEntityId, '') = '' THEN 0 ELSE 1 END,
                   CASE WHEN COALESCE(m.ProcessEntityId, '') = '' THEN 'Module observation retained without a unique scoped process entity.' ELSE 'Module observation linked to its scoped process entity.' END,
                   m.CaseId, m.EvidenceSessionId, m.CaptureId, m.SourceIdentityId, m.HostId, m.ExecutionRootId,
                   m.SourceRunId, m.IngestionJobId, m.ModuleKey, COALESCE(m.LastSeenUtc, m.FirstSeenUtc), m.UnloadedUtc,
                   'ProcessAttachedEvidenceMigration', 'process-attached-v1', COALESCE(m.LastSeenUtc, m.FirstSeenUtc),
                   COALESCE(m.LastSeenUtc, m.FirstSeenUtc), 'Active', '', ''
            FROM Modules m;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ObservedToUtc,
                ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                SupersededByRelationId, AnalystAnnotationId)
            SELECT 'attachment:handle:' || h.HandleKey || ':' || COALESCE(NULLIF(h.SourceRunId, ''), 'legacy') || ':' || COALESCE(h.LastSeenUtc, ''),
                   'attachment:handle:' || h.HandleKey || ':' || COALESCE(NULLIF(h.SourceRunId, ''), 'legacy') || ':' || COALESCE(h.LastSeenUtc, ''),
                   'ProcessEntity', COALESCE(h.ProcessEntityId, ''), 'Handle', h.HandleKey, 'Opened',
                   CASE WHEN COALESCE(h.ProcessEntityId, '') = '' THEN 'Unresolved' ELSE 'Asserted' END,
                   CASE WHEN COALESCE(h.ProcessEntityId, '') = '' THEN 'NoExactProcessEntity' ELSE 'LegacyExactProcessLink' END,
                   CASE WHEN COALESCE(h.ProcessEntityId, '') = '' THEN 0.0 ELSE 1.0 END,
                   CASE WHEN COALESCE(h.ProcessEntityId, '') = '' THEN 0 ELSE 1 END,
                   CASE WHEN COALESCE(h.ProcessEntityId, '') = '' THEN 'Handle observation retained without a unique scoped process entity.' ELSE 'Handle observation linked to its scoped process entity.' END,
                   h.CaseId, h.EvidenceSessionId, h.CaptureId, h.SourceIdentityId, h.HostId, h.ExecutionRootId,
                   h.SourceRunId, h.IngestionJobId, h.HandleKey, COALESCE(h.LastSeenUtc, h.FirstSeenUtc), h.ClosedUtc,
                   'ProcessAttachedEvidenceMigration', 'process-attached-v1', COALESCE(h.LastSeenUtc, h.FirstSeenUtc),
                   COALESCE(h.LastSeenUtc, h.FirstSeenUtc), 'Active', '', ''
            FROM Handles h;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ObservedToUtc,
                ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                SupersededByRelationId, AnalystAnnotationId)
            SELECT 'attachment:dump:' || d.DumpId || ':' || COALESCE(NULLIF(d.SourceRunId, ''), 'legacy') || ':' || d.Status,
                   'attachment:dump:' || d.DumpId || ':' || COALESCE(NULLIF(d.SourceRunId, ''), 'legacy') || ':' || d.Status,
                   'ProcessEntity', COALESCE(d.ProcessEntityId, ''), 'MemoryDump', d.DumpId, 'Created',
                   CASE WHEN COALESCE(d.ProcessEntityId, '') = '' THEN 'Unresolved' ELSE 'Asserted' END,
                   CASE WHEN COALESCE(d.ProcessEntityId, '') = '' THEN 'NoExactProcessEntity' ELSE 'LegacyExactProcessLink' END,
                   CASE WHEN COALESCE(d.ProcessEntityId, '') = '' THEN 0.0 ELSE 1.0 END,
                   CASE WHEN COALESCE(d.ProcessEntityId, '') = '' THEN 0 ELSE 1 END,
                   CASE WHEN COALESCE(d.ProcessEntityId, '') = '' THEN 'Dump metadata retained without a unique scoped process entity.' ELSE 'Dump metadata linked to its source process entity.' END,
                   d.CaseId, d.EvidenceSessionId, d.CaptureId, d.SourceIdentityId, d.HostId, d.ExecutionRootId,
                   d.SourceRunId, d.IngestionJobId, d.DumpId, d.RequestedUtc, d.CompletedUtc,
                   'ProcessAttachedEvidenceMigration', 'process-attached-v1', d.RequestedUtc,
                   COALESCE(d.CompletedUtc, d.RequestedUtc), 'Active', '', ''
            FROM MemoryDumps d;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc,
                ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                SupersededByRelationId, AnalystAnnotationId)
            SELECT 'attachment:pe:' || p.AnalysisId || ':' || COALESCE(NULLIF(p.SourceRunId, ''), 'legacy') || ':' || p.AnalyzedUtc,
                   'attachment:pe:' || p.AnalysisId || ':' || COALESCE(NULLIF(p.SourceRunId, ''), 'legacy') || ':' || p.AnalyzedUtc,
                   'PeAnalysis', p.AnalysisId, 'ProcessEntity', COALESCE(p.ProcessEntityId, ''), 'OwnedBy',
                   CASE WHEN COALESCE(p.ProcessEntityId, '') = '' THEN 'Unresolved' ELSE 'Asserted' END,
                   CASE WHEN COALESCE(p.ProcessEntityId, '') = '' THEN 'NoExactProcessEntity' ELSE 'LegacyExactProcessLink' END,
                   CASE WHEN COALESCE(p.ProcessEntityId, '') = '' THEN 0.0 ELSE 1.0 END,
                   CASE WHEN COALESCE(p.ProcessEntityId, '') = '' THEN 0 ELSE 1 END,
                   CASE WHEN COALESCE(p.ProcessEntityId, '') = '' THEN 'PE analysis retained without a unique scoped process entity.' ELSE 'PE analysis linked to its source process entity.' END,
                   p.CaseId, p.EvidenceSessionId, p.CaptureId, p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                   p.SourceRunId, p.IngestionJobId, COALESCE(NULLIF(p.SourceArtifactId, ''), p.AnalysisId), p.AnalyzedUtc,
                   'ProcessAttachedEvidenceMigration', 'process-attached-v1', p.AnalyzedUtc, p.AnalyzedUtc,
                   'Active', '', ''
            FROM PeAnalyses p;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc,
                ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                SupersededByRelationId, AnalystAnnotationId)
            SELECT 'attachment:pe-input:' || p.AnalysisId || ':' || COALESCE(NULLIF(p.SourceRunId, ''), 'legacy'),
                   'attachment:pe-input:' || p.AnalysisId || ':' || COALESCE(NULLIF(p.SourceRunId, ''), 'legacy'),
                   CASE WHEN p.SourceKind = 'MemoryDumpFile' THEN 'MemoryDump' ELSE 'FileArtifact' END,
                   COALESCE(NULLIF(p.SourceArtifactId, ''), p.FilePath),
                   'PeAnalysis', p.AnalysisId, 'DerivedFrom', 'Asserted', p.SourceKind, 1.0, 1,
                   'PE analysis retains its source artifact by reference.',
                   p.CaseId, p.EvidenceSessionId, p.CaptureId, p.SourceIdentityId, p.HostId, p.ExecutionRootId,
                   p.SourceRunId, p.IngestionJobId, COALESCE(NULLIF(p.SourceArtifactId, ''), p.FilePath), p.AnalyzedUtc,
                   'ProcessAttachedEvidenceMigration', 'process-attached-v1', p.AnalyzedUtc, p.AnalyzedUtc,
                   'Active', '', ''
            FROM PeAnalyses p
            WHERE COALESCE(NULLIF(p.SourceArtifactId, ''), p.FilePath) <> '';
            """);
    }

    private void EnsureIndependentArtifactLineageSchema()
    {
        EnsureSourceRunProvenanceSchema();
        EnsureColumn("Artifacts", "ParentArtifactId", "TEXT");
        ExecuteNonQuery("""
            CREATE INDEX IF NOT EXISTS IX_NetworkCaptures_SourceRunStatus
                ON NetworkCaptures(SourceRunId, Status, RequestedUtc DESC);
            CREATE INDEX IF NOT EXISTS IX_ZeekNetworkArtifacts_SourceRunCapture
                ON ZeekNetworkArtifacts(SourceRunId, CaptureId, TimestampUtc DESC);
            CREATE INDEX IF NOT EXISTS IX_MemoryImages_SourceRunImported
                ON MemoryImages(SourceRunId, ImportedUtc DESC);
            CREATE INDEX IF NOT EXISTS IX_VolatilityPluginRuns_SourceRunImage
                ON VolatilityPluginRuns(SourceRunId, ImageId, RequestedUtc DESC);
            CREATE INDEX IF NOT EXISTS IX_MemoryProcesses_SourceRunPlugin
                ON MemoryProcesses(SourceRunId, PluginRunId, ArtifactId);
            CREATE INDEX IF NOT EXISTS IX_RawRecords_SourceRunExternal
                ON RawRecords(SourceRunId, ExternalRecordId, RawRecordId);
            CREATE INDEX IF NOT EXISTS IX_Artifacts_SourceRunParent
                ON Artifacts(SourceRunId, ParentArtifactId, ArtifactId);
            """);
    }

    private void BackfillIndependentArtifactLineage()
    {
        ExecuteNonQuery("""
            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:capture-source:' || n.CaptureId || ':' || n.SourceRunId,
                   'lineage:capture-source:' || n.CaptureId || ':' || n.SourceRunId,
                   'Capture', n.CaptureId, 'SourceRun', n.SourceRunId, 'DerivedFrom',
                   'Exact', 'MigrationExactSourceRun', 1.0, 1,
                   'Network capture metadata retains the exact acquisition source run and external PCAP reference.',
                   n.CaseId, n.EvidenceSessionId, n.CaptureId, n.SourceIdentityId, n.HostId,
                   n.ExecutionRootId, n.SourceRunId, n.IngestionJobId, COALESCE(NULLIF(n.Sha256Hash, ''), n.FilePath),
                   n.RequestedUtc, 'IndependentArtifactMigration', 'independent-artifact-v1',
                   n.RequestedUtc, COALESCE(n.CompletedUtc, n.RequestedUtc), 'Active', '', ''
            FROM NetworkCaptures n WHERE COALESCE(n.SourceRunId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:zeek-run:' || z.CaptureId || ':' || z.SourceRunId,
                   'lineage:zeek-run:' || z.CaptureId || ':' || z.SourceRunId,
                   'Capture', z.CaptureId, 'SourceRun', z.SourceRunId, 'DerivedFrom',
                   'Exact', 'ZeekRunInput', 1.0, 1, 'The captured PCAP is the explicit Zeek source-run input.',
                   z.CaseId, z.EvidenceSessionId, z.CaptureId, z.SourceIdentityId, z.HostId,
                   z.ExecutionRootId, z.SourceRunId, z.IngestionJobId, z.CaptureId, z.TimestampUtc,
                   'IndependentArtifactMigration', 'independent-artifact-v1', z.TimestampUtc, z.TimestampUtc,
                   'Active', '', ''
            FROM ZeekNetworkArtifacts z
            WHERE COALESCE(z.SourceRunId, '') <> '' AND COALESCE(z.CaptureId, '') <> ''
            GROUP BY z.CaptureId, z.SourceRunId;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:zeek-raw:' || z.ArtifactId, 'lineage:zeek-raw:' || z.ArtifactId,
                   'SourceRun', z.SourceRunId, 'RawRecord', 'zeek-raw:' || z.ArtifactId, 'ExtractedFrom',
                   'Exact', 'ZeekRawLog', 1.0, 1, 'Zeek raw log line remains a file/hash/text reference.',
                   z.CaseId, z.EvidenceSessionId, z.CaptureId, z.SourceIdentityId, z.HostId,
                   z.ExecutionRootId, z.SourceRunId, z.IngestionJobId, COALESCE(z.RawLineHash, ''),
                   z.TimestampUtc, 'IndependentArtifactMigration', 'independent-artifact-v1',
                   z.TimestampUtc, z.TimestampUtc, 'Active', '', ''
            FROM ZeekNetworkArtifacts z WHERE COALESCE(z.SourceRunId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:zeek-flow:' || z.ArtifactId, 'lineage:zeek-flow:' || z.ArtifactId,
                   'RawRecord', 'zeek-raw:' || z.ArtifactId, 'NetworkFlow', z.ArtifactId, 'DerivedFrom',
                   'Exact', 'ZeekNormalization', 1.0, 1, 'Normalized flow retains its exact raw Zeek row.',
                   z.CaseId, z.EvidenceSessionId, z.CaptureId, z.SourceIdentityId, z.HostId,
                   z.ExecutionRootId, z.SourceRunId, z.IngestionJobId, COALESCE(z.RawLineHash, ''),
                   z.TimestampUtc, 'IndependentArtifactMigration', 'independent-artifact-v1',
                   z.TimestampUtc, z.TimestampUtc, 'Active', '', ''
            FROM ZeekNetworkArtifacts z;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:memory-image-source:' || m.ImageId || ':' || m.SourceRunId,
                   'lineage:memory-image-source:' || m.ImageId || ':' || m.SourceRunId,
                   'MemoryImage', m.ImageId, 'SourceRun', m.SourceRunId, 'DerivedFrom', 'Exact',
                   'MemoryImageSourceRun', 1.0, 1, 'Memory image metadata retains the exact import source run.',
                   m.CaseId, m.EvidenceSessionId, m.CaptureId, m.SourceIdentityId, m.HostId,
                   m.ExecutionRootId, m.SourceRunId, m.IngestionJobId, COALESCE(NULLIF(m.Sha256Hash, ''), m.FilePath),
                   m.ImportedUtc, 'IndependentArtifactMigration', 'independent-artifact-v1',
                   m.ImportedUtc, m.ImportedUtc, 'Active', '', ''
            FROM MemoryImages m WHERE COALESCE(m.SourceRunId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:volatility-run:' || v.RunId, 'lineage:volatility-run:' || v.RunId,
                   'SourceRun', v.SourceRunId, 'VolatilityPluginRun', v.RunId, 'DerivedFrom', 'Exact',
                   'VolatilityPluginExecution', 1.0, 1, 'Plugin execution belongs to the exact analyzer source run.',
                   v.CaseId, v.EvidenceSessionId, v.CaptureId, v.SourceIdentityId, v.HostId,
                   v.ExecutionRootId, v.SourceRunId, v.IngestionJobId, v.ImageId, v.RequestedUtc,
                   'IndependentArtifactMigration', 'independent-artifact-v1', v.RequestedUtc,
                   COALESCE(v.CompletedUtc, v.RequestedUtc), 'Active', '', ''
            FROM VolatilityPluginRuns v WHERE COALESCE(v.SourceRunId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:volatility-raw:' || v.RunId, 'lineage:volatility-raw:' || v.RunId,
                   'VolatilityPluginRun', v.RunId, 'RawRecord', 'volatility-raw:' || v.RunId,
                   'ExtractedFrom', 'Exact', 'VolatilityRawSidecar', 1.0, 1,
                   'Volatility stdout/stderr remain external sidecar references with a retained hash.',
                   v.CaseId, v.EvidenceSessionId, v.CaptureId, v.SourceIdentityId, v.HostId,
                   v.ExecutionRootId, v.SourceRunId, v.IngestionJobId, COALESCE(v.RawOutputHash, ''),
                   COALESCE(v.CompletedUtc, v.RequestedUtc), 'IndependentArtifactMigration',
                   'independent-artifact-v1', v.RequestedUtc, COALESCE(v.CompletedUtc, v.RequestedUtc),
                   'Active', '', ''
            FROM VolatilityPluginRuns v;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:memory-row:' || p.ArtifactId, 'lineage:memory-row:' || p.ArtifactId,
                   'RawRecord', 'volatility-raw:' || p.PluginRunId, 'MemoryProcess', p.ArtifactId,
                   'DerivedFrom', 'Exact', 'VolatilityNormalization', 1.0, 1,
                   'Normalized memory evidence retains the exact plugin sidecar and row hash.',
                   p.CaseId, p.EvidenceSessionId, p.CaptureId, p.SourceIdentityId, p.HostId,
                   p.ExecutionRootId, p.SourceRunId, p.IngestionJobId, COALESCE(p.RawRowHash, ''),
                   COALESCE(p.CreateTimeUtc, CURRENT_TIMESTAMP), 'IndependentArtifactMigration',
                   'independent-artifact-v1', COALESCE(p.CreateTimeUtc, CURRENT_TIMESTAMP),
                   CURRENT_TIMESTAMP, 'Active', '', ''
            FROM MemoryProcesses p;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:filesystem-raw:' || a.ArtifactId, 'lineage:filesystem-raw:' || a.ArtifactId,
                   'SourceRun', a.SourceRunId, 'RawRecord', CAST(a.RawRecordId AS TEXT), 'ExtractedFrom',
                   'Exact', 'FilesystemRawImport', 1.0, 1, 'Raw filesystem row belongs to the exact import source run.',
                   a.CaseId, a.EvidenceSessionId, a.CaptureId, a.SourceIdentityId, a.HostId,
                   a.ExecutionRootId, a.SourceRunId, a.IngestionJobId, CAST(a.RawRecordId AS TEXT),
                   COALESCE(a.TimestampUtc, a.CreatedUtc), 'IndependentArtifactMigration',
                   'independent-artifact-v1', a.CreatedUtc, a.UpdatedUtc, 'Active', '', ''
            FROM Artifacts a WHERE COALESCE(a.SourceRunId, '') <> '' AND a.RawRecordId IS NOT NULL;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:filesystem-artifact:' || a.ArtifactId,
                   'lineage:filesystem-artifact:' || a.ArtifactId,
                   'RawRecord', CAST(a.RawRecordId AS TEXT), 'FileArtifact', a.ArtifactId, 'DerivedFrom',
                   'Exact', 'FilesystemNormalization', 1.0, 1,
                   'Normalized filesystem artifact retains its exact raw record.',
                   a.CaseId, a.EvidenceSessionId, a.CaptureId, a.SourceIdentityId, a.HostId,
                   a.ExecutionRootId, a.SourceRunId, a.IngestionJobId, CAST(a.RawRecordId AS TEXT),
                   COALESCE(a.TimestampUtc, a.CreatedUtc), 'IndependentArtifactMigration',
                   'independent-artifact-v1', a.CreatedUtc, a.UpdatedUtc, 'Active', '', ''
            FROM Artifacts a WHERE a.RawRecordId IS NOT NULL;

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceRunId, IngestionJobId, RawInputId, ObservedFromUtc, ResolverName, ResolverVersion,
                CreatedUtc, UpdatedUtc, Status, SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:artifact-parent:' || a.ParentArtifactId || ':' || a.ArtifactId,
                   'lineage:artifact-parent:' || a.ParentArtifactId || ':' || a.ArtifactId,
                   'GenericArtifact', a.ParentArtifactId, 'GenericArtifact', a.ArtifactId, 'DerivedFrom',
                   'Asserted', 'ParentArtifactId', 1.0, 1, 'Generic parent/child artifact relation.',
                   a.CaseId, a.EvidenceSessionId, a.CaptureId, a.SourceIdentityId, a.HostId,
                   a.ExecutionRootId, a.SourceRunId, a.IngestionJobId, CAST(a.RawRecordId AS TEXT),
                   COALESCE(a.TimestampUtc, a.CreatedUtc), 'IndependentArtifactMigration',
                   'independent-artifact-v1', a.CreatedUtc, a.UpdatedUtc, 'Active', '', ''
            FROM Artifacts a WHERE COALESCE(a.ParentArtifactId, '') <> '';

            INSERT OR IGNORE INTO EvidenceRelations (
                RelationId, DecisionKey, FromKind, FromId, ToKind, ToId, RelationType,
                CorrelationState, CorrelationMethod, Confidence, CandidateCount, CorrelationDiagnostics,
                ObservedFromUtc, ResolverName, ResolverVersion, CreatedUtc, UpdatedUtc, Status,
                SupersededByRelationId, AnalystAnnotationId)
            SELECT 'lineage:legacy-artifact:' || ar.FromArtifactId || ':' || ar.ToArtifactId || ':' || ar.RelationType,
                   'lineage:legacy-artifact:' || ar.FromArtifactId || ':' || ar.ToArtifactId || ':' || ar.RelationType,
                   'GenericArtifact', ar.FromArtifactId, 'GenericArtifact', ar.ToArtifactId,
                   CASE ar.RelationType
                       WHEN 'Created' THEN 'Created'
                       WHEN 'ExtractedFrom' THEN 'ExtractedFrom'
                       WHEN 'DerivedFrom' THEN 'DerivedFrom'
                       WHEN 'OwnedBy' THEN 'OwnedBy'
                       ELSE 'DerivedFrom'
                   END,
                   'Asserted', 'LegacyArtifactRelations:' || ar.RelationType, 1.0, 1,
                   'Migrated from the bounded legacy ArtifactRelations compatibility table.',
                   ar.CreatedUtc, 'IndependentArtifactMigration', 'independent-artifact-v1',
                   ar.CreatedUtc, ar.CreatedUtc, 'Active', '', ''
            FROM ArtifactRelations ar;
            """);

        UpsertSchemaInfo(
            "IndependentArtifactLineage",
            "network/zeek/filesystem/memory/raw/generic relations migrated; ArtifactRelations compatibility retained read-only");
    }

    private static readonly string[] SourceRunEvidenceTables =
    [
        "Processes", "ProcessEntities", "ProcessStatistics", "ProcessEvents", "Modules", "Handles",
        "MemoryDumps", "PeAnalyses", "MemoryImages", "VolatilityPluginRuns", "MemoryProcesses",
        "NetworkCaptures", "ZeekNetworkArtifacts", "RawRecords", "Artifacts"
    ];

    private void EnsureSourceRunProvenanceSchema()
    {
        EnsureColumn("IngestionJobs", "SourceRunId", "TEXT");
        EnsureColumn("IngestionJobs", "CaseId", "TEXT");
        EnsureColumn("IngestionJobs", "EvidenceSessionId", "TEXT");
        EnsureColumn("IngestionJobs", "CaptureId", "TEXT");
        EnsureColumn("IngestionJobs", "HostId", "TEXT");
        EnsureColumn("IngestionJobs", "ExecutionRootId", "TEXT");
        foreach (var table in SourceRunEvidenceTables)
        {
            EnsureColumn(table, "SourceRunId", "TEXT");
            EnsureColumn(table, "IngestionJobId", "TEXT");
        }

        ExecuteNonQuery("""
            CREATE INDEX IF NOT EXISTS IX_SourceRuns_ScopeStarted
                ON SourceRuns(CaseId, EvidenceSessionId, CaptureId, HostId, ExecutionRootId, StartedUtc);
            CREATE INDEX IF NOT EXISTS IX_SourceRuns_DefinitionStarted
                ON SourceRuns(SourceId, StartedUtc);
            CREATE INDEX IF NOT EXISTS IX_SourceRuns_Job
                ON SourceRuns(IngestionJobId);
            CREATE INDEX IF NOT EXISTS IX_SourceRunLineage_Parent
                ON SourceRunLineage(ParentSourceRunId);
            CREATE INDEX IF NOT EXISTS IX_IngestionJobs_SourceRun
                ON IngestionJobs(SourceRunId);
            """);
        foreach (var table in SourceRunEvidenceTables)
        {
            ExecuteNonQuery($"CREATE INDEX IF NOT EXISTS IX_{table}_SourceRun ON {table}(SourceRunId);");
            ExecuteNonQuery($"CREATE INDEX IF NOT EXISTS IX_{table}_IngestionJob ON {table}(IngestionJobId);");
        }
    }

    private void BackfillSourceRunProvenance()
    {
        ExecuteNonQuery("""
            INSERT OR IGNORE INTO SourceRuns(
                SourceRunId, SourceId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                HostId, ExecutionRootId, SourceType, DisplayName, SourcePath, Provider, Channel,
                IsLive, Status, StartedUtc, EndedUtc, MetadataJson, CreatedUtc, UpdatedUtc)
            SELECT printf('legacy-srun-%016x', SourceId), SourceId, CaseId, EvidenceSessionId, CaptureId,
                   SourceIdentityId, HostId, ExecutionRootId, SourceType, DisplayName, Path, Provider,
                   Channel, IsLive, Status, COALESCE(StartTimeUtc, CreatedUtc), EndTimeUtc,
                   COALESCE(MetadataJson, '{}'), CreatedUtc, UpdatedUtc
            FROM Sources;

            UPDATE IngestionJobs
            SET SourceRunId = printf('legacy-srun-%016x', SourceId)
            WHERE (SourceRunId IS NULL OR SourceRunId = '') AND SourceId IS NOT NULL;
            UPDATE IngestionJobs
            SET CaseId = (SELECT CaseId FROM SourceRuns r WHERE r.SourceRunId = IngestionJobs.SourceRunId),
                EvidenceSessionId = (SELECT EvidenceSessionId FROM SourceRuns r WHERE r.SourceRunId = IngestionJobs.SourceRunId),
                CaptureId = (SELECT CaptureId FROM SourceRuns r WHERE r.SourceRunId = IngestionJobs.SourceRunId),
                HostId = (SELECT HostId FROM SourceRuns r WHERE r.SourceRunId = IngestionJobs.SourceRunId),
                ExecutionRootId = (SELECT ExecutionRootId FROM SourceRuns r WHERE r.SourceRunId = IngestionJobs.SourceRunId)
            WHERE SourceRunId IS NOT NULL AND SourceRunId <> '';
            """);

        foreach (var table in SourceRunEvidenceTables)
        {
            ExecuteNonQuery($"""
                UPDATE {table}
                SET SourceRunId = printf('legacy-srun-%016x', SourceId)
                WHERE (SourceRunId IS NULL OR SourceRunId = '') AND SourceId IS NOT NULL;
                """);
            using var diagnostic = CreateCommand($"""
                INSERT OR REPLACE INTO SchemaInfo(Key, Value)
                SELECT 'SourceRunBackfill.{table}',
                       'linked=' || COALESCE(SUM(CASE WHEN SourceRunId IS NOT NULL AND SourceRunId <> '' THEN 1 ELSE 0 END), 0) ||
                       ';missing=' || COALESCE(SUM(CASE WHEN SourceRunId IS NULL OR SourceRunId = '' THEN 1 ELSE 0 END), 0)
                FROM {table};
                """);
            diagnostic.ExecuteNonQuery();
        }
    }

    private void EnsureSourceRunProvenanceTriggers()
    {
        foreach (var table in SourceRunEvidenceTables)
        {
            ExecuteNonQuery($"""
                CREATE TRIGGER IF NOT EXISTS TR_{table}_SourceRun_Insert
                AFTER INSERT ON {table}
                WHEN NEW.SourceRunId IS NULL OR NEW.SourceRunId = ''
                BEGIN
                    UPDATE {table}
                    SET SourceRunId = (SELECT SourceRunId FROM WriterProvenanceContext WHERE SingletonId = 1),
                        IngestionJobId = (SELECT IngestionJobId FROM WriterProvenanceContext WHERE SingletonId = 1)
                    WHERE rowid = NEW.rowid
                      AND EXISTS(SELECT 1 FROM WriterProvenanceContext WHERE SingletonId = 1);
                END;
                CREATE TRIGGER IF NOT EXISTS TR_{table}_SourceRun_Update
                AFTER UPDATE ON {table}
                WHEN (NEW.SourceRunId IS NULL OR NEW.SourceRunId = '')
                BEGIN
                    UPDATE {table}
                    SET SourceRunId = (SELECT SourceRunId FROM WriterProvenanceContext WHERE SingletonId = 1),
                        IngestionJobId = (SELECT IngestionJobId FROM WriterProvenanceContext WHERE SingletonId = 1)
                    WHERE rowid = NEW.rowid
                      AND EXISTS(SELECT 1 FROM WriterProvenanceContext WHERE SingletonId = 1);
                END;
                """);
        }
    }

    public static string CalculateConfigurationHash(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value ?? string.Empty))).ToLowerInvariant();

    private static string SanitizeSourceRunMetadata(string? metadataJson)
    {
        if (string.IsNullOrWhiteSpace(metadataJson))
        {
            return "{}";
        }

        var bounded = metadataJson.Length <= 8192 ? metadataJson : metadataJson[..8192];
        foreach (var secretName in new[] { "apikey", "api_key", "token", "secret", "password", "authorization", "credential" })
        {
            if (bounded.Contains(secretName, StringComparison.OrdinalIgnoreCase))
            {
                return "{\"redacted\":true}";
            }
        }

        try
        {
            using var document = JsonDocument.Parse(bounded);
            return JsonSerializer.Serialize(document.RootElement);
        }
        catch (JsonException)
        {
            return "{}";
        }
    }

    private void BackfillProcessEntityIdentity()
    {
        ExecuteNonQuery("""
            INSERT OR IGNORE INTO ProcessEntities (
                ProcessEntityId, ProcessKey, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                HostId, ExecutionRootId, ArtifactId, SourceId, ProcessId, ProcessGuid, StartTimeUtc,
                EndTimeUtc, Status, ParentProcessId, ParentProcessKey, ParentProcessEntityId,
                ParentProcessName, ProcessName, ProcessPath, CommandLine, UserName, SessionId,
                Architecture, CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash,
                TreeDepth, FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus,
                ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError, HandleCaptureStatus,
                HandleCount, HandleLastCapturedUtc, HandleCaptureError)
            SELECT COALESCE(NULLIF(ProcessEntityId, ''), lower(hex(randomblob(16)))), ProcessKey,
                   CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                   ArtifactId, SourceId, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                   ParentProcessId, ParentProcessKey, ParentProcessEntityId, ParentProcessName,
                   ProcessName, ProcessPath, CommandLine, UserName, SessionId, Architecture,
                   CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash, TreeDepth,
                   FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus, ModuleCount,
                   ModuleLastCapturedUtc, ModuleCaptureError, HandleCaptureStatus, HandleCount,
                   HandleLastCapturedUtc, HandleCaptureError
            FROM Processes;

            UPDATE Processes
            SET ProcessEntityId = (
                SELECT pe.ProcessEntityId FROM ProcessEntities pe
                WHERE pe.ProcessKey = Processes.ProcessKey
                  AND COALESCE(pe.CaseId, '') = COALESCE(Processes.CaseId, '')
                  AND COALESCE(pe.EvidenceSessionId, '') = COALESCE(Processes.EvidenceSessionId, '')
                  AND COALESCE(pe.HostId, '') = COALESCE(Processes.HostId, '')
                  AND COALESCE(pe.ExecutionRootId, '') = COALESCE(Processes.ExecutionRootId, '')
                LIMIT 1);

            INSERT OR IGNORE INTO ProcessAliases (
                ProcessEntityId, AliasKind, AliasValue, CaseId, EvidenceSessionId, HostId,
                ExecutionRootId, SourceIdentityId, CreatedUtc)
            SELECT ProcessEntityId, 'LegacyProcessKey', ProcessKey, CaseId, EvidenceSessionId,
                   HostId, ExecutionRootId, SourceIdentityId, datetime('now')
            FROM ProcessEntities WHERE ProcessKey <> '';

            INSERT OR IGNORE INTO ProcessAliases (
                ProcessEntityId, AliasKind, AliasValue, CaseId, EvidenceSessionId, HostId,
                ExecutionRootId, SourceIdentityId, CreatedUtc)
            SELECT ProcessEntityId, 'SysmonProcessGuid', ProcessGuid, CaseId, EvidenceSessionId,
                   HostId, ExecutionRootId, SourceIdentityId, datetime('now')
            FROM ProcessEntities WHERE ProcessGuid IS NOT NULL AND ProcessGuid <> '';
            """);

        ExecuteNonQuery("""
            UPDATE ProcessEntities AS child
            SET ParentProcessEntityId = (
                SELECT MIN(alias.ProcessEntityId)
                FROM ProcessAliases alias
                WHERE alias.AliasKind = 'LegacyProcessKey'
                  AND alias.AliasValue = child.ParentProcessKey
                  AND COALESCE(alias.CaseId, '') = COALESCE(child.CaseId, '')
                  AND COALESCE(alias.EvidenceSessionId, '') = COALESCE(child.EvidenceSessionId, '')
                  AND COALESCE(alias.HostId, '') = COALESCE(child.HostId, '')
                  AND COALESCE(alias.ExecutionRootId, '') = COALESCE(child.ExecutionRootId, '')
                HAVING COUNT(DISTINCT alias.ProcessEntityId) = 1)
            WHERE ParentProcessKey IS NOT NULL AND ParentProcessKey <> '';
            UPDATE Processes
            SET ParentProcessEntityId = (
                SELECT pe.ParentProcessEntityId FROM ProcessEntities pe
                WHERE pe.ProcessEntityId = Processes.ProcessEntityId);
            """);

        foreach (var table in new[]
        {
            "ProcessStatistics", "ProcessEvents", "Modules", "Handles", "MemoryDumps",
            "PeAnalyses", "MemoryProcesses", "ZeekNetworkArtifacts", "Artifacts"
        })
        {
            BackfillProcessEntityLinks(table);
        }
    }

    private void BackfillProcessEntityLinks(string table)
    {
        ExecuteNonQuery($"""
            UPDATE {table} AS evidence
            SET ProcessEntityId = (
                SELECT MIN(alias.ProcessEntityId)
                FROM ProcessAliases alias
                WHERE alias.AliasKind = 'LegacyProcessKey'
                  AND alias.AliasValue = evidence.ProcessKey
                  AND COALESCE(alias.CaseId, '') = COALESCE(evidence.CaseId, '')
                  AND COALESCE(alias.EvidenceSessionId, '') = COALESCE(evidence.EvidenceSessionId, '')
                  AND COALESCE(alias.HostId, '') = COALESCE(evidence.HostId, '')
                  AND COALESCE(alias.ExecutionRootId, '') = COALESCE(evidence.ExecutionRootId, '')
                HAVING COUNT(DISTINCT alias.ProcessEntityId) = 1)
            WHERE ProcessEntityId IS NULL OR ProcessEntityId = '';
            """);

        using var command = CreateCommand($"""
            INSERT OR REPLACE INTO SchemaInfo(Key, Value)
            SELECT 'ProcessEntityBackfill.{table}',
                   'linked=' || COALESCE(SUM(CASE WHEN ProcessEntityId IS NOT NULL AND ProcessEntityId <> '' THEN 1 ELSE 0 END), 0) ||
                   ';unresolved=' || COALESCE(SUM(CASE WHEN ProcessKey IS NOT NULL AND ProcessKey <> '' AND (ProcessEntityId IS NULL OR ProcessEntityId = '') THEN 1 ELSE 0 END), 0) ||
                   ';ambiguous=' || COALESCE(SUM(CASE WHEN (
                       SELECT COUNT(DISTINCT alias.ProcessEntityId)
                       FROM ProcessAliases alias
                       WHERE alias.AliasKind = 'LegacyProcessKey'
                         AND alias.AliasValue = evidence.ProcessKey
                         AND COALESCE(alias.CaseId, '') = COALESCE(evidence.CaseId, '')
                         AND COALESCE(alias.EvidenceSessionId, '') = COALESCE(evidence.EvidenceSessionId, '')
                         AND COALESCE(alias.HostId, '') = COALESCE(evidence.HostId, '')
                         AND COALESCE(alias.ExecutionRootId, '') = COALESCE(evidence.ExecutionRootId, '')
                   ) > 1 THEN 1 ELSE 0 END), 0)
            FROM {table} evidence;
            """);
        command.ExecuteNonQuery();
    }

    private void EnsureProcessEntityLinkTriggers()
    {
        foreach (var table in new[]
        {
            "ProcessStatistics", "ProcessEvents", "Modules", "Handles", "MemoryDumps",
            "PeAnalyses", "MemoryProcesses", "ZeekNetworkArtifacts", "Artifacts"
        })
        {
            ExecuteNonQuery($"""
                CREATE TRIGGER IF NOT EXISTS TR_{table}_ResolveProcessEntity
                AFTER INSERT ON {table}
                WHEN (NEW.ProcessEntityId IS NULL OR NEW.ProcessEntityId = '')
                     AND NEW.ProcessKey IS NOT NULL AND NEW.ProcessKey <> ''
                BEGIN
                    UPDATE {table}
                    SET ProcessEntityId = (
                        SELECT MIN(alias.ProcessEntityId)
                        FROM ProcessAliases alias
                        WHERE alias.AliasKind = 'LegacyProcessKey'
                          AND alias.AliasValue = NEW.ProcessKey
                          AND COALESCE(alias.CaseId, '') = COALESCE(NEW.CaseId, '')
                          AND COALESCE(alias.EvidenceSessionId, '') = COALESCE(NEW.EvidenceSessionId, '')
                          AND COALESCE(alias.HostId, '') = COALESCE(NEW.HostId, '')
                          AND COALESCE(alias.ExecutionRootId, '') = COALESCE(NEW.ExecutionRootId, '')
                        HAVING COUNT(DISTINCT alias.ProcessEntityId) = 1)
                    WHERE rowid = NEW.rowid;
                END;
                """);
        }
    }

    private static void ExecuteWithRetry(Action action, CancellationToken cancellationToken)
    {
        const int maxAttempts = 4;
        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                action();
                return;
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode is 5 or 6 && attempt < maxAttempts)
            {
                var delay = TimeSpan.FromMilliseconds(250 * attempt);
                cancellationToken.WaitHandle.WaitOne(delay);
            }
        }
    }

    private int? EnsureTelemetrySource(string displayName, string sourceType)
    {
        if (string.IsNullOrWhiteSpace(displayName))
        {
            return null;
        }

        return EnsureSource(sourceType, displayName, isLive: IsLiveSource(displayName));
    }

    private void ClearTables(bool preserveSourceCatalog = false)
    {
        var tables = new List<string>
        {
            "SearchIndex",
            "ReputationAttributions",
            "ProcessRiskBaselineInputs",
            "ProcessRiskSigmaInputs",
            "ProcessRiskProjectionContributors",
            "ProcessRiskProjectionSources",
            "ProcessRiskProjections",
            "EvidenceCorrelationInputs",
            "EvidenceRelations",
            "ArtifactRelations",
            "ArtifactProperties",
            "Artifacts",
            "ZeekNetworkArtifacts",
            "NetworkCaptures",
            "MemoryProcesses",
            "VolatilityPluginRuns",
            "MemoryImages",
            "AuthenticodeVerifications",
            "PeAnalyses",
            "MemoryDumps",
            "Handles",
            "Modules",
            "ProcessEvents",
            "ProcessStatistics",
            "RawRecords",
            "ProcessProjectionFields",
            "ProcessObservations",
            "Processes",
            "ProcessAliases",
            "ProcessEntities"
        };
        if (!preserveSourceCatalog)
        {
            tables.AddRange([
                "WriterProvenanceContext",
                "IngestionJobs",
                "SourceRunLineage",
                "SourceRuns",
                "Sources"]);
        }

        foreach (var table in tables)
        {
            using var command = CreateCommand($"DELETE FROM {table};");
            command.ExecuteNonQuery();
        }
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

    private static uint GetUInt(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? 0 : unchecked((uint)reader.GetInt64(ordinal));
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

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum fallback)
        where TEnum : struct
    {
        return !reader.IsDBNull(ordinal) && Enum.TryParse<TEnum>(reader.GetString(ordinal), out var value)
            ? value
            : fallback;
    }

    private void UpsertSchemaInfo(string key, string value)
    {
        using var command = CreateCommand("""
            INSERT INTO SchemaInfo(Key, Value) VALUES($Key, $Value)
            ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value;
            """);
        Add(command, "$Key", key);
        Add(command, "$Value", value);
        command.ExecuteNonQuery();
    }

    private void ExecuteNonQuery(string sql)
    {
        using var command = CreateCommand(sql);
        command.ExecuteNonQuery();
    }

    internal void ExecuteComponentWriteTransaction(Action action)
        => ExecuteInWriteTransaction(action);

    internal SqliteCommand CreateComponentWriteCommand(string sql)
    {
        if (_activeTransaction == null)
        {
            throw new InvalidOperationException(
                "Focused evidence writers may create commands only inside a store-authorized transaction.");
        }

        return CreateCommand(sql);
    }

    internal int? EnsureComponentTelemetrySource(string displayName, string sourceType)
        => EnsureTelemetrySource(displayName, sourceType);

    internal EvidenceIdentity ResolveComponentEvidenceIdentity(
        IHasEvidenceIdentity record,
        string sourceType,
        string displayName)
        => ResolveEvidenceIdentity(record, sourceType, displayName);

    internal ProcessEvidenceAttachmentResolution PrepareComponentProcessAttachedEvidence(
        IHasProcessEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        int processId,
        string processGuid,
        DateTime? processStartTimeUtc,
        string processName,
        DateTime observedUtc)
        => PrepareProcessAttachedEvidence(
            evidence,
            evidenceKind,
            evidenceId,
            processId,
            processGuid,
            processStartTimeUtc,
            processName,
            observedUtc);

    internal void PersistComponentProcessAttachedRelation(
        IHasProcessEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        EvidenceRelationType relationType,
        ProcessEvidenceAttachmentResolution resolution,
        DateTime observedUtc,
        DateTime? observedToUtc,
        string rawInputId,
        string observationDiscriminator,
        bool processIsSource)
        => PersistProcessAttachedRelation(
            evidence,
            evidenceKind,
            evidenceId,
            relationType,
            resolution,
            observedUtc,
            observedToUtc,
            rawInputId,
            observationDiscriminator,
            processIsSource);

    internal void PersistComponentPeAnalysisDerivationRelation(EvidenceRelation relation)
    {
        ArgumentNullException.ThrowIfNull(relation);
        if (_activeTransaction == null)
        {
            throw new InvalidOperationException(
                "Focused PE derivation relations require a store-authorized transaction.");
        }

        if (relation.RelationType != EvidenceRelationType.DerivedFrom ||
            relation.ToKind != EvidenceReferenceKind.PeAnalysis ||
            relation.FromKind is not (EvidenceReferenceKind.FileArtifact or EvidenceReferenceKind.MemoryDump))
        {
            throw new InvalidOperationException(
                "The focused dump/PE writer may publish only file-or-dump to PE derivation relations.");
        }

        UpsertEvidenceRelation(relation);
    }

    internal void PersistComponentAuthenticodeDerivationRelation(EvidenceRelation relation)
    {
        ArgumentNullException.ThrowIfNull(relation);
        if (_activeTransaction == null)
        {
            throw new InvalidOperationException(
                "Focused Authenticode derivation relations require a store-authorized transaction.");
        }

        if (relation.RelationType != EvidenceRelationType.DerivedFrom ||
            relation.FromKind != EvidenceReferenceKind.PeAnalysis ||
            relation.ToKind != EvidenceReferenceKind.AuthenticodeVerification)
        {
            throw new InvalidOperationException(
                "The focused dump/PE writer may publish only PE-analysis to Authenticode-verification derivation relations.");
        }

        UpsertEvidenceRelation(relation);
    }

    internal void ApplyComponentNetworkEvidenceProvenance(IHasSourceRunEvidenceLink evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (evidence is not (NetworkCaptureRecord or ZeekNetworkRecord))
        {
            throw new InvalidOperationException(
                "The focused network writer may apply provenance only to network-capture or Zeek evidence.");
        }

        ApplyCurrentWriterProvenance(evidence);
    }

    internal void ApplyComponentFilesystemEvidenceProvenance(FilesystemArtifactRecord artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        ApplyCurrentWriterProvenance(artifact);
    }

    internal void ApplyComponentSystemMemoryEvidenceProvenance(IHasSourceRunEvidenceLink evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (evidence is not (MemoryImageRecord or VolatilityPluginRunRecord or MemoryProcessRecord))
        {
            throw new InvalidOperationException(
                "The focused system-memory writer may apply provenance only to memory images, Volatility runs, or memory processes.");
        }

        ApplyCurrentWriterProvenance(evidence);
    }

    internal void PersistComponentNetworkSourceRunRelation(
        IHasSourceRunEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        DateTime observedUtc,
        string rawInputId)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        var isCapture = evidence is NetworkCaptureRecord && evidenceKind == EvidenceReferenceKind.Capture;
        var isFlow = evidence is ZeekNetworkRecord && evidenceKind == EvidenceReferenceKind.NetworkFlow;
        if (!isCapture && !isFlow)
        {
            throw new InvalidOperationException(
                "The focused network writer may publish only network-capture or Zeek-flow source-run lineage.");
        }

        PersistIndependentArtifactSourceRunRelation(
            evidence,
            evidenceKind,
            evidenceId,
            observedUtc,
            rawInputId);
    }

    internal void PersistComponentFilesystemSourceRunRelation(
        FilesystemArtifactRecord artifact,
        string artifactId,
        DateTime observedUtc,
        string rawInputId)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (!string.Equals(artifact.ArtifactId, artifactId, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(artifactId))
        {
            throw new InvalidOperationException(
                "The focused filesystem writer may publish source-run lineage only for its current file artifact.");
        }

        PersistIndependentArtifactSourceRunRelation(
            artifact,
            EvidenceReferenceKind.FileArtifact,
            artifactId,
            observedUtc,
            rawInputId);
    }

    internal void PersistComponentSystemMemorySourceRunRelation(
        IHasSourceRunEvidenceLink evidence,
        EvidenceReferenceKind evidenceKind,
        string evidenceId,
        DateTime observedUtc,
        string rawInputId)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        var isImage = evidence is MemoryImageRecord && evidenceKind == EvidenceReferenceKind.MemoryImage;
        var isPluginRun = evidence is VolatilityPluginRunRecord && evidenceKind == EvidenceReferenceKind.VolatilityPluginRun;
        var isMemoryProcess = evidence is MemoryProcessRecord && evidenceKind == EvidenceReferenceKind.MemoryProcess;
        if (!isImage && !isPluginRun && !isMemoryProcess)
        {
            throw new InvalidOperationException(
                "The focused system-memory writer may publish source-run lineage only for its current memory-family row.");
        }

        PersistIndependentArtifactSourceRunRelation(
            evidence,
            evidenceKind,
            evidenceId,
            observedUtc,
            rawInputId);
    }

    internal void UpsertComponentSearchIndex(SearchIndexRow row)
        => _analysisIndexMaintenance.Upsert(row);

    internal SqliteCommand CreateAnalysisMaintenanceCommand(string sql)
        => CreateCommand(sql);

    internal void ExecuteAnalysisMaintenanceTransaction(Action action)
        => ExecuteInWriteTransaction(action);

    internal T ExecuteAnalysisMaintenanceTransactionWithRetry<T>(
        Func<T> action,
        CancellationToken cancellationToken)
    {
        T? result = default;
        ExecuteWithRetry(
            () => ExecuteInWriteTransaction(() => result = action()),
            cancellationToken);
        return result!;
    }

    internal bool AnalysisMaintenanceTableExists(string tableName)
        => TableExists(Connection, tableName);

    internal bool AnalysisMaintenanceColumnExists(string tableName, string columnName)
        => ColumnExists(Connection, tableName, columnName);

    internal void EnsureComponentAnalysisIndexGroup(
        SqliteAnalysisIndexGroup group,
        CancellationToken cancellationToken)
        => ExecuteWithRetry(
            () => SqlitePerformanceProfile.EnsureAnalysisIndexGroup(Connection, group, cancellationToken),
            cancellationToken);

    internal void RecordComponentAnalysisIndexMigration()
        => SqlitePerformanceProfile.RecordIndexMigration(
            Connection,
            SqlitePerformanceProfile.AnalysisIndexMigrationId,
            CaptureCompatibilityPolicy
                .GetMigration(SqlitePerformanceProfile.AnalysisIndexMigrationId)
                .Description);

    internal void UpsertComponentAnalysisSchemaInfo(string key, string value)
        => UpsertSchemaInfo(key, value);

    internal void LogComponentAnalysisOperation(
        string databaseRole,
        string operation,
        TimeSpan elapsed,
        string details)
        => SqliteDiagnosticsLogger.LogOperation(
            _databasePath,
            databaseRole,
            operation,
            elapsed,
            details,
            force: true);

    internal IReadOnlyList<CorrelationSearchIndexEntry> ReadComponentCorrelationSearchEntries(int maxCount)
    {
        maxCount = Math.Clamp(maxCount, 1, 1000);
        var entries = new List<CorrelationSearchIndexEntry>();
        foreach (var input in ReadEvidenceCorrelationInputsCore(
                     new EvidenceReCorrelationRequest
                     {
                         IncludeAlreadyResolved = true,
                         MaxCount = maxCount
                     },
                     maxCount))
        {
            var decision = ReadActiveEvidenceRelation(input.DecisionKey);
            if (decision != null)
            {
                entries.Add(new CorrelationSearchIndexEntry(input, decision));
            }
        }

        return entries;
    }

    internal void ApplyComponentPersistedEventCorrelationProvenance(
        EvidenceCorrelationInput input,
        long sequenceId)
        => ApplyPersistedCorrelationProvenance(input, "ProcessEvents", "SequenceId", sequenceId);

    internal void ApplyComponentPersistedZeekCorrelationProvenance(
        EvidenceCorrelationInput input,
        string artifactId)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.EvidenceKind != EvidenceReferenceKind.NetworkFlow ||
            !string.Equals(input.EvidenceId, artifactId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The focused network writer may bind persisted correlation provenance only for its current Zeek flow.");
        }

        ApplyPersistedCorrelationProvenance(
            input,
            "ZeekNetworkArtifacts",
            "ArtifactId",
            artifactId);
    }

    internal void ApplyComponentPersistedMemoryProcessCorrelationProvenance(
        EvidenceCorrelationInput input,
        string artifactId)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.EvidenceKind != EvidenceReferenceKind.MemoryProcess ||
            !string.Equals(input.EvidenceId, artifactId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The focused system-memory writer may bind persisted correlation provenance only for its current memory-process row.");
        }

        ApplyPersistedCorrelationProvenance(
            input,
            "MemoryProcesses",
            "ArtifactId",
            artifactId);
    }

    internal void UpsertComponentEvidenceCorrelationInput(EvidenceCorrelationInput input)
        => UpsertEvidenceCorrelationInputCore(input);

    internal void EnsureComponentInitialCorrelationDecision(EvidenceCorrelationInput input)
        => EnsureInitialCorrelationDecisionCore(input);

    internal void RefreshComponentProcessDerivedState(ProcessRecord process)
    {
        _analysisIndexMaintenance.UpsertProcess(process);
        ReCorrelateEvidenceCore(new EvidenceReCorrelationRequest
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            ProcessId = process.ProcessId > 0 ? process.ProcessId : null,
            ProcessGuid = process.ProcessId > 0 ? string.Empty : process.ProcessGuid,
            MaxCount = 25
        }, CancellationToken.None);
    }

    internal void RefreshComponentProcessDerivedStates(IReadOnlyList<ProcessRecord> processes)
    {
        ArgumentNullException.ThrowIfNull(processes);
        foreach (var process in processes)
        {
            ArgumentNullException.ThrowIfNull(process);
            _analysisIndexMaintenance.UpsertProcess(process);
        }

        if (processes.Count == 0)
        {
            return;
        }

        using (var command = CreateCommand("SELECT 1 FROM EvidenceCorrelationInputs LIMIT 1;"))
        {
            if (command.ExecuteScalar() == null)
            {
                return;
            }
        }

        foreach (var process in processes)
        {
            ReCorrelateEvidenceCore(new EvidenceReCorrelationRequest
            {
                CaseId = process.CaseId,
                EvidenceSessionId = process.EvidenceSessionId,
                HostId = process.HostId,
                ExecutionRootId = process.ExecutionRootId,
                ProcessId = process.ProcessId > 0 ? process.ProcessId : null,
                ProcessGuid = process.ProcessId > 0 ? string.Empty : process.ProcessGuid,
                MaxCount = 25
            }, CancellationToken.None);
        }
    }

    private void ExecuteInWriteTransaction(Action action)
    {
        lock (_lock)
        {
            if (_activeTransaction != null)
            {
                action();
                return;
            }

            using var transaction = Connection.BeginTransaction();
            _activeTransaction = transaction;
            try
            {
                action();
                transaction.Commit();
            }
            finally
            {
                _activeTransaction = null;
            }
        }
    }

    private SqliteCommand CreateCommand(string sql)
    {
        var command = Connection.CreateCommand();
        command.CommandText = sql;
        command.CommandTimeout = 5;
        if (_activeTransaction != null)
        {
            command.Transaction = _activeTransaction;
        }

        return command;
    }

    private static void Add(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = FormatDate(dateTime);
        }
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    private static void Set(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = FormatDate(dateTime);
        }

        command.Parameters[name].Value = value ?? DBNull.Value;
    }

    private static string FormatDate(DateTime value)
    {
        return value.Kind == DateTimeKind.Utc
            ? value.ToString("O")
            : value.ToUniversalTime().ToString("O");
    }

    private static string BuildProcessStatisticsSampleId(string processKey, DateTime observedUtc)
    {
        var normalizedProcessKey = string.IsNullOrWhiteSpace(processKey)
            ? "unknown"
            : processKey;
        var normalizedObservedUtc = observedUtc == default ? DateTime.UtcNow : observedUtc;
        return $"{normalizedProcessKey}_{normalizedObservedUtc.ToUniversalTime().Ticks}";
    }

    private static bool IsLiveSource(string source)
    {
        return source.Contains("Runtime", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("ETW", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("Security", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("Sysmon", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("Snapshot", StringComparison.OrdinalIgnoreCase) ||
               source.Contains("Burst", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTerminalJobState(JobState state)
    {
        return state is JobState.Completed or JobState.Cancelled or JobState.Failed;
    }

    private sealed class IdentityCarrier : IHasEvidenceIdentity
    {
        public string CaseId { get; set; } = string.Empty;
        public string EvidenceSessionId { get; set; } = string.Empty;
        public string CaptureId { get; set; } = string.Empty;
        public string SourceIdentityId { get; set; } = string.Empty;
        public string HostId { get; set; } = string.Empty;
        public string ExecutionRootId { get; set; } = string.Empty;

        public static IdentityCarrier FromIdentity(EvidenceIdentity? identity)
        {
            return identity == null
                ? new IdentityCarrier()
                : new IdentityCarrier
                {
                    CaseId = identity.CaseId,
                    EvidenceSessionId = identity.EvidenceSessionId,
                    CaptureId = identity.CaptureId,
                    SourceIdentityId = identity.SourceIdentityId,
                    HostId = identity.HostId,
                    ExecutionRootId = identity.ExecutionRootId
                };
        }
    }
}
