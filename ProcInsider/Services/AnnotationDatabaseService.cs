using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Ai;
using ProcInsider.Models.ApplicationCatalog;
using ProcInsider.Models.Telemetry;

namespace ProcInsider.Services;

public sealed class AnnotationDatabaseService
{
    private const string SchemaVersion = "5";
    private static readonly TimeSpan MetadataRegexTimeout = TimeSpan.FromMilliseconds(150);
    private readonly object _lock = new();
    private readonly string _databasePath;

    public AnnotationDatabaseService(string databasePath)
    {
        _databasePath = databasePath;
    }

    public string DatabasePath => _databasePath;

    public void Initialize()
    {
        lock (_lock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_databasePath) ?? AppContext.BaseDirectory);
            using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
            using var command = connection.CreateCommand();
            command.CommandText = """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                PRAGMA synchronous=NORMAL;
                CREATE TABLE IF NOT EXISTS SchemaInfo (
                    Key TEXT PRIMARY KEY,
                    Value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS SchemaMigrations (
                    MigrationId TEXT PRIMARY KEY,
                    AppliedUtc TEXT NOT NULL,
                    Description TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS Bookmarks (
                    BookmarkId TEXT PRIMARY KEY,
                    TargetKind TEXT NOT NULL,
                    TargetTable TEXT,
                    TargetId TEXT NOT NULL,
                    ArtifactId TEXT,
                    CaseId TEXT,
                    EvidenceSessionId TEXT,
                    CaptureId TEXT,
                    SourceIdentityId TEXT,
                    HostId TEXT,
                    ProcessKey TEXT,
                    ProcessId INTEGER,
                    ProcessName TEXT,
                    Label TEXT,
                    DisplayPath TEXT,
                    Notes TEXT,
                    Tags TEXT,
                    CreatedUtc TEXT NOT NULL,
                    UpdatedUtc TEXT NOT NULL,
                    UNIQUE(TargetKind, TargetId)
                );
                CREATE TABLE IF NOT EXISTS Notes (
                    NoteId TEXT PRIMARY KEY,
                    TargetKind TEXT NOT NULL,
                    TargetTable TEXT,
                    TargetId TEXT NOT NULL,
                    ArtifactId TEXT,
                    CaseId TEXT,
                    EvidenceSessionId TEXT,
                    CaptureId TEXT,
                    SourceIdentityId TEXT,
                    HostId TEXT,
                    ProcessKey TEXT,
                    ProcessId INTEGER,
                    ProcessName TEXT,
                    Label TEXT,
                    DisplayPath TEXT,
                    Content TEXT,
                    Tags TEXT,
                    CreatedUtc TEXT NOT NULL,
                    UpdatedUtc TEXT NOT NULL,
                    UNIQUE(TargetKind, TargetId)
                );
                CREATE TABLE IF NOT EXISTS AiInvestigationOutputs (
                    InvestigationId TEXT PRIMARY KEY,
                    TargetKind TEXT NOT NULL,
                    TargetTable TEXT,
                    TargetId TEXT NOT NULL,
                    ArtifactId TEXT,
                    CaseId TEXT,
                    EvidenceSessionId TEXT,
                    CaptureId TEXT,
                    SourceIdentityId TEXT,
                    HostId TEXT,
                    ProcessKey TEXT,
                    ProcessId INTEGER,
                    ProcessName TEXT,
                    Label TEXT,
                    DisplayPath TEXT,
                    SourceScopeKind TEXT,
                    SourceScopeSummary TEXT,
                    PromptTemplateId TEXT,
                    PromptTemplateTitle TEXT,
                    SystemPrompt TEXT,
                    AnalystPrompt TEXT,
                    FinalPrompt TEXT,
                    ProviderKind TEXT,
                    ProviderName TEXT,
                    BaseUrl TEXT,
                    ModelName TEXT,
                    RequestedUtc TEXT NOT NULL,
                    CompletedUtc TEXT,
                    Status TEXT NOT NULL,
                    RequestCharacterCount INTEGER,
                    ResponseCharacterCount INTEGER,
                    PromptTokens INTEGER,
                    CompletionTokens INTEGER,
                    TotalTokens INTEGER,
                    ErrorText TEXT,
                    ResponseText TEXT
                );
                CREATE TABLE IF NOT EXISTS AiChatMessages (
                    MessageId TEXT PRIMARY KEY,
                    ConversationId TEXT NOT NULL,
                    Role TEXT NOT NULL,
                    Content TEXT NOT NULL,
                    ProviderKind TEXT,
                    ProviderName TEXT,
                    BaseUrl TEXT,
                    ModelName TEXT,
                    CreatedUtc TEXT NOT NULL,
                    Status TEXT NOT NULL,
                    ErrorText TEXT
                );
                CREATE TABLE IF NOT EXISTS ApplicationMetadata (
                    ApplicationId TEXT PRIMARY KEY,
                    DisplayName TEXT NOT NULL,
                    ExecutableNamePattern TEXT NOT NULL,
                    IsRegexPattern INTEGER NOT NULL,
                    PackageFamilyName TEXT,
                    AppUserModelId TEXT,
                    BaseProfileId TEXT,
                    BaseProfileRevision TEXT,
                    BaseCatalogRevision TEXT,
                    RecordOrigin TEXT NOT NULL DEFAULT 'LegacySessionMetadata',
                    ReviewState TEXT NOT NULL DEFAULT 'Unreviewed',
                    PathPattern TEXT,
                    CompanyVendor TEXT,
                    ProductName TEXT,
                    Description TEXT,
                    ApplicationCategory TEXT,
                    ExpectedResponsibilities TEXT,
                    NormalBehavior TEXT,
                    LaunchTriggers TEXT,
                    ExpectedContext TEXT,
                    CommandLineExpectations TEXT,
                    FilesystemRegistryExpectations TEXT,
                    ChildProcessExpectations TEXT,
                    NetworkExpectations TEXT,
                    NormalVariants TEXT,
                    AnalystValidationChecks TEXT,
                    KnownBenignNotes TEXT,
                    CybersecurityNotes TEXT,
                    Source TEXT,
                    Confidence REAL NOT NULL,
                    IsAiGenerated INTEGER NOT NULL,
                    ProviderName TEXT,
                    ModelName TEXT,
                    Prompt TEXT,
                    AiProviderKind TEXT,
                    AiEndpointMode TEXT,
                    AiPromptTemplateId TEXT,
                    AiRequestedUtc TEXT,
                    AiUncertainty TEXT,
                    AiValidationWarnings TEXT,
                    AiSourceClaimsUnverified INTEGER NOT NULL DEFAULT 0,
                    SourceReferencesJson TEXT,
                    CatalogProvenance TEXT,
                    ProfileLastReviewedUtc TEXT,
                    ReviewedUtc TEXT,
                    CreatedUtc TEXT NOT NULL,
                    UpdatedUtc TEXT NOT NULL,
                    LastMatchedUtc TEXT,
                    MatchReason TEXT
                );
                CREATE INDEX IF NOT EXISTS IX_Bookmarks_Target ON Bookmarks(TargetKind, TargetId);
                CREATE INDEX IF NOT EXISTS IX_Bookmarks_ProcessKey ON Bookmarks(ProcessKey);
                CREATE INDEX IF NOT EXISTS IX_Bookmarks_Identity ON Bookmarks(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId);
                CREATE INDEX IF NOT EXISTS IX_Notes_Target ON Notes(TargetKind, TargetId);
                CREATE INDEX IF NOT EXISTS IX_Notes_ProcessKey ON Notes(ProcessKey);
                CREATE INDEX IF NOT EXISTS IX_Notes_Identity ON Notes(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId);
                CREATE INDEX IF NOT EXISTS IX_AiInvestigationOutputs_Target ON AiInvestigationOutputs(TargetKind, TargetId, RequestedUtc);
                CREATE INDEX IF NOT EXISTS IX_AiInvestigationOutputs_ProcessKey ON AiInvestigationOutputs(ProcessKey, RequestedUtc);
                CREATE INDEX IF NOT EXISTS IX_AiInvestigationOutputs_Identity ON AiInvestigationOutputs(CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId);
                CREATE INDEX IF NOT EXISTS IX_AiChatMessages_Conversation ON AiChatMessages(ConversationId, CreatedUtc);
                CREATE INDEX IF NOT EXISTS IX_ApplicationMetadata_Executable ON ApplicationMetadata(ExecutableNamePattern, IsRegexPattern);
                CREATE INDEX IF NOT EXISTS IX_ApplicationMetadata_Package ON ApplicationMetadata(PackageFamilyName, AppUserModelId);
                CREATE INDEX IF NOT EXISTS IX_ApplicationMetadata_Updated ON ApplicationMetadata(UpdatedUtc);
                """;
            command.ExecuteNonQuery();

            EnsureColumn(connection, "ApplicationMetadata", "BaseProfileId", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "BaseProfileRevision", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "BaseCatalogRevision", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "RecordOrigin", "TEXT NOT NULL DEFAULT 'LegacySessionMetadata'");
            EnsureColumn(connection, "ApplicationMetadata", "ReviewState", "TEXT NOT NULL DEFAULT 'Unreviewed'");
            EnsureColumn(connection, "ApplicationMetadata", "ApplicationCategory", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "ExpectedResponsibilities", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "NormalBehavior", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "LaunchTriggers", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "ExpectedContext", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "CommandLineExpectations", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "FilesystemRegistryExpectations", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "ChildProcessExpectations", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "NetworkExpectations", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "NormalVariants", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "AnalystValidationChecks", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "SourceReferencesJson", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "CatalogProvenance", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "ProfileLastReviewedUtc", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "ReviewedUtc", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "AiProviderKind", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "AiEndpointMode", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "AiPromptTemplateId", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "AiRequestedUtc", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "AiUncertainty", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "AiValidationWarnings", "TEXT");
            EnsureColumn(connection, "ApplicationMetadata", "AiSourceClaimsUnverified", "INTEGER NOT NULL DEFAULT 0");
            using (var overrideIndexCommand = connection.CreateCommand())
            {
                overrideIndexCommand.CommandText = """
                    CREATE INDEX IF NOT EXISTS IX_ApplicationMetadata_BaseProfile
                    ON ApplicationMetadata(BaseProfileId, BaseProfileRevision, BaseCatalogRevision);
                    """;
                overrideIndexCommand.ExecuteNonQuery();
            }

            UpsertSchemaInfo(connection, "SchemaVersion", SchemaVersion);
            UpsertSchemaInfo(connection, "ApplicationVersion", typeof(AnnotationDatabaseService).Assembly.GetName().Version?.ToString() ?? "unknown");
            UpsertSchemaInfo(connection, "LastOpenedUtc", FormatDate(DateTime.UtcNow));
            using var migrationCommand = connection.CreateCommand();
            migrationCommand.CommandText = """
                INSERT OR IGNORE INTO SchemaInfo(Key, Value) VALUES('CreatedUtc', $CreatedUtc);
                INSERT OR IGNORE INTO SchemaMigrations(MigrationId, AppliedUtc, Description)
                VALUES('001_initial_annotations', $AppliedUtc, 'Initial analyst-owned bookmark and note annotation schema.');
                INSERT OR IGNORE INTO SchemaMigrations(MigrationId, AppliedUtc, Description)
                VALUES('002_ai_investigation_outputs', $AppliedUtc, 'AI investigation outputs stored as analyst-owned session annotations.');
                INSERT OR IGNORE INTO SchemaMigrations(MigrationId, AppliedUtc, Description)
                VALUES('003_ai_chat_messages', $AppliedUtc, 'Explorer AI chat transcript messages stored as analyst-owned session annotations.');
                INSERT OR IGNORE INTO SchemaMigrations(MigrationId, AppliedUtc, Description)
                VALUES('004_application_metadata', $AppliedUtc, 'SQLite-backed known application metadata and AI-generated app info drafts.');
                INSERT OR IGNORE INTO SchemaMigrations(MigrationId, AppliedUtc, Description)
                VALUES('005_application_catalog_overrides', $AppliedUtc, 'Additive built-in profile linkage, typed origin/review state, sources, and expected-behavior override fields.');
                """;
            Add(migrationCommand, "$CreatedUtc", DateTime.UtcNow);
            Add(migrationCommand, "$AppliedUtc", DateTime.UtcNow);
            migrationCommand.ExecuteNonQuery();
        }
    }

    public void ImportBookmarksFromEvidenceDatabase(
        string databasePath,
        CaptureOpenContext openContext = CaptureOpenContext.ViewerArchivedReadOnly,
        CaptureManifestCompatibilityMetadata? manifest = null,
        string expectedEvidenceSessionId = "")
    {
        if (string.IsNullOrWhiteSpace(databasePath) || !File.Exists(databasePath))
        {
            return;
        }

        var assessment = SqliteStagingStore.AssessExistingDatabase(
            databasePath,
            openContext,
            manifest,
            expectedEvidenceSessionId);
        CaptureCompatibilityPolicy.EnsureAllowed(assessment, CaptureOpenCapability.ReadEvidence);

        IReadOnlyList<BookmarkRecord> bookmarks;
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Shared,
            Pooling = false
        }.ToString()))
        {
            connection.Open();
            if (!TableExists(connection, "Bookmarks"))
            {
                return;
            }

            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT BookmarkId, TargetKind, TargetId, ProcessKey, ProcessId, ProcessName,
                       Label, Notes, Tags, CreatedUtc, UpdatedUtc
                FROM Bookmarks;
                """;
            var imported = new List<BookmarkRecord>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                imported.Add(new BookmarkRecord
                {
                    BookmarkId = GetString(reader, 0),
                    TargetKind = GetString(reader, 1),
                    TargetTable = string.Equals(GetString(reader, 1), "Process", StringComparison.OrdinalIgnoreCase) ? "Processes" : string.Empty,
                    TargetId = GetString(reader, 2),
                    ProcessKey = GetString(reader, 3),
                    ProcessId = GetInt(reader, 4),
                    ProcessName = GetString(reader, 5),
                    Label = GetString(reader, 6),
                    Notes = GetString(reader, 7),
                    Tags = GetString(reader, 8),
                    CreatedUtc = GetDateTime(reader, 9) ?? DateTime.UtcNow,
                    UpdatedUtc = GetDateTime(reader, 10) ?? DateTime.UtcNow
                });
            }

            bookmarks = imported;
        }

        foreach (var bookmark in bookmarks)
        {
            if (!IsBookmarked(bookmark.TargetKind, bookmark.TargetId))
            {
                UpsertBookmark(bookmark);
            }
        }
    }

    public void UpsertBookmark(BookmarkRecord bookmark)
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO Bookmarks (
                    BookmarkId, TargetKind, TargetTable, TargetId, ArtifactId,
                    CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                    ProcessKey, ProcessId, ProcessName, Label, DisplayPath,
                    Notes, Tags, CreatedUtc, UpdatedUtc)
                VALUES (
                    $BookmarkId, $TargetKind, $TargetTable, $TargetId, $ArtifactId,
                    $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId,
                    $ProcessKey, $ProcessId, $ProcessName, $Label, $DisplayPath,
                    $Notes, $Tags, $CreatedUtc, $UpdatedUtc)
                ON CONFLICT(TargetKind, TargetId) DO UPDATE SET
                    TargetTable = excluded.TargetTable,
                    ArtifactId = excluded.ArtifactId,
                    CaseId = excluded.CaseId,
                    EvidenceSessionId = excluded.EvidenceSessionId,
                    CaptureId = excluded.CaptureId,
                    SourceIdentityId = excluded.SourceIdentityId,
                    HostId = excluded.HostId,
                    ProcessKey = excluded.ProcessKey,
                    ProcessId = excluded.ProcessId,
                    ProcessName = excluded.ProcessName,
                    Label = excluded.Label,
                    DisplayPath = excluded.DisplayPath,
                    Notes = excluded.Notes,
                    Tags = excluded.Tags,
                    UpdatedUtc = excluded.UpdatedUtc;
                """;
            AddBookmarkParameters(command, bookmark);
            command.ExecuteNonQuery();
        }
    }

    public void DeleteBookmark(string targetKind, string targetId)
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
            using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM Bookmarks
                WHERE TargetKind = $TargetKind AND TargetId = $TargetId;
                """;
            Add(command, "$TargetKind", targetKind);
            Add(command, "$TargetId", targetId);
            command.ExecuteNonQuery();
        }
    }

    public bool IsBookmarked(string targetKind, string targetId)
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT 1
                FROM Bookmarks
                WHERE TargetKind = $TargetKind AND TargetId = $TargetId
                LIMIT 1;
                """;
            Add(command, "$TargetKind", targetKind);
            Add(command, "$TargetId", targetId);
            return command.ExecuteScalar() != null;
        }
    }

    public int CountProcessAnnotationTargets()
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT COUNT(DISTINCT TargetId)
                FROM (
                    SELECT TargetId FROM Bookmarks WHERE TargetKind = 'Process' AND TargetId IS NOT NULL AND TargetId <> ''
                    UNION
                    SELECT TargetId FROM Notes WHERE TargetKind = 'Process' AND TargetId IS NOT NULL AND TargetId <> ''
                );
                """;
            return Convert.ToInt32(command.ExecuteScalar());
        }
    }

    public Task<AnnotationNoteLoadResult> LoadNoteAsync(AnnotationTarget target)
        => Task.Run(() => LoadNote(target));

    public Task<AnnotationNoteSaveResult> SaveNoteAsync(AnnotationTarget target, string content)
        => Task.Run(() => SaveNote(target, content));

    public Task SaveAiInvestigationAsync(AiInvestigationRecord record)
        => Task.Run(() => SaveAiInvestigation(record));

    public Task<IReadOnlyList<AiInvestigationRecord>> LoadAiInvestigationsAsync(AnnotationTarget target, int limit = 25)
        => Task.Run<IReadOnlyList<AiInvestigationRecord>>(() => LoadAiInvestigations(target, limit));

    public Task SaveAiChatMessageAsync(AiChatMessage message)
        => Task.Run(() => SaveAiChatMessage(message));

    public Task<IReadOnlyList<AiChatMessage>> LoadAiChatMessagesAsync(string conversationId, int limit = 200)
        => Task.Run<IReadOnlyList<AiChatMessage>>(() => LoadAiChatMessages(conversationId, limit));

    public Task ClearAiChatMessagesAsync(string conversationId)
        => Task.Run(() => ClearAiChatMessages(conversationId));

    public Task<ApplicationMetadataRecord?> LoadApplicationMetadataForProcessAsync(ProcessInfo process)
        => Task.Run(() => LoadApplicationMetadataForProcess(process));

    public Task SaveApplicationMetadataAsync(ApplicationMetadataRecord record)
        => Task.Run(() => SaveApplicationMetadata(record));

    private ApplicationMetadataRecord? LoadApplicationMetadataForProcess(ProcessInfo process)
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
            var records = ReadApplicationMetadata(connection, maxCount: 2000);
            var executableName = GetExecutableName(process);
            var processName = process.ProcessName;
            var processPath = process.ProcessPath;
            var company = process.CompanyName;

            var match = records
                .Select(record => (Record: record, Score: ScoreApplicationMetadata(record, executableName, processName, processPath, company)))
                .Where(candidate => candidate.Score > 0)
                .OrderByDescending(candidate => candidate.Score)
                .ThenByDescending(candidate => candidate.Record.UpdatedUtc)
                .FirstOrDefault();
            if (match.Record == null)
            {
                return null;
            }

            match.Record.MatchReason = FormatApplicationMetadataMatchReason(match.Record, match.Score);
            match.Record.LastMatchedUtc = DateTime.UtcNow;
            UpdateApplicationMetadataLastMatched(connection, match.Record.ApplicationId, match.Record.LastMatchedUtc.Value, match.Record.MatchReason);
            return match.Record;
        }
    }

    private void SaveApplicationMetadata(ApplicationMetadataRecord record)
    {
        if (record.IsRegexPattern && !string.IsNullOrWhiteSpace(record.ExecutableNamePattern))
        {
            _ = new Regex(record.ExecutableNamePattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, MetadataRegexTimeout);
        }

        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO ApplicationMetadata (
                    ApplicationId, DisplayName, ExecutableNamePattern, IsRegexPattern,
                    PackageFamilyName, AppUserModelId, BaseProfileId, BaseProfileRevision,
                    BaseCatalogRevision, RecordOrigin, ReviewState,
                    PathPattern, CompanyVendor, ProductName,
                    Description, ApplicationCategory, ExpectedResponsibilities, NormalBehavior,
                    LaunchTriggers, ExpectedContext, CommandLineExpectations,
                    FilesystemRegistryExpectations, ChildProcessExpectations, NetworkExpectations,
                    NormalVariants, AnalystValidationChecks,
                    KnownBenignNotes, CybersecurityNotes, Source, Confidence,
                    IsAiGenerated, ProviderName, ModelName, Prompt,
                    AiProviderKind, AiEndpointMode, AiPromptTemplateId, AiRequestedUtc,
                    AiUncertainty, AiValidationWarnings, AiSourceClaimsUnverified,
                    SourceReferencesJson, CatalogProvenance, ProfileLastReviewedUtc, ReviewedUtc,
                    CreatedUtc, UpdatedUtc, LastMatchedUtc, MatchReason)
                VALUES (
                    $ApplicationId, $DisplayName, $ExecutableNamePattern, $IsRegexPattern,
                    $PackageFamilyName, $AppUserModelId, $BaseProfileId, $BaseProfileRevision,
                    $BaseCatalogRevision, $RecordOrigin, $ReviewState,
                    $PathPattern, $CompanyVendor, $ProductName,
                    $Description, $ApplicationCategory, $ExpectedResponsibilities, $NormalBehavior,
                    $LaunchTriggers, $ExpectedContext, $CommandLineExpectations,
                    $FilesystemRegistryExpectations, $ChildProcessExpectations, $NetworkExpectations,
                    $NormalVariants, $AnalystValidationChecks,
                    $KnownBenignNotes, $CybersecurityNotes, $Source, $Confidence,
                    $IsAiGenerated, $ProviderName, $ModelName, $Prompt,
                    $AiProviderKind, $AiEndpointMode, $AiPromptTemplateId, $AiRequestedUtc,
                    $AiUncertainty, $AiValidationWarnings, $AiSourceClaimsUnverified,
                    $SourceReferencesJson, $CatalogProvenance, $ProfileLastReviewedUtc, $ReviewedUtc,
                    $CreatedUtc, $UpdatedUtc, $LastMatchedUtc, $MatchReason)
                ON CONFLICT(ApplicationId) DO UPDATE SET
                    DisplayName = excluded.DisplayName,
                    ExecutableNamePattern = excluded.ExecutableNamePattern,
                    IsRegexPattern = excluded.IsRegexPattern,
                    PackageFamilyName = excluded.PackageFamilyName,
                    AppUserModelId = excluded.AppUserModelId,
                    BaseProfileId = excluded.BaseProfileId,
                    BaseProfileRevision = excluded.BaseProfileRevision,
                    BaseCatalogRevision = excluded.BaseCatalogRevision,
                    RecordOrigin = excluded.RecordOrigin,
                    ReviewState = excluded.ReviewState,
                    PathPattern = excluded.PathPattern,
                    CompanyVendor = excluded.CompanyVendor,
                    ProductName = excluded.ProductName,
                    Description = excluded.Description,
                    ApplicationCategory = excluded.ApplicationCategory,
                    ExpectedResponsibilities = excluded.ExpectedResponsibilities,
                    NormalBehavior = excluded.NormalBehavior,
                    LaunchTriggers = excluded.LaunchTriggers,
                    ExpectedContext = excluded.ExpectedContext,
                    CommandLineExpectations = excluded.CommandLineExpectations,
                    FilesystemRegistryExpectations = excluded.FilesystemRegistryExpectations,
                    ChildProcessExpectations = excluded.ChildProcessExpectations,
                    NetworkExpectations = excluded.NetworkExpectations,
                    NormalVariants = excluded.NormalVariants,
                    AnalystValidationChecks = excluded.AnalystValidationChecks,
                    KnownBenignNotes = excluded.KnownBenignNotes,
                    CybersecurityNotes = excluded.CybersecurityNotes,
                    Source = excluded.Source,
                    Confidence = excluded.Confidence,
                    IsAiGenerated = excluded.IsAiGenerated,
                    ProviderName = excluded.ProviderName,
                    ModelName = excluded.ModelName,
                    Prompt = excluded.Prompt,
                    AiProviderKind = excluded.AiProviderKind,
                    AiEndpointMode = excluded.AiEndpointMode,
                    AiPromptTemplateId = excluded.AiPromptTemplateId,
                    AiRequestedUtc = excluded.AiRequestedUtc,
                    AiUncertainty = excluded.AiUncertainty,
                    AiValidationWarnings = excluded.AiValidationWarnings,
                    AiSourceClaimsUnverified = excluded.AiSourceClaimsUnverified,
                    SourceReferencesJson = excluded.SourceReferencesJson,
                    CatalogProvenance = excluded.CatalogProvenance,
                    ProfileLastReviewedUtc = excluded.ProfileLastReviewedUtc,
                    ReviewedUtc = excluded.ReviewedUtc,
                    UpdatedUtc = excluded.UpdatedUtc,
                    LastMatchedUtc = excluded.LastMatchedUtc,
                    MatchReason = excluded.MatchReason;
                """;
            AddApplicationMetadataParameters(command, record);
            command.ExecuteNonQuery();
        }
    }

    private AnnotationNoteLoadResult LoadNote(AnnotationTarget target)
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT NoteId, TargetKind, TargetTable, TargetId, ArtifactId,
                       CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                       ProcessKey, ProcessId, ProcessName, Label, DisplayPath,
                       Content, Tags, CreatedUtc, UpdatedUtc
                FROM Notes
                WHERE TargetKind = $TargetKind AND TargetId = $TargetId
                LIMIT 1;
                """;
            Add(command, "$TargetKind", target.TargetKind);
            Add(command, "$TargetId", target.TargetId);
            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                return new AnnotationNoteLoadResult
                {
                    Success = true,
                    DatabasePath = DatabasePath,
                    TargetDisplay = FormatTargetDisplay(target),
                    Content = string.Empty,
                    Exists = false
                };
            }

            var note = ReadNote(reader);
            return new AnnotationNoteLoadResult
            {
                Success = true,
                DatabasePath = DatabasePath,
                TargetDisplay = FormatTargetDisplay(target),
                Content = note.Content,
                Exists = true
            };
        }
    }

    private AnnotationNoteSaveResult SaveNote(AnnotationTarget target, string content)
    {
        try
        {
            lock (_lock)
            {
                using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
                using var command = connection.CreateCommand();
                command.CommandText = """
                    INSERT INTO Notes (
                        NoteId, TargetKind, TargetTable, TargetId, ArtifactId,
                        CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                        ProcessKey, ProcessId, ProcessName, Label, DisplayPath,
                        Content, Tags, CreatedUtc, UpdatedUtc)
                    VALUES (
                        $NoteId, $TargetKind, $TargetTable, $TargetId, $ArtifactId,
                        $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId,
                        $ProcessKey, $ProcessId, $ProcessName, $Label, $DisplayPath,
                        $Content, $Tags, $CreatedUtc, $UpdatedUtc)
                    ON CONFLICT(TargetKind, TargetId) DO UPDATE SET
                        TargetTable = excluded.TargetTable,
                        ArtifactId = excluded.ArtifactId,
                        CaseId = excluded.CaseId,
                        EvidenceSessionId = excluded.EvidenceSessionId,
                        CaptureId = excluded.CaptureId,
                        SourceIdentityId = excluded.SourceIdentityId,
                        HostId = excluded.HostId,
                        ProcessKey = excluded.ProcessKey,
                        ProcessId = excluded.ProcessId,
                        ProcessName = excluded.ProcessName,
                        Label = excluded.Label,
                        DisplayPath = excluded.DisplayPath,
                        Content = excluded.Content,
                        Tags = excluded.Tags,
                        UpdatedUtc = excluded.UpdatedUtc;
                    """;
                var now = DateTime.UtcNow;
                Add(command, "$NoteId", Guid.NewGuid().ToString("N"));
                AddTargetParameters(command, target);
                Add(command, "$Content", content);
                Add(command, "$Tags", string.Empty);
                Add(command, "$CreatedUtc", now);
                Add(command, "$UpdatedUtc", now);
                command.ExecuteNonQuery();
            }

            return new AnnotationNoteSaveResult
            {
                Success = true,
                DatabasePath = DatabasePath,
                TargetDisplay = FormatTargetDisplay(target)
            };
        }
        catch (Exception ex)
        {
            return new AnnotationNoteSaveResult
            {
                Success = false,
                DatabasePath = DatabasePath,
                TargetDisplay = FormatTargetDisplay(target),
                ErrorMessage = $"Failed to save note: {ex.Message}"
            };
        }
    }

    private void SaveAiInvestigation(AiInvestigationRecord record)
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO AiInvestigationOutputs (
                    InvestigationId, TargetKind, TargetTable, TargetId, ArtifactId,
                    CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                    ProcessKey, ProcessId, ProcessName, Label, DisplayPath,
                    SourceScopeKind, SourceScopeSummary,
                    PromptTemplateId, PromptTemplateTitle, SystemPrompt, AnalystPrompt, FinalPrompt,
                    ProviderKind, ProviderName, BaseUrl, ModelName,
                    RequestedUtc, CompletedUtc, Status,
                    RequestCharacterCount, ResponseCharacterCount,
                    PromptTokens, CompletionTokens, TotalTokens,
                    ErrorText, ResponseText)
                VALUES (
                    $InvestigationId, $TargetKind, $TargetTable, $TargetId, $ArtifactId,
                    $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId,
                    $ProcessKey, $ProcessId, $ProcessName, $Label, $DisplayPath,
                    $SourceScopeKind, $SourceScopeSummary,
                    $PromptTemplateId, $PromptTemplateTitle, $SystemPrompt, $AnalystPrompt, $FinalPrompt,
                    $ProviderKind, $ProviderName, $BaseUrl, $ModelName,
                    $RequestedUtc, $CompletedUtc, $Status,
                    $RequestCharacterCount, $ResponseCharacterCount,
                    $PromptTokens, $CompletionTokens, $TotalTokens,
                    $ErrorText, $ResponseText)
                ON CONFLICT(InvestigationId) DO UPDATE SET
                    TargetKind = excluded.TargetKind,
                    TargetTable = excluded.TargetTable,
                    TargetId = excluded.TargetId,
                    ArtifactId = excluded.ArtifactId,
                    CaseId = excluded.CaseId,
                    EvidenceSessionId = excluded.EvidenceSessionId,
                    CaptureId = excluded.CaptureId,
                    SourceIdentityId = excluded.SourceIdentityId,
                    HostId = excluded.HostId,
                    ProcessKey = excluded.ProcessKey,
                    ProcessId = excluded.ProcessId,
                    ProcessName = excluded.ProcessName,
                    Label = excluded.Label,
                    DisplayPath = excluded.DisplayPath,
                    SourceScopeKind = excluded.SourceScopeKind,
                    SourceScopeSummary = excluded.SourceScopeSummary,
                    PromptTemplateId = excluded.PromptTemplateId,
                    PromptTemplateTitle = excluded.PromptTemplateTitle,
                    SystemPrompt = excluded.SystemPrompt,
                    AnalystPrompt = excluded.AnalystPrompt,
                    FinalPrompt = excluded.FinalPrompt,
                    ProviderKind = excluded.ProviderKind,
                    ProviderName = excluded.ProviderName,
                    BaseUrl = excluded.BaseUrl,
                    ModelName = excluded.ModelName,
                    RequestedUtc = excluded.RequestedUtc,
                    CompletedUtc = excluded.CompletedUtc,
                    Status = excluded.Status,
                    RequestCharacterCount = excluded.RequestCharacterCount,
                    ResponseCharacterCount = excluded.ResponseCharacterCount,
                    PromptTokens = excluded.PromptTokens,
                    CompletionTokens = excluded.CompletionTokens,
                    TotalTokens = excluded.TotalTokens,
                    ErrorText = excluded.ErrorText,
                    ResponseText = excluded.ResponseText;
                """;
            AddAiRecordParameters(command, record);
            command.ExecuteNonQuery();
        }
    }

    private IReadOnlyList<AiInvestigationRecord> LoadAiInvestigations(AnnotationTarget target, int limit)
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT InvestigationId, TargetKind, TargetTable, TargetId, ArtifactId,
                       CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId,
                       ProcessKey, ProcessId, ProcessName, Label, DisplayPath,
                       SourceScopeKind, SourceScopeSummary,
                       PromptTemplateId, PromptTemplateTitle, SystemPrompt, AnalystPrompt, FinalPrompt,
                       ProviderKind, ProviderName, BaseUrl, ModelName,
                       RequestedUtc, CompletedUtc, Status,
                       RequestCharacterCount, ResponseCharacterCount,
                       PromptTokens, CompletionTokens, TotalTokens,
                       ErrorText, ResponseText
                FROM AiInvestigationOutputs
                WHERE TargetKind = $TargetKind AND TargetId = $TargetId
                ORDER BY RequestedUtc DESC
                LIMIT $Limit;
                """;
            Add(command, "$TargetKind", target.TargetKind);
            Add(command, "$TargetId", target.TargetId);
            Add(command, "$Limit", Math.Clamp(limit, 1, 200));

            var records = new List<AiInvestigationRecord>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                records.Add(ReadAiInvestigation(reader));
            }

            return records;
        }
    }

    private void SaveAiChatMessage(AiChatMessage message)
    {
        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO AiChatMessages (
                    MessageId, ConversationId, Role, Content,
                    ProviderKind, ProviderName, BaseUrl, ModelName,
                    CreatedUtc, Status, ErrorText)
                VALUES (
                    $MessageId, $ConversationId, $Role, $Content,
                    $ProviderKind, $ProviderName, $BaseUrl, $ModelName,
                    $CreatedUtc, $Status, $ErrorText)
                ON CONFLICT(MessageId) DO UPDATE SET
                    ConversationId = excluded.ConversationId,
                    Role = excluded.Role,
                    Content = excluded.Content,
                    ProviderKind = excluded.ProviderKind,
                    ProviderName = excluded.ProviderName,
                    BaseUrl = excluded.BaseUrl,
                    ModelName = excluded.ModelName,
                    CreatedUtc = excluded.CreatedUtc,
                    Status = excluded.Status,
                    ErrorText = excluded.ErrorText;
                """;
            AddAiChatMessageParameters(command, message);
            command.ExecuteNonQuery();
        }
    }

    private IReadOnlyList<AiChatMessage> LoadAiChatMessages(string conversationId, int limit)
    {
        if (string.IsNullOrWhiteSpace(conversationId))
        {
            return [];
        }

        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadOnly);
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT MessageId, ConversationId, Role, Content,
                       ProviderKind, ProviderName, BaseUrl, ModelName,
                       CreatedUtc, Status, ErrorText
                FROM AiChatMessages
                WHERE ConversationId = $ConversationId
                ORDER BY CreatedUtc DESC
                LIMIT $Limit;
                """;
            Add(command, "$ConversationId", conversationId);
            Add(command, "$Limit", Math.Clamp(limit, 1, 1000));

            var messages = new List<AiChatMessage>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                messages.Add(ReadAiChatMessage(reader));
            }

            messages.Reverse();
            return messages;
        }
    }

    private void ClearAiChatMessages(string conversationId)
    {
        if (string.IsNullOrWhiteSpace(conversationId))
        {
            return;
        }

        lock (_lock)
        {
            using var connection = OpenConnection(SqliteOpenMode.ReadWriteCreate);
            using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM AiChatMessages
                WHERE ConversationId = $ConversationId;
                """;
            Add(command, "$ConversationId", conversationId);
            command.ExecuteNonQuery();
        }
    }

    private static IReadOnlyList<ApplicationMetadataRecord> ReadApplicationMetadata(SqliteConnection connection, int maxCount)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ApplicationId, DisplayName, ExecutableNamePattern, IsRegexPattern,
                   PackageFamilyName, AppUserModelId, BaseProfileId, BaseProfileRevision,
                   BaseCatalogRevision, RecordOrigin, ReviewState,
                   PathPattern, CompanyVendor, ProductName,
                   Description, ApplicationCategory, ExpectedResponsibilities, NormalBehavior,
                   LaunchTriggers, ExpectedContext, CommandLineExpectations,
                   FilesystemRegistryExpectations, ChildProcessExpectations, NetworkExpectations,
                   NormalVariants, AnalystValidationChecks,
                   KnownBenignNotes, CybersecurityNotes, Source, Confidence,
                   IsAiGenerated, ProviderName, ModelName, Prompt,
                   AiProviderKind, AiEndpointMode, AiPromptTemplateId, AiRequestedUtc,
                   AiUncertainty, AiValidationWarnings, AiSourceClaimsUnverified,
                   SourceReferencesJson, CatalogProvenance, ProfileLastReviewedUtc, ReviewedUtc,
                   CreatedUtc, UpdatedUtc, LastMatchedUtc, MatchReason
            FROM ApplicationMetadata
            ORDER BY UpdatedUtc DESC
            LIMIT $Limit;
            """;
        Add(command, "$Limit", Math.Clamp(maxCount, 1, 10000));

        var records = new List<ApplicationMetadataRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            records.Add(ReadApplicationMetadata(reader));
        }

        return records;
    }

    private static int ScoreApplicationMetadata(
        ApplicationMetadataRecord record,
        string executableName,
        string processName,
        string processPath,
        string company)
    {
        var score = 0;
        var pattern = record.ExecutableNamePattern.Trim();
        if (!string.IsNullOrWhiteSpace(pattern))
        {
            if (record.IsRegexPattern)
            {
                if (IsRegexMatch(pattern, executableName) || IsRegexMatch(pattern, processName))
                {
                    score += 80;
                }
            }
            else if (MatchesExecutableName(pattern, executableName, processName))
            {
                score += 100;
            }
        }

        if (!string.IsNullOrWhiteSpace(record.PathPattern) &&
            !string.IsNullOrWhiteSpace(processPath) &&
            processPath.Contains(record.PathPattern, StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
        }

        if (!string.IsNullOrWhiteSpace(record.CompanyVendor) &&
            !string.IsNullOrWhiteSpace(company) &&
            company.Contains(record.CompanyVendor, StringComparison.OrdinalIgnoreCase))
        {
            score += 10;
        }

        return score;
    }

    private static bool MatchesExecutableName(string pattern, string executableName, string processName)
    {
        return string.Equals(pattern, executableName, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(Path.GetFileNameWithoutExtension(pattern), processName, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(pattern, processName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRegexMatch(string pattern, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            return Regex.IsMatch(value, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, MetadataRegexTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static string FormatApplicationMetadataMatchReason(ApplicationMetadataRecord record, int score)
    {
        var mode = record.IsRegexPattern ? "regex executable pattern" : "exact executable pattern";
        return $"{mode}; score {score}";
    }

    private static string GetExecutableName(ProcessInfo process)
        => ApplicationInfoResolutionService.ResolveExecutableFilename(process);

    private static void UpdateApplicationMetadataLastMatched(
        SqliteConnection connection,
        string applicationId,
        DateTime lastMatchedUtc,
        string matchReason)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE ApplicationMetadata
            SET LastMatchedUtc = $LastMatchedUtc,
                MatchReason = $MatchReason
            WHERE ApplicationId = $ApplicationId;
            """;
        Add(command, "$LastMatchedUtc", lastMatchedUtc);
        Add(command, "$MatchReason", matchReason);
        Add(command, "$ApplicationId", applicationId);
        command.ExecuteNonQuery();
    }

    private SqliteConnection OpenConnection(SqliteOpenMode mode)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = mode,
            Cache = SqliteCacheMode.Shared,
            Pooling = false
        }.ToString());
        connection.Open();
        return connection;
    }

    private static void UpsertSchemaInfo(SqliteConnection connection, string key, string value)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO SchemaInfo(Key, Value) VALUES($Key, $Value)
            ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value;
            """;
        Add(command, "$Key", key);
        Add(command, "$Value", value);
        command.ExecuteNonQuery();
    }

    private static void AddBookmarkParameters(SqliteCommand command, BookmarkRecord bookmark)
    {
        var now = DateTime.UtcNow;
        Add(command, "$BookmarkId", string.IsNullOrWhiteSpace(bookmark.BookmarkId) ? Guid.NewGuid().ToString("N") : bookmark.BookmarkId);
        Add(command, "$TargetKind", bookmark.TargetKind);
        Add(command, "$TargetTable", bookmark.TargetTable);
        Add(command, "$TargetId", bookmark.TargetId);
        Add(command, "$ArtifactId", bookmark.ArtifactId);
        Add(command, "$CaseId", bookmark.CaseId);
        Add(command, "$EvidenceSessionId", bookmark.EvidenceSessionId);
        Add(command, "$CaptureId", bookmark.CaptureId);
        Add(command, "$SourceIdentityId", bookmark.SourceIdentityId);
        Add(command, "$HostId", bookmark.HostId);
        Add(command, "$ProcessKey", bookmark.ProcessKey);
        Add(command, "$ProcessId", bookmark.ProcessId);
        Add(command, "$ProcessName", bookmark.ProcessName);
        Add(command, "$Label", bookmark.Label);
        Add(command, "$DisplayPath", bookmark.DisplayPath);
        Add(command, "$Notes", bookmark.Notes);
        Add(command, "$Tags", bookmark.Tags);
        Add(command, "$CreatedUtc", bookmark.CreatedUtc == default ? now : bookmark.CreatedUtc);
        Add(command, "$UpdatedUtc", bookmark.UpdatedUtc == default ? now : bookmark.UpdatedUtc);
    }

    private static void AddTargetParameters(SqliteCommand command, AnnotationTarget target)
    {
        Add(command, "$TargetKind", target.TargetKind);
        Add(command, "$TargetTable", target.TargetTable);
        Add(command, "$TargetId", target.TargetId);
        Add(command, "$ArtifactId", target.ArtifactId);
        Add(command, "$CaseId", target.CaseId);
        Add(command, "$EvidenceSessionId", target.EvidenceSessionId);
        Add(command, "$CaptureId", target.CaptureId);
        Add(command, "$SourceIdentityId", target.SourceIdentityId);
        Add(command, "$HostId", target.HostId);
        Add(command, "$ProcessKey", target.ProcessKey);
        Add(command, "$ProcessId", target.ProcessId);
        Add(command, "$ProcessName", target.ProcessName);
        Add(command, "$Label", target.Label);
        Add(command, "$DisplayPath", target.DisplayPath);
    }

    private static void AddAiRecordParameters(SqliteCommand command, AiInvestigationRecord record)
    {
        Add(command, "$InvestigationId", string.IsNullOrWhiteSpace(record.InvestigationId) ? Guid.NewGuid().ToString("N") : record.InvestigationId);
        Add(command, "$TargetKind", record.TargetKind);
        Add(command, "$TargetTable", record.TargetTable);
        Add(command, "$TargetId", record.TargetId);
        Add(command, "$ArtifactId", record.ArtifactId);
        Add(command, "$CaseId", record.CaseId);
        Add(command, "$EvidenceSessionId", record.EvidenceSessionId);
        Add(command, "$CaptureId", record.CaptureId);
        Add(command, "$SourceIdentityId", record.SourceIdentityId);
        Add(command, "$HostId", record.HostId);
        Add(command, "$ProcessKey", record.ProcessKey);
        Add(command, "$ProcessId", record.ProcessId);
        Add(command, "$ProcessName", record.ProcessName);
        Add(command, "$Label", record.Label);
        Add(command, "$DisplayPath", record.DisplayPath);
        Add(command, "$SourceScopeKind", record.SourceScopeKind);
        Add(command, "$SourceScopeSummary", record.SourceScopeSummary);
        Add(command, "$PromptTemplateId", record.PromptTemplateId);
        Add(command, "$PromptTemplateTitle", record.PromptTemplateTitle);
        Add(command, "$SystemPrompt", record.SystemPrompt);
        Add(command, "$AnalystPrompt", record.AnalystPrompt);
        Add(command, "$FinalPrompt", record.FinalPrompt);
        Add(command, "$ProviderKind", record.ProviderKind.ToString());
        Add(command, "$ProviderName", record.ProviderName);
        Add(command, "$BaseUrl", record.BaseUrl);
        Add(command, "$ModelName", record.ModelName);
        Add(command, "$RequestedUtc", record.RequestedUtc);
        Add(command, "$CompletedUtc", record.CompletedUtc);
        Add(command, "$Status", record.Status.ToString());
        Add(command, "$RequestCharacterCount", record.RequestCharacterCount);
        Add(command, "$ResponseCharacterCount", record.ResponseCharacterCount);
        Add(command, "$PromptTokens", record.PromptTokens);
        Add(command, "$CompletionTokens", record.CompletionTokens);
        Add(command, "$TotalTokens", record.TotalTokens);
        Add(command, "$ErrorText", record.ErrorText);
        Add(command, "$ResponseText", record.ResponseText);
    }

    private static void AddAiChatMessageParameters(SqliteCommand command, AiChatMessage message)
    {
        Add(command, "$MessageId", string.IsNullOrWhiteSpace(message.MessageId) ? Guid.NewGuid().ToString("N") : message.MessageId);
        Add(command, "$ConversationId", message.ConversationId);
        Add(command, "$Role", message.Role);
        Add(command, "$Content", message.Content);
        Add(command, "$ProviderKind", message.ProviderKind.ToString());
        Add(command, "$ProviderName", message.ProviderName);
        Add(command, "$BaseUrl", message.BaseUrl);
        Add(command, "$ModelName", message.ModelName);
        Add(command, "$CreatedUtc", message.CreatedUtc == default ? DateTime.UtcNow : message.CreatedUtc);
        Add(command, "$Status", message.Status.ToString());
        Add(command, "$ErrorText", message.ErrorText);
    }

    private static void AddApplicationMetadataParameters(SqliteCommand command, ApplicationMetadataRecord record)
    {
        var now = DateTime.UtcNow;
        var createdUtc = record.CreatedUtc == default ? now : record.CreatedUtc;
        Add(command, "$ApplicationId", string.IsNullOrWhiteSpace(record.ApplicationId) ? Guid.NewGuid().ToString("N") : record.ApplicationId);
        Add(command, "$DisplayName", record.DisplayName);
        Add(command, "$ExecutableNamePattern", record.ExecutableNamePattern);
        Add(command, "$IsRegexPattern", record.IsRegexPattern ? 1 : 0);
        Add(command, "$PackageFamilyName", record.PackageFamilyName);
        Add(command, "$AppUserModelId", record.AppUserModelId);
        Add(command, "$BaseProfileId", record.BaseProfileId);
        Add(command, "$BaseProfileRevision", record.BaseProfileRevision);
        Add(command, "$BaseCatalogRevision", record.BaseCatalogRevision);
        Add(command, "$RecordOrigin", record.RecordOrigin.ToString());
        Add(command, "$ReviewState", record.ReviewState.ToString());
        Add(command, "$PathPattern", record.PathPattern);
        Add(command, "$CompanyVendor", record.CompanyVendor);
        Add(command, "$ProductName", record.ProductName);
        Add(command, "$Description", record.Description);
        Add(command, "$ApplicationCategory", record.ApplicationCategory);
        Add(command, "$ExpectedResponsibilities", record.ExpectedResponsibilities);
        Add(command, "$NormalBehavior", record.NormalBehavior);
        Add(command, "$LaunchTriggers", record.LaunchTriggers);
        Add(command, "$ExpectedContext", record.ExpectedContext);
        Add(command, "$CommandLineExpectations", record.CommandLineExpectations);
        Add(command, "$FilesystemRegistryExpectations", record.FilesystemRegistryExpectations);
        Add(command, "$ChildProcessExpectations", record.ChildProcessExpectations);
        Add(command, "$NetworkExpectations", record.NetworkExpectations);
        Add(command, "$NormalVariants", record.NormalVariants);
        Add(command, "$AnalystValidationChecks", record.AnalystValidationChecks);
        Add(command, "$KnownBenignNotes", record.KnownBenignNotes);
        Add(command, "$CybersecurityNotes", record.CybersecurityNotes);
        Add(command, "$Source", record.Source);
        Add(command, "$Confidence", Math.Clamp(record.Confidence, 0, 1));
        Add(command, "$IsAiGenerated", record.IsAiGenerated ? 1 : 0);
        Add(command, "$ProviderName", record.ProviderName);
        Add(command, "$ModelName", record.ModelName);
        Add(command, "$Prompt", record.Prompt);
        Add(command, "$AiProviderKind", record.AiProviderKind.ToString());
        Add(command, "$AiEndpointMode", record.AiEndpointMode);
        Add(command, "$AiPromptTemplateId", record.AiPromptTemplateId);
        Add(command, "$AiRequestedUtc", record.AiRequestedUtc);
        Add(command, "$AiUncertainty", record.AiUncertainty);
        Add(command, "$AiValidationWarnings", record.AiValidationWarnings);
        Add(command, "$AiSourceClaimsUnverified", record.AiSourceClaimsUnverified ? 1 : 0);
        Add(command, "$SourceReferencesJson", ApplicationInfoResolutionService.SerializeSources(record.SourceReferences));
        Add(command, "$CatalogProvenance", record.CatalogProvenance);
        Add(command, "$ProfileLastReviewedUtc", record.ProfileLastReviewedUtc);
        Add(command, "$ReviewedUtc", record.ReviewedUtc);
        Add(command, "$CreatedUtc", createdUtc);
        Add(command, "$UpdatedUtc", now);
        Add(command, "$LastMatchedUtc", record.LastMatchedUtc);
        Add(command, "$MatchReason", record.MatchReason);
    }

    private static NoteRecord ReadNote(SqliteDataReader reader)
    {
        return new NoteRecord
        {
            NoteId = GetString(reader, 0),
            TargetKind = GetString(reader, 1),
            TargetTable = GetString(reader, 2),
            TargetId = GetString(reader, 3),
            ArtifactId = GetString(reader, 4),
            CaseId = GetString(reader, 5),
            EvidenceSessionId = GetString(reader, 6),
            CaptureId = GetString(reader, 7),
            SourceIdentityId = GetString(reader, 8),
            HostId = GetString(reader, 9),
            ProcessKey = GetString(reader, 10),
            ProcessId = GetInt(reader, 11),
            ProcessName = GetString(reader, 12),
            Label = GetString(reader, 13),
            DisplayPath = GetString(reader, 14),
            Content = GetString(reader, 15),
            Tags = GetString(reader, 16),
            CreatedUtc = GetDateTime(reader, 17) ?? DateTime.UtcNow,
            UpdatedUtc = GetDateTime(reader, 18) ?? DateTime.UtcNow
        };
    }

    private static AiInvestigationRecord ReadAiInvestigation(SqliteDataReader reader)
    {
        return new AiInvestigationRecord
        {
            InvestigationId = GetString(reader, 0),
            TargetKind = GetString(reader, 1),
            TargetTable = GetString(reader, 2),
            TargetId = GetString(reader, 3),
            ArtifactId = GetString(reader, 4),
            CaseId = GetString(reader, 5),
            EvidenceSessionId = GetString(reader, 6),
            CaptureId = GetString(reader, 7),
            SourceIdentityId = GetString(reader, 8),
            HostId = GetString(reader, 9),
            ProcessKey = GetString(reader, 10),
            ProcessId = GetInt(reader, 11),
            ProcessName = GetString(reader, 12),
            Label = GetString(reader, 13),
            DisplayPath = GetString(reader, 14),
            SourceScopeKind = GetString(reader, 15),
            SourceScopeSummary = GetString(reader, 16),
            PromptTemplateId = GetString(reader, 17),
            PromptTemplateTitle = GetString(reader, 18),
            SystemPrompt = GetString(reader, 19),
            AnalystPrompt = GetString(reader, 20),
            FinalPrompt = GetString(reader, 21),
            ProviderKind = ParseEnum(GetString(reader, 22), AiProviderKind.Disabled),
            ProviderName = GetString(reader, 23),
            BaseUrl = GetString(reader, 24),
            ModelName = GetString(reader, 25),
            RequestedUtc = GetDateTime(reader, 26) ?? DateTime.UtcNow,
            CompletedUtc = GetDateTime(reader, 27),
            Status = ParseEnum(GetString(reader, 28), AiInvestigationStatus.Failed),
            RequestCharacterCount = GetInt(reader, 29),
            ResponseCharacterCount = GetInt(reader, 30),
            PromptTokens = GetNullableInt(reader, 31),
            CompletionTokens = GetNullableInt(reader, 32),
            TotalTokens = GetNullableInt(reader, 33),
            ErrorText = GetString(reader, 34),
            ResponseText = GetString(reader, 35)
        };
    }

    private static AiChatMessage ReadAiChatMessage(SqliteDataReader reader)
    {
        return new AiChatMessage
        {
            MessageId = GetString(reader, 0),
            ConversationId = GetString(reader, 1),
            Role = GetString(reader, 2),
            Content = GetString(reader, 3),
            ProviderKind = ParseEnum(GetString(reader, 4), AiProviderKind.Disabled),
            ProviderName = GetString(reader, 5),
            BaseUrl = GetString(reader, 6),
            ModelName = GetString(reader, 7),
            CreatedUtc = GetDateTime(reader, 8) ?? DateTime.UtcNow,
            Status = ParseEnum(GetString(reader, 9), AiInvestigationStatus.Pending),
            ErrorText = GetString(reader, 10)
        };
    }

    private static ApplicationMetadataRecord ReadApplicationMetadata(SqliteDataReader reader)
    {
        return new ApplicationMetadataRecord
        {
            ApplicationId = GetString(reader, 0),
            DisplayName = GetString(reader, 1),
            ExecutableNamePattern = GetString(reader, 2),
            IsRegexPattern = GetBool(reader, 3),
            PackageFamilyName = GetString(reader, 4),
            AppUserModelId = GetString(reader, 5),
            BaseProfileId = GetString(reader, 6),
            BaseProfileRevision = GetString(reader, 7),
            BaseCatalogRevision = GetString(reader, 8),
            RecordOrigin = ParseEnum(GetString(reader, 9), ApplicationProfileOrigin.LegacySessionMetadata),
            ReviewState = ParseEnum(GetString(reader, 10), ApplicationProfileReviewState.Unreviewed),
            PathPattern = GetString(reader, 11),
            CompanyVendor = GetString(reader, 12),
            ProductName = GetString(reader, 13),
            Description = GetString(reader, 14),
            ApplicationCategory = GetString(reader, 15),
            ExpectedResponsibilities = GetString(reader, 16),
            NormalBehavior = GetString(reader, 17),
            LaunchTriggers = GetString(reader, 18),
            ExpectedContext = GetString(reader, 19),
            CommandLineExpectations = GetString(reader, 20),
            FilesystemRegistryExpectations = GetString(reader, 21),
            ChildProcessExpectations = GetString(reader, 22),
            NetworkExpectations = GetString(reader, 23),
            NormalVariants = GetString(reader, 24),
            AnalystValidationChecks = GetString(reader, 25),
            KnownBenignNotes = GetString(reader, 26),
            CybersecurityNotes = GetString(reader, 27),
            Source = GetString(reader, 28),
            Confidence = GetDouble(reader, 29),
            IsAiGenerated = GetBool(reader, 30),
            ProviderName = GetString(reader, 31),
            ModelName = GetString(reader, 32),
            Prompt = GetString(reader, 33),
            AiProviderKind = ParseEnum(GetString(reader, 34), AiProviderKind.Disabled),
            AiEndpointMode = GetString(reader, 35),
            AiPromptTemplateId = GetString(reader, 36),
            AiRequestedUtc = GetDateTime(reader, 37),
            AiUncertainty = GetString(reader, 38),
            AiValidationWarnings = GetString(reader, 39),
            AiSourceClaimsUnverified = GetBool(reader, 40),
            SourceReferences = ApplicationInfoResolutionService.DeserializeSources(GetString(reader, 41)),
            CatalogProvenance = GetString(reader, 42),
            ProfileLastReviewedUtc = GetDateTime(reader, 43),
            ReviewedUtc = GetDateTime(reader, 44),
            CreatedUtc = GetDateTime(reader, 45) ?? DateTime.UtcNow,
            UpdatedUtc = GetDateTime(reader, 46) ?? DateTime.UtcNow,
            LastMatchedUtc = GetDateTime(reader, 47),
            MatchReason = GetString(reader, 48)
        };
    }

    private static void EnsureColumn(
        SqliteConnection connection,
        string tableName,
        string columnName,
        string declaration)
    {
        using (var tableInfo = connection.CreateCommand())
        {
            tableInfo.CommandText = $"PRAGMA table_info(\"{tableName}\");";
            using var reader = tableInfo.ExecuteReader();
            while (reader.Read())
            {
                if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }
        }

        using var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE \"{tableName}\" ADD COLUMN \"{columnName}\" {declaration};";
        alter.ExecuteNonQuery();
    }

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = $TableName
            LIMIT 1;
            """;
        Add(command, "$TableName", tableName);
        return command.ExecuteScalar() != null;
    }

    private static void Add(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = FormatDate(dateTime);
        }

        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    private static string FormatDate(DateTime value)
    {
        return value.Kind == DateTimeKind.Utc
            ? value.ToString("O")
            : value.ToUniversalTime().ToString("O");
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

    private static bool GetBool(SqliteDataReader reader, int ordinal)
    {
        return !reader.IsDBNull(ordinal) && reader.GetInt32(ordinal) != 0;
    }

    private static double GetDouble(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? 0 : reader.GetDouble(ordinal);
    }

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) || !DateTimeOffset.TryParse(reader.GetString(ordinal), out var value)
            ? null
            : value.UtcDateTime;
    }

    private static TEnum ParseEnum<TEnum>(string value, TEnum fallback)
        where TEnum : struct
    {
        return Enum.TryParse<TEnum>(value, ignoreCase: true, out var parsed)
            ? parsed
            : fallback;
    }

    private static string FormatTargetDisplay(AnnotationTarget target)
    {
        if (!string.IsNullOrWhiteSpace(target.Label))
        {
            return $"{target.Label} [{target.TargetKind}:{target.TargetId}]";
        }

        return $"{target.TargetKind}:{target.TargetId}";
    }
}

public sealed class AnnotationNoteLoadResult
{
    public bool Success { get; init; }
    public string DatabasePath { get; init; } = string.Empty;
    public string TargetDisplay { get; init; } = string.Empty;
    public string Content { get; init; } = string.Empty;
    public bool Exists { get; init; }
    public string? ErrorMessage { get; init; }
}

public sealed class AnnotationNoteSaveResult
{
    public bool Success { get; init; }
    public string DatabasePath { get; init; } = string.Empty;
    public string TargetDisplay { get; init; } = string.Empty;
    public string? ErrorMessage { get; init; }
}
