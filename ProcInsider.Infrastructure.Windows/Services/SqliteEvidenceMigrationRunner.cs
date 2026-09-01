using System.IO;
using System.Text;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed record SqliteEvidenceMigrationRequest
{
    public InvestigationSessionPaths SessionPaths { get; init; } = new();

    public string DatabasePath { get; init; } = string.Empty;

    public string ExpectedEvidenceSessionId { get; init; } = string.Empty;

    public string AppliedByRelease { get; init; } = string.Empty;

    public bool CaptureSealed { get; init; }

    public SqliteLiveDatabaseOwnershipLease? OwnershipLease { get; init; }
}

public sealed class SqliteLiveDatabaseOwnershipLease : IDisposable
{
    private FileStream? _stream;

    private SqliteLiveDatabaseOwnershipLease(
        FileStream stream,
        string lockPath,
        string databasePath,
        string sessionId)
    {
        _stream = stream;
        LockPath = lockPath;
        DatabasePath = databasePath;
        SessionId = sessionId;
    }

    public string LockPath { get; }

    public string DatabasePath { get; }

    public string SessionId { get; }

    public bool IsHeld => _stream != null;

    public static SqliteLiveDatabaseOwnershipLease Acquire(
        InvestigationSessionPaths paths,
        string databasePath)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var requestedPath = Path.GetFullPath(databasePath);
        var sessionPath = Path.GetFullPath(paths.LiveDatabasePath);
        if (!string.Equals(requestedPath, sessionPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "migration.ownership.target-mismatch: The ownership lease must target the active session live database.");
        }

        var lockPath = SessionPathService.GetLiveDatabaseOwnershipLockPath(paths);
        Directory.CreateDirectory(Path.GetDirectoryName(lockPath)!);
        FileStream stream;
        try
        {
            stream = new FileStream(
                lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough);
        }
        catch (IOException ex)
        {
            throw new IOException(
                $"migration.ownership.unavailable: Another {ProductIdentity.DisplayName} live writer owns '{requestedPath}'.",
                ex);
        }

        try
        {
            stream.SetLength(0);
            var ownerText = $"session={paths.SessionId}\ndatabase={requestedPath}\nprocess={Environment.ProcessId}\nacquiredUtc={DateTime.UtcNow:O}\n";
            var bytes = Encoding.UTF8.GetBytes(ownerText);
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(flushToDisk: true);
            stream.Position = 0;
            return new SqliteLiveDatabaseOwnershipLease(
                stream,
                lockPath,
                requestedPath,
                paths.SessionId);
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        var stream = Interlocked.Exchange(ref _stream, null);
        stream?.Dispose();
    }
}

public sealed class SqliteEvidenceMigrationRunner
{
    public static CaptureCompatibilityAssessment AssessExistingDatabase(
        string databasePath,
        CaptureOpenContext context,
        CaptureManifestCompatibilityMetadata? manifest,
        string expectedEvidenceSessionId,
        CaptureArtifactKind? artifactKind) =>
        SqliteStagingStore.AssessExistingDatabase(
            databasePath,
            context,
            manifest,
            expectedEvidenceSessionId,
            artifactKind);

    private static readonly HashSet<string> DeferredAnalysisMigrationIds =
        new(StringComparer.Ordinal)
        {
            SqlitePerformanceProfile.AnalysisIndexMigrationId
        };

    private readonly SqliteStagingStore _store;

    public SqliteEvidenceMigrationRunner(SqliteStagingStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public EvidenceMigrationPlan Plan(SqliteEvidenceMigrationRequest request)
    {
        var validationFailure = ValidateRequest(request);
        if (validationFailure != null)
        {
            return Blocked("migration.target.invalid", validationFailure);
        }

        var databasePath = Path.GetFullPath(request.DatabasePath);
        var isFresh = !File.Exists(databasePath) || new FileInfo(databasePath).Length == 0;
        if (isFresh)
        {
            var freshSteps = SqliteEvidenceMigrationCatalog.Definitions
                .Where(ShouldExecuteInLiveWriter)
                .OrderBy(definition => definition.Sequence)
                .ToArray();
            return new EvidenceMigrationPlan
            {
                State = EvidenceMigrationPlanState.Ready,
                StatusCode = "migration.plan.fresh",
                Message = $"A fresh evidence database will be created through {freshSteps.Length} catalogued steps.",
                TargetEvidenceFormatVersion = CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion,
                IsFreshDatabase = true,
                PendingSteps = freshSteps.Where(IsPrimary).ToArray(),
                PendingAnalysisSteps = freshSteps.Where(definition => !IsPrimary(definition)).ToArray(),
                MigrationLedgerUpgradeRequired = true
            };
        }

        CaptureCompatibilityAssessment assessment;
        IReadOnlyList<AppliedCaptureMigration> applied;
        try
        {
            assessment = SqliteStagingStore.AssessExistingDatabase(
                databasePath,
                CaptureOpenContext.AgentWritableLive,
                expectedEvidenceSessionId: request.ExpectedEvidenceSessionId);
            applied = SqliteStagingStore.ReadAppliedMigrations(databasePath);
        }
        catch (Exception ex) when (ex is SqliteException or IOException or InvalidDataException)
        {
            return Blocked("migration.plan.inspect-failed", $"Migration metadata could not be inspected: {ex.Message}");
        }

        if (assessment.State is not (
                CaptureCompatibilityState.CompatibleCurrent or
                CaptureCompatibilityState.MigrationRequired or
                CaptureCompatibilityState.IncompleteMigration))
        {
            return Blocked(assessment.StatusCode, assessment.Message, assessment.EvidenceFormatVersion);
        }

        var historyFailure = ValidateAppliedHistory(applied);
        if (historyFailure != null)
        {
            return Blocked(historyFailure.Value.Code, historyFailure.Value.Message, assessment.EvidenceFormatVersion);
        }

        var appliedIds = applied
            .Select(migration => migration.MigrationId)
            .ToHashSet(StringComparer.Ordinal);
        var pending = SqliteEvidenceMigrationCatalog.Definitions
            .Where(ShouldExecuteInLiveWriter)
            .Where(definition => !appliedIds.Contains(definition.MigrationId))
            .OrderBy(definition => definition.Sequence)
            .ToArray();
        var prerequisiteFailure = ValidatePendingPrerequisites(pending, appliedIds);
        if (prerequisiteFailure != null)
        {
            return Blocked(
                prerequisiteFailure.Value.Code,
                prerequisiteFailure.Value.Message,
                assessment.EvidenceFormatVersion);
        }

        var ledgerUpgradeRequired = SqliteStagingStore.MigrationLedgerUpgradeRequired(databasePath);
        var primary = pending.Where(IsPrimary).ToArray();
        var analysis = pending.Where(definition => !IsPrimary(definition)).ToArray();
        if (pending.Length == 0 && !ledgerUpgradeRequired)
        {
            return new EvidenceMigrationPlan
            {
                State = EvidenceMigrationPlanState.Current,
                StatusCode = "migration.plan.current",
                Message = "The evidence database is current; no migration work is required.",
                CurrentEvidenceFormatVersion = assessment.EvidenceFormatVersion,
                TargetEvidenceFormatVersion = CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion
            };
        }

        return new EvidenceMigrationPlan
        {
            State = EvidenceMigrationPlanState.Ready,
            StatusCode = "migration.plan.ready",
            Message = $"Migration plan is ready: {primary.Length} primary and {analysis.Length} live-analysis steps pending" +
                      (ledgerUpgradeRequired ? "; ledger audit metadata will be upgraded." : "."),
            CurrentEvidenceFormatVersion = assessment.EvidenceFormatVersion,
            TargetEvidenceFormatVersion = CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion,
            RecoveryCopyRequired = primary.Length > 0,
            MigrationLedgerUpgradeRequired = ledgerUpgradeRequired,
            PendingSteps = primary,
            PendingAnalysisSteps = analysis
        };
    }

    public EvidenceMigrationResult Execute(
        SqliteEvidenceMigrationRequest request,
        CancellationToken cancellationToken = default,
        IProgress<CaptureMigrationDefinition>? progress = null)
    {
        var plan = Plan(request);
        if (plan.State == EvidenceMigrationPlanState.Blocked)
        {
            return Result(EvidenceMigrationResultState.Blocked, plan.StatusCode, plan.Message, plan);
        }

        var ownershipFailure = ValidateExecutionOwnership(request);
        if (ownershipFailure != null)
        {
            return Result(
                EvidenceMigrationResultState.Blocked,
                "migration.ownership.required",
                ownershipFailure,
                plan);
        }

        if (plan.State == EvidenceMigrationPlanState.Current)
        {
            _store.OpenCurrentAgentOwnedDatabase();
            return Result(
                EvidenceMigrationResultState.NotRequired,
                "migration.current",
                "The evidence database is current; no migration was executed.",
                plan);
        }

        var recoveryCopyPath = string.Empty;
        var applied = new List<string>();
        var lastApplied = string.Empty;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (plan.RecoveryCopyRequired)
            {
                recoveryCopyPath = CreateRecoveryCopy(request, cancellationToken);
            }

            _store.OpenForAgentOwnedMigration();
            if (plan.MigrationLedgerUpgradeRequired && !plan.IsFreshDatabase)
            {
                _store.UpgradeMigrationLedger(request.AppliedByRelease);
            }

            var orderedSteps = plan.PendingSteps
                .Concat(plan.PendingAnalysisSteps)
                .OrderBy(definition => definition.Sequence)
                .ToArray();
            foreach (var definition in orderedSteps)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var step = SqliteEvidenceMigrationCatalog.GetStep(definition.MigrationId);
                _store.ExecuteCatalogMigrationStep(step, request.AppliedByRelease, cancellationToken);
                lastApplied = definition.MigrationId;
                applied.Add(lastApplied);
                progress?.Report(definition);
            }

            _store.FinalizeAgentOwnedDatabaseOpen();
            var finalAssessment = SqliteStagingStore.AssessExistingDatabase(
                request.DatabasePath,
                CaptureOpenContext.AgentWritableLive,
                expectedEvidenceSessionId: request.ExpectedEvidenceSessionId);
            CaptureCompatibilityPolicy.EnsureAllowed(
                finalAssessment,
                CaptureOpenCapability.WritePrimaryEvidence);
            return new EvidenceMigrationResult
            {
                State = EvidenceMigrationResultState.Completed,
                StatusCode = "migration.completed",
                Message = applied.Count == 0
                    ? "Migration ledger audit metadata was upgraded; evidence was unchanged."
                    : $"Applied {applied.Count} catalogued migration steps successfully.",
                LastAppliedMigrationId = lastApplied,
                AppliedMigrationIds = applied,
                RecoveryCopyPath = recoveryCopyPath,
                Plan = plan
            };
        }
        catch (OperationCanceledException)
        {
            return new EvidenceMigrationResult
            {
                State = EvidenceMigrationResultState.Cancelled,
                StatusCode = "migration.cancelled",
                Message = "Migration was cancelled between atomic steps; the active step was rolled back.",
                LastAppliedMigrationId = lastApplied,
                AppliedMigrationIds = applied,
                RecoveryCopyPath = recoveryCopyPath,
                Plan = plan
            };
        }
        catch (Exception ex) when (ex is SqliteException or IOException or InvalidDataException or UnauthorizedAccessException)
        {
            return new EvidenceMigrationResult
            {
                State = EvidenceMigrationResultState.RolledBack,
                StatusCode = "migration.rolled-back",
                Message = $"Migration failed and the active step was rolled back: {ex.Message}",
                LastAppliedMigrationId = lastApplied,
                AppliedMigrationIds = applied,
                RecoveryCopyPath = recoveryCopyPath,
                Plan = plan
            };
        }
    }

    private static string? ValidateRequest(SqliteEvidenceMigrationRequest request)
    {
        if (request == null)
        {
            return "A migration request is required.";
        }

        if (request.CaptureSealed)
        {
            return "Archived or sealed captures cannot execute primary-evidence migrations.";
        }

        if (request.SessionPaths == null ||
            string.IsNullOrWhiteSpace(request.SessionPaths.SessionRoot) ||
            string.IsNullOrWhiteSpace(request.SessionPaths.LiveDatabasePath) ||
            string.IsNullOrWhiteSpace(request.DatabasePath))
        {
            return "The active session root and live database path are required.";
        }

        string requestedPath;
        string sessionPath;
        string sessionRoot;
        try
        {
            requestedPath = Path.GetFullPath(request.DatabasePath);
            sessionPath = Path.GetFullPath(request.SessionPaths.LiveDatabasePath);
            sessionRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(request.SessionPaths.SessionRoot));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return $"The migration target contains an invalid path: {ex.Message}";
        }

        if (!string.Equals(requestedPath, sessionPath, StringComparison.OrdinalIgnoreCase))
        {
            return $"Requested database '{requestedPath}' is not the active session live database '{sessionPath}'.";
        }

        var rootPrefix = sessionRoot + Path.DirectorySeparatorChar;
        if (!requestedPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return "The live database path is outside the active session root.";
        }

        if (string.IsNullOrWhiteSpace(request.ExpectedEvidenceSessionId) ||
            !string.Equals(
                request.ExpectedEvidenceSessionId,
                request.SessionPaths.SessionId,
                StringComparison.Ordinal))
        {
            return "The expected evidence session identity does not match the active session path identity.";
        }

        if (string.IsNullOrWhiteSpace(request.AppliedByRelease))
        {
            return "The applying application/release identity is required.";
        }

        return null;
    }

    private static string? ValidateExecutionOwnership(SqliteEvidenceMigrationRequest request)
    {
        var lease = request.OwnershipLease;
        if (lease == null || !lease.IsHeld)
        {
            return "An active exclusive live-database ownership lease is required before migration or writer startup.";
        }

        if (!string.Equals(
                Path.GetFullPath(request.DatabasePath),
                lease.DatabasePath,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(request.ExpectedEvidenceSessionId, lease.SessionId, StringComparison.Ordinal))
        {
            return "The live-database ownership lease does not match the requested database and session identity.";
        }

        return null;
    }

    private static (string Code, string Message)? ValidateAppliedHistory(
        IReadOnlyList<AppliedCaptureMigration> applied)
    {
        var catalog = SqliteEvidenceMigrationCatalog.Definitions.ToDictionary(
            definition => definition.MigrationId,
            StringComparer.Ordinal);
        var appliedIds = applied.Select(item => item.MigrationId).ToHashSet(StringComparer.Ordinal);
        var previousSequence = 0;
        foreach (var item in applied.OrderBy(item => item.LedgerOrdinal))
        {
            if (!catalog.TryGetValue(item.MigrationId, out var definition))
            {
                continue;
            }

            var sequence = item.Sequence ?? definition.Sequence;
            if (sequence != definition.Sequence)
            {
                return (
                    "migration.history.sequence-mismatch",
                    $"Applied migration {item.MigrationId} records sequence {sequence}; catalog sequence is {definition.Sequence}.");
            }

            if (sequence < previousSequence)
            {
                return (
                    "migration.history.out-of-order",
                    $"Applied migration {item.MigrationId} appears out of catalog order at ledger ordinal {item.LedgerOrdinal}.");
            }

            foreach (var prerequisiteId in definition.PrerequisiteMigrationIds)
            {
                if (!appliedIds.Contains(prerequisiteId))
                {
                    return (
                        "migration.history.prerequisite-missing",
                        $"Applied migration {item.MigrationId} is missing prerequisite {prerequisiteId}.");
                }
            }

            previousSequence = sequence;
        }

        return null;
    }

    private static (string Code, string Message)? ValidatePendingPrerequisites(
        IReadOnlyList<CaptureMigrationDefinition> pending,
        HashSet<string> appliedIds)
    {
        var available = new HashSet<string>(appliedIds, StringComparer.Ordinal);
        foreach (var definition in pending.OrderBy(definition => definition.Sequence))
        {
            var missing = definition.PrerequisiteMigrationIds
                .Where(prerequisiteId => !available.Contains(prerequisiteId))
                .ToArray();
            if (missing.Length > 0)
            {
                return (
                    "migration.plan.prerequisite-missing",
                    $"Migration {definition.MigrationId} cannot run because prerequisites are missing: {string.Join(", ", missing)}.");
            }

            available.Add(definition.MigrationId);
        }

        return null;
    }

    private static string CreateRecoveryCopy(
        SqliteEvidenceMigrationRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var recoveryPath = SessionPathService.AllocateEvidenceMigrationRecoveryPath(request.SessionPaths);
        if (File.Exists(recoveryPath))
        {
            throw new IOException($"Recovery copy already exists and will not be overwritten: {recoveryPath}");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(recoveryPath)!);
        var partialPath = recoveryPath + ".partial";
        if (File.Exists(partialPath))
        {
            throw new IOException($"Partial recovery copy already exists and will not be overwritten: {partialPath}");
        }

        try
        {
            using (var source = SqlitePerformanceProfile.OpenConnection(
                       request.DatabasePath,
                       SqliteOpenMode.ReadOnly,
                       SqlitePerformanceProfileName.Conservative))
            using (var destination = SqlitePerformanceProfile.OpenConnection(
                       partialPath,
                       SqliteOpenMode.ReadWriteCreate,
                       SqlitePerformanceProfileName.Conservative))
            {
                source.BackupDatabase(destination);
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(partialPath, recoveryPath, overwrite: false);
            return recoveryPath;
        }
        catch
        {
            if (File.Exists(partialPath))
            {
                File.Delete(partialPath);
            }

            throw;
        }
    }

    private static bool ShouldExecuteInLiveWriter(CaptureMigrationDefinition definition)
        => definition.Kind == CaptureMigrationKind.PrimaryEvidence ||
           !DeferredAnalysisMigrationIds.Contains(definition.MigrationId);

    private static bool IsPrimary(CaptureMigrationDefinition definition)
        => definition.Kind == CaptureMigrationKind.PrimaryEvidence;

    private static EvidenceMigrationPlan Blocked(
        string statusCode,
        string message,
        int? currentEvidenceFormatVersion = null)
        => new()
        {
            State = EvidenceMigrationPlanState.Blocked,
            StatusCode = statusCode,
            Message = message,
            CurrentEvidenceFormatVersion = currentEvidenceFormatVersion,
            TargetEvidenceFormatVersion = CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion
        };

    private static EvidenceMigrationResult Result(
        EvidenceMigrationResultState state,
        string statusCode,
        string message,
        EvidenceMigrationPlan plan)
        => new()
        {
            State = state,
            StatusCode = statusCode,
            Message = message,
            Plan = plan
        };
}
