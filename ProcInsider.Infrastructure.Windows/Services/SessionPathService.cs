using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcInsider.Compatibility;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services;

public sealed record InvestigationSessionPaths
{
    public string SessionId { get; init; } = string.Empty;

    public DateTime CreatedUtc { get; init; }

    public string SessionRoot { get; init; } = string.Empty;

    public string LiveDatabasePath { get; init; } = string.Empty;

    public string AnnotationDatabasePath { get; init; } = string.Empty;

    public string SnapshotDirectory { get; init; } = string.Empty;

    public string SnapshotDatabasePath { get; init; } = string.Empty;

    public string BaselinePolicyPath { get; init; } = string.Empty;

    public string DumpsDirectory { get; init; } = string.Empty;

    public string MemoryDirectory { get; init; } = string.Empty;

    /// <summary>
    /// Lazily created Agent-owned working root for bounded YARA execution. It is
    /// derived from the active investigation root but is not created during
    /// ordinary startup while the feature remains unpublished.
    /// </summary>
    public string YaraWorkingDirectory => Path.Combine(SessionRoot, "YaraWorking");

    public string NetworkCapturesDirectory { get; init; } = string.Empty;

    public string ZeekDirectory { get; init; } = string.Empty;

    public string ProcessMonitorDirectory { get; init; } = string.Empty;

    public string BenchmarkDirectory { get; init; } = string.Empty;

    public string LogsDirectory { get; init; } = string.Empty;

    public string AgentLogPath => AgentRuntimeIdentity.ResolveLogPath(LogsDirectory);

    public string PrimaryAgentLogPath => Path.Combine(LogsDirectory, AgentRuntimeIdentity.LogFileName);

    public string LegacyAgentLogPath => Path.Combine(LogsDirectory, AgentRuntimeIdentity.LegacyLogFileName);

    public string AiSettingsPath { get; init; } = string.Empty;

    public string AiSecretPath { get; init; } = string.Empty;

    public string NsrlSettingsPath { get; init; } = string.Empty;

    /// <summary>
    /// Account-local, session-bound pairing state. These paths deliberately live
    /// outside the capture package so credentials and discovery leases are never
    /// included in evidence exports.
    /// </summary>
    public string AgentPairingDirectory { get; init; } = string.Empty;

    public string AgentPairingLeasePath { get; init; } = string.Empty;

    public string AgentPairingSecretPath { get; init; } = string.Empty;

    public bool UsedFallbackRoot { get; init; }

    public string PreferredParentDirectory { get; init; } = string.Empty;

    public string FallbackReason { get; init; } = string.Empty;
}

public sealed record CapturePackageInfo
{
    public string FormatName { get; init; } = string.Empty;

    public string ProductDisplayName { get; init; } = ProductIdentity.FormerName;

    public bool HasDeclaredProductDisplayName { get; init; }

    public int SchemaVersion { get; init; }

    public int? EvidenceFormatVersion { get; init; }

    public string SessionId { get; init; } = string.Empty;

    public string AppVersion { get; init; } = string.Empty;

    public DateTime CreatedUtc { get; init; }

    public string MachineName { get; init; } = string.Empty;

    public string ManifestPath { get; init; } = string.Empty;

    public string SessionRoot { get; init; } = string.Empty;

    public string LiveDatabasePath { get; init; } = string.Empty;

    public string AnnotationDatabasePath { get; init; } = string.Empty;

    public string SnapshotDirectory { get; init; } = string.Empty;

    public string SnapshotDatabasePath { get; init; } = string.Empty;

    public string BaselinePolicyPath { get; init; } = string.Empty;

    public string AiSettingsPath { get; init; } = string.Empty;

    public string AiSecretPath { get; init; } = string.Empty;

    public bool HasLiveDatabase { get; init; }

    public bool HasAnnotationDatabase { get; init; }

    public bool HasSnapshotDatabase { get; init; }

    public bool HasBaselinePolicy { get; init; }

    public bool HasCaptureConfiguration { get; init; }

    public bool HasHostMonitoringConfiguration { get; init; }

    public bool HasHostMonitoringOriginalState { get; init; }

    public bool HasAiSettings { get; init; }

    public bool HasAiSecrets { get; init; }

    public IReadOnlyList<CapturePackageFolderInfo> ArtifactFolders { get; init; } = Array.Empty<CapturePackageFolderInfo>();

    public CaptureCompatibilityAssessment CompatibilityAssessment { get; init; } = new();

    public CaptureManifestCompatibilityMetadata CompatibilityMetadata => new(
        SchemaVersion,
        SessionId,
        EvidenceFormatVersion);
}

public sealed record CapturePackageFolderInfo
{
    public string Name { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public bool Exists { get; init; }
}

public sealed record InfrastructureAgentMachinePaths
{
    public string RootDirectory { get; init; } = string.Empty;

    public string ConfigurationDirectory { get; init; } = string.Empty;

    public string ConfigurationFilePath { get; init; } = string.Empty;

    public string ConfigurationRecoveryFilePath { get; init; } = string.Empty;

    public string SessionsDirectory { get; init; } = string.Empty;

    public string OperationalLogsDirectory { get; init; } = string.Empty;

    public string SpoolDirectory { get; init; } = string.Empty;

    public string ArtifactsDirectory { get; init; } = string.Empty;

    public string SecretsDirectory { get; init; } = string.Empty;

    public string ServiceLifecycleLogPath { get; init; } = string.Empty;
}

public sealed record InfrastructureServerMachinePaths
{
    public string RootDirectory { get; init; } = string.Empty;

    public string ConfigurationDirectory { get; init; } = string.Empty;

    public string ConfigurationFilePath { get; init; } = string.Empty;

    public string ConfigurationRecoveryFilePath { get; init; } = string.Empty;

    public string OperationalControlDirectory { get; init; } = string.Empty;

    public string OperationalControlDatabasePath { get; init; } = string.Empty;

    public string OperationalLogsDirectory { get; init; } = string.Empty;

    public string ServiceLifecycleLogPath { get; init; } = string.Empty;

    public string ArtifactsDirectory { get; init; } = string.Empty;

    public string BackupsDirectory { get; init; } = string.Empty;

    public string ExportsDirectory { get; init; } = string.Empty;
}

public static class SessionPathService
{
    public delegate CaptureCompatibilityAssessment EvidenceDatabaseAssessment(
        string databasePath,
        CaptureOpenContext context,
        CaptureManifestCompatibilityMetadata? manifest,
        string expectedEvidenceSessionId,
        CaptureArtifactKind? artifactKind);

    public const int SessionSchemaVersion = CaptureCompatibilityPolicy.CurrentManifestSchemaVersion;
    public const string CapturePackageFormatName = ProductIdentity.DisplayName + " session folder";
    public const string CapturePackageManifestFileName = "session.json";
    public const string ProductDisplayNameMetadataKey = "ProductDisplayName";
    public const string LocalDataRootFolderName = "DFIRoscope";
    public const string LegacyLocalDataRootFolderName = "ProcInsider";
    public const string SessionPrefix = "DFIRoscope-Session";
    public const string LegacySessionPrefix = "ProcInsider-Session";
    public const string InfrastructureAgentRootFolderName = "Agent";
    public const string InfrastructureServerRootFolderName = "Server";
    public const string InfrastructureAgentConfigurationFileName = "infrastructure-agent.g1.json";
    public const string InfrastructureServerConfigurationFileName = "infrastructure-server.g1.json";
    public const string InfrastructureConfigurationRecoverySuffix = ".previous";
    private const string LiveDatabaseFileName = "procinsider-live.sqlite3";
    private const string AnnotationDatabaseFileName = "annotations.sqlite";
    private const string SnapshotDatabaseFileName = "procinsider-snapshot.sqlite3";
    private const string BaselinePolicyFileName = "baseline-policy.json";
    private const string AiSettingsFileName = "ai-settings.json";
    private const string AiSecretFileName = "ai-secrets.dpapi.json";
    private const string NsrlSettingsFileName = "nsrl-settings.json";
    private const string AgentPairingDirectoryName = "AgentPairings";
    private const string AgentPairingLeaseFileName = "agent-lease.json";
    private const string AgentPairingSecretFileName = "agent-pairing.dpapi.json";
    private const string AgentCaptureConfigurationFileName = "agent-capture-configuration.json";
    private const string AgentHostMonitoringConfigurationFileName = "agent-host-monitoring-configuration.json";
    private const string AgentMonitoringOriginalStateFileName = "agent-monitoring-original-state.json";
    private const string ViewerIncidentDirectoryName = "ViewerIncidents";
    private const string EvidenceMigrationRecoveryDirectoryName = "MigrationRecovery";
    private const string LiveDatabaseOwnershipLockFileName = "procinsider-live.writer.lock";
    private const string LocalDataMigrationLogRelativePath = @"Migration\local-data-migration.jsonl";

    private static readonly object LocalDataMigrationGate = new();
    private static bool _defaultLocalDataMigrationAttempted;

    public static DirectoryMigrationResult? LastLocalDataMigrationResult { get; private set; }

    private static readonly JsonSerializerOptions MetadataJsonOptions = new()
    {
        WriteIndented = true
    };

    public static InvestigationSessionPaths CreateDefaultSession() =>
        CreateDefaultSessionForApplicationBaseDirectory(
            AppContext.BaseDirectory,
            localAppDataDirectory: null);

    public static InvestigationSessionPaths CreateDefaultSessionForApplicationBaseDirectory(
        string applicationBaseDirectory,
        string? localAppDataDirectory = null)
    {
        var portableLocation = PortablePackageLocationService.TryResolve(applicationBaseDirectory);
        return portableLocation == null
            ? CreateDefaultSessionCore(localAppDataDirectory)
            : CreatePortablePackageSession(portableLocation, localAppDataDirectory);
    }

    public static InfrastructureAgentMachinePaths GetInfrastructureAgentMachinePaths(
        string? commonApplicationDataDirectory = null)
    {
        var commonApplicationData = string.IsNullOrWhiteSpace(commonApplicationDataDirectory)
            ? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            : Path.GetFullPath(commonApplicationDataDirectory);
        if (string.IsNullOrWhiteSpace(commonApplicationData))
        {
            throw new DirectoryNotFoundException("The Windows common application-data directory is unavailable.");
        }

        var root = Path.Combine(
            Path.GetFullPath(commonApplicationData),
            LocalDataRootFolderName,
            InfrastructureAgentRootFolderName);
        var logs = Path.Combine(root, "Logs");
        var configurationDirectory = Path.Combine(root, "Configuration");
        var configurationPath = Path.Combine(
            configurationDirectory,
            InfrastructureAgentConfigurationFileName);
        return new InfrastructureAgentMachinePaths
        {
            RootDirectory = root,
            ConfigurationDirectory = configurationDirectory,
            ConfigurationFilePath = configurationPath,
            ConfigurationRecoveryFilePath = configurationPath + InfrastructureConfigurationRecoverySuffix,
            SessionsDirectory = Path.Combine(root, "Sessions"),
            OperationalLogsDirectory = logs,
            SpoolDirectory = Path.Combine(root, "Spool"),
            ArtifactsDirectory = Path.Combine(root, "Artifacts"),
            SecretsDirectory = Path.Combine(root, "Secrets"),
            ServiceLifecycleLogPath = Path.Combine(logs, "agent-service-lifecycle.jsonl")
        };
    }

    public static InfrastructureServerMachinePaths GetInfrastructureServerMachinePaths(
        string? commonApplicationDataDirectory = null)
    {
        var commonApplicationData = string.IsNullOrWhiteSpace(commonApplicationDataDirectory)
            ? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            : Path.GetFullPath(commonApplicationDataDirectory);
        if (string.IsNullOrWhiteSpace(commonApplicationData))
        {
            throw new DirectoryNotFoundException("The Windows common application-data directory is unavailable.");
        }

        var root = Path.Combine(
            Path.GetFullPath(commonApplicationData),
            LocalDataRootFolderName,
            InfrastructureServerRootFolderName);
        var configurationDirectory = Path.Combine(root, "Configuration");
        var configurationPath = Path.Combine(
            configurationDirectory,
            InfrastructureServerConfigurationFileName);
        var operationalControlDirectory = Path.Combine(root, "Control");
        return new InfrastructureServerMachinePaths
        {
            RootDirectory = root,
            ConfigurationDirectory = configurationDirectory,
            ConfigurationFilePath = configurationPath,
            ConfigurationRecoveryFilePath = configurationPath + InfrastructureConfigurationRecoverySuffix,
            OperationalControlDirectory = operationalControlDirectory,
            OperationalControlDatabasePath = Path.Combine(operationalControlDirectory, "server-control.sqlite3"),
            OperationalLogsDirectory = Path.Combine(root, "Logs"),
            ServiceLifecycleLogPath = Path.Combine(root, "Logs", "server-service-lifecycle.jsonl"),
            ArtifactsDirectory = Path.Combine(root, "Artifacts"),
            BackupsDirectory = Path.Combine(root, "Backups"),
            ExportsDirectory = Path.Combine(root, "Exports")
        };
    }

    public static InvestigationSessionPaths CreateInfrastructureAgentServiceSession(
        string? commonApplicationDataDirectory = null)
    {
        var machinePaths = GetInfrastructureAgentMachinePaths(commonApplicationDataDirectory);
        if (!Directory.Exists(machinePaths.RootDirectory))
        {
            throw new DirectoryNotFoundException(
                $"The installed Agent Service root does not exist: {machinePaths.RootDirectory}");
        }

        var sessionId = $"{SessionPrefix}-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
        return CreateSessionUnderParent(
            machinePaths.SessionsDirectory,
            machinePaths.SessionsDirectory,
            sessionId,
            DateTime.UtcNow,
            usedFallbackRoot: false,
            fallbackReason: string.Empty,
            agentPairingRootDirectory: machinePaths.SecretsDirectory);
    }

    public static InvestigationSessionPaths BindInfrastructureAgentMachineScope(
        InvestigationSessionPaths paths,
        string? commonApplicationDataDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var machinePaths = GetInfrastructureAgentMachinePaths(commonApplicationDataDirectory);
        if (!IsPathWithinRoot(machinePaths.RootDirectory, paths.SessionRoot))
        {
            throw new InvalidDataException(
                $"The Agent Service session root must stay under the installed machine root '{machinePaths.RootDirectory}'.");
        }

        var pairingPaths = ResolveAgentPairingPaths(
            paths.SessionId,
            paths.LiveDatabasePath,
            localAppDataDirectory: null,
            pairingRootDirectory: machinePaths.SecretsDirectory);
        return paths with
        {
            AgentPairingDirectory = pairingPaths.Directory,
            AgentPairingLeasePath = pairingPaths.LeasePath,
            AgentPairingSecretPath = pairingPaths.SecretPath,
            PreferredParentDirectory = machinePaths.SessionsDirectory,
            UsedFallbackRoot = false,
            FallbackReason = string.Empty
        };
    }

    public static InvestigationSessionPaths CreateDefaultSession(string localAppDataDirectory)
    {
        if (string.IsNullOrWhiteSpace(localAppDataDirectory))
        {
            throw new ArgumentException("A local application-data directory is required.", nameof(localAppDataDirectory));
        }

        return CreateDefaultSessionCore(localAppDataDirectory);
    }

    private static InvestigationSessionPaths CreateDefaultSessionCore(string? localAppDataDirectory)
    {
        _ = MigrateLegacyLocalData(localAppDataDirectory);
        var sessionId = $"{SessionPrefix}-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
        var createdUtc = DateTime.UtcNow;
        var preferredParent = GetLocalAppDataSessionsDirectory(localAppDataDirectory);
        var fallbackParent = localAppDataDirectory == null
            ? Path.Combine(Path.GetTempPath(), LocalDataRootFolderName, "Sessions")
            : preferredParent;

        try
        {
            return CreateSessionUnderParent(
                preferredParent,
                preferredParent,
                sessionId,
                createdUtc,
                usedFallbackRoot: false,
                fallbackReason: string.Empty,
                localAppDataDirectory);
        }
        catch (Exception ex) when (IsPathSetupFailure(ex))
        {
            if (string.Equals(preferredParent, fallbackParent, StringComparison.OrdinalIgnoreCase))
            {
                throw;
            }

            return CreateSessionUnderParent(
                fallbackParent,
                preferredParent,
                sessionId,
                createdUtc,
                usedFallbackRoot: true,
                fallbackReason: $"LocalAppData session root was not writable: {ex.Message}",
                localAppDataDirectory);
        }
    }

    private static InvestigationSessionPaths CreatePortablePackageSession(
        PortablePackageLocation portableLocation,
        string? localAppDataDirectory)
    {
        var sessionId = $"{SessionPrefix}-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
        var createdUtc = DateTime.UtcNow;
        try
        {
            PortablePackageLocationService.ValidateCaptureDirectory(portableLocation);
            var paths = CreateSessionUnderParent(
                portableLocation.CapturesDirectory,
                portableLocation.CapturesDirectory,
                sessionId,
                createdUtc,
                usedFallbackRoot: false,
                fallbackReason: string.Empty,
                localAppDataDirectory);
            PortablePackageLocationService.ValidateCaptureDirectory(portableLocation);
            if (!IsPathWithinRoot(portableLocation.CapturesDirectory, paths.SessionRoot))
            {
                throw new PortablePackageLocationException(
                    "The fresh portable capture resolved outside the package-owned Captures directory.");
            }

            return paths;
        }
        catch (PortablePackageLocationException)
        {
            throw;
        }
        catch (Exception ex) when (IsPathSetupFailure(ex) || ex is ArgumentException)
        {
            throw new PortablePackageLocationException(
                $"The portable capture directory is unavailable or unsafe. No fallback capture was created: {portableLocation.CapturesDirectory}",
                ex);
        }
    }

    public static DirectoryMigrationResult MigrateLegacyLocalData(string? localAppDataDirectory = null)
    {
        lock (LocalDataMigrationGate)
        {
            if (localAppDataDirectory == null &&
                _defaultLocalDataMigrationAttempted &&
                LastLocalDataMigrationResult != null)
            {
                return LastLocalDataMigrationResult;
            }

            try
            {
                var baseDirectory = ResolveLocalAppDataDirectory(localAppDataDirectory);
                var legacyRoot = Path.Combine(baseDirectory, LegacyLocalDataRootFolderName);
                var targetRoot = Path.Combine(baseDirectory, LocalDataRootFolderName);
                var result = DirectoryCompatibilityMigration.Migrate(new DirectoryMigrationRequest
                {
                    SourceRoot = legacyRoot,
                    TargetRoot = targetRoot,
                    ObservationLogPath = Path.Combine(targetRoot, LocalDataMigrationLogRelativePath),
                    AcquireSourceDirectoryLease = AcquireLegacySessionDirectoryLease
                });
                LastLocalDataMigrationResult = result;
                if (localAppDataDirectory == null)
                {
                    _defaultLocalDataMigrationAttempted = true;
                }

                return result;
            }
            catch (Exception ex) when (IsPathSetupFailure(ex) || ex is ArgumentException)
            {
                Trace.TraceWarning($"Local-data migration could not start: {ex.GetType().Name}: {ex.Message}");
                var result = new DirectoryMigrationResult
                {
                    Outcome = DirectoryMigrationOutcome.Failed,
                    FailureCount = 1,
                    Diagnostics = [$"startup: {ex.GetType().Name}: {ex.Message}"]
                };
                LastLocalDataMigrationResult = result;
                if (localAppDataDirectory == null)
                {
                    _defaultLocalDataMigrationAttempted = true;
                }

                return result;
            }
        }
    }

    public static IReadOnlyList<string> GetSessionDiscoveryDirectories(string? localAppDataDirectory = null)
    {
        var baseDirectory = ResolveLocalAppDataDirectory(localAppDataDirectory);
        var preferred = Path.Combine(baseDirectory, LocalDataRootFolderName, "Sessions");
        var legacy = Path.Combine(baseDirectory, LegacyLocalDataRootFolderName, "Sessions");
        return string.Equals(preferred, legacy, StringComparison.OrdinalIgnoreCase)
            ? [preferred]
            : [preferred, legacy];
    }

    public static string GetAgentPairingRootDirectory(string? localAppDataDirectory = null) =>
        Path.Combine(
            ResolveLocalAppDataDirectory(localAppDataDirectory),
            LocalDataRootFolderName,
            AgentPairingDirectoryName);

    public static IReadOnlyList<string> DiscoverCaptureManifests(string? localAppDataDirectory = null)
    {
        var manifests = new List<string>();
        var observedSessionDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var sessionsDirectory in GetSessionDiscoveryDirectories(localAppDataDirectory))
        {
            if (!Directory.Exists(sessionsDirectory))
            {
                continue;
            }

            try
            {
                foreach (var sessionDirectory in Directory.GetDirectories(sessionsDirectory)
                             .OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase))
                {
                    var sessionFolderName = Path.GetFileName(sessionDirectory);
                    var manifestPath = Path.Combine(sessionDirectory, CapturePackageManifestFileName);
                    if (File.Exists(manifestPath) && observedSessionDirectories.Add(sessionFolderName))
                    {
                        manifests.Add(manifestPath);
                    }
                }
            }
            catch (Exception ex) when (IsPathSetupFailure(ex))
            {
                Trace.TraceWarning($"Session discovery skipped '{sessionsDirectory}': {ex.GetType().Name}: {ex.Message}");
            }
        }

        return manifests;
    }

    public static InvestigationSessionPaths CreateForLiveDatabasePath(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            return CreateDefaultSession();
        }

        var fullDatabasePath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(databasePath));
        var sessionRoot = Path.GetDirectoryName(fullDatabasePath) ?? AppContext.BaseDirectory;
        var sessionId = Path.GetFileName(sessionRoot);
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            sessionId = $"{SessionPrefix}-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
        }

        var paths = BuildPaths(
            sessionRoot,
            sessionId,
            DateTime.UtcNow,
            usedFallbackRoot: false,
            fallbackReason: string.Empty,
            preferredParentDirectory: Path.GetDirectoryName(sessionRoot) ?? AppContext.BaseDirectory,
            liveDatabasePath: fullDatabasePath);
        EnsureCoreDirectories(paths);
        PersistMetadata(paths);
        return paths;
    }

    public static InvestigationSessionPaths OpenExistingCapturePackage(
        string captureManifestPath,
        CaptureOpenContext context = CaptureOpenContext.ViewerArchivedReadOnly,
        EvidenceDatabaseAssessment? evidenceDatabaseAssessment = null)
    {
        if (string.IsNullOrWhiteSpace(captureManifestPath))
        {
            throw new ArgumentException("A capture manifest path is required.", nameof(captureManifestPath));
        }

        if (context == CaptureOpenContext.InspectionOnly)
        {
            throw new ArgumentException(
                "InspectionOnly returns metadata but cannot activate package paths; use InspectCapturePackage instead.",
                nameof(context));
        }

        var packageInfo = InspectCapturePackage(
            captureManifestPath,
            context,
            evidenceDatabaseAssessment);
        if (!packageInfo.HasLiveDatabase &&
            packageInfo.CompatibilityAssessment.State == CaptureCompatibilityState.CompatibleCurrent)
        {
            throw new FileNotFoundException(
                "The selected capture manifest does not resolve to an existing procinsider-live.sqlite3 database.",
                packageInfo.LiveDatabasePath);
        }
        EnsurePackageOpenAllowed(packageInfo, context);
        var location = NormalizeCapturePackageManifest(captureManifestPath, allowFolderCompatibility: true);
        var sessionRoot = location.SessionRoot;
        var metadataPath = location.ManifestPath;
        var metadata = ReadSessionMetadata(metadataPath);
        ValidateSessionMetadata(metadata);
        return BuildPathsFromManifest(sessionRoot, metadataPath, metadata, requireLiveDatabase: true);
    }

    public static InvestigationSessionPaths OpenOrCreateAgentLiveCapturePackage(
        string captureManifestPath,
        EvidenceDatabaseAssessment evidenceDatabaseAssessment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(captureManifestPath);
        ArgumentNullException.ThrowIfNull(evidenceDatabaseAssessment);

        var packageInfo = InspectCapturePackage(
            captureManifestPath,
            CaptureOpenContext.AgentWritableLive,
            evidenceDatabaseAssessment);
        if (packageInfo.HasLiveDatabase)
        {
            EnsurePackageOpenAllowed(packageInfo, CaptureOpenContext.AgentWritableLive);
        }
        else if (packageInfo.CompatibilityAssessment.State !=
                 CaptureCompatibilityState.CompatibleCurrent ||
                 packageInfo.CompatibilityAssessment.Context !=
                 CaptureOpenContext.AgentWritableLive ||
                 packageInfo.CompatibilityAssessment.ArtifactKind !=
                 CaptureArtifactKind.LiveAuthoritativeDatabase)
        {
            throw new InvalidDataException(CaptureCompatibilityPolicy.FormatDiagnostic(
                packageInfo.CompatibilityAssessment,
                packageInfo.ManifestPath));
        }

        var location = NormalizeCapturePackageManifest(
            captureManifestPath,
            allowFolderCompatibility: true);
        var metadata = ReadSessionMetadata(location.ManifestPath);
        ValidateSessionMetadata(metadata);
        return BuildPathsFromManifest(
            location.SessionRoot,
            location.ManifestPath,
            metadata,
            requireLiveDatabase: packageInfo.HasLiveDatabase);
    }

    public static InvestigationSessionPaths OpenExistingSessionFolder(
        string sessionFolder,
        EvidenceDatabaseAssessment? evidenceDatabaseAssessment = null)
    {
        var location = NormalizeCapturePackageManifest(sessionFolder, allowFolderCompatibility: true);
        return OpenExistingCapturePackage(
            location.ManifestPath,
            CaptureOpenContext.ViewerArchivedReadOnly,
            evidenceDatabaseAssessment);
    }

    public static CapturePackageInfo InspectCapturePackage(
        string captureManifestPath,
        CaptureOpenContext context = CaptureOpenContext.InspectionOnly,
        EvidenceDatabaseAssessment? evidenceDatabaseAssessment = null)
    {
        var location = NormalizeCapturePackageManifest(captureManifestPath, allowFolderCompatibility: true);
        var sessionRoot = location.SessionRoot;
        var metadataPath = location.ManifestPath;
        var metadata = ReadSessionMetadata(metadataPath);
        var manifest = new CaptureManifestCompatibilityMetadata(
            metadata.SchemaVersion,
            metadata.SessionId,
            metadata.EvidenceFormatVersion);
        CaptureCompatibilityAssessment assessment;
        InvestigationSessionPaths? paths = null;
        try
        {
            ValidateSessionMetadata(metadata);
            paths = BuildPathsFromManifest(sessionRoot, metadataPath, metadata, requireLiveDatabase: false);
            assessment = File.Exists(paths.LiveDatabasePath)
                ? (evidenceDatabaseAssessment ?? throw new InvalidOperationException(
                    "Capture database inspection requires the owning SQLite compatibility assessor."))(
                    paths.LiveDatabasePath,
                    context,
                    manifest,
                    paths.SessionId,
                    artifactKind: null)
                : CaptureCompatibilityPolicy.Assess(new CaptureCompatibilityInput
                {
                    Context = context,
                    ArtifactKind = GetArtifactKind(context),
                    Manifest = manifest,
                    ExpectedEvidenceSessionId = paths.SessionId
                });
        }
        catch (InvalidDataException ex) when (ex.Message.Contains("outside the capture folder", StringComparison.OrdinalIgnoreCase))
        {
            assessment = CaptureCompatibilityPolicy.Assess(new CaptureCompatibilityInput
            {
                Context = context,
                ArtifactKind = GetArtifactKind(context),
                Manifest = manifest,
                PathsAreContained = false
            });
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            assessment = CaptureCompatibilityPolicy.Assess(new CaptureCompatibilityInput
            {
                Context = context,
                ArtifactKind = GetArtifactKind(context),
                Manifest = manifest,
                InspectionFailure = ex.Message
            });
        }

        paths ??= BuildDiagnosticPaths(sessionRoot, metadataPath, metadata);
        var productIdentity = ResolveProductDisplayIdentity(metadata.FutureMetadata);

        var artifactFolders = new[]
        {
            BuildFolderInfo("Dumps", paths.DumpsDirectory),
            BuildFolderInfo("Memory", paths.MemoryDirectory),
            BuildFolderInfo("NetworkCaptures", paths.NetworkCapturesDirectory),
            BuildFolderInfo("Zeek", paths.ZeekDirectory),
            BuildFolderInfo("ProcessMonitor", paths.ProcessMonitorDirectory),
            BuildFolderInfo("Benchmarks", paths.BenchmarkDirectory),
            BuildFolderInfo("Logs", paths.LogsDirectory)
        };

        return new CapturePackageInfo
        {
            FormatName = CapturePackageFormatName,
            ProductDisplayName = productIdentity.DisplayName,
            HasDeclaredProductDisplayName = productIdentity.IsDeclared,
            SchemaVersion = metadata.SchemaVersion,
            EvidenceFormatVersion = metadata.EvidenceFormatVersion,
            SessionId = paths.SessionId,
            AppVersion = metadata.AppVersion,
            CreatedUtc = paths.CreatedUtc,
            MachineName = metadata.MachineName,
            ManifestPath = metadataPath,
            SessionRoot = sessionRoot,
            LiveDatabasePath = paths.LiveDatabasePath,
            AnnotationDatabasePath = paths.AnnotationDatabasePath,
            SnapshotDirectory = paths.SnapshotDirectory,
            SnapshotDatabasePath = paths.SnapshotDatabasePath,
            BaselinePolicyPath = paths.BaselinePolicyPath,
            AiSettingsPath = paths.AiSettingsPath,
            AiSecretPath = paths.AiSecretPath,
            HasLiveDatabase = File.Exists(paths.LiveDatabasePath),
            HasAnnotationDatabase = File.Exists(paths.AnnotationDatabasePath),
            HasSnapshotDatabase = File.Exists(paths.SnapshotDatabasePath),
            HasBaselinePolicy = File.Exists(paths.BaselinePolicyPath),
            HasCaptureConfiguration = File.Exists(Path.Combine(sessionRoot, AgentCaptureConfigurationFileName)),
            HasHostMonitoringConfiguration = File.Exists(Path.Combine(sessionRoot, AgentHostMonitoringConfigurationFileName)),
            HasHostMonitoringOriginalState = File.Exists(Path.Combine(sessionRoot, AgentMonitoringOriginalStateFileName)),
            HasAiSettings = File.Exists(paths.AiSettingsPath),
            HasAiSecrets = File.Exists(paths.AiSecretPath),
            ArtifactFolders = artifactFolders,
            CompatibilityAssessment = assessment
        };
    }

    private static void EnsurePackageOpenAllowed(CapturePackageInfo packageInfo, CaptureOpenContext context)
    {
        var assessment = packageInfo.CompatibilityAssessment;
        if (context == CaptureOpenContext.AgentWritableLive)
        {
            if (assessment.Allows(CaptureOpenCapability.WritePrimaryEvidence) ||
                assessment.Allows(CaptureOpenCapability.MigratePrimaryEvidence))
            {
                return;
            }

            throw new InvalidDataException(CaptureCompatibilityPolicy.FormatDiagnostic(
                assessment,
                packageInfo.ManifestPath));
        }

        var capability = context switch
        {
            CaptureOpenContext.ViewerLiveSourceReadOnly or
                CaptureOpenContext.ViewerLiveSnapshot or
                CaptureOpenContext.ViewerArchivedReadOnly =>
                CaptureOpenCapability.ReadEvidence,
            CaptureOpenContext.ArchivedAnalysisMaintenance => CaptureOpenCapability.MaintainAnalysisState,
            _ => CaptureOpenCapability.InspectMetadata
        };
        if (!assessment.Allows(capability))
        {
            throw new InvalidDataException(CaptureCompatibilityPolicy.FormatDiagnostic(
                assessment,
                packageInfo.ManifestPath));
        }
    }

    private static InvestigationSessionPaths BuildDiagnosticPaths(
        string sessionRoot,
        string metadataPath,
        SessionMetadata metadata)
    {
        var sessionId = string.IsNullOrWhiteSpace(metadata.SessionId)
            ? Path.GetFileName(sessionRoot)
            : metadata.SessionId;
        return BuildPaths(
            sessionRoot,
            sessionId,
            metadata.CreatedUtc == default ? File.GetCreationTimeUtc(metadataPath) : metadata.CreatedUtc,
            metadata.UsedFallbackRoot,
            metadata.FallbackReason,
            Path.GetDirectoryName(sessionRoot) ?? AppContext.BaseDirectory,
            Path.Combine(sessionRoot, LiveDatabaseFileName));
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

    public static string GetDefaultDumpsDirectory() => CreateDefaultSession().DumpsDirectory;

    public static string GetDefaultNetworkCapturesDirectory() => CreateDefaultSession().NetworkCapturesDirectory;

    public static string GetDefaultMemoryDirectory() => CreateDefaultSession().MemoryDirectory;

    public static string GetDefaultZeekDirectory(string captureId, Guid jobId)
    {
        var session = CreateDefaultSession();
        var id = string.IsNullOrWhiteSpace(captureId) ? jobId.ToString("N") : SanitizePathPart(captureId);
        return Path.Combine(session.ZeekDirectory, id);
    }

    public static string GetDefaultProcessMonitorDirectory() => CreateDefaultSession().ProcessMonitorDirectory;

    /// <summary>
    /// Returns viewer crash destinations in priority order. Only a live session
    /// may receive incidents in its Logs folder; archived, switching, empty, and
    /// pre-session states use the owned bootstrap location so sealed captures are
    /// never mutated.
    /// </summary>
    public static IReadOnlyList<string> GetViewerCrashDiagnosticDirectories(
        InvestigationSessionPaths? activeSession,
        CaptureWorkspaceMode workspaceMode)
    {
        var bootstrap = GetBootstrapViewerCrashDiagnosticsDirectory();
        if (workspaceMode != CaptureWorkspaceMode.LiveCapture ||
            activeSession == null ||
            string.IsNullOrWhiteSpace(activeSession.LogsDirectory))
        {
            return [bootstrap];
        }

        var sessionDirectory = Path.Combine(activeSession.LogsDirectory, ViewerIncidentDirectoryName);
        return string.Equals(sessionDirectory, bootstrap, StringComparison.OrdinalIgnoreCase)
            ? [bootstrap]
            : [sessionDirectory, bootstrap];
    }

    public static string GetBootstrapViewerCrashDiagnosticsDirectory(string? localAppDataDirectory = null)
    {
        var root = Path.Combine(ResolveLocalAppDataDirectory(localAppDataDirectory), LocalDataRootFolderName);
        return Path.Combine(root, "Diagnostics", ViewerIncidentDirectoryName);
    }

    private static InvestigationSessionPaths CreateSessionUnderParent(
        string parentDirectory,
        string preferredParentDirectory,
        string requestedSessionId,
        DateTime createdUtc,
        bool usedFallbackRoot,
        string fallbackReason,
        string? localAppDataDirectory = null,
        string? agentPairingRootDirectory = null)
    {
        Directory.CreateDirectory(parentDirectory);
        var sessionRoot = AllocateUniqueSessionRoot(parentDirectory, requestedSessionId);
        var paths = BuildPaths(
            sessionRoot,
            Path.GetFileName(sessionRoot),
            createdUtc,
            usedFallbackRoot,
            fallbackReason,
            preferredParentDirectory,
            liveDatabasePath: Path.Combine(sessionRoot, LiveDatabaseFileName),
            localAppDataDirectory: localAppDataDirectory,
            agentPairingRootDirectory: agentPairingRootDirectory);
        EnsureCoreDirectories(paths);
        PersistMetadata(paths);
        return paths;
    }

    private static InvestigationSessionPaths BuildPaths(
        string sessionRoot,
        string sessionId,
        DateTime createdUtc,
        bool usedFallbackRoot,
        string fallbackReason,
        string preferredParentDirectory,
        string liveDatabasePath,
        string? baselinePolicyPath = null,
        string? localAppDataDirectory = null,
        string? agentPairingRootDirectory = null)
    {
        sessionRoot = Path.GetFullPath(sessionRoot);
        liveDatabasePath = NormalizeLiveDatabaseIdentity(liveDatabasePath);
        var snapshotDirectory = Path.Combine(sessionRoot, "Snapshots");
        var pairingPaths = ResolveAgentPairingPaths(
            sessionId,
            liveDatabasePath,
            localAppDataDirectory,
            agentPairingRootDirectory);
        return new InvestigationSessionPaths
        {
            SessionId = sessionId,
            CreatedUtc = createdUtc,
            SessionRoot = sessionRoot,
            LiveDatabasePath = liveDatabasePath,
            AnnotationDatabasePath = Path.Combine(sessionRoot, AnnotationDatabaseFileName),
            SnapshotDirectory = snapshotDirectory,
            SnapshotDatabasePath = Path.Combine(snapshotDirectory, SnapshotDatabaseFileName),
            BaselinePolicyPath = baselinePolicyPath ?? Path.Combine(sessionRoot, BaselinePolicyFileName),
            DumpsDirectory = Path.Combine(sessionRoot, "Dumps"),
            MemoryDirectory = Path.Combine(sessionRoot, "Memory"),
            NetworkCapturesDirectory = Path.Combine(sessionRoot, "NetworkCaptures"),
            ZeekDirectory = Path.Combine(sessionRoot, "Zeek"),
            ProcessMonitorDirectory = Path.Combine(sessionRoot, "ProcessMonitor"),
            BenchmarkDirectory = Path.Combine(sessionRoot, "Benchmarks"),
            LogsDirectory = Path.Combine(sessionRoot, "Logs"),
            AiSettingsPath = Path.Combine(sessionRoot, AiSettingsFileName),
            AiSecretPath = Path.Combine(sessionRoot, AiSecretFileName),
            NsrlSettingsPath = Path.Combine(sessionRoot, NsrlSettingsFileName),
            AgentPairingDirectory = pairingPaths.Directory,
            AgentPairingLeasePath = pairingPaths.LeasePath,
            AgentPairingSecretPath = pairingPaths.SecretPath,
            UsedFallbackRoot = usedFallbackRoot,
            PreferredParentDirectory = preferredParentDirectory,
            FallbackReason = fallbackReason
        };
    }

    private static InvestigationSessionPaths BuildPathsFromManifest(
        string sessionRoot,
        string metadataPath,
        SessionMetadata metadata,
        bool requireLiveDatabase)
    {
        var declaredSessionRoot = string.IsNullOrWhiteSpace(metadata.Paths.SessionRoot)
            ? sessionRoot
            : Path.GetFullPath(Environment.ExpandEnvironmentVariables(metadata.Paths.SessionRoot));
        var snapshotDirectory = ResolveManifestPath(
            sessionRoot,
            declaredSessionRoot,
            metadata.Paths.SnapshotDirectory,
            Path.Combine(sessionRoot, "Snapshots"),
            nameof(metadata.Paths.SnapshotDirectory));
        var resolvedLiveDatabasePath = ResolveManifestPath(
            sessionRoot,
            declaredSessionRoot,
            metadata.Paths.LiveDatabasePath,
            Path.Combine(sessionRoot, LiveDatabaseFileName),
            nameof(metadata.Paths.LiveDatabasePath));
        var resolvedSessionId = string.IsNullOrWhiteSpace(metadata.SessionId)
            ? Path.GetFileName(sessionRoot)
            : metadata.SessionId;
        var pairingPaths = ResolveAgentPairingPaths(
            resolvedSessionId,
            resolvedLiveDatabasePath,
            localAppDataDirectory: null);

        var paths = new InvestigationSessionPaths
        {
            SessionId = resolvedSessionId,
            CreatedUtc = metadata.CreatedUtc == default ? File.GetCreationTimeUtc(metadataPath) : metadata.CreatedUtc,
            SessionRoot = sessionRoot,
            LiveDatabasePath = resolvedLiveDatabasePath,
            AnnotationDatabasePath = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.AnnotationDatabasePath,
                Path.Combine(sessionRoot, AnnotationDatabaseFileName),
                nameof(metadata.Paths.AnnotationDatabasePath)),
            SnapshotDirectory = snapshotDirectory,
            SnapshotDatabasePath = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.SnapshotDatabasePath,
                Path.Combine(snapshotDirectory, SnapshotDatabaseFileName),
                nameof(metadata.Paths.SnapshotDatabasePath)),
            BaselinePolicyPath = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.BaselinePolicyPath,
                Path.Combine(sessionRoot, BaselinePolicyFileName),
                nameof(metadata.Paths.BaselinePolicyPath)),
            DumpsDirectory = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.DumpsDirectory,
                Path.Combine(sessionRoot, "Dumps"),
                nameof(metadata.Paths.DumpsDirectory)),
            MemoryDirectory = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.MemoryDirectory,
                Path.Combine(sessionRoot, "Memory"),
                nameof(metadata.Paths.MemoryDirectory)),
            NetworkCapturesDirectory = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.NetworkCapturesDirectory,
                Path.Combine(sessionRoot, "NetworkCaptures"),
                nameof(metadata.Paths.NetworkCapturesDirectory)),
            ZeekDirectory = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.ZeekDirectory,
                Path.Combine(sessionRoot, "Zeek"),
                nameof(metadata.Paths.ZeekDirectory)),
            ProcessMonitorDirectory = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.ProcessMonitorDirectory,
                Path.Combine(sessionRoot, "ProcessMonitor"),
                nameof(metadata.Paths.ProcessMonitorDirectory)),
            BenchmarkDirectory = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.BenchmarkDirectory,
                Path.Combine(sessionRoot, "Benchmarks"),
                nameof(metadata.Paths.BenchmarkDirectory)),
            LogsDirectory = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.LogsDirectory,
                Path.Combine(sessionRoot, "Logs"),
                nameof(metadata.Paths.LogsDirectory)),
            AiSettingsPath = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.AiSettingsPath,
                Path.Combine(sessionRoot, AiSettingsFileName),
                nameof(metadata.Paths.AiSettingsPath)),
            AiSecretPath = ResolveManifestPath(
                sessionRoot,
                declaredSessionRoot,
                metadata.Paths.AiSecretPath,
                Path.Combine(sessionRoot, AiSecretFileName),
                nameof(metadata.Paths.AiSecretPath)),
            NsrlSettingsPath = Path.Combine(sessionRoot, NsrlSettingsFileName),
            AgentPairingDirectory = pairingPaths.Directory,
            AgentPairingLeasePath = pairingPaths.LeasePath,
            AgentPairingSecretPath = pairingPaths.SecretPath,
            UsedFallbackRoot = metadata.UsedFallbackRoot,
            PreferredParentDirectory = Path.GetDirectoryName(sessionRoot) ?? AppContext.BaseDirectory,
            FallbackReason = metadata.FallbackReason
        };

        if (requireLiveDatabase && !File.Exists(paths.LiveDatabasePath))
        {
            throw new FileNotFoundException(
                "The selected capture manifest does not resolve to an existing procinsider-live.sqlite3 database.",
                paths.LiveDatabasePath);
        }

        return paths;
    }

    public static string NormalizeLiveDatabaseIdentity(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        return Path.GetFullPath(Environment.ExpandEnvironmentVariables(databasePath));
    }

    private static AgentPairingPaths ResolveAgentPairingPaths(
        string sessionId,
        string liveDatabasePath,
        string? localAppDataDirectory,
        string? pairingRootDirectory = null)
    {
        var normalizedSessionId = sessionId?.Trim() ?? string.Empty;
        var normalizedDatabase = NormalizeLiveDatabaseIdentity(liveDatabasePath);
        var identityBytes = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{normalizedSessionId.Length}:{normalizedSessionId}{normalizedDatabase.Length}:{normalizedDatabase.ToUpperInvariant()}"));
        var identity = Convert.ToHexString(identityBytes.AsSpan(0, 16)).ToLowerInvariant();
        var root = string.IsNullOrWhiteSpace(pairingRootDirectory)
            ? GetAgentPairingRootDirectory(localAppDataDirectory)
            : Path.GetFullPath(pairingRootDirectory);
        var directory = Path.Combine(root, identity);
        return new AgentPairingPaths(
            directory,
            Path.Combine(directory, AgentPairingLeaseFileName),
            Path.Combine(directory, AgentPairingSecretFileName));
    }

    public static string GetEvidenceMigrationRecoveryDirectory(InvestigationSessionPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (string.IsNullOrWhiteSpace(paths.SessionRoot))
        {
            throw new ArgumentException("The session root is required.", nameof(paths));
        }

        return Path.Combine(Path.GetFullPath(paths.SessionRoot), EvidenceMigrationRecoveryDirectoryName);
    }

    public static string AllocateEvidenceMigrationRecoveryPath(InvestigationSessionPaths paths)
    {
        var directory = GetEvidenceMigrationRecoveryDirectory(paths);
        var fileName = $"procinsider-live.pre-migration-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}-{Guid.NewGuid():N}.sqlite3";
        return Path.Combine(directory, fileName);
    }

    public static string GetLiveDatabaseOwnershipLockPath(InvestigationSessionPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (string.IsNullOrWhiteSpace(paths.LogsDirectory))
        {
            throw new ArgumentException("The session logs directory is required.", nameof(paths));
        }

        return Path.Combine(Path.GetFullPath(paths.LogsDirectory), LiveDatabaseOwnershipLockFileName);
    }

    private static void EnsureCoreDirectories(InvestigationSessionPaths paths)
    {
        Directory.CreateDirectory(paths.SessionRoot);
        Directory.CreateDirectory(paths.SnapshotDirectory);
        Directory.CreateDirectory(paths.LogsDirectory);
    }

    private static void PersistMetadata(InvestigationSessionPaths paths)
    {
        var metadataPath = Path.Combine(paths.SessionRoot, CapturePackageManifestFileName);
        if (File.Exists(metadataPath))
        {
            return;
        }

        var metadata = new SessionMetadata
        {
            SchemaVersion = SessionSchemaVersion,
            EvidenceFormatVersion = CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion,
            SessionId = paths.SessionId,
            AppVersion = GetAppVersion(),
            CreatedUtc = paths.CreatedUtc,
            MachineName = Environment.MachineName,
            CaseId = null,
            HostId = null,
            FutureMetadata = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [ProductDisplayNameMetadataKey] = ProductIdentity.DisplayName
            },
            Paths = new SessionMetadataPaths
            {
                SessionRoot = paths.SessionRoot,
                LiveDatabasePath = paths.LiveDatabasePath,
                AnnotationDatabasePath = paths.AnnotationDatabasePath,
                SnapshotDirectory = paths.SnapshotDirectory,
                SnapshotDatabasePath = paths.SnapshotDatabasePath,
                BaselinePolicyPath = paths.BaselinePolicyPath,
                DumpsDirectory = paths.DumpsDirectory,
                MemoryDirectory = paths.MemoryDirectory,
                NetworkCapturesDirectory = paths.NetworkCapturesDirectory,
                ZeekDirectory = paths.ZeekDirectory,
                ProcessMonitorDirectory = paths.ProcessMonitorDirectory,
                BenchmarkDirectory = paths.BenchmarkDirectory,
                LogsDirectory = paths.LogsDirectory,
                AiSettingsPath = paths.AiSettingsPath,
                AiSecretPath = paths.AiSecretPath
            },
            UsedFallbackRoot = paths.UsedFallbackRoot,
            PreferredParentDirectory = paths.PreferredParentDirectory,
            FallbackReason = paths.FallbackReason
        };
        File.WriteAllText(metadataPath, JsonSerializer.Serialize(metadata, MetadataJsonOptions));
    }

    private static string AllocateUniqueSessionRoot(string parentDirectory, string requestedSessionId)
    {
        var basePath = Path.Combine(parentDirectory, requestedSessionId);
        if (!Directory.Exists(basePath))
        {
            return basePath;
        }

        for (var index = 1; index <= 999; index++)
        {
            var candidate = Path.Combine(parentDirectory, $"{requestedSessionId}-{index:000}");
            if (!Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException($"Unable to allocate a unique DFIRoscope session folder under {parentDirectory}.");
    }

    private static string GetLocalAppDataSessionsDirectory(string? localAppDataDirectory = null)
    {
        var root = Path.Combine(ResolveLocalAppDataDirectory(localAppDataDirectory), LocalDataRootFolderName);
        return Path.Combine(root, "Sessions");
    }

    private static string ResolveLocalAppDataDirectory(string? localAppDataDirectory = null)
    {
        if (!string.IsNullOrWhiteSpace(localAppDataDirectory))
        {
            return Path.GetFullPath(localAppDataDirectory);
        }

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrWhiteSpace(localAppData)
            ? Path.GetFullPath(Path.GetTempPath())
            : Path.GetFullPath(localAppData);
    }

    private static IDisposable? AcquireLegacySessionDirectoryLease(string sourceDirectory)
    {
        if (!string.Equals(Path.GetFileName(Path.GetDirectoryName(sourceDirectory)), "Sessions", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(Path.Combine(sourceDirectory, CapturePackageManifestFileName)))
        {
            return null;
        }

        var writerLockPath = Path.Combine(sourceDirectory, "Logs", LiveDatabaseOwnershipLockFileName);
        return File.Exists(writerLockPath)
            ? new FileStream(writerLockPath, FileMode.Open, FileAccess.Read, FileShare.Read)
            : null;
    }

    private static string GetAppVersion()
    {
        var assembly = typeof(SessionPathService).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            return informational;
        }

        return FileVersionInfo.GetVersionInfo(assembly.Location).ProductVersion ??
               assembly.GetName().Version?.ToString() ??
               "unknown";
    }

    private static bool IsPathSetupFailure(Exception ex)
    {
        return ex is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException;
    }

    private static string SanitizePathPart(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            if (invalid.Contains(chars[i]))
            {
                chars[i] = '_';
            }
        }

        return new string(chars).Trim();
    }

    private static CaptureManifestLocation NormalizeCapturePackageManifest(
        string captureManifestPath,
        bool allowFolderCompatibility)
    {
        var fullPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(captureManifestPath));
        if (Directory.Exists(fullPath))
        {
            if (!allowFolderCompatibility)
            {
                throw new InvalidDataException("Open Capture expects the capture's session.json manifest file.");
            }

            var compatibilityManifestPath = Path.Combine(fullPath, CapturePackageManifestFileName);
            if (!File.Exists(compatibilityManifestPath))
            {
                throw new FileNotFoundException(
                    $"The selected folder is missing session.json. Select the canonical {ProductIdentity.DisplayName} capture manifest.",
                    compatibilityManifestPath);
            }

            return new CaptureManifestLocation(fullPath, compatibilityManifestPath);
        }

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(
                $"The selected {ProductIdentity.DisplayName} capture manifest does not exist. Select the capture's session.json file.",
                fullPath);
        }

        if (!string.Equals(Path.GetFileName(fullPath), CapturePackageManifestFileName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "Open Capture expects the canonical session.json manifest. Raw SQLite files, legacy .pistage archives, and other JSON files are not supported.");
        }

        var sessionRoot = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("The selected session.json manifest does not have a containing capture folder.");
        return new CaptureManifestLocation(sessionRoot, fullPath);
    }

    private static SessionMetadata ReadSessionMetadata(string metadataPath)
    {
        try
        {
            return JsonSerializer.Deserialize<SessionMetadata>(
                File.ReadAllText(metadataPath),
                MetadataJsonOptions) ?? throw new InvalidDataException("session.json is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"session.json could not be parsed: {ex.Message}", ex);
        }
    }

    private static void ValidateSessionMetadata(SessionMetadata metadata)
    {
        if ((object?)metadata.Paths is null)
        {
            throw new InvalidDataException("session.json is missing its Paths object.");
        }
    }

    private static CaptureProductDisplayIdentity ResolveProductDisplayIdentity(
        IReadOnlyDictionary<string, string>? futureMetadata)
    {
        if (futureMetadata != null)
        {
            foreach (var pair in futureMetadata)
            {
                if (string.Equals(pair.Key, ProductDisplayNameMetadataKey, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(pair.Value))
                {
                    return new CaptureProductDisplayIdentity(pair.Value.Trim(), IsDeclared: true);
                }
            }
        }

        // Manifests created before the DFIRoscope Live transition did not declare a
        // display identity. Treat that absence as the former product label without
        // making branding part of schema or evidence compatibility.
        return new CaptureProductDisplayIdentity(ProductIdentity.FormerName, IsDeclared: false);
    }

    private static string ResolveManifestPath(
        string sessionRoot,
        string declaredSessionRoot,
        string? metadataPath,
        string defaultPath,
        string pathName)
    {
        var candidate = string.IsNullOrWhiteSpace(metadataPath)
            ? Path.GetFullPath(defaultPath)
            : ResolveManifestCandidate(sessionRoot, declaredSessionRoot, metadataPath);
        if (!IsPathWithinRoot(sessionRoot, candidate))
        {
            throw new InvalidDataException(
                $"session.json path '{pathName}' resolves outside the capture folder: {candidate}");
        }

        return candidate;
    }

    private static CapturePackageFolderInfo BuildFolderInfo(
        string name,
        string path)
    {
        return new CapturePackageFolderInfo
        {
            Name = name,
            Path = path,
            Exists = Directory.Exists(path)
        };
    }

    private static string ResolveManifestCandidate(
        string sessionRoot,
        string declaredSessionRoot,
        string metadataPath)
    {
        var expanded = Environment.ExpandEnvironmentVariables(metadataPath);
        if (!Path.IsPathRooted(expanded))
        {
            return Path.GetFullPath(Path.Combine(sessionRoot, expanded));
        }

        var absolute = Path.GetFullPath(expanded);
        if (IsPathWithinRoot(sessionRoot, absolute))
        {
            return absolute;
        }

        if (IsPathWithinRoot(declaredSessionRoot, absolute))
        {
            var relative = Path.GetRelativePath(declaredSessionRoot, absolute);
            return Path.GetFullPath(Path.Combine(sessionRoot, relative));
        }

        return absolute;
    }

    private static bool IsPathWithinRoot(string rootPath, string candidatePath)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(rootPath), Path.GetFullPath(candidatePath));
        return !Path.IsPathRooted(relative) &&
               !string.Equals(relative, "..", StringComparison.Ordinal) &&
               !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
               !relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal);
    }

    private sealed record CaptureManifestLocation(string SessionRoot, string ManifestPath);

    private sealed record AgentPairingPaths(string Directory, string LeasePath, string SecretPath);

    private sealed record CaptureProductDisplayIdentity(string DisplayName, bool IsDeclared);

    private sealed class SessionMetadata
    {
        public int SchemaVersion { get; init; }
        public int? EvidenceFormatVersion { get; init; }
        public string SessionId { get; init; } = string.Empty;
        public string AppVersion { get; init; } = string.Empty;
        public DateTime CreatedUtc { get; init; }
        public string MachineName { get; init; } = string.Empty;
        public string? CaseId { get; init; }
        public string? HostId { get; init; }
        public Dictionary<string, string> FutureMetadata { get; init; } = new();
        public SessionMetadataPaths Paths { get; init; } = new();
        public bool UsedFallbackRoot { get; init; }
        public string PreferredParentDirectory { get; init; } = string.Empty;
        public string FallbackReason { get; init; } = string.Empty;
    }

    private sealed class SessionMetadataPaths
    {
        public string SessionRoot { get; init; } = string.Empty;
        public string LiveDatabasePath { get; init; } = string.Empty;
        public string AnnotationDatabasePath { get; init; } = string.Empty;
        public string SnapshotDirectory { get; init; } = string.Empty;
        public string SnapshotDatabasePath { get; init; } = string.Empty;
        public string BaselinePolicyPath { get; init; } = string.Empty;
        public string DumpsDirectory { get; init; } = string.Empty;
        public string MemoryDirectory { get; init; } = string.Empty;
        public string NetworkCapturesDirectory { get; init; } = string.Empty;
        public string ZeekDirectory { get; init; } = string.Empty;
        public string ProcessMonitorDirectory { get; init; } = string.Empty;
        public string BenchmarkDirectory { get; init; } = string.Empty;
        public string LogsDirectory { get; init; } = string.Empty;
        public string AiSettingsPath { get; init; } = string.Empty;
        public string AiSecretPath { get; init; } = string.Empty;
    }
}
