// Core-owned capture compatibility and migration policy contracts shared by viewer and agent.
namespace ProcInsider.Models;

public enum CaptureOpenContext
{
    AgentWritableLive,
    ViewerLiveSnapshot,
    ViewerArchivedReadOnly,
    ArchivedAnalysisMaintenance,
    InspectionOnly,
    ViewerLiveSourceReadOnly
}

[Flags]
public enum CaptureOpenCapability
{
    None = 0,
    InspectMetadata = 1 << 0,
    ReadEvidence = 1 << 1,
    WritePrimaryEvidence = 1 << 2,
    MigratePrimaryEvidence = 1 << 3,
    MaintainAnalysisState = 1 << 4
}

public enum CaptureArtifactKind
{
    Unknown,
    LiveAuthoritativeDatabase,
    ViewerSnapshotCopy,
    ArchivedSealedPackage
}

public enum CaptureCompatibilityState
{
    CompatibleCurrent,
    SupportedLegacy,
    MigrationRequired,
    IncompleteMigration,
    MissingVersionMetadata,
    CorruptVersionMetadata,
    UnsupportedOlderManifestVersion,
    UnsupportedOlderEvidenceFormatVersion,
    NewerManifestVersion,
    NewerEvidenceFormatVersion,
    UnknownMigrationHistory,
    MigrationDefinitionMismatch,
    ManifestEvidenceVersionMismatch,
    SessionIdentityMismatch,
    InvalidContainedPath,
    MissingRequiredEvidenceSchema
}

public enum CaptureAnalysisState
{
    NotAssessed,
    Current,
    RebuildRequired
}

public enum CaptureMigrationKind
{
    PrimaryEvidence,
    RebuildableAnalysisState
}

public sealed record CaptureMigrationDefinition(
    int Sequence,
    string MigrationId,
    int SourceEvidenceFormatVersion,
    int TargetEvidenceFormatVersion,
    CaptureMigrationKind Kind,
    string Description,
    string DefinitionHash,
    IReadOnlyList<string> PrerequisiteMigrationIds,
    bool RequiresExclusiveLiveDatabaseOwnership)
{
    public int EvidenceFormatVersion => TargetEvidenceFormatVersion;
}

public sealed record AppliedCaptureMigration(
    string MigrationId,
    string Description,
    string DefinitionHash = "",
    int? Sequence = null,
    DateTime? AppliedUtc = null,
    long LedgerOrdinal = 0,
    string AppliedByRelease = "");

public enum EvidenceMigrationPlanState
{
    Current,
    Ready,
    Blocked
}

public enum EvidenceMigrationResultState
{
    NotRequired,
    Completed,
    RolledBack,
    Cancelled,
    Blocked
}

public sealed record EvidenceMigrationPlan
{
    public EvidenceMigrationPlanState State { get; init; }

    public string StatusCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public int? CurrentEvidenceFormatVersion { get; init; }

    public int TargetEvidenceFormatVersion { get; init; }

    public bool IsFreshDatabase { get; init; }

    public bool RecoveryCopyRequired { get; init; }

    public bool MigrationLedgerUpgradeRequired { get; init; }

    public IReadOnlyList<CaptureMigrationDefinition> PendingSteps { get; init; } =
        Array.Empty<CaptureMigrationDefinition>();

    public IReadOnlyList<CaptureMigrationDefinition> PendingAnalysisSteps { get; init; } =
        Array.Empty<CaptureMigrationDefinition>();

    public bool CanExecute => State is EvidenceMigrationPlanState.Current or EvidenceMigrationPlanState.Ready;
}

public sealed record EvidenceMigrationResult
{
    public EvidenceMigrationResultState State { get; init; }

    public string StatusCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string LastAppliedMigrationId { get; init; } = string.Empty;

    public IReadOnlyList<string> AppliedMigrationIds { get; init; } = Array.Empty<string>();

    public string RecoveryCopyPath { get; init; } = string.Empty;

    public EvidenceMigrationPlan Plan { get; init; } = new();
}

public sealed record CaptureManifestCompatibilityMetadata(
    int? SchemaVersion,
    string SessionId,
    int? DeclaredEvidenceFormatVersion = null);

public sealed record CaptureEvidenceCompatibilityMetadata(
    int? FormatVersion,
    string EvidenceSessionId,
    bool HasRequiredSchema,
    IReadOnlyList<AppliedCaptureMigration> AppliedMigrations);

public sealed record CaptureCompatibilityInput
{
    public CaptureOpenContext Context { get; init; }

    public CaptureArtifactKind ArtifactKind { get; init; }

    public CaptureManifestCompatibilityMetadata? Manifest { get; init; }

    public CaptureEvidenceCompatibilityMetadata? Evidence { get; init; }

    public string ExpectedEvidenceSessionId { get; init; } = string.Empty;

    public bool PathsAreContained { get; init; } = true;

    public string InspectionFailure { get; init; } = string.Empty;
}

public sealed record CaptureCompatibilityAssessment
{
    public CaptureCompatibilityState State { get; init; }

    public CaptureAnalysisState AnalysisState { get; init; }

    public CaptureOpenContext Context { get; init; }

    public CaptureArtifactKind ArtifactKind { get; init; }

    public int? ManifestSchemaVersion { get; init; }

    public int? EvidenceFormatVersion { get; init; }

    public int MinimumSupportedManifestSchemaVersion { get; init; }

    public int MaximumSupportedManifestSchemaVersion { get; init; }

    public int MinimumSupportedEvidenceFormatVersion { get; init; }

    public int MaximumSupportedEvidenceFormatVersion { get; init; }

    public CaptureOpenCapability Capabilities { get; init; }

    public string StatusCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public IReadOnlyList<string> MissingPrimaryMigrations { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> MissingAnalysisMigrations { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> UnknownMigrations { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DefinitionMismatches { get; init; } = Array.Empty<string>();

    public string SafeNextAction { get; init; } = string.Empty;

    public bool Allows(CaptureOpenCapability capability)
        => (Capabilities & capability) == capability;
}
