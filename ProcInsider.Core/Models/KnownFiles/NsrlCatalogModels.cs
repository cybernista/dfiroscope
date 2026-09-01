namespace ProcInsider.Models.KnownFiles;

public enum NsrlDigestAlgorithm
{
    Sha1 = 0,
    Sha256 = 1,
    SqliteDbHashSha1 = 2
}

public sealed record NsrlExpectedDigest(
    NsrlDigestAlgorithm Algorithm,
    string Value);

public sealed class NsrlReleaseDescriptor
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string ReleaseId { get; init; } = string.Empty;

    public DateTime ReleaseDateUtc { get; init; }

    public string DataSet { get; init; } = "Modern";

    public string Profile { get; init; } = "Minimal";

    public string PublicationKind { get; init; } = "FullSql";

    public Uri ReleasePageUri { get; init; } = new("https://www.nist.gov/");

    public Uri ReadmeUri { get; init; } = new("https://www.nist.gov/");

    public Uri VersionDocumentUri { get; init; } = new("https://www.nist.gov/");

    public Uri DatabaseHashDocumentUri { get; init; } = new("https://www.nist.gov/");

    public Uri ArchiveUri { get; init; } = new("https://www.nist.gov/");

    public Uri ArchiveHashUri { get; init; } = new("https://www.nist.gov/");

    public string ArchiveFileName { get; init; } = string.Empty;

    public string DatabaseFileName { get; init; } = string.Empty;

    public long? ArchiveSizeBytes { get; init; }

    public long EstimatedExtractedSizeBytes { get; init; }

    public string ExtractedSizeEstimateSource { get; init; } = string.Empty;

    public NsrlExpectedDigest? ExpectedArchiveDigest { get; init; }

    public NsrlExpectedDigest? ExpectedDatabaseDigest { get; init; }
}

public enum NsrlCatalogAcquisitionPhase
{
    Preflight = 0,
    Download = 1,
    ArchiveVerification = 2,
    Extraction = 3,
    DatabaseIntegrity = 4,
    DatabaseSchema = 5,
    DatabaseVerification = 6,
    Manifest = 7,
    Activation = 8,
    Completed = 9
}

public sealed record NsrlCatalogAcquisitionProgress(
    NsrlCatalogAcquisitionPhase Phase,
    string Detail,
    long BytesCompleted = 0,
    long? BytesTotal = null);

public sealed record NsrlCatalogAcquisitionRequest(
    NsrlReleaseDescriptor Release,
    bool AllowResume = true);

public sealed record NsrlCatalogPreflight(
    string DestinationRoot,
    string ReleaseId,
    string DataSet,
    string Profile,
    Uri SourceUri,
    long? ArchiveSizeBytes,
    long EstimatedExtractedSizeBytes,
    long RequiredFreeSpaceBytes,
    long AvailableFreeSpaceBytes,
    bool HasEnoughFreeSpace);

public enum NsrlCatalogAcquisitionOutcome
{
    Succeeded = 0,
    Canceled = 1,
    InvalidRequest = 2,
    UnsafeSource = 3,
    ReleaseDiscoveryFailed = 4,
    MissingExpectedHash = 5,
    AmbiguousExpectedHash = 6,
    InsufficientDiskSpace = 7,
    DownloadFailed = 8,
    ArchiveHashMismatch = 9,
    ArchiveInvalid = 10,
    ArchiveUnsafe = 11,
    ArchiveLimitExceeded = 12,
    DatabaseHashMismatch = 13,
    DatabaseIntegrityFailure = 14,
    DatabaseSchemaUnsupported = 15,
    ManifestInvalid = 16,
    PromotionFailed = 17,
    RollbackFailed = 18
}

public sealed class NsrlCatalogValidationSummary
{
    public bool ArchiveHashMatched { get; init; }

    public bool DatabaseHashMatched { get; init; }

    public bool IntegrityCheckPassed { get; init; }

    public bool SupportedSchema { get; init; }

    public bool ReleaseIdentityMatched { get; init; }

    public string DatabaseVersion { get; init; } = string.Empty;

    public string BuildSet { get; init; } = string.Empty;
}

public sealed class NsrlCatalogGenerationManifest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string GenerationId { get; init; } = string.Empty;

    public string ReleaseId { get; init; } = string.Empty;

    public DateTime ReleaseDateUtc { get; init; }

    public string DataSet { get; init; } = string.Empty;

    public string Profile { get; init; } = string.Empty;

    public string PublicationKind { get; init; } = string.Empty;

    public string DatabaseRelativePath { get; init; } = string.Empty;

    public long ArchiveSizeBytes { get; init; }

    public long DatabaseSizeBytes { get; init; }

    public NsrlExpectedDigest ExpectedArchiveDigest { get; init; } = new(NsrlDigestAlgorithm.Sha1, string.Empty);

    public NsrlExpectedDigest ActualArchiveDigest { get; init; } = new(NsrlDigestAlgorithm.Sha1, string.Empty);

    public NsrlExpectedDigest ExpectedDatabaseDigest { get; init; } = new(NsrlDigestAlgorithm.SqliteDbHashSha1, string.Empty);

    public NsrlExpectedDigest ActualDatabaseDigest { get; init; } = new(NsrlDigestAlgorithm.SqliteDbHashSha1, string.Empty);

    public IReadOnlyList<string> SourceUris { get; init; } = [];

    public DateTime RetrievedUtc { get; init; }

    public string AcquisitionToolVersion { get; init; } = string.Empty;

    public NsrlCatalogValidationSummary Validation { get; init; } = new();
}

public sealed record NsrlCatalogGeneration(
    string GenerationId,
    string GenerationRoot,
    string DatabasePath,
    string ManifestPath,
    string ManifestSha256,
    NsrlCatalogGenerationManifest Manifest);

public sealed record NsrlCatalogAcquisitionResult(
    NsrlCatalogAcquisitionOutcome Outcome,
    string Detail,
    NsrlCatalogGeneration? Generation = null,
    NsrlCatalogPreflight? Preflight = null)
{
    public bool Succeeded => Outcome == NsrlCatalogAcquisitionOutcome.Succeeded;
}

public interface INsrlReleaseDiscoveryService
{
    Task<NsrlReleaseDescriptor> DiscoverLatestModernMinimalFullAsync(
        CancellationToken cancellationToken = default);
}

public interface INsrlCatalogAcquisitionService
{
    NsrlCatalogPreflight GetPreflight(NsrlCatalogAcquisitionRequest request);

    Task<NsrlCatalogAcquisitionResult> AcquireAsync(
        NsrlCatalogAcquisitionRequest request,
        IProgress<NsrlCatalogAcquisitionProgress>? progress = null,
        CancellationToken cancellationToken = default);

    Task<NsrlCatalogGeneration?> GetActiveGenerationAsync(
        CancellationToken cancellationToken = default);

    Task<NsrlCatalogAcquisitionResult> RollbackAsync(
        string expectedActiveGenerationId,
        CancellationToken cancellationToken = default);
}
