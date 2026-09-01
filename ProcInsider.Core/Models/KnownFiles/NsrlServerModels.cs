namespace ProcInsider.Models.KnownFiles;

public static class NsrlServerProtocol
{
    public const int SchemaVersion = 3;
    public const string CompatibilityVersion = "dfiroscope-nsrl/3";
    public const string ProviderVersion = "DFIRoscope.ManagedNsrl/1";
    public const string DerivedTransformVersion = "nsrl-rdsv3-sha256-index/1";
    public const string DefaultControlPipeName = "DFIRoscope.Nsrl.Control.v1";
    public const string DefaultEndpoint = "http://127.0.0.1:5000/";
}

public enum NsrlLookupItemStatus
{
    Match = 0,
    NoMatch = 1,
    Invalid = 2,
    Unavailable = 3,
    Error = 4
}

public sealed class NsrlLookupRecord
{
    public string Sha256 { get; init; } = string.Empty;

    public string FileName { get; init; } = string.Empty;

    public long? FileSizeBytes { get; init; }

    public long PackageId { get; init; }

    public string ProductName { get; init; } = string.Empty;

    public string ProductVersion { get; init; } = string.Empty;

    public string Manufacturer { get; init; } = string.Empty;

    public string OperatingSystemName { get; init; } = string.Empty;

    public string OperatingSystemVersion { get; init; } = string.Empty;

    public string Language { get; init; } = string.Empty;

    public string ApplicationType { get; init; } = string.Empty;

    public string ProviderSource { get; init; } = string.Empty;
}

public sealed class NsrlLookupItemResult
{
    public int Ordinal { get; init; }

    public string Sha256 { get; init; } = string.Empty;

    public NsrlLookupItemStatus Status { get; init; }

    public string Detail { get; init; } = string.Empty;

    public int TotalRecordCount { get; init; }

    public bool IsTruncated { get; init; }

    public IReadOnlyList<NsrlLookupRecord> Records { get; init; } = [];
}

public sealed class NsrlBatchLookupRequest
{
    public int SchemaVersion { get; init; } = NsrlServerProtocol.SchemaVersion;

    public IReadOnlyList<string> Hashes { get; init; } = [];
}

public sealed class NsrlBatchLookupResponse
{
    public int SchemaVersion { get; init; } = NsrlServerProtocol.SchemaVersion;

    public string CompatibilityVersion { get; init; } = NsrlServerProtocol.CompatibilityVersion;

    public string ProviderVersion { get; init; } = NsrlServerProtocol.ProviderVersion;

    public string CatalogVersion { get; init; } = string.Empty;

    public string GenerationId { get; init; } = string.Empty;

    public int DatabaseCommandCount { get; init; }

    public DateTime LookupUtc { get; init; }

    public TimeSpan Elapsed { get; init; }

    public IReadOnlyList<NsrlLookupItemResult> Results { get; init; } = [];
}

public sealed class NsrlDerivedIndexManifest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public bool Completed { get; init; }

    public string DerivedGenerationId { get; init; } = string.Empty;

    public string SourceGenerationId { get; init; } = string.Empty;

    public string SourceReleaseId { get; init; } = string.Empty;

    public string SourceDataSet { get; init; } = string.Empty;

    public string SourceProfile { get; init; } = string.Empty;

    public string SourceDatabaseSha256 { get; init; } = string.Empty;

    public string SourceDatabaseLogicalDigest { get; init; } = string.Empty;

    public string TransformVersion { get; init; } = NsrlServerProtocol.DerivedTransformVersion;

    public string DatabaseRelativePath { get; init; } = string.Empty;

    public string DerivedDatabaseSha256 { get; init; } = string.Empty;

    public int DerivedSchemaVersion { get; init; } = 1;

    public long RecordCount { get; init; }

    public long DistinctHashCount { get; init; }

    public DateTime BuiltUtc { get; init; }
}

public sealed record NsrlDerivedLookupGeneration(
    string DerivedGenerationId,
    string SourceGenerationId,
    string Root,
    string DatabasePath,
    string ManifestPath,
    string ManifestSha256,
    NsrlDerivedIndexManifest Manifest);

public static class NsrlAcceptedArtifactRoles
{
    public const string ActivePointer = "active-pointer";
    public const string OfficialManifest = "official-manifest";
    public const string OfficialDatabase = "official-database";
    public const string DerivedManifest = "derived-manifest";
    public const string DerivedDatabase = "derived-database";

    public static IReadOnlyList<string> Required { get; } =
    [
        ActivePointer,
        OfficialManifest,
        OfficialDatabase,
        DerivedManifest,
        DerivedDatabase
    ];
}

public sealed record NsrlAcceptedArtifactIdentity
{
    public string Role { get; init; } = string.Empty;

    public string CatalogRelativePath { get; init; } = string.Empty;

    public long Length { get; init; }

    public long LastWriteUtcTicks { get; init; }

    public FileAttributes Attributes { get; init; }

    public string FileId { get; init; } = string.Empty;

    public string SmallFileSha256 { get; init; } = string.Empty;
}

public sealed record NsrlAcceptedGenerationReceipt
{
    public const int CurrentSchemaVersion = 1;
    public const string CurrentPolicyVersion = "nsrl-fast-start/1";

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string PolicyVersion { get; init; } = CurrentPolicyVersion;

    public string ReceiptId { get; init; } = string.Empty;

    public DateTime AcceptedUtc { get; init; }

    public string AcceptanceSource { get; init; } = string.Empty;

    public string SourceReportSha256 { get; init; } = string.Empty;

    public string SourceGenerationId { get; init; } = string.Empty;

    public string SourceReleaseId { get; init; } = string.Empty;

    public string SourceDataSet { get; init; } = string.Empty;

    public string SourceProfile { get; init; } = string.Empty;

    public string SourceManifestSha256 { get; init; } = string.Empty;

    public string SourceDatabaseSha256 { get; init; } = string.Empty;

    public string SourceDatabaseLogicalDigest { get; init; } = string.Empty;

    public string DerivedGenerationId { get; init; } = string.Empty;

    public string DerivedManifestSha256 { get; init; } = string.Empty;

    public string DerivedDatabaseSha256 { get; init; } = string.Empty;

    public string TransformVersion { get; init; } = string.Empty;

    public int DerivedSchemaVersion { get; init; }

    public long RecordCount { get; init; }

    public long DistinctHashCount { get; init; }

    public DateTime ValidationCompletedUtc { get; init; }

    public bool IntegrityPassed { get; init; }

    public bool QueryPlansPassed { get; init; }

    public bool DirectStoreCorrectnessPassed { get; init; }

    public bool NonmutationPassed { get; init; }

    public IReadOnlyList<NsrlAcceptedArtifactIdentity> Artifacts { get; init; } = [];

    public string ReceiptSha256 { get; init; } = string.Empty;
}

public sealed record NsrlAcceptedLookupGeneration(
    NsrlCatalogGeneration SourceGeneration,
    NsrlDerivedLookupGeneration DerivedGeneration,
    NsrlAcceptedGenerationReceipt Receipt,
    TimeSpan AdmissionElapsed);

public interface INsrlAcceptedGenerationLoader
{
    Task<NsrlAcceptedLookupGeneration> LoadAsync(CancellationToken cancellationToken = default);
}

public enum NsrlServerReadiness
{
    Starting = 0,
    Ready = 1,
    Unavailable = 2,
    Reloading = 3,
    Faulted = 4,
    Stopping = 5
}

public sealed class NsrlServerInfo
{
    public int SchemaVersion { get; init; } = NsrlServerProtocol.SchemaVersion;

    public string CompatibilityVersion { get; init; } = NsrlServerProtocol.CompatibilityVersion;

    public string ProviderVersion { get; init; } = NsrlServerProtocol.ProviderVersion;

    public string ServerReleaseId { get; init; } = string.Empty;

    public int ProcessId { get; init; }

    public DateTime ProcessStartUtc { get; init; }

    public string ControlGeneration { get; init; } = string.Empty;

    public NsrlServerReadiness Readiness { get; init; }

    public string Detail { get; init; } = string.Empty;

    public string ActiveGenerationId { get; init; } = string.Empty;

    public string CatalogVersion { get; init; } = string.Empty;

    public string DataSet { get; init; } = string.Empty;

    public string Profile { get; init; } = string.Empty;

    public string DerivedGenerationId { get; init; } = string.Empty;

    public string DerivedTransformVersion { get; init; } = string.Empty;

    public string DerivedDatabaseSha256 { get; init; } = string.Empty;

    public long RecordCount { get; init; }

    public long DistinctHashCount { get; init; }

    public DateTime? DerivedBuiltUtc { get; init; }

    public string AcceptedGenerationReceiptId { get; init; } = string.Empty;

    public string StartupValidationMode { get; init; } = string.Empty;

    public double StartupAdmissionElapsedMilliseconds { get; init; }

    public long OfficialDatabaseBytes { get; init; }

    public long DerivedDatabaseBytes { get; init; }

    public long TotalStorageBytes { get; init; }

    public DateTime? LastSuccessfulValidationUtc { get; init; }

    public DateTime ObservedUtc { get; init; }
}

public enum NsrlControlCommand
{
    Status = 0,
    ReloadActiveGeneration = 1,
    AcquireLatestModernMinimalFull = 2,
    Shutdown = 3,
    Challenge = 4,
    BeginCheckLatestModernMinimalFull = 5,
    BeginAcquireLatestModernMinimalFull = 6,
    CancelOperation = 7,
    BeginRollback = 8
}

public enum NsrlManagementOperationKind
{
    None = 0,
    CheckRelease = 1,
    AcquireOrUpdate = 2,
    Rollback = 3
}

public enum NsrlManagementOperationState
{
    None = 0,
    Running = 1,
    Succeeded = 2,
    Failed = 3,
    Canceled = 4
}

public sealed record NsrlManagementOperationSnapshot(
    string OperationId,
    NsrlManagementOperationKind Kind,
    NsrlManagementOperationState State,
    string Phase,
    string Detail,
    long BytesCompleted,
    long? BytesTotal,
    DateTime StartedUtc,
    DateTime? CompletedUtc = null,
    NsrlReleaseDescriptor? Release = null,
    NsrlCatalogPreflight? Preflight = null,
    NsrlCatalogAcquisitionResult? Acquisition = null);

public sealed class NsrlControlRequest
{
    public int SchemaVersion { get; init; } = NsrlServerProtocol.SchemaVersion;

    public string RequestId { get; init; } = string.Empty;

    public string ControlGeneration { get; init; } = string.Empty;

    public string ChallengeProof { get; init; } = string.Empty;

    public NsrlControlCommand Command { get; init; }

    public string ExpectedActiveGenerationId { get; init; } = string.Empty;

    public string ExpectedOperationId { get; init; } = string.Empty;

    public string ExpectedReleaseId { get; init; } = string.Empty;
}

public sealed class NsrlControlResponse
{
    public int SchemaVersion { get; init; } = NsrlServerProtocol.SchemaVersion;

    public string RequestId { get; init; } = string.Empty;

    public bool Succeeded { get; init; }

    public string Detail { get; init; } = string.Empty;

    public string Challenge { get; init; } = string.Empty;

    public NsrlServerInfo? Server { get; init; }

    public NsrlCatalogAcquisitionResult? Acquisition { get; init; }

    public NsrlManagementOperationSnapshot? Operation { get; init; }
}
