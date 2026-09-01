namespace ProcInsider.Models.KnownFiles;

public enum KnownFileLookupProviderMode
{
    ExternalCompatible = 0,
    ManagedLocal = 1
}

public enum KnownFileLookupOutcome
{
    Match = 0,
    NoMatch = 1,
    Unavailable = 2,
    Error = 3,
    Canceled = 4
}

public sealed class KnownFileLookupSettings
{
    public const int CurrentSchemaVersion = 3;
    public const int DefaultTimeoutSeconds = 15;
    public const int DefaultMaxResponseBytes = 1024 * 1024;
    public const int DefaultMaxRecords = 50;
    public const string DefaultEndpoint = "http://127.0.0.1:5000/";

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public KnownFileLookupProviderMode ProviderMode { get; set; } = KnownFileLookupProviderMode.ExternalCompatible;

    public string Endpoint { get; set; } = DefaultEndpoint;

    public int TimeoutSeconds { get; set; } = DefaultTimeoutSeconds;

    public bool AllowNonLoopback { get; set; }

    public int MaxResponseBytes { get; set; } = DefaultMaxResponseBytes;

    public int MaxRecords { get; set; } = DefaultMaxRecords;

    public string ManagedCatalogRoot { get; set; } = string.Empty;

    public string ManagedValidationReceiptPath { get; set; } = string.Empty;

    public string ManagedControlPipeName { get; set; } = NsrlServerProtocol.DefaultControlPipeName;

    public KnownFileLookupSettings Clone() => new()
    {
        SchemaVersion = SchemaVersion,
        ProviderMode = ProviderMode,
        Endpoint = Endpoint,
        TimeoutSeconds = TimeoutSeconds,
        AllowNonLoopback = AllowNonLoopback,
        MaxResponseBytes = MaxResponseBytes,
        MaxRecords = MaxRecords,
        ManagedCatalogRoot = ManagedCatalogRoot,
        ManagedValidationReceiptPath = ManagedValidationReceiptPath,
        ManagedControlPipeName = ManagedControlPipeName
    };
}

public sealed record KnownFileLookupRequest(
    string Sha256,
    string FileName,
    long? FileSizeBytes);

public sealed class KnownFilePackageRecord
{
    public IReadOnlyList<string> FileNames { get; init; } = [];

    public long? FileSizeBytes { get; init; }

    public string ProductName { get; init; } = string.Empty;

    public string ProductVersion { get; init; } = string.Empty;

    public string Manufacturer { get; init; } = string.Empty;

    public string OperatingSystemName { get; init; } = string.Empty;

    public string OperatingSystemVersion { get; init; } = string.Empty;

    public string Language { get; init; } = string.Empty;

    public string ApplicationType { get; init; } = string.Empty;

    public string ProviderSource { get; init; } = string.Empty;
}

public sealed class KnownFileLookupResult
{
    public KnownFileLookupOutcome Outcome { get; init; }

    public string ProviderName { get; init; } = string.Empty;

    public string ProviderVersion { get; init; } = string.Empty;

    public string CatalogVersion { get; init; } = string.Empty;

    public string ProviderProvenance { get; init; } = string.Empty;

    public string StatusDetail { get; init; } = string.Empty;

    public DateTime LookupUtc { get; init; }

    public TimeSpan Elapsed { get; init; }

    public int? HttpStatusCode { get; init; }

    /// <summary>
    /// Number of bounded response-body bytes actually read from the provider.
    /// Header-only and pre-I/O outcomes report zero.
    /// </summary>
    public int ResponseLength { get; init; }

    public int TotalRecordCount { get; init; }

    public bool IsTruncated { get; init; }

    public IReadOnlyList<KnownFilePackageRecord> Records { get; init; } = [];
}

public interface IKnownFileLookupProvider : IDisposable
{
    string ProviderName { get; }

    bool SupportsFilenameSearch { get; }

    Task<KnownFileLookupResult> LookupSha256Async(
        KnownFileLookupRequest request,
        CancellationToken cancellationToken);
}

public interface IKnownFileLookupProviderFactory
{
    IKnownFileLookupProvider Create(KnownFileLookupSettings settings);
}
