using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models.Analysis;
using ProcInsider.Models.KnownFiles;

namespace ProcInsider.Services;

/// <summary>
/// Viewer-composed local-reference bridge from one currently verified managed
/// NSRL connection to the provider-neutral reputation execution boundary. It
/// delegates HTTP and response parsing to the existing known-file provider.
/// </summary>
public sealed class ManagedNsrlReputationProviderAdapter : IReputationProviderAdapter
{
    public const string ProviderId = "dfiroscope-managed-nsrl";
    public const string DatasetId = "nist-nsrl-modern-minimal-derived";
    public const string PrivacyNoticeVersion = "local-managed-nsrl-v1";

    private const int MaximumIdentityLength = 256;
    private readonly ReputationProviderAdmission _admission;
    private readonly KnownFileLookupSettings _settings;
    private readonly Func<KnownFileServerConnection?> _connectionAccessor;
    private readonly IKnownFileLookupProviderFactory _lookupProviderFactory;
    private readonly Func<DateTime> _utcNow;

    public ManagedNsrlReputationProviderAdapter(
        ReputationProviderAdmission admission,
        KnownFileLookupSettings settings,
        Func<KnownFileServerConnection?> connectionAccessor,
        IKnownFileLookupProviderFactory lookupProviderFactory,
        Func<DateTime> utcNow)
    {
        ArgumentNullException.ThrowIfNull(admission);
        _connectionAccessor = connectionAccessor
            ?? throw new ArgumentNullException(nameof(connectionAccessor));
        _lookupProviderFactory = lookupProviderFactory
            ?? throw new ArgumentNullException(nameof(lookupProviderFactory));
        _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
        _settings = ValidateSettings(settings);

        var currentConnection = _connectionAccessor()
            ?? throw new ArgumentException(
                "The managed NSRL adapter requires one currently verified connection.",
                nameof(connectionAccessor));
        var expected = BuildAdmission(
            currentConnection,
            _settings,
            admission.Limits.MaximumConcurrency,
            admission.Limits.MaximumRequestsPerMinute,
            admission.Limits.MaximumRequestsPerDay);
        var decision = ReputationProviderAuthorizationPolicy.ValidateAdmission(admission);
        if (!decision.Accepted || decision.Admission == null ||
            !string.Equals(
                decision.Admission.AdmissionHashSha256,
                expected.AdmissionHashSha256,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The managed NSRL adapter requires the canonical admission for the exact verified connection.",
                nameof(admission));
        }

        _admission = decision.Admission;
    }

    /// <summary>
    /// Creates the only admission shape accepted by this adapter. The opaque
    /// dataset version is a deterministic fingerprint of the managed protocol,
    /// active catalog and derived lookup generation identities.
    /// </summary>
    public static ReputationProviderAdmission CreateAdmission(
        KnownFileServerConnection connection,
        KnownFileLookupSettings settings,
        int maximumConcurrency,
        int maximumRequestsPerMinute,
        int maximumRequestsPerDay) =>
        BuildAdmission(
            connection,
            ValidateSettings(settings),
            maximumConcurrency,
            maximumRequestsPerMinute,
            maximumRequestsPerDay);

    public async ValueTask<ReputationProviderAdapterResponse> ExecuteAsync(
        ReputationProviderAuthorization authorization,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var authorizationDecision =
            ReputationProviderAuthorizationPolicy.ValidateAuthorization(authorization);
        if (!authorizationDecision.Accepted || authorizationDecision.Authorization == null ||
            !string.Equals(
                authorizationDecision.Authorization.Admission.AdmissionHashSha256,
                _admission.AdmissionHashSha256,
                StringComparison.Ordinal) ||
            authorizationDecision.Authorization.LookupRequest.Indicator.Kind !=
                ReputationIndicatorKind.Sha256)
        {
            throw new InvalidOperationException(
                "The managed NSRL lookup authorization is invalid.");
        }

        var canonicalAuthorization = authorizationDecision.Authorization;
        var connection = _connectionAccessor();
        if (!TryBuildCurrentAdmission(connection, out var currentAdmission) ||
            !string.Equals(
                currentAdmission.AdmissionHashSha256,
                _admission.AdmissionHashSha256,
                StringComparison.Ordinal))
        {
            return Failure(
                canonicalAuthorization.LookupRequest,
                AnalysisSourceAvailability.Unavailable,
                "The exact managed NSRL connection is unavailable or changed.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        using var provider = _lookupProviderFactory.Create(_settings.Clone());
        var lookup = await provider.LookupSha256Async(
                new KnownFileLookupRequest(
                    canonicalAuthorization.LookupRequest.Indicator.Value,
                    string.Empty,
                    null),
                cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        if (lookup == null || lookup.ResponseLength < 0 ||
            lookup.ResponseLength > _admission.Limits.MaximumResponseLength)
        {
            return Failure(
                canonicalAuthorization.LookupRequest,
                AnalysisSourceAvailability.Failed,
                "The managed NSRL response failed bounded validation.");
        }

        if ((!string.IsNullOrEmpty(lookup.ProviderVersion) &&
             !string.Equals(
                 lookup.ProviderVersion,
                 connection!.Server.ProviderVersion,
                 StringComparison.Ordinal)) ||
            (!string.IsNullOrEmpty(lookup.CatalogVersion) &&
             !string.Equals(
                 lookup.CatalogVersion,
                 connection!.Server.CatalogVersion,
                 StringComparison.Ordinal)))
        {
            return Failure(
                canonicalAuthorization.LookupRequest,
                AnalysisSourceAvailability.Failed,
                "The managed NSRL response identity does not match the admitted catalog.",
                lookup.ResponseLength);
        }

        return lookup.Outcome switch
        {
            KnownFileLookupOutcome.Match when lookup.Records.Count > 0 =>
                Success(canonicalAuthorization.LookupRequest, lookup, recordFound: true),
            KnownFileLookupOutcome.NoMatch =>
                Success(canonicalAuthorization.LookupRequest, lookup, recordFound: false),
            KnownFileLookupOutcome.Unavailable =>
                Failure(
                    canonicalAuthorization.LookupRequest,
                    AnalysisSourceAvailability.Unavailable,
                    "The managed NSRL reference lookup is unavailable.",
                    lookup.ResponseLength),
            KnownFileLookupOutcome.Canceled when cancellationToken.IsCancellationRequested =>
                throw new OperationCanceledException(cancellationToken),
            _ => Failure(
                canonicalAuthorization.LookupRequest,
                AnalysisSourceAvailability.Failed,
                "The managed NSRL reference lookup failed validation.",
                lookup.ResponseLength)
        };
    }

    private bool TryBuildCurrentAdmission(
        KnownFileServerConnection? connection,
        out ReputationProviderAdmission admission)
    {
        admission = new ReputationProviderAdmission();
        try
        {
            if (connection == null)
            {
                return false;
            }

            admission = BuildAdmission(
                connection,
                _settings,
                _admission.Limits.MaximumConcurrency,
                _admission.Limits.MaximumRequestsPerMinute,
                _admission.Limits.MaximumRequestsPerDay);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private ReputationProviderAdapterResponse Success(
        ReputationLookupRequest request,
        KnownFileLookupResult lookup,
        bool recordFound)
    {
        var result = new ReputationLookupResult
        {
            Request = request,
            Provider = _admission.Provider,
            Availability = AnalysisSourceAvailability.Available,
            RecordFound = recordFound,
            ProviderRecordId = recordFound ? ComputeProviderRecordId(request, lookup) : string.Empty,
            RetrievedUtc = ReadUtcNow(request.RequestedUtc)
        };
        result = result with
        {
            ContentHashSha256 = ReputationLookupContractPolicy.ComputeContentHash(result)
        };
        return new ReputationProviderAdapterResponse
        {
            Result = result,
            ResponseLength = lookup.ResponseLength
        };
    }

    private ReputationProviderAdapterResponse Failure(
        ReputationLookupRequest? request,
        AnalysisSourceAvailability availability,
        string diagnostic,
        int responseLength = 0)
    {
        var canonicalRequest = request ?? new ReputationLookupRequest();
        var result = new ReputationLookupResult
        {
            Request = canonicalRequest,
            Provider = _admission.Provider,
            Availability = availability,
            RetrievedUtc = ReadUtcNow(canonicalRequest.RequestedUtc),
            Diagnostic = diagnostic
        };
        result = result with
        {
            ContentHashSha256 = ReputationLookupContractPolicy.ComputeContentHash(result)
        };
        return new ReputationProviderAdapterResponse
        {
            Result = result,
            ResponseLength = responseLength
        };
    }

    private DateTime ReadUtcNow(DateTime earliestUtc)
    {
        var value = _utcNow();
        if (value == default || value.Kind != DateTimeKind.Utc || value < earliestUtc)
        {
            throw new InvalidOperationException(
                "The managed NSRL adapter clock is invalid or precedes the lookup request.");
        }

        return value;
    }

    private static ReputationProviderAdmission BuildAdmission(
        KnownFileServerConnection connection,
        KnownFileLookupSettings settings,
        int maximumConcurrency,
        int maximumRequestsPerMinute,
        int maximumRequestsPerDay)
    {
        if (!TryValidateConnection(connection, settings, out var destinationOrigin))
        {
            throw new ArgumentException(
                "The managed NSRL connection is not ready, complete, or bound to the exact local endpoint.",
                nameof(connection));
        }

        var admission = new ReputationProviderAdmission
        {
            Provider = new ReputationProviderIdentity
            {
                ProviderId = ProviderId,
                ProviderVersion = connection.Server.ProviderVersion,
                DatasetId = DatasetId,
                DatasetVersion = ComputeDatasetVersion(connection.Server),
                QueryMode = ReputationQueryMode.LocalReference
            },
            PrivacyKind = ReputationProviderPrivacyKind.LocalOnly,
            DestinationOrigin = destinationOrigin,
            CredentialRequirement = ReputationCredentialRequirement.None,
            PrivacyNoticeVersion = PrivacyNoticeVersion,
            SupportedIndicatorKinds = new[] { ReputationIndicatorKind.Sha256 },
            Limits = new ReputationProviderResourceLimits
            {
                RequestTimeoutSeconds = settings.TimeoutSeconds,
                MaximumResponseLength = settings.MaxResponseBytes,
                MaximumConcurrency = maximumConcurrency,
                MaximumRequestsPerMinute = maximumRequestsPerMinute,
                MaximumRequestsPerDay = maximumRequestsPerDay
            }
        };
        var hash = ReputationProviderAuthorizationPolicy.ComputeAdmissionHash(admission);
        if (string.IsNullOrEmpty(hash))
        {
            throw new ArgumentException(
                "The managed NSRL settings or provider resource limits are outside the portable admission contract.");
        }

        admission = admission with { AdmissionHashSha256 = hash };
        return ReputationProviderAuthorizationPolicy.ValidateAdmission(admission).Admission
            ?? throw new ArgumentException("The managed NSRL admission could not be canonicalized.");
    }

    private static KnownFileLookupSettings ValidateSettings(KnownFileLookupSettings settings)
    {
        if (settings == null)
        {
            throw new ArgumentNullException(nameof(settings));
        }

        var normalized = KnownFileLookupSettingsService.Normalize(settings);
        if (settings.SchemaVersion != KnownFileLookupSettings.CurrentSchemaVersion ||
            settings.ProviderMode != KnownFileLookupProviderMode.ManagedLocal ||
            settings.AllowNonLoopback ||
            settings.TimeoutSeconds != normalized.TimeoutSeconds ||
            settings.MaxResponseBytes != normalized.MaxResponseBytes ||
            settings.MaxRecords != normalized.MaxRecords ||
            !string.Equals(
                settings.ManagedValidationReceiptPath,
                normalized.ManagedValidationReceiptPath,
                StringComparison.Ordinal) ||
            !string.Equals(
                settings.ManagedControlPipeName,
                normalized.ManagedControlPipeName,
                StringComparison.Ordinal) ||
            settings.MaxResponseBytes > ReputationProviderAuthorizationPolicy.MaximumResponseLength)
        {
            throw new ArgumentException(
                "The managed NSRL adapter requires canonical local-only lookup settings within the provider admission ceilings.",
                nameof(settings));
        }

        return normalized;
    }

    private static bool TryValidateConnection(
        KnownFileServerConnection? connection,
        KnownFileLookupSettings settings,
        out string destinationOrigin)
    {
        destinationOrigin = string.Empty;
        if (connection?.Process == null || connection.Server == null ||
            connection.Configuration == null || connection.Configuration.Endpoint == null)
        {
            return false;
        }

        var process = connection.Process;
        var server = connection.Server;
        var endpoint = connection.Configuration.Endpoint;
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttp ||
            !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment) || endpoint.AbsolutePath != "/" ||
            endpoint.HostNameType is not (UriHostNameType.IPv4 or UriHostNameType.IPv6) ||
            !IPAddress.TryParse(endpoint.IdnHost, out var address) ||
            !IPAddress.IsLoopback(address) ||
            !string.Equals(endpoint.AbsoluteUri, settings.Endpoint, StringComparison.Ordinal) ||
            !string.Equals(
                connection.Configuration.ControlPipeName,
                settings.ManagedControlPipeName,
                StringComparison.Ordinal) ||
            !string.Equals(
                connection.Configuration.ValidationReceiptPath,
                settings.ManagedValidationReceiptPath,
                StringComparison.OrdinalIgnoreCase) ||
            process.ProcessId <= 0 || process.StartUtc.Kind != DateTimeKind.Utc ||
            string.IsNullOrWhiteSpace(process.ExecutablePath) ||
            string.IsNullOrWhiteSpace(process.UserSid) || process.SessionId < 0 ||
            server.SchemaVersion != NsrlServerProtocol.SchemaVersion ||
            !string.Equals(server.CompatibilityVersion, NsrlServerProtocol.CompatibilityVersion,
                StringComparison.Ordinal) ||
            !string.Equals(server.ProviderVersion, NsrlServerProtocol.ProviderVersion,
                StringComparison.Ordinal) ||
            server.ProcessId != process.ProcessId || server.ProcessStartUtc != process.StartUtc ||
            !IsBoundedRequired(server.ServerReleaseId) ||
            !IsBoundedRequired(server.ControlGeneration) ||
            server.Readiness != NsrlServerReadiness.Ready ||
            !IsBoundedRequired(server.ActiveGenerationId) ||
            !IsBoundedRequired(server.CatalogVersion, 128) ||
            !string.Equals(server.DataSet, "Modern", StringComparison.Ordinal) ||
            !string.Equals(server.Profile, "Minimal", StringComparison.Ordinal) ||
            !IsBoundedRequired(server.DerivedGenerationId) ||
            !string.Equals(server.DerivedTransformVersion,
                NsrlServerProtocol.DerivedTransformVersion, StringComparison.Ordinal) ||
            !IsSha256(server.DerivedDatabaseSha256) ||
            !IsSha256(server.AcceptedGenerationReceiptId) ||
            !string.Equals(server.StartupValidationMode, "accepted-generation-fast-start", StringComparison.Ordinal) ||
            server.StartupAdmissionElapsedMilliseconds < 0 ||
            server.RecordCount < 0 || server.DistinctHashCount < 0 ||
            server.DistinctHashCount > server.RecordCount ||
            server.DerivedBuiltUtc is not { Kind: DateTimeKind.Utc } derivedBuiltUtc ||
            server.LastSuccessfulValidationUtc is not { Kind: DateTimeKind.Utc } validatedUtc ||
            server.ObservedUtc.Kind != DateTimeKind.Utc ||
            derivedBuiltUtc > server.ObservedUtc || validatedUtc > server.ObservedUtc)
        {
            return false;
        }

        destinationOrigin = endpoint.GetLeftPart(UriPartial.Authority);
        return true;
    }

    private static string ComputeDatasetVersion(NsrlServerInfo server)
    {
        var builder = new StringBuilder();
        Append(builder, server.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(builder, server.CompatibilityVersion);
        Append(builder, server.ProviderVersion);
        Append(builder, server.ServerReleaseId);
        Append(builder, server.ActiveGenerationId);
        Append(builder, server.CatalogVersion);
        Append(builder, server.DataSet);
        Append(builder, server.Profile);
        Append(builder, server.DerivedGenerationId);
        Append(builder, server.DerivedTransformVersion);
        Append(builder, server.DerivedDatabaseSha256.ToLowerInvariant());
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();
    }

    private string ComputeProviderRecordId(
        ReputationLookupRequest request,
        KnownFileLookupResult lookup)
    {
        var builder = new StringBuilder();
        Append(builder, _admission.Provider.ProviderVersion);
        Append(builder, _admission.Provider.DatasetVersion);
        Append(builder, request.Indicator.Value);
        Append(builder, lookup.TotalRecordCount.ToString(CultureInfo.InvariantCulture));
        Append(builder, lookup.IsTruncated ? "1" : "0");
        foreach (var record in lookup.Records)
        {
            foreach (var fileName in record.FileNames)
            {
                Append(builder, fileName);
            }

            Append(builder, record.FileSizeBytes?.ToString(CultureInfo.InvariantCulture) ?? string.Empty);
            Append(builder, record.ProductName);
            Append(builder, record.ProductVersion);
            Append(builder, record.Manufacturer);
            Append(builder, record.OperatingSystemName);
            Append(builder, record.OperatingSystemVersion);
            Append(builder, record.Language);
            Append(builder, record.ApplicationType);
            Append(builder, record.ProviderSource);
        }

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();
        return $"managed-nsrl:{hash}";
    }

    private static void Append(StringBuilder builder, string value) =>
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture))
            .Append(':')
            .Append(value);

    private static bool IsBoundedRequired(string? value, int maximumLength = MaximumIdentityLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
        !value.Any(char.IsControl);

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F'));
}
