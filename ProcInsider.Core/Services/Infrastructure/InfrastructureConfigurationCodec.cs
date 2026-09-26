using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Contracts = ProcInsider.Models.Infrastructure.InfrastructureConfigurationContracts;

namespace ProcInsider.Services.Infrastructure;

/// <summary>
/// Pure validation, deterministic serialization, and canonical hashing for non-secret
/// Infrastructure configuration. It performs no file, protected-store, network, or database I/O.
/// </summary>
public static class InfrastructureConfigurationCodec
{
    private const string ExpectedServerServiceIdentity = @"NT SERVICE\DFIRoscope.Server";
    private const int MaximumIdentityLength = 128;
    private const int MaximumReferenceLength = 256;
    private const int MaximumPolicyReferenceLength = 128;
    private const int MaximumAuditCorrelationLength = 128;
    private static readonly Regex IdentifierPattern = new(
        @"\A[A-Za-z0-9][A-Za-z0-9._/-]*\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public static Contracts.ValidationResult Validate(
        Contracts.InfrastructureAgentConfiguration? configuration)
    {
        var diagnostics = new List<Contracts.ValidationDiagnostic>();
        if (configuration == null)
        {
            Add(diagnostics, "ConfigurationMissing", "$", "The Agent configuration is missing.");
            return new Contracts.ValidationResult(diagnostics);
        }

        ValidateEnvelope(
            configuration.SchemaVersion,
            configuration.Kind,
            Contracts.ConfigurationKind.Agent,
            configuration.PublicationGroupId,
            configuration.DeploymentProfileId,
            configuration.ReleaseId,
            configuration.ProtocolGeneration,
            configuration.Metadata,
            diagnostics);
        ValidateIdentity(configuration.AgentId, "agentId", diagnostics);
        ValidateIdentity(configuration.HostId, "hostId", diagnostics);
        ValidateEndpoints(configuration.ServerEndpoints, diagnostics);
        ValidateProtectedReference(configuration.EnrollmentReference, "enrollmentReference", diagnostics);
        ValidateProtectedReference(configuration.CredentialReference, "credentialReference", diagnostics);
        ValidateTokens(
            configuration.RequiredCapabilities,
            "requiredCapabilities",
            Contracts.MaximumCapabilities,
            MaximumPolicyReferenceLength,
            allowEmpty: true,
            diagnostics);
        ValidateToken(configuration.RetryPolicyReference, "retryPolicyReference", MaximumPolicyReferenceLength, diagnostics);
        ValidateToken(configuration.SpoolPolicyReference, "spoolPolicyReference", MaximumPolicyReferenceLength, diagnostics);
        ValidateToken(configuration.RetentionPolicyReference, "retentionPolicyReference", MaximumPolicyReferenceLength, diagnostics);
        return new Contracts.ValidationResult(diagnostics);
    }

    public static Contracts.ValidationResult Validate(
        Contracts.InfrastructureServerConfiguration? configuration)
    {
        var diagnostics = new List<Contracts.ValidationDiagnostic>();
        if (configuration == null)
        {
            Add(diagnostics, "ConfigurationMissing", "$", "The Server configuration is missing.");
            return new Contracts.ValidationResult(diagnostics);
        }

        ValidateEnvelope(
            configuration.SchemaVersion,
            configuration.Kind,
            Contracts.ConfigurationKind.Server,
            configuration.PublicationGroupId,
            configuration.DeploymentProfileId,
            configuration.ReleaseId,
            configuration.ProtocolGeneration,
            configuration.Metadata,
            diagnostics);
        ValidateIdentity(configuration.ServerId, "serverId", diagnostics);
        if (!string.Equals(configuration.ServiceIdentity, ExpectedServerServiceIdentity, StringComparison.Ordinal))
        {
            Add(
                diagnostics,
                "ServerServiceIdentityInvalid",
                "serviceIdentity",
                "The Server service identity does not match the compiled least-privilege virtual account.");
        }

        if (!Enum.IsDefined(configuration.PublicationState) ||
            configuration.PublicationState == Contracts.ServerPublicationState.Unknown)
        {
            Add(diagnostics, "PublicationStateInvalid", "publicationState", "The Server publication state is unknown.");
        }

        if (configuration.Enabled && configuration.PublicationState == Contracts.ServerPublicationState.Disabled)
        {
            Add(diagnostics, "EnabledPublicationContradiction", "enabled", "An enabled Server cannot use the Disabled publication state.");
        }

        ValidateListeners(configuration.Listeners, configuration.Enabled, diagnostics);
        ValidateProtectedReference(configuration.TlsCertificateReference, "tlsCertificateReference", diagnostics);
        ValidateProtectedReference(configuration.EnrollmentIssuerReference, "enrollmentIssuerReference", diagnostics);
        ValidateProvider(configuration.DatabaseProvider, Contracts.ProviderKind.Postgres, "databaseProvider", diagnostics);
        ValidateProvider(configuration.ArtifactProvider, Contracts.ProviderKind.HashAddressedFileSystem, "artifactProvider", diagnostics);
        ValidateResourceLimits(configuration.ResourceLimits, diagnostics);
        ValidateToken(configuration.AuditPolicyReference, "auditPolicyReference", MaximumPolicyReferenceLength, diagnostics);
        ValidateToken(configuration.RetentionPolicyReference, "retentionPolicyReference", MaximumPolicyReferenceLength, diagnostics);
        return new Contracts.ValidationResult(diagnostics);
    }

    public static byte[] SerializeCanonical(Contracts.InfrastructureAgentConfiguration configuration)
    {
        var validation = Validate(configuration);
        ThrowIfInvalid(validation);
        return JsonSerializer.SerializeToUtf8Bytes(Normalize(configuration), JsonOptions);
    }

    public static byte[] SerializeCanonical(Contracts.InfrastructureServerConfiguration configuration)
    {
        var validation = Validate(configuration);
        ThrowIfInvalid(validation);
        return JsonSerializer.SerializeToUtf8Bytes(Normalize(configuration), JsonOptions);
    }

    public static Contracts.DecodeResult<Contracts.InfrastructureAgentConfiguration> DeserializeAgent(
        ReadOnlySpan<byte> utf8Json) =>
        Deserialize(
            utf8Json,
            Contracts.ConfigurationKind.Agent,
            static bytes => JsonSerializer.Deserialize<Contracts.InfrastructureAgentConfiguration>(bytes, JsonOptions),
            Validate,
            Normalize);

    public static Contracts.DecodeResult<Contracts.InfrastructureAgentConfiguration> DeserializeAgent(
        byte[] utf8Json)
    {
        ArgumentNullException.ThrowIfNull(utf8Json);
        return DeserializeAgent(utf8Json.AsSpan());
    }

    public static Contracts.DecodeResult<Contracts.InfrastructureServerConfiguration> DeserializeServer(
        ReadOnlySpan<byte> utf8Json) =>
        Deserialize(
            utf8Json,
            Contracts.ConfigurationKind.Server,
            static bytes => JsonSerializer.Deserialize<Contracts.InfrastructureServerConfiguration>(bytes, JsonOptions),
            Validate,
            Normalize);

    public static Contracts.DecodeResult<Contracts.InfrastructureServerConfiguration> DeserializeServer(
        byte[] utf8Json)
    {
        ArgumentNullException.ThrowIfNull(utf8Json);
        return DeserializeServer(utf8Json.AsSpan());
    }

    public static string ComputeCanonicalSha256(Contracts.InfrastructureAgentConfiguration configuration) =>
        ComputeSha256(SerializeCanonical(configuration));

    public static string ComputeCanonicalSha256(Contracts.InfrastructureServerConfiguration configuration) =>
        ComputeSha256(SerializeCanonical(configuration));

    public static Contracts.ConfigurationSummary Summarize(
        Contracts.InfrastructureAgentConfiguration configuration) =>
        new(
            Contracts.ConfigurationKind.Agent,
            configuration.SchemaVersion,
            configuration.Metadata.Revision,
            configuration.Metadata.Owner,
            configuration.Enabled,
            Contracts.ServerPublicationState.Disabled,
            configuration.ServerEndpoints.Count,
            2,
            ComputeCanonicalSha256(configuration));

    public static Contracts.ConfigurationSummary Summarize(
        Contracts.InfrastructureServerConfiguration configuration) =>
        new(
            Contracts.ConfigurationKind.Server,
            configuration.SchemaVersion,
            configuration.Metadata.Revision,
            configuration.Metadata.Owner,
            configuration.Enabled,
            configuration.PublicationState,
            configuration.Listeners.Count,
            2,
            ComputeCanonicalSha256(configuration));

    private static Contracts.DecodeResult<T> Deserialize<T>(
        ReadOnlySpan<byte> utf8Json,
        Contracts.ConfigurationKind expectedKind,
        Func<ReadOnlySpan<byte>, T?> deserialize,
        Func<T?, Contracts.ValidationResult> validate,
        Func<T, T> normalize)
        where T : class
    {
        if (utf8Json.IsEmpty)
        {
            return DecodeFailure<T>(Contracts.DecodeOutcome.Empty, "ConfigurationEmpty", "The configuration document is empty.");
        }

        if (utf8Json.Length > Contracts.MaximumDocumentBytes)
        {
            return DecodeFailure<T>(Contracts.DecodeOutcome.TooLarge, "ConfigurationTooLarge", "The configuration document exceeds the compiled byte limit.");
        }

        try
        {
            using var document = JsonDocument.Parse(utf8Json.ToArray(), new JsonDocumentOptions { MaxDepth = 16 });
            if (document.RootElement.ValueKind != JsonValueKind.Object || !HasUniqueProperties(document.RootElement))
            {
                return DecodeFailure<T>(Contracts.DecodeOutcome.Malformed, "ConfigurationObjectInvalid", "The configuration must be one JSON object with unique property names.");
            }

            if (!document.RootElement.TryGetProperty("schemaVersion", out var schemaElement) ||
                !schemaElement.TryGetInt32(out var schemaVersion))
            {
                return DecodeFailure<T>(Contracts.DecodeOutcome.Malformed, "SchemaVersionMissing", "The configuration schema version is missing or malformed.");
            }

            if (schemaVersion != Contracts.CurrentSchemaVersion)
            {
                return DecodeFailure<T>(Contracts.DecodeOutcome.UnsupportedVersion, "SchemaVersionUnsupported", "The configuration schema version is unsupported and fails closed.");
            }

            if (!document.RootElement.TryGetProperty("kind", out var kindElement) ||
                kindElement.ValueKind != JsonValueKind.String ||
                !Enum.TryParse<Contracts.ConfigurationKind>(kindElement.GetString(), ignoreCase: true, out var kind) ||
                kind != expectedKind)
            {
                return DecodeFailure<T>(Contracts.DecodeOutcome.WrongKind, "ConfigurationKindMismatch", "The configuration kind does not match the selected machine owner.");
            }

            var configuration = deserialize(utf8Json);
            var validation = validate(configuration);
            if (configuration == null || !validation.IsValid)
            {
                return new Contracts.DecodeResult<T>(Contracts.DecodeOutcome.Invalid, null, validation.Diagnostics);
            }

            return new Contracts.DecodeResult<T>(
                Contracts.DecodeOutcome.Valid,
                normalize(configuration),
                Array.Empty<Contracts.ValidationDiagnostic>());
        }
        catch (JsonException)
        {
            return DecodeFailure<T>(Contracts.DecodeOutcome.Malformed, "ConfigurationJsonRejected", "The configuration JSON is malformed or contains an unsupported field/value.");
        }
    }

    private static void ValidateEnvelope(
        int schemaVersion,
        Contracts.ConfigurationKind kind,
        Contracts.ConfigurationKind expectedKind,
        string publicationGroupId,
        string deploymentProfileId,
        string releaseId,
        int protocolGeneration,
        Contracts.ConfigurationMetadata? metadata,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (schemaVersion != Contracts.CurrentSchemaVersion)
        {
            Add(diagnostics, "SchemaVersionUnsupported", "schemaVersion", "The configuration schema version is unsupported and fails closed.");
        }

        if (kind != expectedKind)
        {
            Add(diagnostics, "ConfigurationKindMismatch", "kind", "The configuration kind does not match its owning component.");
        }

        ValidateToken(publicationGroupId, "publicationGroupId", MaximumIdentityLength, diagnostics);
        ValidateToken(deploymentProfileId, "deploymentProfileId", MaximumIdentityLength, diagnostics);
        ValidateToken(releaseId, "releaseId", MaximumIdentityLength, diagnostics);
        if (protocolGeneration <= 0)
        {
            Add(diagnostics, "ProtocolGenerationInvalid", "protocolGeneration", "The protocol generation must be positive.");
        }

        if (metadata == null)
        {
            Add(diagnostics, "MetadataMissing", "metadata", "The configuration metadata is missing.");
            return;
        }

        if (metadata.Owner != Contracts.ConfigurationOwnerKind.Administrator)
        {
            Add(diagnostics, "ConfigurationOwnerInvalid", "metadata.owner", "Infrastructure machine configuration must be administrator-owned.");
        }

        if (metadata.Revision <= 0)
        {
            Add(diagnostics, "ConfigurationRevisionInvalid", "metadata.revision", "The configuration revision must be positive.");
        }

        if (metadata.UpdatedAtUtc.Kind != DateTimeKind.Utc)
        {
            Add(diagnostics, "ConfigurationTimestampInvalid", "metadata.updatedAtUtc", "The configuration update time must be UTC.");
        }

        ValidateToken(metadata.AuditCorrelationId, "metadata.auditCorrelationId", MaximumAuditCorrelationLength, diagnostics);
    }

    private static void ValidateEndpoints(
        IReadOnlyList<Contracts.ServerEndpoint>? endpoints,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (endpoints == null || endpoints.Count == 0 || endpoints.Count > Contracts.MaximumEndpoints)
        {
            Add(diagnostics, "ServerEndpointsInvalid", "serverEndpoints", "Agent configuration requires a bounded non-empty Server endpoint list.");
            return;
        }

        foreach (var endpoint in endpoints)
        {
            if (endpoint == null ||
                !System.Uri.TryCreate(endpoint.Uri, UriKind.Absolute, out var uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrEmpty(uri.UserInfo) ||
                !string.IsNullOrEmpty(uri.Query) ||
                !string.IsNullOrEmpty(uri.Fragment) ||
                uri.AbsolutePath != "/")
            {
                Add(diagnostics, "ServerEndpointInvalid", "serverEndpoints", "Every Server endpoint must be an absolute HTTPS authority without credentials, path, query, or fragment.");
                continue;
            }

            ValidateIdentity(endpoint.ExpectedServerIdentity, "serverEndpoints.expectedServerIdentity", diagnostics);
        }

        if (endpoints.Select(endpoint => endpoint?.Uri).Distinct(StringComparer.OrdinalIgnoreCase).Count() != endpoints.Count)
        {
            Add(diagnostics, "ServerEndpointDuplicate", "serverEndpoints", "Server endpoint URIs must be unique.");
        }
    }

    private static void ValidateListeners(
        IReadOnlyList<Contracts.ServerListener>? listeners,
        bool enabled,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (listeners == null || listeners.Count > Contracts.MaximumListeners || (enabled && listeners.Count == 0))
        {
            Add(diagnostics, "ServerListenersInvalid", "listeners", "Enabled Server configuration requires a bounded non-empty listener list.");
            return;
        }

        foreach (var listener in listeners)
        {
            if (listener == null || !IPAddress.TryParse(listener.Address, out var address) || listener.Port is < 1 or > 65535)
            {
                Add(diagnostics, "ServerListenerInvalid", "listeners", "Every Server listener requires one literal IP address and a valid port.");
                continue;
            }

            var wildcard = address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
            if (wildcard && !listener.AllowWildcardBind)
            {
                Add(diagnostics, "WildcardBindAcknowledgementMissing", "listeners.allowWildcardBind", "A wildcard listener requires explicit acknowledgement.");
            }
            else if (!wildcard && listener.AllowWildcardBind)
            {
                Add(diagnostics, "WildcardBindAcknowledgementContradiction", "listeners.allowWildcardBind", "Wildcard acknowledgement is valid only for a wildcard listener.");
            }
        }

        if (listeners.Select(listener => $"{listener?.Address}|{listener?.Port}").Distinct(StringComparer.OrdinalIgnoreCase).Count() != listeners.Count)
        {
            Add(diagnostics, "ServerListenerDuplicate", "listeners", "Server listener address/port pairs must be unique.");
        }
    }

    private static void ValidateProtectedReference(
        Contracts.ProtectedStoreReference? reference,
        string field,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (reference == null ||
            reference.Store == Contracts.ProtectedStoreKind.Unknown ||
            !Enum.IsDefined(reference.Store))
        {
            Add(diagnostics, "ProtectedStoreReferenceInvalid", field, "The protected-store reference kind is missing or unknown.");
            return;
        }

        ValidateToken(reference.Identifier, $"{field}.identifier", MaximumReferenceLength, diagnostics);
    }

    private static void ValidateProvider(
        Contracts.ProviderReference? provider,
        Contracts.ProviderKind expected,
        string field,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (provider == null || provider.Provider != expected)
        {
            Add(diagnostics, "ProviderKindInvalid", field, "The configured provider kind does not match its owned storage role.");
            return;
        }

        ValidateToken(provider.ConfigurationReferenceId, $"{field}.configurationReferenceId", MaximumReferenceLength, diagnostics);
    }

    private static void ValidateResourceLimits(
        Contracts.InfrastructureResourceLimits? limits,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (limits == null)
        {
            Add(diagnostics, "ResourceLimitsMissing", "resourceLimits", "The Server resource limits are missing.");
            return;
        }

        ValidateLimit(limits.MaximumUnauthenticatedHandshakes, 32, "maximumUnauthenticatedHandshakes", diagnostics);
        ValidateLimit(limits.MaximumUnauthenticatedHandshakesPerAddress, 4, "maximumUnauthenticatedHandshakesPerAddress", diagnostics);
        ValidateLimit(limits.MaximumAuthenticatedAgentSessions, 256, "maximumAuthenticatedAgentSessions", diagnostics);
        ValidateLimit(limits.MaximumAuthenticatedViewerSessions, 64, "maximumAuthenticatedViewerSessions", diagnostics);
        ValidateLimit(limits.MaximumControlEnvelopeBytes, 1024 * 1024, "maximumControlEnvelopeBytes", diagnostics);
        ValidateLimit(limits.MaximumEvidenceChunkBytes, 4 * 1024 * 1024, "maximumEvidenceChunkBytes", diagnostics);
        ValidateLimit(limits.MaximumEvidenceBatchBytes, 64 * 1024 * 1024, "maximumEvidenceBatchBytes", diagnostics);
        ValidateLimit(limits.MaximumDecompressionRatio, 100, "maximumDecompressionRatio", diagnostics);
        if (limits.MaximumUnauthenticatedHandshakesPerAddress > limits.MaximumUnauthenticatedHandshakes)
        {
            Add(diagnostics, "ResourceLimitContradiction", "resourceLimits", "The per-address handshake limit cannot exceed the global limit.");
        }
    }

    private static void ValidateLimit(
        int value,
        int maximum,
        string field,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (value <= 0 || value > maximum)
        {
            Add(diagnostics, "ResourceLimitOutOfRange", $"resourceLimits.{field}", "A configured resource limit is outside its compiled positive ceiling.");
        }
    }

    private static void ValidateIdentity(
        string value,
        string field,
        List<Contracts.ValidationDiagnostic> diagnostics) =>
        ValidateToken(value, field, MaximumIdentityLength, diagnostics);

    private static void ValidateTokens(
        IReadOnlyList<string>? values,
        string field,
        int maximumCount,
        int maximumLength,
        bool allowEmpty,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (values == null || values.Count > maximumCount || (!allowEmpty && values.Count == 0))
        {
            Add(diagnostics, "ReferenceListInvalid", field, "The reference list is missing or exceeds its compiled item limit.");
            return;
        }

        foreach (var value in values)
        {
            ValidateToken(value, field, maximumLength, diagnostics);
        }

        if (values.Distinct(StringComparer.Ordinal).Count() != values.Count)
        {
            Add(diagnostics, "ReferenceListDuplicate", field, "The reference list contains a duplicate identifier.");
        }
    }

    private static void ValidateToken(
        string? value,
        string field,
        int maximumLength,
        List<Contracts.ValidationDiagnostic> diagnostics)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || !IdentifierPattern.IsMatch(value))
        {
            Add(diagnostics, "IdentifierInvalid", field, "The field must contain one bounded stable identifier and cannot contain secret material.");
        }
    }

    private static Contracts.InfrastructureAgentConfiguration Normalize(
        Contracts.InfrastructureAgentConfiguration configuration) =>
        configuration with
        {
            ServerEndpoints = configuration.ServerEndpoints
                .OrderBy(endpoint => endpoint.Uri, StringComparer.OrdinalIgnoreCase)
                .ThenBy(endpoint => endpoint.ExpectedServerIdentity, StringComparer.Ordinal)
                .ToArray(),
            RequiredCapabilities = configuration.RequiredCapabilities
                .OrderBy(capability => capability, StringComparer.Ordinal)
                .ToArray()
        };

    private static Contracts.InfrastructureServerConfiguration Normalize(
        Contracts.InfrastructureServerConfiguration configuration) =>
        configuration with
        {
            Listeners = configuration.Listeners
                .OrderBy(listener => listener.Address, StringComparer.OrdinalIgnoreCase)
                .ThenBy(listener => listener.Port)
                .ToArray()
        };

    private static bool HasUniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name) || !HasUniqueProperties(property.Value))
                {
                    return false;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (!HasUniqueProperties(item))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static string ComputeSha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static Contracts.DecodeResult<T> DecodeFailure<T>(
        Contracts.DecodeOutcome outcome,
        string errorCode,
        string message)
        where T : class =>
        new(
            outcome,
            null,
            [new Contracts.ValidationDiagnostic(Contracts.DiagnosticSeverity.Error, errorCode, "$", message)]);

    private static void ThrowIfInvalid(Contracts.ValidationResult result)
    {
        if (!result.IsValid)
        {
            throw new InvalidDataException(
                string.Join("; ", result.Diagnostics.Select(diagnostic => $"{diagnostic.ErrorCode} ({diagnostic.Field})")));
        }
    }

    private static void Add(
        List<Contracts.ValidationDiagnostic> diagnostics,
        string errorCode,
        string field,
        string message) =>
        diagnostics.Add(new Contracts.ValidationDiagnostic(
            Contracts.DiagnosticSeverity.Error,
            errorCode,
            field,
            message));

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            MaxDepth = 16,
            WriteIndented = false
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        return options;
    }
}
