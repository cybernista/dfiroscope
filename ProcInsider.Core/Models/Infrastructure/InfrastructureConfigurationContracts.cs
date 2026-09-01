namespace ProcInsider.Models.Infrastructure;

/// <summary>
/// Dependency-light, non-secret configuration contracts shared by the Infrastructure Agent
/// Service and Server. Protected values never appear here; only bounded identifiers owned by
/// an approved Windows protected store may be serialized.
/// </summary>
public static class InfrastructureConfigurationContracts
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumDocumentBytes = 64 * 1024;
    public const int MaximumEndpoints = 8;
    public const int MaximumCapabilities = 64;
    public const int MaximumListeners = 8;

    public enum ConfigurationKind
    {
        Unknown = 0,
        Agent = 1,
        Server = 2
    }

    public enum ConfigurationOwnerKind
    {
        Unknown = 0,
        Administrator = 1
    }

    public enum ProtectedStoreKind
    {
        Unknown = 0,
        WindowsCertificateStore = 1,
        WindowsCngKey = 2
    }

    public enum ServerPublicationState
    {
        Unknown = 0,
        Disabled = 1,
        ReadyHidden = 2,
        Published = 3
    }

    public enum ProviderKind
    {
        Unknown = 0,
        Postgres = 1,
        HashAddressedFileSystem = 2
    }

    public enum DiagnosticSeverity
    {
        Error = 0,
        Warning = 1,
        Information = 2
    }

    public enum DecodeOutcome
    {
        Valid = 0,
        Empty = 1,
        TooLarge = 2,
        Malformed = 3,
        WrongKind = 4,
        UnsupportedVersion = 5,
        Invalid = 6
    }

    public sealed record ConfigurationMetadata
    {
        public ConfigurationOwnerKind Owner { get; init; }

        public long Revision { get; init; }

        public DateTime UpdatedAtUtc { get; init; }

        public string AuditCorrelationId { get; init; } = string.Empty;
    }

    public sealed record ProtectedStoreReference
    {
        public ProtectedStoreKind Store { get; init; }

        public string Identifier { get; init; } = string.Empty;
    }

    public sealed record ServerEndpoint
    {
        public string Uri { get; init; } = string.Empty;

        public string ExpectedServerIdentity { get; init; } = string.Empty;
    }

    public sealed record InfrastructureAgentConfiguration
    {
        public int SchemaVersion { get; init; } = CurrentSchemaVersion;

        public ConfigurationKind Kind { get; init; } = ConfigurationKind.Agent;

        public string PublicationGroupId { get; init; } = string.Empty;

        public string DeploymentProfileId { get; init; } = string.Empty;

        public string ReleaseId { get; init; } = string.Empty;

        public int ProtocolGeneration { get; init; }

        public ConfigurationMetadata Metadata { get; init; } = new();

        public bool Enabled { get; init; }

        public string AgentId { get; init; } = string.Empty;

        public string HostId { get; init; } = string.Empty;

        public IReadOnlyList<ServerEndpoint> ServerEndpoints { get; init; } =
            Array.Empty<ServerEndpoint>();

        public ProtectedStoreReference EnrollmentReference { get; init; } = new();

        public ProtectedStoreReference CredentialReference { get; init; } = new();

        public IReadOnlyList<string> RequiredCapabilities { get; init; } =
            Array.Empty<string>();

        public string RetryPolicyReference { get; init; } = string.Empty;

        public string SpoolPolicyReference { get; init; } = string.Empty;

        public string RetentionPolicyReference { get; init; } = string.Empty;
    }

    public sealed record ServerListener
    {
        public string Address { get; init; } = string.Empty;

        public int Port { get; init; }

        public bool AllowWildcardBind { get; init; }
    }

    public sealed record ProviderReference
    {
        public ProviderKind Provider { get; init; }

        public string ConfigurationReferenceId { get; init; } = string.Empty;
    }

    public sealed record InfrastructureResourceLimits
    {
        public int MaximumUnauthenticatedHandshakes { get; init; }

        public int MaximumUnauthenticatedHandshakesPerAddress { get; init; }

        public int MaximumAuthenticatedAgentSessions { get; init; }

        public int MaximumAuthenticatedViewerSessions { get; init; }

        public int MaximumControlEnvelopeBytes { get; init; }

        public int MaximumEvidenceChunkBytes { get; init; }

        public int MaximumEvidenceBatchBytes { get; init; }

        public int MaximumDecompressionRatio { get; init; }
    }

    public sealed record InfrastructureServerConfiguration
    {
        public int SchemaVersion { get; init; } = CurrentSchemaVersion;

        public ConfigurationKind Kind { get; init; } = ConfigurationKind.Server;

        public string PublicationGroupId { get; init; } = string.Empty;

        public string DeploymentProfileId { get; init; } = string.Empty;

        public string ReleaseId { get; init; } = string.Empty;

        public int ProtocolGeneration { get; init; }

        public ConfigurationMetadata Metadata { get; init; } = new();

        public bool Enabled { get; init; }

        public ServerPublicationState PublicationState { get; init; }

        public string ServerId { get; init; } = string.Empty;

        public string ServiceIdentity { get; init; } = string.Empty;

        public IReadOnlyList<ServerListener> Listeners { get; init; } =
            Array.Empty<ServerListener>();

        public ProtectedStoreReference TlsCertificateReference { get; init; } = new();

        public ProtectedStoreReference EnrollmentIssuerReference { get; init; } = new();

        public ProviderReference DatabaseProvider { get; init; } = new();

        public ProviderReference ArtifactProvider { get; init; } = new();

        public InfrastructureResourceLimits ResourceLimits { get; init; } = new();

        public string AuditPolicyReference { get; init; } = string.Empty;

        public string RetentionPolicyReference { get; init; } = string.Empty;
    }

    public sealed record ValidationDiagnostic(
        DiagnosticSeverity Severity,
        string ErrorCode,
        string Field,
        string Message);

    public sealed record ValidationResult(IReadOnlyList<ValidationDiagnostic> Diagnostics)
    {
        public bool IsValid => Diagnostics.All(diagnostic => diagnostic.Severity != DiagnosticSeverity.Error);
    }

    public sealed record DecodeResult<T>(
        DecodeOutcome Outcome,
        T? Configuration,
        IReadOnlyList<ValidationDiagnostic> Diagnostics)
        where T : class
    {
        public bool IsValid => Outcome == DecodeOutcome.Valid && Configuration != null;
    }

    public sealed record ConfigurationSummary(
        ConfigurationKind Kind,
        int SchemaVersion,
        long Revision,
        ConfigurationOwnerKind Owner,
        bool Enabled,
        ServerPublicationState PublicationState,
        int EndpointOrListenerCount,
        int ProtectedReferenceCount,
        string CanonicalSha256);
}
