using System.Collections.ObjectModel;

namespace ProcInsider.Models.Features;

public readonly record struct InfrastructurePublicationGroupId
{
    public InfrastructurePublicationGroupId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Infrastructure publication-group IDs cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public string Value { get; }

    public bool IsEmpty => string.IsNullOrEmpty(Value);

    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct DeploymentProfileId
{
    public DeploymentProfileId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Deployment profile IDs cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public string Value { get; }

    public bool IsEmpty => string.IsNullOrEmpty(Value);

    public override string ToString() => Value ?? string.Empty;
}

public enum DeploymentModeKind
{
    Unknown = 0,
    Standalone = 1,
    Infrastructure = 2
}

public enum InfrastructureComponentKind
{
    Unknown = 0,
    Viewer = 1,
    Server = 2,
    AgentService = 3
}

public enum InfrastructureEntryPointKind
{
    Unknown = 0,
    ServiceConstruction = 1,
    EndpointBinding = 2,
    CredentialAccess = 3,
    ConfigurationAccess = 4,
    DatabaseConnection = 5,
    IpcOrNetworkClientCreation = 6,
    HandlerConstruction = 7,
    UserInterfaceDescriptor = 8,
    Navigation = 9
}

public enum InfrastructureFeatureArea
{
    Unknown = 0,
    AgentManagement = 1,
    CaseWorkspaces = 2,
    Administration = 3
}

public sealed record InfrastructureComponentProfileIdentity
{
    public InfrastructureComponentProfileIdentity(
        InfrastructureComponentKind component,
        DeploymentModeKind deploymentMode,
        InfrastructurePublicationGroupId publicationGroupId,
        DeploymentProfileId profileId,
        string releaseId,
        int protocolGeneration)
    {
        if (component == InfrastructureComponentKind.Unknown || !Enum.IsDefined(component))
        {
            throw new ArgumentOutOfRangeException(nameof(component));
        }

        if (deploymentMode == DeploymentModeKind.Unknown || !Enum.IsDefined(deploymentMode))
        {
            throw new ArgumentOutOfRangeException(nameof(deploymentMode));
        }

        if (publicationGroupId.IsEmpty)
        {
            throw new ArgumentException("A component identity requires a publication-group ID.", nameof(publicationGroupId));
        }

        if (profileId.IsEmpty)
        {
            throw new ArgumentException("A component identity requires a deployment-profile ID.", nameof(profileId));
        }

        if (string.IsNullOrWhiteSpace(releaseId))
        {
            throw new ArgumentException("A component identity requires a release ID.", nameof(releaseId));
        }

        if (protocolGeneration <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(protocolGeneration));
        }

        Component = component;
        DeploymentMode = deploymentMode;
        PublicationGroupId = publicationGroupId;
        ProfileId = profileId;
        ReleaseId = releaseId;
        ProtocolGeneration = protocolGeneration;
    }

    public InfrastructureComponentKind Component { get; }

    public DeploymentModeKind DeploymentMode { get; }

    public InfrastructurePublicationGroupId PublicationGroupId { get; }

    public DeploymentProfileId ProfileId { get; }

    public string ReleaseId { get; }

    public int ProtocolGeneration { get; }
}

/// <summary>
/// Immutable compiled publication/deployment description shared by the future Infrastructure
/// Viewer, Server, and Agent Service. It contains identity and feature ownership only; it does
/// not construct a service, read configuration, or perform I/O.
/// </summary>
public sealed class InfrastructurePublicationGroupDefinition
{
    public InfrastructurePublicationGroupDefinition(
        InfrastructurePublicationGroupId id,
        DeploymentProfileId profileId,
        string releaseId,
        int protocolGeneration,
        FeatureId rootFeatureId,
        IReadOnlyDictionary<InfrastructureFeatureArea, FeatureId> userVisibleFeatures,
        IEnumerable<InfrastructureComponentKind> components,
        IEnumerable<InfrastructureEntryPointKind> protectedEntryPoints)
    {
        if (id.IsEmpty)
        {
            throw new ArgumentException("An Infrastructure publication group requires an ID.", nameof(id));
        }

        if (profileId.IsEmpty)
        {
            throw new ArgumentException("An Infrastructure publication group requires a profile ID.", nameof(profileId));
        }

        if (string.IsNullOrWhiteSpace(releaseId))
        {
            throw new ArgumentException("An Infrastructure publication group requires a release ID.", nameof(releaseId));
        }

        if (protocolGeneration <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(protocolGeneration));
        }

        if (rootFeatureId.IsEmpty)
        {
            throw new ArgumentException("An Infrastructure publication group requires a root feature ID.", nameof(rootFeatureId));
        }

        ArgumentNullException.ThrowIfNull(userVisibleFeatures);
        ArgumentNullException.ThrowIfNull(components);
        ArgumentNullException.ThrowIfNull(protectedEntryPoints);

        Id = id;
        ProfileId = profileId;
        ReleaseId = releaseId;
        ProtocolGeneration = protocolGeneration;
        RootFeatureId = rootFeatureId;
        UserVisibleFeatures = new ReadOnlyDictionary<InfrastructureFeatureArea, FeatureId>(
            userVisibleFeatures.ToDictionary(pair => pair.Key, pair => pair.Value));
        Components = new ReadOnlyCollection<InfrastructureComponentKind>(components.Distinct().ToArray());
        ProtectedEntryPoints = new ReadOnlyCollection<InfrastructureEntryPointKind>(
            protectedEntryPoints.Distinct().ToArray());
    }

    public InfrastructurePublicationGroupId Id { get; }

    public DeploymentModeKind DeploymentMode => DeploymentModeKind.Infrastructure;

    public DeploymentProfileId ProfileId { get; }

    public string ReleaseId { get; }

    public int ProtocolGeneration { get; }

    public FeatureId RootFeatureId { get; }

    public IReadOnlyDictionary<InfrastructureFeatureArea, FeatureId> UserVisibleFeatures { get; }

    public IReadOnlyList<InfrastructureComponentKind> Components { get; }

    public IReadOnlyList<InfrastructureEntryPointKind> ProtectedEntryPoints { get; }

    public InfrastructureComponentProfileIdentity CreateIdentity(InfrastructureComponentKind component) =>
        new(component, DeploymentMode, Id, ProfileId, ReleaseId, ProtocolGeneration);

    public InfrastructurePublicationGroupDefinition ForRelease(string releaseId) =>
        new(
            Id,
            ProfileId,
            releaseId,
            ProtocolGeneration,
            RootFeatureId,
            UserVisibleFeatures,
            Components,
            ProtectedEntryPoints);
}
