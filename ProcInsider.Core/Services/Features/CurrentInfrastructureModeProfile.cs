using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// The single compiled Infrastructure Mode publication and deployment identity. No public
/// runtime input selects or overrides this profile.
/// </summary>
public static class CurrentInfrastructureModeProfile
{
    public static readonly InfrastructurePublicationGroupId PublicationGroupId =
        new("infrastructure-mode");

    public static readonly DeploymentProfileId ProfileId =
        new("infrastructure-g1");

    public const int ProtocolGeneration = 1;

    public static InfrastructurePublicationGroupDefinition Definition { get; } =
        new(
            PublicationGroupId,
            ProfileId,
            CurrentEducationalReleaseProfile.ReleaseId,
            ProtocolGeneration,
            FeatureIds.InfrastructureMode,
            new Dictionary<InfrastructureFeatureArea, FeatureId>
            {
                [InfrastructureFeatureArea.AgentManagement] = FeatureIds.InfrastructureAgentManagement,
                [InfrastructureFeatureArea.CaseWorkspaces] = FeatureIds.InfrastructureCaseWorkspaces,
                [InfrastructureFeatureArea.Administration] = FeatureIds.InfrastructureAdministration
            },
            Enum.GetValues<InfrastructureComponentKind>()
                .Where(component => component != InfrastructureComponentKind.Unknown),
            Enum.GetValues<InfrastructureEntryPointKind>()
                .Where(entryPoint => entryPoint != InfrastructureEntryPointKind.Unknown));

    public static InfrastructureModeAccessService CreateAccessService(
        InfrastructureComponentKind component) =>
        new(
            CurrentEducationalReleaseProfile.Catalog,
            Definition,
            Definition.CreateIdentity(component));
}
