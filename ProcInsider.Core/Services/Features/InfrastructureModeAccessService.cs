using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

public enum InfrastructureAccessOutcome
{
    Allowed = 0,
    Unavailable = 1,
    ProfileMismatch = 2,
    ProtocolMismatch = 3,
    TopologyMismatch = 4,
    UnknownEntryPoint = 5,
    FeatureAreaRequired = 6,
    UnknownFeatureArea = 7
}

public static class InfrastructureAccessErrorCodes
{
    public const string Allowed = "InfrastructureAccessAllowed";
    public const string Unavailable = "InfrastructureUnavailable";
    public const string ProfileMismatch = "InfrastructureProfileMismatch";
    public const string ProtocolMismatch = "InfrastructureProtocolMismatch";
    public const string TopologyMismatch = "InfrastructureTopologyMismatch";
    public const string UnknownEntryPoint = "InfrastructureEntryPointUnknown";
    public const string FeatureAreaRequired = "InfrastructureFeatureAreaRequired";
    public const string UnknownFeatureArea = "InfrastructureFeatureAreaUnknown";
}

public sealed record InfrastructureAccessDecision(
    InfrastructureAccessOutcome Outcome,
    string ErrorCode,
    string Message)
{
    public bool IsAllowed => Outcome == InfrastructureAccessOutcome.Allowed;
}

/// <summary>
/// Side-effect-free fence that future Infrastructure components must cross before construction
/// or activation. Publication is additive to later authentication, authorization, prerequisites,
/// target identity, sealing, provenance, and write-policy checks.
/// </summary>
public sealed class InfrastructureModeAccessService
{
    private readonly IFeatureCatalog _catalog;
    private readonly InfrastructurePublicationGroupDefinition _definition;
    private readonly InfrastructureComponentProfileIdentity _localIdentity;

    public InfrastructureModeAccessService(
        IFeatureCatalog catalog,
        InfrastructurePublicationGroupDefinition definition,
        InfrastructureComponentProfileIdentity localIdentity)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(localIdentity);

        _catalog = catalog;
        _definition = definition;
        _localIdentity = localIdentity;
    }

    public InfrastructureAccessDecision Evaluate(
        InfrastructureEntryPointKind entryPoint,
        InfrastructureFeatureArea featureArea = InfrastructureFeatureArea.Unknown,
        InfrastructureComponentProfileIdentity? peerIdentity = null)
    {
        if (entryPoint == InfrastructureEntryPointKind.Unknown || !Enum.IsDefined(entryPoint))
        {
            return Deny(
                InfrastructureAccessOutcome.UnknownEntryPoint,
                InfrastructureAccessErrorCodes.UnknownEntryPoint,
                $"Infrastructure entry point '{entryPoint}' is unknown and fails closed.");
        }

        if (!_definition.ProtectedEntryPoints.Contains(entryPoint))
        {
            return Deny(
                InfrastructureAccessOutcome.UnknownEntryPoint,
                InfrastructureAccessErrorCodes.UnknownEntryPoint,
                $"Infrastructure entry point '{entryPoint}' has no compiled publication classification.");
        }

        if (!MatchesProfile(_localIdentity))
        {
            return ProfileMismatch(_localIdentity, "local");
        }

        if (_localIdentity.ProtocolGeneration != _definition.ProtocolGeneration)
        {
            return ProtocolMismatch(_localIdentity, "local");
        }

        if (peerIdentity is not null)
        {
            if (!MatchesProfile(peerIdentity))
            {
                return ProfileMismatch(peerIdentity, "peer");
            }

            if (peerIdentity.ProtocolGeneration != _definition.ProtocolGeneration)
            {
                return ProtocolMismatch(peerIdentity, "peer");
            }

            if (!IsAllowedPeer(_localIdentity.Component, peerIdentity.Component))
            {
                return Deny(
                    InfrastructureAccessOutcome.TopologyMismatch,
                    InfrastructureAccessErrorCodes.TopologyMismatch,
                    $"Infrastructure topology forbids {_localIdentity.Component} to {peerIdentity.Component} activation.");
            }
        }

        if (!_catalog.IsPublished(_definition.RootFeatureId))
        {
            return FeatureUnavailable(_definition.RootFeatureId);
        }

        var requiresFeatureArea = entryPoint is
            InfrastructureEntryPointKind.UserInterfaceDescriptor or
            InfrastructureEntryPointKind.Navigation;
        if (requiresFeatureArea && featureArea == InfrastructureFeatureArea.Unknown)
        {
            return Deny(
                InfrastructureAccessOutcome.FeatureAreaRequired,
                InfrastructureAccessErrorCodes.FeatureAreaRequired,
                $"Infrastructure entry point '{entryPoint}' requires one compiled user-visible feature area.");
        }

        if (featureArea != InfrastructureFeatureArea.Unknown)
        {
            if (!Enum.IsDefined(featureArea) ||
                !_definition.UserVisibleFeatures.TryGetValue(featureArea, out var featureId))
            {
                return Deny(
                    InfrastructureAccessOutcome.UnknownFeatureArea,
                    InfrastructureAccessErrorCodes.UnknownFeatureArea,
                    $"Infrastructure feature area '{featureArea}' is unknown and fails closed.");
            }

            if (!_catalog.IsPublished(featureId))
            {
                return FeatureUnavailable(featureId);
            }
        }

        return new InfrastructureAccessDecision(
            InfrastructureAccessOutcome.Allowed,
            InfrastructureAccessErrorCodes.Allowed,
            $"Infrastructure entry point '{entryPoint}' is published for release '{_catalog.ReleaseId}'.");
    }

    public bool TryCreate<T>(
        InfrastructureEntryPointKind entryPoint,
        Func<T> factory,
        out T? value,
        out InfrastructureAccessDecision decision,
        InfrastructureFeatureArea featureArea = InfrastructureFeatureArea.Unknown,
        InfrastructureComponentProfileIdentity? peerIdentity = null)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(factory);

        decision = Evaluate(entryPoint, featureArea, peerIdentity);
        if (!decision.IsAllowed)
        {
            value = null;
            return false;
        }

        value = factory();
        return true;
    }

    private bool MatchesProfile(InfrastructureComponentProfileIdentity identity) =>
        identity.Component != InfrastructureComponentKind.Unknown &&
        Enum.IsDefined(identity.Component) &&
        identity.DeploymentMode == _definition.DeploymentMode &&
        identity.PublicationGroupId == _definition.Id &&
        identity.ProfileId == _definition.ProfileId &&
        string.Equals(identity.ReleaseId, _definition.ReleaseId, StringComparison.Ordinal);

    private InfrastructureAccessDecision ProfileMismatch(
        InfrastructureComponentProfileIdentity identity,
        string subject) =>
        Deny(
            InfrastructureAccessOutcome.ProfileMismatch,
            InfrastructureAccessErrorCodes.ProfileMismatch,
            $"Infrastructure {subject} profile '{identity.ProfileId}' release '{identity.ReleaseId}' does not match compiled profile '{_definition.ProfileId}' release '{_definition.ReleaseId}'.");

    private InfrastructureAccessDecision ProtocolMismatch(
        InfrastructureComponentProfileIdentity identity,
        string subject) =>
        Deny(
            InfrastructureAccessOutcome.ProtocolMismatch,
            InfrastructureAccessErrorCodes.ProtocolMismatch,
            $"Infrastructure {subject} protocol generation {identity.ProtocolGeneration} does not match compiled generation {_definition.ProtocolGeneration}.");

    private InfrastructureAccessDecision FeatureUnavailable(FeatureId featureId)
    {
        var state = _catalog.GetReleaseState(featureId)?.ToString() ?? "Unknown";
        return Deny(
            InfrastructureAccessOutcome.Unavailable,
            InfrastructureAccessErrorCodes.Unavailable,
            $"Infrastructure feature '{featureId}' is {state} in release '{_catalog.ReleaseId}' and is unavailable.");
    }

    private static bool IsAllowedPeer(
        InfrastructureComponentKind local,
        InfrastructureComponentKind peer) =>
        (local, peer) switch
        {
            (InfrastructureComponentKind.Viewer, InfrastructureComponentKind.Server) => true,
            (InfrastructureComponentKind.AgentService, InfrastructureComponentKind.Server) => true,
            (InfrastructureComponentKind.Server, InfrastructureComponentKind.Viewer) => true,
            (InfrastructureComponentKind.Server, InfrastructureComponentKind.AgentService) => true,
            _ => false
        };

    private static InfrastructureAccessDecision Deny(
        InfrastructureAccessOutcome outcome,
        string errorCode,
        string message) =>
        new(outcome, errorCode, message);
}
