namespace ProcInsider.Features.Infrastructure;

/// <summary>
/// Immutable presentation-only grouping for exact Server case/host/Agent/capture/source-run
/// identities. It never supplies query authority; selected scope fields remain explicit inputs.
/// </summary>
public sealed record InfrastructureScopeNodeViewModel(
    string DisplayText,
    bool IsAmbiguous,
    IReadOnlyList<InfrastructureScopeNodeViewModel> Children)
{
    public string RelationshipState => IsAmbiguous ? "ambiguous" : string.Empty;
}
