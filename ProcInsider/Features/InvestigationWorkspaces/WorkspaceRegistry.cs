using ProcInsider.Models.Features;
using ProcInsider.Models.InvestigationWorkspaces;
using ProcInsider.Services.Features;

namespace ProcInsider.Features.InvestigationWorkspaces;

internal sealed class WorkspaceRegistry(FeatureAccessService access)
{
    private readonly Dictionary<WorkspaceTypeId, (WorkspaceTypeMetadata Metadata, FeatureId Feature, Func<int, WorkspaceInstanceViewModel> Factory)> _types = [];
    internal bool IsAvailable(WorkspaceTypeId type) => _types.TryGetValue(type, out var entry) && access.IsPublished(entry.Feature);
    public void Register(WorkspaceTypeMetadata type, FeatureId feature, Func<int, WorkspaceInstanceViewModel> factory)
    {
        if (string.IsNullOrWhiteSpace(type.Id.Value) || !_types.TryAdd(type.Id, (type, feature, factory)))
            throw new InvalidOperationException("A workspace type must have a unique stable identity.");
    }
    public WorkspaceInstanceViewModel Create(WorkspaceTypeId type, int ordinal)
    {
        if (!_types.TryGetValue(type, out var registration) || !access.IsPublished(registration.Feature))
            throw new InvalidOperationException("This workspace type is unavailable.");
        return registration.Factory(ordinal);
    }
}
