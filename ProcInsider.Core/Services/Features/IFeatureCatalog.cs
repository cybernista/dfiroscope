using System.Diagnostics.CodeAnalysis;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>Core-owned read-only educational release catalog contract.</summary>
public interface IFeatureCatalog
{
    string ReleaseId { get; }

    IReadOnlyList<FeatureDefinition> Features { get; }

    bool IsKnown(FeatureId featureId);

    bool IsPublished(FeatureId featureId);

    FeatureReleaseState? GetReleaseState(FeatureId featureId);

    IReadOnlyList<FeatureId> GetDependencies(FeatureId featureId);

    bool TryGetDefinition(
        FeatureId featureId,
        [NotNullWhen(true)] out FeatureDefinition? definition);
}
