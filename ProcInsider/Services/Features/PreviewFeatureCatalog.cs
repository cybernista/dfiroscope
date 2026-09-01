using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// Explicit test/preview catalog that promotes ReadyHidden only. Public startup
/// never constructs this wrapper.
/// </summary>
public sealed class PreviewFeatureCatalog : IFeatureCatalog
{
    private readonly IFeatureCatalog _source;

    public PreviewFeatureCatalog(IFeatureCatalog source)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        ReleaseId = $"{source.ReleaseId}-preview";
        Features = new ReadOnlyCollection<FeatureDefinition>(source.Features.ToArray());

        foreach (var definition in Features.Where(definition => IsPublished(definition.Id)))
        {
            var hiddenDependency = definition.Dependencies.FirstOrDefault(dependency => !IsPublished(dependency));
            if (!hiddenDependency.IsEmpty)
            {
                throw new InvalidOperationException(
                    $"Preview feature '{definition.Id}' depends on unavailable feature '{hiddenDependency}'.");
            }
        }
    }

    public string ReleaseId { get; }
    public IReadOnlyList<FeatureDefinition> Features { get; }
    public bool IsKnown(FeatureId featureId) => _source.IsKnown(featureId);
    public bool IsPublished(FeatureId featureId) =>
        _source.GetReleaseState(featureId) is FeatureReleaseState.Published or FeatureReleaseState.ReadyHidden;
    public FeatureReleaseState? GetReleaseState(FeatureId featureId) => _source.GetReleaseState(featureId);
    public IReadOnlyList<FeatureId> GetDependencies(FeatureId featureId) => _source.GetDependencies(featureId);
    public bool TryGetDefinition(
        FeatureId featureId,
        [NotNullWhen(true)] out FeatureDefinition? definition) =>
        _source.TryGetDefinition(featureId, out definition);
}
