using System.Collections.ObjectModel;

namespace ProcInsider.Models.Features;

/// <summary>
/// Core-owned immutable publication metadata for one releasable feature.
/// </summary>
public sealed record FeatureDefinition
{
    public FeatureDefinition(
        FeatureId id,
        FeatureReleaseState state,
        IEnumerable<FeatureId>? dependencies = null)
    {
        if (id.IsEmpty)
        {
            throw new ArgumentException("Feature definitions require a non-empty ID.", nameof(id));
        }

        Id = id;
        State = state;
        Dependencies = new ReadOnlyCollection<FeatureId>(
            (dependencies ?? []).Distinct().ToArray());
    }

    public FeatureId Id { get; }

    public FeatureReleaseState State { get; }

    public IReadOnlyList<FeatureId> Dependencies { get; }
}
