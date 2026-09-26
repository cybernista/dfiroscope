using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// Core-owned read-only, validated publication catalog. Publication is product metadata,
/// not a security boundary or a runtime prerequisite check.
/// </summary>
public sealed class FeatureCatalog : IFeatureCatalog
{
    private static readonly IReadOnlyList<FeatureId> NoDependencies =
        Array.AsReadOnly(Array.Empty<FeatureId>());

    private readonly IReadOnlyDictionary<FeatureId, FeatureDefinition> _definitionsById;

    public FeatureCatalog(string releaseId, IEnumerable<FeatureDefinition> definitions)
    {
        if (string.IsNullOrWhiteSpace(releaseId))
        {
            throw new ArgumentException("A release catalog requires a stable release ID.", nameof(releaseId));
        }

        ArgumentNullException.ThrowIfNull(definitions);

        var definitionArray = definitions.ToArray();
        var definitionsById = new Dictionary<FeatureId, FeatureDefinition>();
        foreach (var definition in definitionArray)
        {
            ArgumentNullException.ThrowIfNull(definition);
            if (!definitionsById.TryAdd(definition.Id, definition))
            {
                throw new InvalidOperationException(
                    $"Release '{releaseId}' contains duplicate feature ID '{definition.Id}'.");
            }
        }

        ValidateDependencies(releaseId, definitionsById);
        ValidateAcyclic(releaseId, definitionsById);
        ValidatePublishedDependencies(releaseId, definitionsById);

        ReleaseId = releaseId;
        Features = new ReadOnlyCollection<FeatureDefinition>(definitionArray);
        _definitionsById = new ReadOnlyDictionary<FeatureId, FeatureDefinition>(definitionsById);
    }

    public string ReleaseId { get; }

    public IReadOnlyList<FeatureDefinition> Features { get; }

    public bool IsKnown(FeatureId featureId) =>
        !featureId.IsEmpty && _definitionsById.ContainsKey(featureId);

    public bool IsPublished(FeatureId featureId) =>
        TryGetDefinition(featureId, out var definition) &&
        definition.State == FeatureReleaseState.Published;

    public FeatureReleaseState? GetReleaseState(FeatureId featureId) =>
        TryGetDefinition(featureId, out var definition) ? definition.State : null;

    public IReadOnlyList<FeatureId> GetDependencies(FeatureId featureId) =>
        TryGetDefinition(featureId, out var definition)
            ? definition.Dependencies
            : NoDependencies;

    public bool TryGetDefinition(
        FeatureId featureId,
        [NotNullWhen(true)] out FeatureDefinition? definition)
    {
        if (featureId.IsEmpty)
        {
            definition = null;
            return false;
        }

        return _definitionsById.TryGetValue(featureId, out definition);
    }

    private static void ValidateDependencies(
        string releaseId,
        IReadOnlyDictionary<FeatureId, FeatureDefinition> definitions)
    {
        foreach (var definition in definitions.Values)
        {
            foreach (var dependency in definition.Dependencies)
            {
                if (!definitions.ContainsKey(dependency))
                {
                    throw new InvalidOperationException(
                        $"Release '{releaseId}' feature '{definition.Id}' depends on unknown feature '{dependency}'.");
                }
            }
        }
    }

    private static void ValidatePublishedDependencies(
        string releaseId,
        IReadOnlyDictionary<FeatureId, FeatureDefinition> definitions)
    {
        foreach (var definition in definitions.Values.Where(
                     definition => definition.State == FeatureReleaseState.Published))
        {
            foreach (var dependency in definition.Dependencies)
            {
                var dependencyDefinition = definitions[dependency];
                if (dependencyDefinition.State != FeatureReleaseState.Published)
                {
                    throw new InvalidOperationException(
                        $"Release '{releaseId}' publishes '{definition.Id}' but its dependency " +
                        $"'{dependency}' is {dependencyDefinition.State}.");
                }
            }
        }
    }

    private static void ValidateAcyclic(
        string releaseId,
        IReadOnlyDictionary<FeatureId, FeatureDefinition> definitions)
    {
        var visitState = new Dictionary<FeatureId, int>();
        var path = new List<FeatureId>();

        foreach (var featureId in definitions.Keys)
        {
            Visit(featureId);
        }

        return;

        void Visit(FeatureId featureId)
        {
            if (visitState.TryGetValue(featureId, out var state))
            {
                if (state == 2)
                {
                    return;
                }

                var cycleStart = path.IndexOf(featureId);
                var cycle = path.Skip(Math.Max(0, cycleStart)).Append(featureId);
                throw new InvalidOperationException(
                    $"Release '{releaseId}' contains a feature dependency cycle: {string.Join(" -> ", cycle)}.");
            }

            visitState[featureId] = 1;
            path.Add(featureId);
            foreach (var dependency in definitions[featureId].Dependencies)
            {
                Visit(dependency);
            }

            path.RemoveAt(path.Count - 1);
            visitState[featureId] = 2;
        }
    }
}
