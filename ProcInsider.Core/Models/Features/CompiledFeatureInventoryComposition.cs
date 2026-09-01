using System.Collections.ObjectModel;

namespace ProcInsider.Models.Features;

/// <summary>
/// Compile-time-only extension point for feature identities and canonical hidden
/// definitions contributed by the private source boundary. Public builds have no
/// implementation for the partial methods and therefore retain the exact base
/// inventory.
/// </summary>
public static partial class CompiledFeatureInventoryComposition
{
    public static IReadOnlyList<FeatureId> CompleteFeatureIds(
        IEnumerable<FeatureId> baseFeatureIds)
    {
        ArgumentNullException.ThrowIfNull(baseFeatureIds);
        var baseIds = baseFeatureIds.ToArray();
        var completed = new List<FeatureId>(baseIds);
        AddPrivateFeatureIds(completed);
        ValidateFeatureIds(baseIds, completed);
        return new ReadOnlyCollection<FeatureId>(completed.ToArray());
    }

    public static IReadOnlyList<FeatureDefinition> CompleteFeatureDefinitions(
        IEnumerable<FeatureDefinition> baseDefinitions)
    {
        ArgumentNullException.ThrowIfNull(baseDefinitions);
        var baseArray = baseDefinitions.ToArray();
        if (baseArray.Any(definition => definition == null))
        {
            throw new ArgumentException(
                "Base feature definitions cannot contain null entries.",
                nameof(baseDefinitions));
        }

        var completed = new List<FeatureDefinition>(baseArray);
        AddPrivateFeatureDefinitions(completed);
        ValidateFeatureDefinitions(baseArray, completed);
        return new ReadOnlyCollection<FeatureDefinition>(completed.ToArray());
    }

    internal static void ValidateFeatureIds(
        IReadOnlyList<FeatureId> baseFeatureIds,
        IReadOnlyList<FeatureId> completedFeatureIds)
    {
        ArgumentNullException.ThrowIfNull(baseFeatureIds);
        ArgumentNullException.ThrowIfNull(completedFeatureIds);
        if (completedFeatureIds.Any(featureId => featureId.IsEmpty))
        {
            throw new InvalidOperationException(
                "Compiled feature inventory cannot contain an empty feature ID.");
        }

        var duplicate = completedFeatureIds
            .GroupBy(featureId => featureId)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate != null)
        {
            throw new InvalidOperationException(
                $"Compiled feature inventory contains duplicate ID '{duplicate.Key}'.");
        }

        var completedSet = completedFeatureIds.ToHashSet();
        var missingBase = baseFeatureIds.FirstOrDefault(featureId => !completedSet.Contains(featureId));
        if (!missingBase.IsEmpty)
        {
            throw new InvalidOperationException(
                $"Compiled feature inventory removed base feature ID '{missingBase}'.");
        }
    }

    internal static void ValidateFeatureDefinitions(
        IReadOnlyList<FeatureDefinition> baseDefinitions,
        IReadOnlyList<FeatureDefinition> completedDefinitions)
    {
        ArgumentNullException.ThrowIfNull(baseDefinitions);
        ArgumentNullException.ThrowIfNull(completedDefinitions);
        if (completedDefinitions.Any(definition => definition == null))
        {
            throw new InvalidOperationException(
                "Compiled feature definitions cannot contain null entries.");
        }

        var duplicate = completedDefinitions
            .GroupBy(definition => definition.Id)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate != null)
        {
            throw new InvalidOperationException(
                $"Compiled feature definitions contain duplicate ID '{duplicate.Key}'.");
        }

        var completedById = completedDefinitions.ToDictionary(definition => definition.Id);
        foreach (var baseDefinition in baseDefinitions)
        {
            if (!completedById.TryGetValue(baseDefinition.Id, out var completedDefinition) ||
                completedDefinition.State != baseDefinition.State ||
                !completedDefinition.Dependencies.ToHashSet().SetEquals(baseDefinition.Dependencies))
            {
                throw new InvalidOperationException(
                    $"Compiled feature definitions changed or removed base feature '{baseDefinition.Id}'.");
            }
        }

        foreach (var privateDefinition in completedDefinitions.Skip(baseDefinitions.Count))
        {
            if (privateDefinition.State is not
                (FeatureReleaseState.ReadyHidden or FeatureReleaseState.InDevelopment))
            {
                throw new InvalidOperationException(
                    $"Private compiled feature '{privateDefinition.Id}' must remain ReadyHidden or InDevelopment.");
            }
        }
    }

    static partial void AddPrivateFeatureIds(List<FeatureId> featureIds);

    static partial void AddPrivateFeatureDefinitions(List<FeatureDefinition> featureDefinitions);
}
