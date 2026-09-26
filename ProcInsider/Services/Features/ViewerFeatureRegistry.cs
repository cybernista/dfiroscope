using System.Collections.ObjectModel;
using System.Text;
using ProcInsider.Models.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Services.Features;

/// <summary>
/// Validates and composes the bounded set of viewer features migrated to typed
/// definitions. It does not replace the release catalog, tab-set policy, agent
/// command policy, runtime prerequisites, or capture policy.
/// </summary>
public sealed class ViewerFeatureRegistry
{
    private readonly IReadOnlyList<IViewerFeatureDefinition> _definitions;

    public ViewerFeatureRegistry(
        IFeatureCatalog catalog,
        IEnumerable<IViewerFeatureDefinition> definitions,
        IEnumerable<FeatureId> requiredFeatureIds)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(definitions);
        ArgumentNullException.ThrowIfNull(requiredFeatureIds);

        var definitionArray = definitions.ToArray();
        var requiredArray = requiredFeatureIds.ToArray();
        if (definitionArray.Any(definition => definition == null))
        {
            throw new ArgumentException("Viewer feature definitions cannot contain null entries.", nameof(definitions));
        }

        var duplicateRequiredId = requiredArray
            .GroupBy(id => id)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateRequiredId != null)
        {
            throw new InvalidOperationException(
                $"Viewer feature mapping contains duplicate required ID '{duplicateRequiredId.Key}'.");
        }

        var duplicateDefinitionId = definitionArray
            .GroupBy(definition => definition.Id)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateDefinitionId != null)
        {
            throw new InvalidOperationException(
                $"Viewer feature registry contains duplicate feature ID '{duplicateDefinitionId.Key}'.");
        }

        var required = requiredArray.ToHashSet();
        var definitionsById = definitionArray.ToDictionary(definition => definition.Id);
        foreach (var requiredFeatureId in requiredArray)
        {
            if (requiredFeatureId.IsEmpty)
            {
                throw new InvalidOperationException("Viewer feature mappings cannot require an empty feature ID.");
            }

            if (!catalog.IsKnown(requiredFeatureId))
            {
                throw new InvalidOperationException(
                    $"Viewer feature '{requiredFeatureId}' has no publication classification in release '{catalog.ReleaseId}'.");
            }

            if (!definitionsById.ContainsKey(requiredFeatureId))
            {
                throw new InvalidOperationException(
                    $"Viewer feature '{requiredFeatureId}' is missing its typed definition mapping.");
            }
        }

        foreach (var definition in definitionArray)
        {
            if (!required.Contains(definition.Id))
            {
                throw new InvalidOperationException(
                    $"Viewer feature '{definition.Id}' has a definition but is not declared in the required mapping.");
            }

            if (!catalog.TryGetDefinition(definition.Id, out var publicationDefinition))
            {
                throw new InvalidOperationException(
                    $"Viewer feature '{definition.Id}' activation has no matching publication definition in release '{catalog.ReleaseId}'.");
            }

            if (!HaveSameDependencies(definition.Dependencies, publicationDefinition.Dependencies))
            {
                throw new InvalidOperationException(
                    $"Viewer feature '{definition.Id}' dependency disagreement: viewer=[{FormatIds(definition.Dependencies)}], " +
                    $"publication=[{FormatIds(publicationDefinition.Dependencies)}].");
            }

            if (definition.Tabs.Count > 0 && !definition.HasActivationFactory)
            {
                throw new InvalidOperationException(
                    $"Viewer feature '{definition.Id}' maps tabs but has no activation factory.");
            }

            if (definition.HasActivationFactory && !definition.HasDeactivation)
            {
                throw new InvalidOperationException(
                    $"Viewer feature '{definition.Id}' has an activation factory but no explicit lifecycle cleanup delegate.");
            }
        }

        var tabs = definitionArray.SelectMany(definition => definition.Tabs).ToArray();
        var duplicateTabKey = tabs
            .GroupBy(tab => tab.Key)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateTabKey != null)
        {
            throw new InvalidOperationException(
                $"Viewer feature registry contains duplicate tab key '{duplicateTabKey.Key}'.");
        }

        var duplicateTabOrder = tabs
            .GroupBy(tab => new { tab.Key.Surface, tab.Order })
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateTabOrder != null)
        {
            throw new InvalidOperationException(
                $"Viewer feature registry contains duplicate {duplicateTabOrder.Key.Surface} tab order " +
                $"'{duplicateTabOrder.Key.Order}'.");
        }

        Catalog = catalog;
        _definitions = new ReadOnlyCollection<IViewerFeatureDefinition>(definitionArray);
        DiagnosticInventory = BuildDiagnosticInventory(definitionArray);
    }

    public IFeatureCatalog Catalog { get; }

    public IReadOnlyList<IViewerFeatureDefinition> Definitions => _definitions;

    public string DiagnosticInventory { get; }

    public void RegisterActivations(FeatureActivationRegistry activationRegistry)
    {
        ArgumentNullException.ThrowIfNull(activationRegistry);
        foreach (var definition in _definitions)
        {
            definition.RegisterActivation(activationRegistry);
        }
    }

    public IReadOnlyList<FeatureTabDescriptor> CreateTabDescriptors(
        FeatureTabSurface surface,
        FeatureActivationRegistry activationRegistry)
    {
        if (!Enum.IsDefined(surface))
        {
            throw new ArgumentOutOfRangeException(nameof(surface), surface, "Unknown viewer tab surface.");
        }

        ArgumentNullException.ThrowIfNull(activationRegistry);
        return new ReadOnlyCollection<FeatureTabDescriptor>(
            _definitions
                .SelectMany(definition => definition.CreateTabDescriptors(activationRegistry))
                .Where(descriptor => descriptor.Key.Surface == surface)
                .OrderBy(descriptor => descriptor.Order)
                .ThenBy(descriptor => descriptor.Key.TabId, StringComparer.Ordinal)
                .ToArray());
    }

    private static bool HaveSameDependencies(
        IReadOnlyList<FeatureId> left,
        IReadOnlyList<FeatureId> right) =>
        left.Count == right.Count && left.ToHashSet().SetEquals(right);

    private static string FormatIds(IEnumerable<FeatureId> featureIds)
    {
        var values = featureIds
            .Select(featureId => featureId.Value)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        return values.Length == 0 ? "(none)" : string.Join(',', values);
    }

    private static string BuildDiagnosticInventory(
        IReadOnlyList<IViewerFeatureDefinition> definitions)
    {
        var builder = new StringBuilder();
        builder.Append("viewer_feature_definitions[")
            .Append(definitions.Count)
            .Append("]\n");

        foreach (var definition in definitions.OrderBy(
                     definition => definition.Id.Value,
                     StringComparer.Ordinal))
        {
            var tabs = definition.Tabs
                .OrderBy(tab => tab.Key.Surface)
                .ThenBy(tab => tab.Order)
                .ThenBy(tab => tab.Key.TabId, StringComparer.Ordinal)
                .Select(tab => $"{tab.Key}@{tab.Order}")
                .ToArray();
            builder.Append(definition.Id)
                .Append(" module=")
                .Append(definition.ModuleType.FullName ?? definition.ModuleType.Name)
                .Append(" activation=")
                .Append(definition.HasActivationFactory ? "yes" : "no")
                .Append(" cleanup=")
                .Append(definition.HasDeactivation ? "yes" : "no")
                .Append(" dependencies=")
                .Append(FormatIds(definition.Dependencies))
                .Append(" tabs=")
                .Append(tabs.Length == 0 ? "(none)" : string.Join(',', tabs))
                .Append('\n');
        }

        return builder.ToString();
    }
}
