using System.Collections.ObjectModel;
using ProcInsider.Models.Features;
using ProcInsider.ViewModels;

namespace ProcInsider.Services.Features;

/// <summary>
/// Catalog-filtered, explicitly ordered descriptors for one shell surface.
/// </summary>
public sealed class FeatureTabSet
{
    private readonly IReadOnlyDictionary<FeatureTabKey, FeatureTabDescriptor> _byKey;

    public FeatureTabSet(
        IFeatureCatalog catalog,
        FeatureTabSurface surface,
        IEnumerable<FeatureTabDescriptor> descriptors,
        FeatureTabKey preferredFallbackKey,
        bool allowEmpty = false)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(descriptors);

        if (!Enum.IsDefined(surface))
        {
            throw new ArgumentOutOfRangeException(nameof(surface), surface, "Unknown feature tab surface.");
        }

        if (preferredFallbackKey.Surface != surface)
        {
            throw new InvalidOperationException(
                $"The preferred {surface} fallback '{preferredFallbackKey}' belongs to another surface.");
        }

        var descriptorArray = descriptors.ToArray();
        if (descriptorArray.Any(descriptor => descriptor.Key.Surface != surface))
        {
            throw new InvalidOperationException(
                $"The {surface} tab set contains a descriptor for another surface.");
        }

        var duplicateKey = descriptorArray
            .GroupBy(descriptor => descriptor.Key)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateKey != null)
        {
            throw new InvalidOperationException($"Duplicate feature tab key '{duplicateKey.Key}'.");
        }

        var duplicateOrder = descriptorArray
            .GroupBy(descriptor => descriptor.Order)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateOrder != null)
        {
            throw new InvalidOperationException(
                $"Duplicate {surface} feature tab order '{duplicateOrder.Key}'.");
        }

        if (descriptorArray.Length > 0 && descriptorArray.All(descriptor => descriptor.Key != preferredFallbackKey))
        {
            throw new InvalidOperationException(
                $"The preferred {surface} fallback '{preferredFallbackKey}' has no descriptor mapping.");
        }

        var published = descriptorArray
            .Where(descriptor => catalog.IsPublished(descriptor.FeatureId))
            .OrderBy(descriptor => descriptor.Order)
            .ThenBy(descriptor => descriptor.Key.TabId, StringComparer.Ordinal)
            .ToArray();
        if (published.Length == 0 && !allowEmpty)
        {
            throw new InvalidOperationException(
                $"Release '{catalog.ReleaseId}' has no published {surface} tab fallback.");
        }

        Items = new ReadOnlyCollection<FeatureTabDescriptor>(published);
        _byKey = new ReadOnlyDictionary<FeatureTabKey, FeatureTabDescriptor>(
            published.ToDictionary(descriptor => descriptor.Key));
        SafeFallback = _byKey.TryGetValue(preferredFallbackKey, out var preferred)
            ? preferred
            : published.FirstOrDefault();
    }

    public IReadOnlyList<FeatureTabDescriptor> Items { get; }

    public FeatureTabDescriptor? SafeFallback { get; }

    public bool TryGet(FeatureTabKey key, out FeatureTabDescriptor? descriptor) =>
        _byKey.TryGetValue(key, out descriptor);

    public bool Contains(FeatureTabDescriptor descriptor) =>
        _byKey.TryGetValue(descriptor.Key, out var registered) && ReferenceEquals(registered, descriptor);
}
