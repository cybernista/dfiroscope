using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// Resolves an optional compile-time private development catalog. There is no
/// runtime setting, environment variable, command-line switch, IPC selector, or
/// discovery path. With no private implementation, the exact source catalog is
/// returned unchanged.
/// </summary>
public static partial class CompiledFeatureCatalogResolver
{
    private static readonly FeatureId UnknownProbe = new("compiled-catalog-unknown-probe");

    public static IFeatureCatalog Resolve(IFeatureCatalog sourceCatalog)
    {
        ArgumentNullException.ThrowIfNull(sourceCatalog);
        IFeatureCatalog? resolvedCatalog = null;
        ResolvePrivateCatalog(sourceCatalog, ref resolvedCatalog);
        if (resolvedCatalog == null)
        {
            return sourceCatalog;
        }

        ValidateResolvedCatalog(sourceCatalog, resolvedCatalog);
        return resolvedCatalog;
    }

    internal static void ValidateResolvedCatalog(
        IFeatureCatalog sourceCatalog,
        IFeatureCatalog resolvedCatalog)
    {
        ArgumentNullException.ThrowIfNull(sourceCatalog);
        ArgumentNullException.ThrowIfNull(resolvedCatalog);
        if (string.IsNullOrWhiteSpace(resolvedCatalog.ReleaseId))
        {
            throw new InvalidOperationException(
                "A compiled development catalog requires a non-empty release ID.");
        }

        var sourceDefinitions = sourceCatalog.Features.ToDictionary(definition => definition.Id);
        var resolvedDefinitions = resolvedCatalog.Features.ToDictionary(definition => definition.Id);
        if (sourceDefinitions.Count != resolvedDefinitions.Count ||
            sourceDefinitions.Keys.Any(featureId => !resolvedDefinitions.ContainsKey(featureId)))
        {
            throw new InvalidOperationException(
                "A compiled development catalog must preserve the exact canonical feature inventory.");
        }

        foreach (var pair in sourceDefinitions)
        {
            var sourceDefinition = pair.Value;
            var resolvedDefinition = resolvedDefinitions[pair.Key];
            if (resolvedDefinition.State != sourceDefinition.State ||
                !resolvedDefinition.Dependencies.ToHashSet().SetEquals(sourceDefinition.Dependencies) ||
                resolvedCatalog.GetReleaseState(pair.Key) != sourceCatalog.GetReleaseState(pair.Key))
            {
                throw new InvalidOperationException(
                    $"A compiled development catalog changed canonical definition '{pair.Key}'.");
            }

            if (sourceCatalog.IsPublished(pair.Key) && !resolvedCatalog.IsPublished(pair.Key))
            {
                throw new InvalidOperationException(
                    $"A compiled development catalog cannot demote public feature '{pair.Key}'.");
            }

            if (resolvedCatalog.IsPublished(pair.Key) &&
                sourceDefinition.State == FeatureReleaseState.InDevelopment)
            {
                throw new InvalidOperationException(
                    $"A compiled development catalog cannot publish InDevelopment feature '{pair.Key}'.");
            }

            if (!resolvedCatalog.IsPublished(pair.Key))
            {
                continue;
            }

            var hiddenDependency = sourceDefinition.Dependencies
                .FirstOrDefault(dependency => !resolvedCatalog.IsPublished(dependency));
            if (!hiddenDependency.IsEmpty)
            {
                throw new InvalidOperationException(
                    $"Compiled development feature '{pair.Key}' depends on unpublished feature '{hiddenDependency}'.");
            }
        }

        if (resolvedCatalog.IsKnown(UnknownProbe) || resolvedCatalog.IsPublished(UnknownProbe))
        {
            throw new InvalidOperationException(
                "A compiled development catalog must fail closed for unknown feature IDs.");
        }

        var publicationChanged = sourceDefinitions.Keys.Any(featureId =>
            sourceCatalog.IsPublished(featureId) != resolvedCatalog.IsPublished(featureId));
        if (publicationChanged && string.Equals(
                sourceCatalog.ReleaseId,
                resolvedCatalog.ReleaseId,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "A compiled development catalog with changed publication requires a distinct release ID.");
        }
    }

    static partial void ResolvePrivateCatalog(
        IFeatureCatalog sourceCatalog,
        ref IFeatureCatalog? resolvedCatalog);
}
