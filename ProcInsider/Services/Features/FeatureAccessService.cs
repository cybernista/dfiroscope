using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// Viewer-facing release publication guard. Runtime prerequisites remain the
/// caller's responsibility and are combined with this policy by CanExecute.
/// </summary>
public sealed class FeatureAccessService
{
    public FeatureAccessService(IFeatureCatalog catalog)
    {
        Catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
    }

    public IFeatureCatalog Catalog { get; }

    public bool IsPublished(FeatureId featureId) => Catalog.IsPublished(featureId);

    public bool CanExecute(FeatureId featureId, bool runtimePrerequisites = true) =>
        IsPublished(featureId) && runtimePrerequisites;

    public bool TryAccess(FeatureId featureId, out string unavailableMessage)
    {
        if (IsPublished(featureId))
        {
            unavailableMessage = string.Empty;
            return true;
        }

        unavailableMessage =
            $"Feature '{featureId}' is not published in educational release '{Catalog.ReleaseId}'.";
        return false;
    }
}
