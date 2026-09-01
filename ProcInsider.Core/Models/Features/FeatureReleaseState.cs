// Core-owned fail-closed educational release publication states.
namespace ProcInsider.Models.Features;

public enum FeatureReleaseState
{
    /// <summary>Officially available, documented, trained, and supported in this release.</summary>
    Published = 0,

    /// <summary>
    /// Compiled but unpublished and unsupported. The implementation may still require maintainer
    /// review, changes, documentation, training, or functional completion before publication.
    /// </summary>
    ReadyHidden = 1,

    /// <summary>Private development state that is never eligible for public activation.</summary>
    InDevelopment = 2
}
