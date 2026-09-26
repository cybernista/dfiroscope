namespace ProcInsider.Models.Agent;

/// <summary>
/// Portable append-only job identity and planning rules for configured artifact enrichment.
/// </summary>
public static class AgentEnrichmentPlanning
{
    public static bool ShouldQueue(AgentArtifactCapturePolicy policy)
        => policy.CaptureModules || policy.CaptureHandles || policy.CapturePeMetadata;

    public static JobKind GetJobKind(bool captureModules, bool captureHandles, bool capturePe)
    {
        if (captureModules)
        {
            return JobKind.ModuleEnrichment;
        }

        if (captureHandles)
        {
            return JobKind.HandleEnrichment;
        }

        return capturePe ? JobKind.PeAnalysis : JobKind.Unknown;
    }
}
