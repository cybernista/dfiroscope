namespace ProcInsider.Models;

/// <summary>
/// Process-level status for artifact capture/enrichment attempts.
/// </summary>
public enum ArtifactCaptureStatus
{
    Pending,
    Capturing,
    Captured,
    Failed,
    NotFound,
    NotAvailable
}
