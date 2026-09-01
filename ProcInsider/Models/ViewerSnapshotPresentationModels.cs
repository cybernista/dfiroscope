namespace ProcInsider.Models;

/// <summary>
/// Stable keys for the fixed Details tabs. The key, rather than a visual index,
/// survives optional-tab visibility changes during snapshot publication.
/// </summary>
public enum ViewerDetailsTabKey
{
    Object,
    Ai
}

/// <summary>
/// WPF-free identity for the first visible process row. RelativeOffset is the
/// row's vertical offset from the process-grid viewport when captured.
/// </summary>
public sealed record ViewerProcessViewportAnchor(
    string ProcessEntityId,
    string ProcessKey,
    double RelativeOffset);
