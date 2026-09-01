// Core-owned capture workspace identity shared by viewer and agent.
namespace ProcInsider.Models;

public sealed record CaptureWorkspaceIdentity(
    CaptureWorkspaceMode Mode,
    string SessionId,
    string SessionRoot)
{
    public static CaptureWorkspaceIdentity None { get; } = new(
        CaptureWorkspaceMode.None,
        string.Empty,
        string.Empty);
}
