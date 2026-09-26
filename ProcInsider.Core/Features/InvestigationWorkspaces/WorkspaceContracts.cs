using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("DFIRoscope.Live")]
[assembly: InternalsVisibleTo("InvestigationWorkspacesSelfTest")]
namespace ProcInsider.Models.InvestigationWorkspaces;

internal readonly record struct WorkspaceTypeId(string Value)
{
    public static WorkspaceTypeId Processes => new("processes");
    public static WorkspaceTypeId Events => new("events");
}

internal readonly record struct WorkspaceInstanceId(Guid Value)
{
    public static WorkspaceInstanceId Create() => new(Guid.NewGuid());
}

internal sealed record WorkspaceContext(string SessionId, long CaptureGeneration, EvidenceIdentity? EvidenceScope = null);
internal readonly record struct WorkspaceOperationStamp(WorkspaceInstanceId InstanceId, long CaptureGeneration, long SnapshotGeneration, long RequestGeneration);
internal readonly record struct WorkspaceChildTabKey(WorkspaceInstanceId InstanceId, string Surface, string TabId);
internal sealed record WorkspaceTypeMetadata(WorkspaceTypeId Id, string Name, string Description);

// Values only; a workspace never retains a WPF control as its layout state.
internal sealed record WorkspacePanelLayout(double ListingWeight = 2, double DataWeight = 3, double DetailsWidth = 360, double DataWidth = 540);
