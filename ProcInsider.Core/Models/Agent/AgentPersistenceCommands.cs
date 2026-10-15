namespace ProcInsider.Models.Agent;

public sealed record CollectPersistenceNowCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.CollectPersistenceNow;
    public string CaptureId { get; init; } = string.Empty;
}

public sealed record RebaselinePersistenceCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.RebaselinePersistence;
    public string CaptureId { get; init; } = string.Empty;
    public string ResetReason { get; init; } = string.Empty;
}
