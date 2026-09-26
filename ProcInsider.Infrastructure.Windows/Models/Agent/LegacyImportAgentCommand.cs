namespace ProcInsider.Models.Agent;

/// <summary>
/// Queues an import job that reads a <c>.pistage</c> archive file into staging.
/// </summary>
public sealed record QueueImportCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.QueueImport;

    /// <summary>Absolute path to the <c>.pistage</c> archive to import.</summary>
    public string ArchivePath { get; init; } = string.Empty;
}
