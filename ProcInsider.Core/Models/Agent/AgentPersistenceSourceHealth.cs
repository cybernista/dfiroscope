using ProcInsider.Models.Persistence;

namespace ProcInsider.Models.Agent;

public sealed record AgentPersistenceSourceHealth
{
    public string CollectorId { get; init; } = string.Empty;
    public PersistenceCollectionStatus Status { get; init; }
    public int ArtifactCount { get; init; }
    public IReadOnlyList<PersistenceCoverage> Coverage { get; init; } = [];
    public DateTime? LastSuccessfulCollectionUtc { get; init; }
    public string Diagnostic { get; init; } = string.Empty;
}
