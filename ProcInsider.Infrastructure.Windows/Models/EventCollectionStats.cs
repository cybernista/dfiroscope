namespace ProcInsider.Models;

/// <summary>
/// Snapshot of current event collection counters.
/// </summary>
public class EventCollectionStats
{
    public long CurrentMemoryBytes { get; set; }
    public int InMemoryEventCount { get; set; }
    public long TotalCollected { get; set; }
    public long TotalDropped { get; set; }
    public bool IsCollectionPaused { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
}
