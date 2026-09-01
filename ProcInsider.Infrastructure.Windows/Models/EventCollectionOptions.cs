using System;

namespace ProcInsider.Models;

/// <summary>
/// Configures bounded in-memory event collection.
/// </summary>
public class EventCollectionOptions
{
    public long MemoryCapBytes { get; set; }
    public TimeSpan RetentionPeriod { get; set; }
    public bool OverwriteMemoryWhenFull { get; set; }
    public bool CollectProcessEvents { get; set; }
    public bool CollectNetworkEvents { get; set; }
    public bool CollectDnsEvents { get; set; }
    public bool HonorSysmonIntegrationToggle { get; set; }
    public bool InterestingOnlyDefault { get; set; }

    public static EventCollectionOptions CreateDefault()
    {
        return new EventCollectionOptions
        {
            MemoryCapBytes = 512L * 1024 * 1024,
            RetentionPeriod = TimeSpan.FromHours(1),
            OverwriteMemoryWhenFull = true,
            CollectProcessEvents = true,
            CollectNetworkEvents = true,
            CollectDnsEvents = true,
            HonorSysmonIntegrationToggle = true,
            InterestingOnlyDefault = false
        };
    }

    public void Validate()
    {
        if (MemoryCapBytes <= 0)
        {
            throw new InvalidOperationException("Memory cap must be greater than zero.");
        }

        if (RetentionPeriod <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("Retention period must be greater than zero.");
        }
    }
}
