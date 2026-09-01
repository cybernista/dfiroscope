using System;

namespace ProcInsider.Models;

/// <summary>
/// Represents a single open handle in a process.
/// </summary>
public class HandleInfo
{
    public string ProcessEntityId { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;
    public string HandleValue { get; set; } = "<not available>";
    public ulong HandleValueNumeric { get; set; }
    public string ObjectType { get; set; } = "<unknown>";
    public string ObjectName { get; set; } = "<not available>";
    public string GrantedAccess { get; set; } = "<not available>";
    public uint GrantedAccessValue { get; set; }
    public string HandleAttributes { get; set; } = "<not available>";
    public uint HandleAttributesValue { get; set; }
    public string ObjectAddress { get; set; } = "<not available>";
    public DateTime? FirstSeenUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public DateTime? ClosedUtc { get; set; }
    public HandleObservationState State { get; set; } = HandleObservationState.Open;
    public bool IsStale => State == HandleObservationState.Closed || State == HandleObservationState.NotFound;
    public string StatusDisplay => State switch
    {
        HandleObservationState.Closed when ClosedUtc.HasValue => $"Closed {ClosedUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}",
        _ => State.ToString()
    };
}
