using System;

namespace ProcInsider.Models;

public enum HandleObservationState
{
    Open,
    Closed,
    Observed,
    NotFound,
    Failed
}

public class HandleObservationRecord : IHasProcessEvidenceLink
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public long SequenceId { get; set; }
    public string ProcessEntityId { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string HandleKey { get; set; } = string.Empty;
    public string HandleValue { get; set; } = "<not available>";
    public ulong HandleValueNumeric { get; set; }
    public string ObjectType { get; set; } = "<unknown>";
    public string ObjectName { get; set; } = "<not available>";
    public string GrantedAccess { get; set; } = "<not available>";
    public uint GrantedAccessValue { get; set; }
    public string HandleAttributes { get; set; } = "<not available>";
    public uint HandleAttributesValue { get; set; }
    public string ObjectAddress { get; set; } = "<not available>";
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public DateTime? ClosedUtc { get; set; }
    public HandleObservationState State { get; set; } = HandleObservationState.Open;
    public string LastSource { get; set; } = string.Empty;
    public string SourceRunId { get; set; } = string.Empty;
    public string IngestionJobId { get; set; } = string.Empty;

    public HandleInfo ToHandleInfo()
    {
        return new HandleInfo
        {
            ProcessEntityId = ProcessEntityId,
            SourceRunId = SourceRunId,
            IngestionJobId = IngestionJobId,
            HandleValue = HandleValue,
            HandleValueNumeric = HandleValueNumeric,
            ObjectType = ObjectType,
            ObjectName = ObjectName,
            GrantedAccess = GrantedAccess,
            GrantedAccessValue = GrantedAccessValue,
            HandleAttributes = HandleAttributes,
            HandleAttributesValue = HandleAttributesValue,
            ObjectAddress = ObjectAddress,
            FirstSeenUtc = FirstSeenUtc,
            LastSeenUtc = LastSeenUtc,
            ClosedUtc = ClosedUtc,
            State = State
        };
    }
}
