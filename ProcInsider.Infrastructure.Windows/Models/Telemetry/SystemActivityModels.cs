using System;
using System.Collections.Generic;

namespace ProcInsider.Models;

public enum SystemActivityScopeKind
{
    All,
    Authentication,
    SuccessfulLogons,
    FailedLogons,
    RemoteInteractive,
    ExplicitCredentialUse,
    PrivilegedLogons,
    Accounts,
    CreatedUsers,
    DisabledDeletedUsers,
    PasswordChanges,
    Groups,
    LocalAdministratorsChanges,
    SecurityGroupMembershipChanges,
    PolicyAudit,
    AuditPolicyChanged,
    LogIntegrity,
    SecurityLogCleared,
    ServicesTasks,
    ServicesInstalled,
    ScheduledTasksChanged
}

public enum SystemActivityResult
{
    Unknown,
    Success,
    Failure
}

public sealed class SystemActivityQuery
{
    public SystemActivityScopeKind? Scope { get; set; }
    public string? AccountKey { get; set; }
    public string? CaseId { get; set; }
    public string? EvidenceSessionId { get; set; }
    public string? CaptureId { get; set; }
    public string? SourceIdentityId { get; set; }
    public string? HostId { get; set; }
    public string? ExecutionRootId { get; set; }
    public int MaxCount { get; set; } = 10000;
}

public sealed class SystemActivityRecord : IHasEvidenceIdentity
{
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
    public long SourceSequenceId { get; set; }
    public DateTime TimestampUtc { get; set; }
    public string Source { get; set; } = string.Empty;
    public int? EventId { get; set; }
    public string Provider { get; set; } = string.Empty;
    public string LogName { get; set; } = string.Empty;
    public string RecordId { get; set; } = string.Empty;
    public string Activity { get; set; } = string.Empty;
    public SystemActivityResult Result { get; set; }
    public IReadOnlyList<SystemActivityScopeKind> Scopes { get; set; } = Array.Empty<SystemActivityScopeKind>();
    public string SubjectAccount { get; set; } = string.Empty;
    public string SubjectSid { get; set; } = string.Empty;
    public string TargetAccount { get; set; } = string.Empty;
    public string TargetSid { get; set; } = string.Empty;
    public string MemberAccount { get; set; } = string.Empty;
    public string MemberSid { get; set; } = string.Empty;
    public string TargetGroup { get; set; } = string.Empty;
    public string SourceHost { get; set; } = string.Empty;
    public string SourceAddress { get; set; } = string.Empty;
    public string LogonType { get; set; } = string.Empty;
    public string LogonId { get; set; } = string.Empty;
    public string StatusCode { get; set; } = string.Empty;
    public string FailureReason { get; set; } = string.Empty;
    public string ProcessKey { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string RawXml { get; set; } = string.Empty;
}

public sealed class SystemActivityAccountSummary
{
    public string AccountKey { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string Sid { get; set; } = string.Empty;
    public int ActivityCount { get; set; }
    public int LogonCount { get; set; }
    public int GroupChangeCount { get; set; }
    public int PrivilegedActivityCount { get; set; }
    public string CaseId { get; set; } = string.Empty;
    public string EvidenceSessionId { get; set; } = string.Empty;
    public string CaptureId { get; set; } = string.Empty;
    public string SourceIdentityId { get; set; } = string.Empty;
    public string HostId { get; set; } = string.Empty;
    public string ExecutionRootId { get; set; } = string.Empty;
}
