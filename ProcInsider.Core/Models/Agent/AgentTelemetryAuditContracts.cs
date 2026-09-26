using System;
using System.Collections.Generic;

namespace ProcInsider.Models.Agent;

/// <summary>Fixed Agent-owned adapters exposed to Telemetrios. No caller-supplied executable or arguments exist.</summary>
public static class AgentTelemetryAuditAdapterIds
{
    public const string LocalUserLifecycle = "agent-audit-local-user-lifecycle-v1";
    public const string LocalGroupLifecycle = "agent-audit-local-group-lifecycle-v1";
    public const string ProcessLifecycle = "agent-audit-process-lifecycle-v1";
    public const string LocalLogonLifecycle = "agent-audit-local-logon-lifecycle-v1";
    public const string FileLifecycle = "agent-audit-file-lifecycle-v1";
    public const string RegistryLifecycle = "agent-audit-registry-lifecycle-v1";
    public const string GlobalFileLifecycle = "agent-audit-global-file-lifecycle-v1";
    public const string GlobalRegistryLifecycle = "agent-audit-global-registry-lifecycle-v1";
    public const string CryptoKeyLifecycle = "agent-audit-crypto-key-lifecycle-v1";
    public const string PrivilegeUse = "agent-audit-privilege-use-v1";
}

public enum AgentTelemetryAuditPrerequisiteOutcome
{
    NotChecked = 0,
    Satisfied = 1,
    NotRequired = 2,
    Missing = 3,
    Unavailable = 4,
}

public enum AgentTelemetryAuditActivityOutcome
{
    NotRun = 0,
    Succeeded = 1,
    Failed = 2,
    TimedOut = 3,
    Cancelled = 4,
}

public enum AgentTelemetryAuditEvidenceOutcome
{
    NotChecked = 0,
    Observed = 1,
    Missing = 2,
    Unrelated = 3,
    Ambiguous = 4,
    Unavailable = 5,
}

public enum AgentTelemetryAuditCleanupOutcome
{
    NotRun = 0,
    NotRequired = 1,
    Verified = 2,
    Failed = 3,
}

public sealed record AgentTelemetryAuditPrerequisiteReceipt
{
    public AgentTelemetryAuditPrerequisiteOutcome AuditPolicy { get; init; }
    public AgentTelemetryAuditPrerequisiteOutcome Sacl { get; init; }
    public AgentTelemetryAuditPrerequisiteOutcome Role { get; init; }
    public AgentTelemetryAuditPrerequisiteOutcome SecuritySource { get; init; }
    public string PolicyGeneration { get; init; } = string.Empty;
    public string AuditPolicyDetail { get; init; } = string.Empty;
    public string SaclDetail { get; init; } = string.Empty;
    public string RoleDetail { get; init; } = string.Empty;
    public string SecuritySourceDetail { get; init; } = string.Empty;
}

public sealed record AgentTelemetryAuditActivityReceipt
{
    public AgentTelemetryAuditActivityOutcome Outcome { get; init; }
    public string AdapterId { get; init; } = string.Empty;
    public string ActivityId { get; init; } = string.Empty;
    public string CorrelationId { get; init; } = string.Empty;
    public string SourceRunId { get; init; } = string.Empty;
    public DateTimeOffset StartedUtc { get; init; }
    public DateTimeOffset CompletedUtc { get; init; }
    public IReadOnlyDictionary<string, string> TargetFacts { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
    public string Detail { get; init; } = string.Empty;
}

public sealed record AgentTelemetryAuditEvidenceReceipt
{
    public AgentTelemetryAuditEvidenceOutcome Outcome { get; init; }
    public string SourceId { get; init; } = "windows-security";
    public int? EventId { get; init; }
    public long? RecordId { get; init; }
    public DateTimeOffset? ObservedUtc { get; init; }
    public string CorrelationId { get; init; } = string.Empty;
    public string SourceRunId { get; init; } = string.Empty;
    public string TargetDesignationId { get; init; } = string.Empty;
    public IReadOnlyDictionary<string, string> MatchedTargetFacts { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
    public string Detail { get; init; } = string.Empty;
}

public sealed record AgentTelemetryAuditCleanupReceipt
{
    public AgentTelemetryAuditCleanupOutcome Outcome { get; init; }
    public string CleanupId { get; init; } = string.Empty;
    public IReadOnlyList<string> ArtifactIdentities { get; init; } = Array.Empty<string>();
    public string Detail { get; init; } = string.Empty;
}

public sealed record AgentTelemetryAuditTestResult
{
    public string SubcategoryGuid { get; init; } = string.Empty;
    public string AdapterId { get; init; } = string.Empty;
    public string DesignatedMachineName { get; init; } = string.Empty;
    public string ActualMachineName { get; init; } = string.Empty;
    public string TargetDesignationId { get; init; } = string.Empty;
    public bool ExactTargetDesignated { get; init; }
    public AgentTelemetryAuditPrerequisiteReceipt Prerequisites { get; init; } = new();
    public AgentTelemetryAuditActivityReceipt Activity { get; init; } = new();
    public AgentTelemetryAuditEvidenceReceipt Evidence { get; init; } = new();
    public AgentTelemetryAuditCleanupReceipt Cleanup { get; init; } = new();
    public bool Passed { get; init; }
    public string Summary { get; init; } = string.Empty;
}

/// <summary>
/// Runs one registered, fixed benign audit activity. The Agent independently resolves all behavior;
/// the request cannot carry command text, paths, credentials, event queries, or cleanup instructions.
/// </summary>
public sealed record RunTelemetryAuditTestCommand : AgentCommand
{
    public override AgentCommandKind Kind => AgentCommandKind.RunTelemetryAuditTest;
    public string SubcategoryGuid { get; init; } = string.Empty;
    public string AdapterId { get; init; } = string.Empty;
    public string DesignatedMachineName { get; init; } = string.Empty;
    public bool DisposableTargetConfirmed { get; init; }
}
