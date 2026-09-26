using Microsoft.Win32;

namespace ProcInsider.Models;

/// <summary>
/// Exact registry values affected by the supported PowerShell auditing policy operations.
/// The Agent persists this only as host-configuration recovery provenance.
/// </summary>
public sealed record PowerShellAuditingPolicySnapshot
{
    public bool IsAvailable { get; init; }

    public string Error { get; init; } = string.Empty;

    public PowerShellAuditingPolicyKeySnapshot[] Keys { get; init; } = [];
}

public sealed record PowerShellAuditingPolicyKeySnapshot
{
    public string Root { get; init; } = string.Empty;

    public string SubKey { get; init; } = string.Empty;

    public bool Exists { get; init; }

    public PowerShellAuditingPolicyValueSnapshot[] Values { get; init; } = [];
}

public sealed record PowerShellAuditingPolicyValueSnapshot
{
    public string Name { get; init; } = string.Empty;

    public RegistryValueKind Kind { get; init; }

    public int DwordValue { get; init; }

    public long QwordValue { get; init; }

    public string StringValue { get; init; } = string.Empty;

    public string[] MultiStringValue { get; init; } = [];

    public byte[] BinaryValue { get; init; } = [];
}
