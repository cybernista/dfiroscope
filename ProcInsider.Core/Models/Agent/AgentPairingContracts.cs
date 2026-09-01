using System;
using System.Collections.Generic;

namespace ProcInsider.Models.Agent;

/// <summary>Fail-closed state of the session-bound local-agent pairing.</summary>
public enum AgentPairingState
{
    Unknown = 0,
    Ready = 1,
    ReconnectRequired = 2,
    Connected = 3,
    RePairRequired = 4,
    Revoked = 5,
    Expired = 6,
    Corrupt = 7,
    WrongUser = 8,
    WrongSession = 9,
    WrongRelease = 10,
    AgentExited = 11,
    ProcessMismatch = 12
}

/// <summary>
/// Context authenticated by every local pairing proof. DatabaseIdentity is the
/// canonical full live-database path; it is never a PID-only or display alias.
/// </summary>
public sealed record AgentPairingContext
{
    public int PairingContractVersion { get; init; } = AgentContracts.PairingContractVersion;

    public int IpcContractVersion { get; init; } = AgentContracts.ContractVersion;

    public string SessionId { get; init; } = string.Empty;

    public string DatabaseIdentity { get; init; } = string.Empty;

    public string ReleaseId { get; init; } = string.Empty;

    public string Endpoint { get; init; } = string.Empty;

    public long PairingGeneration { get; init; }
}

public sealed record AgentPairingChallengeRequest
{
    public AgentPairingContext Context { get; init; } = new();

    /// <summary>The request that the one-time response will authorize.</summary>
    public Guid ProtectedRequestId { get; init; }
}

public sealed record AgentPairingChallenge
{
    public Guid ChallengeId { get; init; }

    public string Nonce { get; init; } = string.Empty;

    public DateTime ExpiresAtUtc { get; init; }

    public long PairingGeneration { get; init; }
}

public sealed record AgentPairingProof
{
    public Guid ChallengeId { get; init; }

    public string ResponseMac { get; init; } = string.Empty;
}

public sealed record AgentPairingStatusSnapshot
{
    public AgentPairingState State { get; init; }

    public long PairingGeneration { get; init; }

    public DateTime? ExpiresAtUtc { get; init; }

    public DateTime? LastHeartbeatUtc { get; init; }

    public string Status { get; init; } = string.Empty;
}

/// <summary>
/// Non-secret discovery lease. The DPAPI-protected secret is stored separately
/// and outside capture packages.
/// </summary>
public sealed record AgentPairingLeaseMetadata
{
    public int PairingContractVersion { get; init; } = AgentContracts.PairingContractVersion;

    public int IpcContractVersion { get; init; } = AgentContracts.ContractVersion;

    public string SessionId { get; init; } = string.Empty;

    public string DatabaseIdentity { get; init; } = string.Empty;

    public string ReleaseId { get; init; } = string.Empty;

    public CaptureWorkspaceMode WorkspaceMode { get; init; } = CaptureWorkspaceMode.None;

    public bool CaptureSealed { get; init; }

    public int AgentProcessId { get; init; }

    public DateTime AgentStartedAtUtc { get; init; }

    public string ExecutableName { get; init; } = string.Empty;

    public string ExecutablePath { get; init; } = string.Empty;

    public IReadOnlyList<string> Endpoints { get; init; } = Array.Empty<string>();

    public long PairingGeneration { get; init; }

    public DateTime ExpiresAtUtc { get; init; }

    public DateTime LastHeartbeatUtc { get; init; }

    public AgentPairingState State { get; init; }
}
