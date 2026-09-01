namespace ProcInsider.Models.Agent;

/// <summary>
/// Top-level request kinds carried over the local agent named pipe.
/// Keep this envelope lightweight; large telemetry tables stay in SQLite.
/// </summary>
public enum AgentIpcRequestKind
{
    Unknown = 0,
    Health = 1,
    SubmitCommand = 2,
    GetJobStatus = 3,
    PairingChallenge = 4,
    RotatePairing = 5,
    RevokePairing = 6,
}
