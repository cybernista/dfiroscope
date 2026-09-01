namespace ProcInsider.Models.Agent;

/// <summary>
/// Shared constants for the Phase 4 agent/viewer IPC contract.
/// Both the viewer and the future agent process should validate
/// <see cref="ContractVersion"/> on connection to detect mismatches early.
/// </summary>
public static class AgentContracts
{
    /// <summary>
    /// Monotonically incremented integer version for the IPC message contract.
    /// Bump this whenever a breaking change is made to command or status message shapes.
    /// </summary>
    public const int ContractVersion = 2;

    /// <summary>Version of the durable local pairing and challenge/response contract.</summary>
    public const int PairingContractVersion = 1;

    /// <summary>
    /// Primary named-pipe name used by current DFIRoscope viewers and agents.
    /// Defined here so both sides share the same constant without requiring a separate assembly.
    /// </summary>
    public const string PipeName = "DFIRoscopeAgent";

    /// <summary>
    /// Former named-pipe name retained during the product-identity transition.
    /// A current viewer probes it only when the primary endpoint is unavailable,
    /// and a current agent hosts it as an alias to the same in-process command service.
    /// </summary>
    public const string LegacyPipeName = "ProcInsiderAgent";

    public static IReadOnlyList<string> CompatiblePipeNames { get; } =
        [PipeName, LegacyPipeName];

    /// <summary>
    /// Dedicated, shutdown-only local control pipe. Keeping this separate from the
    /// normal command pipe lets a viewer repeat a stop request when the main IPC
    /// path is busy or has become unhealthy during agent shutdown.
    /// </summary>
    public const string ShutdownControlPipeName = "DFIRoscopeAgentControl";

    /// <summary>
    /// Former shutdown-only control pipe retained as an alias with the same
    /// expected-database and shutdown-command restrictions as the primary pipe.
    /// </summary>
    public const string LegacyShutdownControlPipeName = "ProcInsiderAgentControl";

    public static IReadOnlyList<string> CompatibleShutdownControlPipeNames { get; } =
        [ShutdownControlPipeName, LegacyShutdownControlPipeName];
}
