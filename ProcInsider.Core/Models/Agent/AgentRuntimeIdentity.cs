using System.IO;

namespace ProcInsider.Models.Agent;

/// <summary>
/// OS and file identities used by the local agent host. Current and former mutex
/// names are acquired together so binaries from either side of the rename cannot
/// become independent evidence writers.
/// </summary>
public static class AgentRuntimeIdentity
{
    public const string InstanceMutexName = @"Global\DFIRoscope.Agent.Singleton";

    public const string LegacyInstanceMutexName = @"Global\ProcInsider.Agent.Singleton";

    public static IReadOnlyList<string> CompatibleInstanceMutexNames { get; } =
        [InstanceMutexName, LegacyInstanceMutexName];

    public const string InstanceGuardThreadName = "DFIRoscope.Agent.InstanceGuard";

    public const string LogFileName = "DFIRoscope.Agent.log";

    public const string LegacyLogFileName = "ProcInsider.Agent.log";

    public static string ResolveLogPath(string logsDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logsDirectory);
        var fullLogsDirectory = Path.GetFullPath(logsDirectory);
        var primaryPath = Path.Combine(fullLogsDirectory, LogFileName);
        var legacyPath = Path.Combine(fullLogsDirectory, LegacyLogFileName);

        // Continue an existing legacy-only log instead of splitting one session's
        // operational history across filenames. Fresh sessions and sessions that
        // already have the current log always use the primary identity.
        return File.Exists(primaryPath) || !File.Exists(legacyPath)
            ? primaryPath
            : legacyPath;
    }
}
