using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;

namespace ProcInsider.Cli;

internal sealed record CliCommandDefinition(
    CliCommandKind Kind,
    string Name,
    string Usage,
    string Summary,
    FeatureId? DomainFeature = null,
    bool RequiresSession = false,
    AgentCommandKind? AgentCommand = null);

internal static class CliCommandRegistry
{
    private static readonly IReadOnlyList<CliCommandDefinition> DefinitionsValue =
        Array.AsReadOnly<CliCommandDefinition>(
        [
            new(
                CliCommandKind.Help,
                "help",
                "DFIRoscope.Live.exe --help",
                "Show published command help."),
            new(
                CliCommandKind.Version,
                "version",
                "DFIRoscope.Live.exe --version",
                "Show product and educational-release versions."),
            new(
                CliCommandKind.AgentDiscover,
                "agent discover",
                "DFIRoscope.Live.exe agent discover [--output text|json]",
                "Discover bounded non-secret local-agent candidates.",
                FeatureIds.AgentsAndCapture),
            new(
                CliCommandKind.AgentStatus,
                "agent status",
                "DFIRoscope.Live.exe agent status --session <absolute-session-root-or-session.json> [--output text|json]",
                "Read freshly authenticated local-agent status.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentCapabilities,
                "agent capabilities",
                "DFIRoscope.Live.exe agent capabilities --session <absolute-session-root-or-session.json> [--output text|json]",
                "Read published and operational local-agent capabilities.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.CaptureConfigurationShow,
                "agent capture configuration show",
                "DFIRoscope.Live.exe agent capture configuration show --session <absolute-session-root-or-session.json> [--output text|json]",
                "Read the saved capture configuration without changing it.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.GetCaptureConfiguration),
            new(
                CliCommandKind.AgentReconnect,
                "agent reconnect",
                "DFIRoscope.Live.exe agent reconnect --session <absolute-session-root-or-session.json> [--output text|json]",
                "Recover and authenticate one existing exact local agent without launching it.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentStart,
                "agent start",
                "DFIRoscope.Live.exe agent start --session <absolute-session-root-or-session.json> [--live-buffer-memory-mb 500|1024|2048] [--output text|json]",
                "Start or safely reuse and authenticate the exact local agent without starting capture.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentStop,
                "agent stop",
                "DFIRoscope.Live.exe agent stop --session <absolute-session-root-or-session.json> --yes [--timeout-seconds 1..120] [--output text|json]",
                "Gracefully stop the exact local agent with an authorized verified fallback.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentPairingStatus,
                "agent pairing status",
                "DFIRoscope.Live.exe agent pairing status --session <absolute-session-root-or-session.json> [--output text|json]",
                "Inspect bounded non-secret pairing state for the explicit session.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentPairingRotate,
                "agent pairing rotate",
                "DFIRoscope.Live.exe agent pairing rotate --session <absolute-session-root-or-session.json> --yes [--output text|json]",
                "Rotate pairing for the exact attached local agent.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentPairingRevoke,
                "agent pairing revoke",
                "DFIRoscope.Live.exe agent pairing revoke --session <absolute-session-root-or-session.json> --yes [--output text|json]",
                "Revoke pairing without stopping the agent or deleting evidence.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.CaptureConfigurationCheck,
                "agent capture configuration check",
                "DFIRoscope.Live.exe agent capture configuration check --session <absolute-session-root-or-session.json> [--file <absolute-json>] [--output text|json]",
                "Check the saved or supplied typed capture configuration without saving it.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.CheckCaptureConfiguration),
            new(
                CliCommandKind.CaptureConfigurationSave,
                "agent capture configuration save",
                "DFIRoscope.Live.exe agent capture configuration save --session <absolute-session-root-or-session.json> --file <absolute-json> [--output text|json]",
                "Save one complete typed capture configuration without starting capture.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.SaveCaptureConfiguration),
            new(
                CliCommandKind.CaptureStart,
                "agent capture start",
                "DFIRoscope.Live.exe agent capture start --session <absolute-session-root-or-session.json> [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Start the saved exact capture configuration without starting the agent.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.StartConfiguredCapture),
            new(
                CliCommandKind.CaptureStop,
                "agent capture stop",
                "DFIRoscope.Live.exe agent capture stop --session <absolute-session-root-or-session.json> [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Stop only the authoritative configured capture and preserve drain completion.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.StopConfiguredCapture),
            new(
                CliCommandKind.CaptureSourceStart,
                "agent capture source start",
                "DFIRoscope.Live.exe agent capture source start --session <absolute-session-root-or-session.json> --source <Runtime|ETW|Security|PowerShell|WindowsOther|Sysmon> [--output text|json]",
                "Start one published source within the authoritative configured live capture.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.StartLiveCaptureSource),
            new(
                CliCommandKind.CaptureSourceStop,
                "agent capture source stop",
                "DFIRoscope.Live.exe agent capture source stop --session <absolute-session-root-or-session.json> --source <Runtime|ETW|Security|PowerShell|WindowsOther|Sysmon> [--output text|json]",
                "Stop one published source without stopping the other configured sources.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.StopLiveCaptureSource),
            new(
                CliCommandKind.AgentJobList,
                "agent job list",
                "DFIRoscope.Live.exe agent job list --session <absolute-session-root-or-session.json> [--output text|json]",
                "List bounded queued and running work from fresh authoritative health.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentJobStatus,
                "agent job status",
                "DFIRoscope.Live.exe agent job status --session <absolute-session-root-or-session.json> --job-id <guid> [--output text|json]",
                "Read current or terminal status for one exact agent job.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentJobWait,
                "agent job wait",
                "DFIRoscope.Live.exe agent job wait --session <absolute-session-root-or-session.json> --job-id <guid> [--timeout-seconds 1..86400] [--output text|json]",
                "Wait boundedly for one exact agent job to reach a terminal state.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true),
            new(
                CliCommandKind.AgentJobCancel,
                "agent job cancel",
                "DFIRoscope.Live.exe agent job cancel --session <absolute-session-root-or-session.json> --job-id <guid> [--output text|json]",
                "Request cancellation of one exact agent job.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.CancelJob),
            new(
                CliCommandKind.AgentEvidenceEnrich,
                "agent evidence enrich",
                "DFIRoscope.Live.exe agent evidence enrich --session <...> (--all | --process-entity-id <id>... | --process-key <PID_StartTimeTicks>...) [--modules] [--handles] [--pe] [--pe-strings deferred|immediate] [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Queue bounded explicit module, handle, or PE enrichment and return one trackable job.",
                FeatureIds.AgentsAndCapture,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueEnrichment),
            new(
                CliCommandKind.AgentProcessDump,
                "agent process dump",
                "DFIRoscope.Live.exe agent process dump --session <...> --process-key <PID_StartTimeTicks> --kind full|mini --yes [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Queue one confirmed exact-process dump inside the active session Dumps directory.",
                FeatureIds.DumpsAndPeAnalysis,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueProcessDump),
            new(
                CliCommandKind.AgentFilesystemImport,
                "agent filesystem import",
                "DFIRoscope.Live.exe agent filesystem import --session <...> --path <absolute-file-or-folder> [--recurse] [--include-ntfs] [--include-prefetch] [--max-files 1..10000] [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Queue a bounded read-only NTFS/Prefetch source import and return one trackable job.",
                FeatureIds.FilesystemArtifacts,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueArtifactImport),
            new(
                CliCommandKind.AgentNetworkStart,
                "agent network start",
                "DFIRoscope.Live.exe agent network start --session <...> [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Start agent-owned Packet Monitor capture in the active session network directory.",
                FeatureIds.NetworkAndZeek,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.StartNetworkCapture),
            new(
                CliCommandKind.AgentNetworkStop,
                "agent network stop",
                "DFIRoscope.Live.exe agent network stop --session <...> [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Stop exactly one authoritative network capture and preserve finalization.",
                FeatureIds.NetworkAndZeek,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.StopNetworkCapture),
            new(
                CliCommandKind.AgentZeekRun,
                "agent zeek run",
                "DFIRoscope.Live.exe agent zeek run --session <...> (--capture-id <id> | --pcap-path <absolute-pcap-or-pcapng>) [--zeek-path <absolute-exe> | --wsl-distribution <name> [--wsl-command <token>]] [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Queue bounded native or WSL Zeek analysis for one explicit read-only source.",
                FeatureIds.NetworkAndZeek,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueZeekAnalysis),
            new(
                CliCommandKind.AgentProcessMonitorStart,
                "agent procmon start",
                "DFIRoscope.Live.exe agent procmon start --session <...> [--procmon-path <absolute-exe>] --accept-eula [--max-rows 1..200000] [--wait] [--output text|json]",
                "Start confirmed agent-owned Process Monitor capture with session-owned sidecars.",
                FeatureIds.EventTelemetry,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.StartProcessMonitorCapture),
            new(
                CliCommandKind.AgentProcessMonitorStop,
                "agent procmon stop",
                "DFIRoscope.Live.exe agent procmon stop --session <...> [--procmon-path <absolute-exe>] [--wait] [--output text|json]",
                "Stop exactly one authoritative Process Monitor capture and wait through export/import when requested.",
                FeatureIds.EventTelemetry,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.StopProcessMonitorCapture),
            new(
                CliCommandKind.AgentProcessMonitorImport,
                "agent procmon import",
                "DFIRoscope.Live.exe agent procmon import --session <...> --input <absolute-csv-or-pml> [--procmon-path <absolute-exe>] [--max-rows 1..200000] [--wait] [--output text|json]",
                "Queue bounded read-only Process Monitor CSV/PML import.",
                FeatureIds.EventTelemetry,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueProcessMonitorImport),
            new(
                CliCommandKind.AgentSqliteBenchmarkStart,
                "agent sqlite benchmark start",
                "DFIRoscope.Live.exe agent sqlite benchmark start --session <...> [--phase-duration-seconds 1..60] [--max-phase-count 1..8] [--initial-process-batch-size 1..5000] [--initial-events-per-process 0..25] [--max-in-flight-batches 1..64] [--max-pending-writer-work-items 1..4096] [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Queue an isolated bounded SQLite writer benchmark under the session Benchmarks directory.",
                FeatureIds.EventTelemetry,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueSqliteBenchmark),
            new(
                CliCommandKind.AgentMemoryAcquire,
                "agent memory acquire",
                "DFIRoscope.Live.exe agent memory acquire --session <...> --yes [--output-file-name <leaf>] [--acquisition-timeout-seconds 1..7200] [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Queue confirmed agent-owned system-memory acquisition into the active session Memory directory.",
                FeatureIds.SystemMemoryAndVolatility,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueMemoryAcquisition),
            new(
                CliCommandKind.AgentMemoryImport,
                "agent memory import",
                "DFIRoscope.Live.exe agent memory import --session <...> --image-path <absolute-file> [--display-name <text>] [--host-name <text>] [--os-build <text>] [--acquisition-tool <text>] [--acquisition-tool-version <text>] [--acquisition-command-line <text>] [--privilege-state <text>] [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Queue a bounded read-only system-memory image import with analyst-supplied provenance.",
                FeatureIds.SystemMemoryAndVolatility,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueMemoryImageImport),
            new(
                CliCommandKind.AgentVolatilityRun,
                "agent volatility run",
                "DFIRoscope.Live.exe agent volatility run --session <...> (--image-id <id> | --image-path <absolute-file>) [--plugin <name>...] [--plugin-timeout-seconds 30..86400] [--wait] [--timeout-seconds 1..86400] [--output text|json]",
                "Queue bounded Volatility analysis for one staged or explicit read-only memory image.",
                FeatureIds.SystemMemoryAndVolatility,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.QueueVolatilityAnalysis),
            new(
                CliCommandKind.HostMonitoringConfigurationShow,
                "agent monitoring configuration show",
                "DFIRoscope.Live.exe agent monitoring configuration show --session <absolute-session-root-or-session.json> [--output text|json]",
                "Read the saved host-monitoring draft and baseline metadata without changing either.",
                FeatureIds.SecurityMonitoringConfiguration,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.GetHostMonitoringConfiguration),
            new(
                CliCommandKind.HostMonitoringConfigurationCheck,
                "agent monitoring configuration check",
                "DFIRoscope.Live.exe agent monitoring configuration check --session <absolute-session-root-or-session.json> [--file <absolute-json>] [--output text|json]",
                "Check the saved or supplied typed host-monitoring draft without saving or deploying it.",
                FeatureIds.SecurityMonitoringConfiguration,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.CheckHostMonitoringConfiguration),
            new(
                CliCommandKind.HostMonitoringConfigurationSave,
                "agent monitoring configuration save",
                "DFIRoscope.Live.exe agent monitoring configuration save --session <absolute-session-root-or-session.json> --file <absolute-json> [--output text|json]",
                "Save one typed host-monitoring draft without checking, deploying, or starting capture.",
                FeatureIds.SecurityMonitoringConfiguration,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.SaveHostMonitoringConfiguration),
            new(
                CliCommandKind.HostMonitoringDeploy,
                "agent monitoring deploy",
                "DFIRoscope.Live.exe agent monitoring deploy --session <absolute-session-root-or-session.json> --yes [--output text|json]",
                "Deploy the saved exact host-monitoring draft without starting capture.",
                FeatureIds.SecurityMonitoringConfiguration,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.DeployHostMonitoringConfiguration),
            new(
                CliCommandKind.HostMonitoringReverse,
                "agent monitoring reverse",
                "DFIRoscope.Live.exe agent monitoring reverse --session <absolute-session-root-or-session.json> --yes [--output text|json]",
                "Restore only the recorded exact original-state baseline without stopping capture.",
                FeatureIds.SecurityMonitoringConfiguration,
                RequiresSession: true,
                AgentCommand: AgentCommandKind.ReverseHostMonitoringDeployment),
            new(
                CliCommandKind.Shell,
                "shell",
                "DFIRoscope.Live.exe shell [--session <absolute-session-root-or-session.json>] [--output text|json] [--no-prompt]",
                "Enter the interactive DFIRoscope command shell.")
        ]);

    static CliCommandRegistry()
    {
        var expected = Enum.GetValues<CliCommandKind>()
            .Where(kind => kind != CliCommandKind.Unknown)
            .OrderBy(kind => (int)kind)
            .ToArray();
        var actual = DefinitionsValue
            .Select(definition => definition.Kind)
            .OrderBy(kind => (int)kind)
            .ToArray();
        if (!actual.SequenceEqual(expected) ||
            DefinitionsValue.Select(definition => definition.Name).Distinct(StringComparer.Ordinal).Count() !=
            DefinitionsValue.Count)
        {
            throw new InvalidOperationException(
                "The CLI command registry is incomplete or contains duplicate command names.");
        }
    }

    public static IReadOnlyList<CliCommandDefinition> Definitions => DefinitionsValue;

    public static CliCommandDefinition Get(CliCommandKind kind) =>
        DefinitionsValue.Single(definition => definition.Kind == kind);
}
