using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;

namespace ProcInsider.Cli;

internal enum CliAgentCommandDispositionKind
{
    RunnableTypedCommand = 0,
    ReadOnlyStatusCapabilityJobOperation = 1,
    ReservedStableUnavailable = 2,
    HiddenUnpublishedZeroConstruction = 3,
    CompatibilityOnlyInternalPath = 4,
    DeliberatelyGuiOnly = 5
}

internal enum CliSharedServiceBoundary
{
    PresentationLocal = 0,
    LocalAgentRecoveryCoordinator = 1,
    ViewerAgentCommandExecutor = 2,
    ViewerAgentCaptureActionService = 3,
    ViewerAgentEvidenceActionService = 4,
    ViewerAgentToolActionService = 5,
    ViewerMemoryActionService = 6,
    ViewerHostMonitoringActionService = 7,
    LocalAgentControlCoordinator = 8
}

internal sealed record CliAgentCommandDisposition(
    AgentCommandKind AgentCommand,
    CliAgentCommandDispositionKind Disposition,
    CliCommandKind? CliCommand,
    CliSharedServiceBoundary? SharedService,
    FeatureId? DomainFeature,
    string Reason);

internal sealed record CliSurfaceOperationDisposition(
    CliCommandKind CliCommand,
    CliAgentCommandDispositionKind Disposition,
    CliSharedServiceBoundary SharedService,
    string Reason);

/// <summary>
/// Exhaustive product disposition for the agent wire inventory and every CLI
/// operation that has no one-to-one wire discriminator. This table is kept in
/// the viewer presentation adapter because it classifies public CLI exposure;
/// agent release policy remains owned by AgentCommandFeaturePolicy.
/// </summary>
internal static class CliCommandDispositionCatalog
{
    private static readonly IReadOnlyList<CliAgentCommandDisposition> AgentCommandsValue =
        Array.AsReadOnly<CliAgentCommandDisposition>(
        [
            GuiOnly(AgentCommandKind.StartLiveCapture,
                "The WPF quick-start path projects its current interactive selections; CLI uses the saved typed configured-capture contract."),
            GuiOnly(AgentCommandKind.StopLiveCapture,
                "The WPF legacy quick-stop path remains bounded compatibility behavior; CLI stops the saved configured capture."),
            Reserved(AgentCommandKind.QueueBackfill,
                "Historical event-log backfill is explicitly unavailable and has no constructible command type."),
            GuiOnly(AgentCommandKind.QueueImport,
                "The legacy WPF archive import flow owns its selected-file compatibility contract; CLI exposes only typed bounded filesystem import."),
            Hidden(AgentCommandKind.QueueEnrichment, CliCommandKind.AgentEvidenceEnrich,
                CliSharedServiceBoundary.ViewerAgentEvidenceActionService, FeatureIds.ModulesAndHandles,
                "Typed enrichment is ready but absent from the current profile until its owning analysis feature is published."),
            Runnable(AgentCommandKind.CancelJob, CliCommandKind.AgentJobCancel,
                CliSharedServiceBoundary.ViewerAgentCaptureActionService, FeatureIds.AgentsAndCapture,
                "Typed generic job cancellation is shared with WPF capture/job control."),
            GuiOnly(AgentCommandKind.PauseJob,
                "WPF configured-capture control uses the typed shared capture action service; no public generic job-pause CLI is exposed."),
            GuiOnly(AgentCommandKind.ResumeJob,
                "WPF configured-capture control uses the typed shared capture action service; no public generic job-resume CLI is exposed."),
            Hidden(AgentCommandKind.QueueProcessDump, CliCommandKind.AgentProcessDump,
                CliSharedServiceBoundary.ViewerAgentEvidenceActionService, FeatureIds.DumpsAndPeAnalysis,
                "Exact-process dump is typed and confirmation-gated but hidden until its domain feature is published."),
            Hidden(AgentCommandKind.StartNetworkCapture, CliCommandKind.AgentNetworkStart,
                CliSharedServiceBoundary.ViewerAgentToolActionService, FeatureIds.NetworkAndZeek,
                "Network capture is typed but hidden until Network and Zeek is published."),
            Hidden(AgentCommandKind.StopNetworkCapture, CliCommandKind.AgentNetworkStop,
                CliSharedServiceBoundary.ViewerAgentToolActionService, FeatureIds.NetworkAndZeek,
                "Network capture stop is typed but hidden with its owning feature."),
            Hidden(AgentCommandKind.QueueZeekAnalysis, CliCommandKind.AgentZeekRun,
                CliSharedServiceBoundary.ViewerAgentToolActionService, FeatureIds.NetworkAndZeek,
                "Zeek analysis is typed but hidden until Network and Zeek is published."),
            Hidden(AgentCommandKind.QueueArtifactImport, CliCommandKind.AgentFilesystemImport,
                CliSharedServiceBoundary.ViewerAgentEvidenceActionService, FeatureIds.FilesystemArtifacts,
                "Bounded filesystem import is typed but hidden until Filesystem Artifacts is published."),
            Runnable(AgentCommandKind.ShutdownAgent, CliCommandKind.AgentStop,
                CliSharedServiceBoundary.LocalAgentControlCoordinator, FeatureIds.AgentsAndCapture,
                "Graceful shutdown and verified fallback are exposed only through the shared lifecycle coordinator."),
            Hidden(AgentCommandKind.QueueMemoryImageImport, CliCommandKind.AgentMemoryImport,
                CliSharedServiceBoundary.ViewerMemoryActionService, FeatureIds.SystemMemoryAndVolatility,
                "Memory-image import is typed but hidden until System Memory and Volatility is published."),
            Hidden(AgentCommandKind.QueueVolatilityAnalysis, CliCommandKind.AgentVolatilityRun,
                CliSharedServiceBoundary.ViewerMemoryActionService, FeatureIds.SystemMemoryAndVolatility,
                "Volatility analysis is typed but hidden until System Memory and Volatility is published."),
            Hidden(AgentCommandKind.GetHostMonitoringConfiguration, CliCommandKind.HostMonitoringConfigurationShow,
                CliSharedServiceBoundary.ViewerHostMonitoringActionService, FeatureIds.SecurityMonitoringConfiguration,
                "Host-monitoring reads remain zero-construction while Security Monitoring Configuration is hidden."),
            Hidden(AgentCommandKind.SaveHostMonitoringConfiguration, CliCommandKind.HostMonitoringConfigurationSave,
                CliSharedServiceBoundary.ViewerHostMonitoringActionService, FeatureIds.SecurityMonitoringConfiguration,
                "Host-monitoring save remains zero-construction while Security Monitoring Configuration is hidden."),
            Hidden(AgentCommandKind.CheckHostMonitoringConfiguration, CliCommandKind.HostMonitoringConfigurationCheck,
                CliSharedServiceBoundary.ViewerHostMonitoringActionService, FeatureIds.SecurityMonitoringConfiguration,
                "Host-monitoring check remains zero-construction while Security Monitoring Configuration is hidden."),
            Hidden(AgentCommandKind.DeployHostMonitoringConfiguration, CliCommandKind.HostMonitoringDeploy,
                CliSharedServiceBoundary.ViewerHostMonitoringActionService, FeatureIds.SecurityMonitoringConfiguration,
                "Host-monitoring deployment is typed and confirmation-gated but hidden in the current profile."),
            Hidden(AgentCommandKind.ReverseHostMonitoringDeployment, CliCommandKind.HostMonitoringReverse,
                CliSharedServiceBoundary.ViewerHostMonitoringActionService, FeatureIds.SecurityMonitoringConfiguration,
                "Host-monitoring reversal is typed and confirmation-gated but hidden in the current profile."),
            Runnable(AgentCommandKind.GetCaptureConfiguration, CliCommandKind.CaptureConfigurationShow,
                CliSharedServiceBoundary.ViewerAgentCaptureActionService, FeatureIds.AgentsAndCapture,
                "Saved capture configuration is a typed shared read."),
            Runnable(AgentCommandKind.SaveCaptureConfiguration, CliCommandKind.CaptureConfigurationSave,
                CliSharedServiceBoundary.ViewerAgentCaptureActionService, FeatureIds.AgentsAndCapture,
                "Capture configuration save uses the shared typed capture action."),
            Runnable(AgentCommandKind.CheckCaptureConfiguration, CliCommandKind.CaptureConfigurationCheck,
                CliSharedServiceBoundary.ViewerAgentCaptureActionService, FeatureIds.AgentsAndCapture,
                "Capture configuration check uses the shared typed capture action."),
            Runnable(AgentCommandKind.StartConfiguredCapture, CliCommandKind.CaptureStart,
                CliSharedServiceBoundary.ViewerAgentCaptureActionService, FeatureIds.AgentsAndCapture,
                "Configured capture start uses the exact saved configuration through the shared action service."),
            Runnable(AgentCommandKind.StopConfiguredCapture, CliCommandKind.CaptureStop,
                CliSharedServiceBoundary.ViewerAgentCaptureActionService, FeatureIds.AgentsAndCapture,
                "Configured capture stop uses authoritative shared capture state."),
            Hidden(AgentCommandKind.StartProcessMonitorCapture, CliCommandKind.AgentProcessMonitorStart,
                CliSharedServiceBoundary.ViewerAgentToolActionService, FeatureIds.EventTelemetry,
                "Process Monitor start is typed but hidden until Event Telemetry is published."),
            Hidden(AgentCommandKind.StopProcessMonitorCapture, CliCommandKind.AgentProcessMonitorStop,
                CliSharedServiceBoundary.ViewerAgentToolActionService, FeatureIds.EventTelemetry,
                "Process Monitor stop is typed but hidden until Event Telemetry is published."),
            Hidden(AgentCommandKind.QueueProcessMonitorImport, CliCommandKind.AgentProcessMonitorImport,
                CliSharedServiceBoundary.ViewerAgentToolActionService, FeatureIds.EventTelemetry,
                "Process Monitor import is typed but hidden until Event Telemetry is published."),
            Hidden(AgentCommandKind.QueueSqliteBenchmark, CliCommandKind.AgentSqliteBenchmarkStart,
                CliSharedServiceBoundary.ViewerAgentToolActionService, FeatureIds.EventTelemetry,
                "The isolated benchmark is typed but hidden until Event Telemetry is published."),
            Compatibility(AgentCommandKind.StopEtwCapture,
                "The former ETW-only stop discriminator remains an agent compatibility path; new CLI and WPF source control use StopLiveCaptureSource."),
            Runnable(AgentCommandKind.StopLiveCaptureSource, CliCommandKind.CaptureSourceStop,
                CliSharedServiceBoundary.ViewerAgentCaptureActionService, FeatureIds.AgentsAndCapture,
                "Typed source stop uses shared authoritative source state."),
            Runnable(AgentCommandKind.StartLiveCaptureSource, CliCommandKind.CaptureSourceStart,
                CliSharedServiceBoundary.ViewerAgentCaptureActionService, FeatureIds.AgentsAndCapture,
                "Typed source start uses shared authoritative source state."),
            Hidden(AgentCommandKind.QueueMemoryAcquisition, CliCommandKind.AgentMemoryAcquire,
                CliSharedServiceBoundary.ViewerMemoryActionService, FeatureIds.SystemMemoryAndVolatility,
                "System-memory acquisition is typed and confirmation-gated but hidden until its domain feature is published.")
        ]);

    private static readonly IReadOnlyList<CliSurfaceOperationDisposition> SurfaceOperationsValue =
        Array.AsReadOnly<CliSurfaceOperationDisposition>(
        [
            Local(CliCommandKind.Help, "Published help is rendered from the central registry."),
            Local(CliCommandKind.Version, "Version output reads the compiled product and release identities."),
            ReadOnly(CliCommandKind.AgentDiscover, CliSharedServiceBoundary.LocalAgentRecoveryCoordinator,
                "Discovery returns bounded non-secret candidates and performs no pairing or health read."),
            ReadOnly(CliCommandKind.AgentStatus, CliSharedServiceBoundary.ViewerAgentCommandExecutor,
                "Status is a fresh authenticated validation-only health operation."),
            ReadOnly(CliCommandKind.AgentCapabilities, CliSharedServiceBoundary.ViewerAgentCommandExecutor,
                "Capabilities are projected from fresh authenticated health and compiled policy."),
            ReadOnly(CliCommandKind.AgentJobList, CliSharedServiceBoundary.ViewerAgentCaptureActionService,
                "Job list projects bounded authoritative control state."),
            ReadOnly(CliCommandKind.AgentJobStatus, CliSharedServiceBoundary.ViewerAgentCaptureActionService,
                "Job status is a typed exact-job read."),
            ReadOnly(CliCommandKind.AgentJobWait, CliSharedServiceBoundary.ViewerAgentCaptureActionService,
                "Job wait repeats bounded typed status reads and submits no generic command."),
            ReadOnly(CliCommandKind.AgentPairingStatus, CliSharedServiceBoundary.LocalAgentControlCoordinator,
                "Pairing status is an explicit-session bounded non-secret read."),
            RunnableSurface(CliCommandKind.AgentReconnect, CliSharedServiceBoundary.LocalAgentControlCoordinator),
            RunnableSurface(CliCommandKind.AgentStart, CliSharedServiceBoundary.LocalAgentControlCoordinator),
            RunnableSurface(CliCommandKind.AgentPairingRotate, CliSharedServiceBoundary.LocalAgentControlCoordinator),
            RunnableSurface(CliCommandKind.AgentPairingRevoke, CliSharedServiceBoundary.LocalAgentControlCoordinator),
            Local(CliCommandKind.Shell, "The REPL is a presentation loop over the same parser and dispatcher.")
        ]);

    static CliCommandDispositionCatalog()
    {
        EnsureExactCoverage(
            Enum.GetValues<AgentCommandKind>().Where(kind => kind != AgentCommandKind.Unknown),
            AgentCommandsValue.Select(entry => entry.AgentCommand),
            "agent command");

        var coveredCliKinds = AgentCommandsValue
            .Where(entry => entry.CliCommand.HasValue)
            .Select(entry => entry.CliCommand!.Value)
            .Concat(SurfaceOperationsValue.Select(entry => entry.CliCommand))
            .Distinct()
            .OrderBy(kind => (int)kind)
            .ToArray();
        var expectedCliKinds = Enum.GetValues<CliCommandKind>()
            .Where(kind => kind != CliCommandKind.Unknown)
            .OrderBy(kind => (int)kind)
            .ToArray();
        if (!coveredCliKinds.SequenceEqual(expectedCliKinds))
        {
            throw new InvalidOperationException(
                "The CLI disposition catalog does not classify every command kind.");
        }
    }

    public static IReadOnlyList<CliAgentCommandDisposition> AgentCommands => AgentCommandsValue;

    public static IReadOnlyList<CliSurfaceOperationDisposition> SurfaceOperations => SurfaceOperationsValue;

    private static CliAgentCommandDisposition Runnable(
        AgentCommandKind agentCommand,
        CliCommandKind cliCommand,
        CliSharedServiceBoundary service,
        FeatureId feature,
        string reason) =>
        new(agentCommand, CliAgentCommandDispositionKind.RunnableTypedCommand, cliCommand, service, feature, reason);

    private static CliAgentCommandDisposition Hidden(
        AgentCommandKind agentCommand,
        CliCommandKind cliCommand,
        CliSharedServiceBoundary service,
        FeatureId feature,
        string reason) =>
        new(agentCommand, CliAgentCommandDispositionKind.HiddenUnpublishedZeroConstruction, cliCommand, service, feature, reason);

    private static CliAgentCommandDisposition Reserved(AgentCommandKind agentCommand, string reason) =>
        new(agentCommand, CliAgentCommandDispositionKind.ReservedStableUnavailable, null, null, null, reason);

    private static CliAgentCommandDisposition Compatibility(AgentCommandKind agentCommand, string reason) =>
        new(agentCommand, CliAgentCommandDispositionKind.CompatibilityOnlyInternalPath, null, null, null, reason);

    private static CliAgentCommandDisposition GuiOnly(AgentCommandKind agentCommand, string reason) =>
        new(agentCommand, CliAgentCommandDispositionKind.DeliberatelyGuiOnly, null, null, FeatureIds.AgentsAndCapture, reason);

    private static CliSurfaceOperationDisposition Local(CliCommandKind cliCommand, string reason) =>
        new(cliCommand, CliAgentCommandDispositionKind.RunnableTypedCommand,
            CliSharedServiceBoundary.PresentationLocal, reason);

    private static CliSurfaceOperationDisposition ReadOnly(
        CliCommandKind cliCommand,
        CliSharedServiceBoundary service,
        string reason) =>
        new(cliCommand, CliAgentCommandDispositionKind.ReadOnlyStatusCapabilityJobOperation, service, reason);

    private static CliSurfaceOperationDisposition RunnableSurface(
        CliCommandKind cliCommand,
        CliSharedServiceBoundary service) =>
        new(cliCommand, CliAgentCommandDispositionKind.RunnableTypedCommand, service,
            "Typed shared application operation without a one-to-one public agent command discriminator.");

    private static void EnsureExactCoverage<T>(IEnumerable<T> expected, IEnumerable<T> actual, string label)
        where T : struct, Enum
    {
        var expectedValues = expected.OrderBy(value => Convert.ToInt32(value)).ToArray();
        var actualValues = actual.OrderBy(value => Convert.ToInt32(value)).ToArray();
        if (!actualValues.SequenceEqual(expectedValues) || actualValues.Distinct().Count() != actualValues.Length)
        {
            throw new InvalidOperationException(
                $"The CLI disposition catalog does not classify every {label} exactly once.");
        }
    }
}
