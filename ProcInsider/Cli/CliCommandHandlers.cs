using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Services.AgentIpc;
using ProcInsider.Services.Features;

namespace ProcInsider.Cli;

internal interface ICliCommandHandler
{
    CliCommandKind Kind { get; }

    Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken);
}

internal interface ICliCommandHandlerFactory : IDisposable
{
    ICliCommandHandler Create(CliCommandKind kind);
}

internal sealed class CliDispatcher
{
    private readonly IFeatureCatalog _featureCatalog;
    private readonly ICliCommandHandlerFactory _handlerFactory;

    public CliDispatcher(
        IFeatureCatalog featureCatalog,
        ICliCommandHandlerFactory handlerFactory)
    {
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
        _handlerFactory = handlerFactory ?? throw new ArgumentNullException(nameof(handlerFactory));
    }

    public Task<CliCommandResult> DispatchAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        var unavailable = GetAvailabilityFailure(_featureCatalog, invocation);
        if (unavailable != null)
        {
            return Task.FromResult(unavailable);
        }

        var handler = _handlerFactory.Create(invocation.Kind);
        if (handler.Kind != invocation.Kind)
        {
            return Task.FromResult(CliCommandResult.Failed(
                CliExitCode.Failure,
                "HandlerMismatch",
                "The command registry selected an incompatible handler."));
        }

        return handler.ExecuteAsync(invocation, cancellationToken);
    }

    public static CliCommandResult? GetAvailabilityFailure(
        IFeatureCatalog featureCatalog,
        CliInvocation invocation)
    {
        ArgumentNullException.ThrowIfNull(featureCatalog);
        ArgumentNullException.ThrowIfNull(invocation);
        var definition = CliCommandRegistry.Get(invocation.Kind);
        if (definition.DomainFeature is { } domainFeature &&
            !featureCatalog.IsPublished(domainFeature))
        {
            return CliCommandResult.Failed(
                CliExitCode.Rejected,
                "FeatureNotPublished",
                $"Command '{definition.Name}' is not published in release '{CliValueSanitizer.Value(featureCatalog.ReleaseId)}'.");
        }

        if (definition.AgentCommand is { } agentCommand &&
            !AgentCommandFeaturePolicy.GetPublishedCommandCapabilities(featureCatalog)
                .Any(capability =>
                    capability.CommandKind == agentCommand &&
                    capability.OperationalAvailability == AgentCommandOperationalAvailability.Supported))
        {
            return CliCommandResult.Failed(
                CliExitCode.Rejected,
                ViewerAgentCommandErrorCodes.CommandNotAvailable,
                $"Command '{definition.Name}' is not operationally available.");
        }

        return null;
    }
}

internal sealed class DefaultCliCommandHandlerFactory : ICliCommandHandlerFactory
{
    private readonly IFeatureCatalog _featureCatalog;
    private readonly Func<IViewerCliAgentService> _agentServiceFactory;
    private IViewerCliAgentService? _agentService;
    private bool _disposed;

    public DefaultCliCommandHandlerFactory(
        IFeatureCatalog featureCatalog,
        Func<IViewerCliAgentService>? agentServiceFactory = null)
    {
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
        _agentServiceFactory = agentServiceFactory ?? (() => new ViewerCliAgentService(
            _featureCatalog,
            _featureCatalog.ReleaseId));
    }

    public ICliCommandHandler Create(CliCommandKind kind)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return kind switch
        {
            CliCommandKind.Help => new HelpCliCommandHandler(_featureCatalog),
            CliCommandKind.Version => new VersionCliCommandHandler(_featureCatalog.ReleaseId),
            CliCommandKind.AgentDiscover or
            CliCommandKind.AgentStatus or
            CliCommandKind.AgentCapabilities =>
                new AgentReadCliCommandHandler(kind, GetAgentService(), _featureCatalog),
            CliCommandKind.CaptureConfigurationShow or
            CliCommandKind.CaptureConfigurationCheck or
            CliCommandKind.CaptureConfigurationSave or
            CliCommandKind.CaptureStart or
            CliCommandKind.CaptureStop or
            CliCommandKind.CaptureSourceStart or
            CliCommandKind.CaptureSourceStop or
            CliCommandKind.AgentJobList or
            CliCommandKind.AgentJobStatus or
            CliCommandKind.AgentJobWait or
            CliCommandKind.AgentJobCancel =>
                new AgentCaptureCliCommandHandler(kind, GetAgentService()),
            CliCommandKind.AgentEvidenceEnrich or
            CliCommandKind.AgentProcessDump or
            CliCommandKind.AgentFilesystemImport =>
                new AgentEvidenceCliCommandHandler(kind, GetAgentService()),
            CliCommandKind.AgentNetworkStart or
            CliCommandKind.AgentNetworkStop or
            CliCommandKind.AgentZeekRun or
            CliCommandKind.AgentProcessMonitorStart or
            CliCommandKind.AgentProcessMonitorStop or
            CliCommandKind.AgentProcessMonitorImport or
            CliCommandKind.AgentSqliteBenchmarkStart =>
                new AgentToolCliCommandHandler(kind, GetAgentService()),
            CliCommandKind.AgentMemoryAcquire or
            CliCommandKind.AgentMemoryImport or
            CliCommandKind.AgentVolatilityRun =>
                new AgentMemoryCliCommandHandler(kind, GetAgentService()),
            CliCommandKind.HostMonitoringConfigurationShow or
            CliCommandKind.HostMonitoringConfigurationCheck or
            CliCommandKind.HostMonitoringConfigurationSave or
            CliCommandKind.HostMonitoringDeploy or
            CliCommandKind.HostMonitoringReverse =>
                new HostMonitoringCliCommandHandler(kind, GetAgentService()),
            CliCommandKind.AgentReconnect or
            CliCommandKind.AgentStart or
            CliCommandKind.AgentStop or
            CliCommandKind.AgentPairingStatus or
            CliCommandKind.AgentPairingRotate or
            CliCommandKind.AgentPairingRevoke =>
                new AgentControlCliCommandHandler(kind, GetAgentService()),
            CliCommandKind.Shell => throw new InvalidOperationException(
                "The shell is a presentation loop and cannot be dispatched as a product command."),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown CLI command kind.")
        };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _agentService?.Dispose();
    }

    private IViewerCliAgentService GetAgentService() =>
        _agentService ??= _agentServiceFactory();
}

internal sealed class HelpCliCommandHandler : ICliCommandHandler
{
    private readonly IFeatureCatalog _featureCatalog;

    public HelpCliCommandHandler(IFeatureCatalog featureCatalog)
    {
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
    }

    public CliCommandKind Kind => CliCommandKind.Help;

    public Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var published = CliHelpFormatter.GetPublishedDefinitions(_featureCatalog);
        var monitoringPublished = _featureCatalog.IsPublished(
            FeatureIds.SecurityMonitoringConfiguration);
        return Task.FromResult(CliCommandResult.Succeeded(
            CliHelpFormatter.Format(published, monitoringPublished),
            new CliHelpDto(
                "dfiroscope <noun> <verb> [options]",
                published.Select(definition => new CliHelpCommandDto(
                    definition.Name,
                    definition.Usage,
                    definition.Summary)).ToArray(),
                new[]
                {
                    "--output text|json",
                    "--session <absolute-session-root-or-session.json>",
                    "--yes",
                    "--live-buffer-memory-mb 500|1024|2048",
                    "--timeout-seconds 1..86400",
                    monitoringPublished
                        ? "--file <absolute-json> (capture or host-monitoring configuration)"
                        : "--file <absolute-json> (capture configuration)",
                    "--source <Runtime|ETW|Security|PowerShell|WindowsOther|Sysmon>",
                    "--job-id <guid>",
                    "--wait",
                    "--all | --process-entity-id <id>... | --process-key <PID_StartTimeTicks>...",
                    "--modules | --handles | --pe [--pe-strings deferred|immediate]",
                    "--kind full|mini",
                    "--path <absolute-file-or-folder> [--recurse] [--include-ntfs] [--include-prefetch] [--max-files 1..10000]",
                    "--output-file-name <leaf> [--acquisition-timeout-seconds 1..7200]",
                    "--image-path <absolute-memory-image> | --image-id <staged-image-id>",
                    "--plugin <name>... [--plugin-timeout-seconds 30..86400]"
                },
                CliShellBuiltInCatalog.Definitions.Select(definition => new CliHelpCommandDto(
                    definition.Name,
                    definition.Usage,
                    definition.Summary)).ToArray())));
    }
}

internal sealed class VersionCliCommandHandler : ICliCommandHandler
{
    private readonly string _releaseId;

    public VersionCliCommandHandler(string releaseId)
    {
        _releaseId = releaseId;
    }

    public CliCommandKind Kind => CliCommandKind.Version;

    public Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var version = typeof(VersionCliCommandHandler).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        var data = new CliVersionDto(
            ProductIdentity.DisplayName,
            version,
            CliValueSanitizer.Value(_releaseId));
        return Task.FromResult(CliCommandResult.Succeeded(
            $"{data.Product} {data.Version} ({data.ReleaseId})",
            data));
    }
}

internal sealed class AgentReadCliCommandHandler : ICliCommandHandler
{
    private readonly IViewerCliAgentService _agentService;
    private readonly IFeatureCatalog _featureCatalog;

    public AgentReadCliCommandHandler(
        CliCommandKind kind,
        IViewerCliAgentService agentService,
        IFeatureCatalog featureCatalog)
    {
        if (kind is not
            (CliCommandKind.AgentDiscover or
             CliCommandKind.AgentStatus or
             CliCommandKind.AgentCapabilities))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        _agentService = agentService ?? throw new ArgumentNullException(nameof(agentService));
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
    }

    public CliCommandKind Kind { get; }

    public async Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }

        return Kind == CliCommandKind.AgentDiscover
            ? ExecuteDiscover(cancellationToken)
            : await ExecuteAuthenticatedAsync(invocation, cancellationToken).ConfigureAwait(false);
    }

    private CliCommandResult ExecuteDiscover(CancellationToken cancellationToken)
    {
        LocalAgentDiscoveryResult discovery;
        try
        {
            discovery = _agentService.Discover();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }
        catch
        {
            return CliCommandResult.Failed(
                CliExitCode.Failure,
                "DiscoveryFailure",
                "Local-agent discovery failed internally.");
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }

        var data = CliDtoMapper.FromDiscovery(discovery);
        var text = CliTextFormatter.Discovery(data);
        if (discovery.Outcome == LocalAgentDiscoveryOutcome.SingleCandidate)
        {
            return CliCommandResult.Succeeded(text, data);
        }

        var code = discovery.Outcome switch
        {
            LocalAgentDiscoveryOutcome.Absent => "AgentUnavailable",
            LocalAgentDiscoveryOutcome.DiscoveryUnavailable => "DiscoveryUnavailable",
            LocalAgentDiscoveryOutcome.MultipleCandidates => "MultipleAgents",
            LocalAgentDiscoveryOutcome.AmbiguousCandidates => "AmbiguousAgents",
            LocalAgentDiscoveryOutcome.UnresolvedInspection => "AgentIdentityUnresolved",
            _ => "DiscoveryFailure"
        };
        return CliCommandResult.Failed(
            CliExitCode.Unavailable,
            code,
            CliDtoMapper.DiscoveryMessage(discovery.Outcome),
            text: text,
            data: data);
    }

    private async Task<CliCommandResult> ExecuteAuthenticatedAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        var opened = await _agentService.OpenSessionAsync(
                invocation.SessionTarget!,
                cancellationToken)
            .ConfigureAwait(false);
        if (!opened.Success)
        {
            return opened.Failure ?? CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The explicit local-agent session could not be opened.");
        }

        using var session = opened.Session!;
        if (Kind == CliCommandKind.AgentStatus)
        {
            var data = CliDtoMapper.FromHealth(session.Health);
            return CliCommandResult.Succeeded(CliTextFormatter.Status(data), data);
        }

        if (Kind == CliCommandKind.AgentCapabilities)
        {
            var data = CliDtoMapper.FromCapabilities(
                session.Health.ReleaseProfile,
                _featureCatalog);
            return CliCommandResult.Succeeded(CliTextFormatter.Capabilities(data), data);
        }

        throw new InvalidOperationException("The selected read handler has no remaining command branch.");
    }
}

internal sealed class AgentCaptureCliCommandHandler : ICliCommandHandler
{
    private readonly IViewerCliAgentService _agentService;

    public AgentCaptureCliCommandHandler(
        CliCommandKind kind,
        IViewerCliAgentService agentService)
    {
        if (kind is not
            (CliCommandKind.CaptureConfigurationShow or
             CliCommandKind.CaptureConfigurationCheck or
             CliCommandKind.CaptureConfigurationSave or
             CliCommandKind.CaptureStart or
             CliCommandKind.CaptureStop or
             CliCommandKind.CaptureSourceStart or
             CliCommandKind.CaptureSourceStop or
             CliCommandKind.AgentJobList or
             CliCommandKind.AgentJobStatus or
             CliCommandKind.AgentJobWait or
             CliCommandKind.AgentJobCancel))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        _agentService = agentService ?? throw new ArgumentNullException(nameof(agentService));
    }

    public CliCommandKind Kind { get; }

    public async Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }

        var opened = await _agentService.OpenSessionAsync(
                invocation.SessionTarget!,
                cancellationToken)
            .ConfigureAwait(false);
        if (!opened.Success)
        {
            return opened.Failure ?? CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The explicit local-agent session could not be opened.");
        }

        using var session = opened.Session!;
        using var actions = new ViewerAgentCaptureActionService(
            new DelegateViewerAgentCaptureActionRuntime(
                target => target == session.CaptureTarget,
                async (command, _, _, token) => ToCaptureActionResponse(
                    await session.ExecuteAsync(command, token).ConfigureAwait(false)),
                _ => Task.FromResult(new AgentIpcResponse
                {
                    Success = true,
                    Health = session.Health
                }),
                session.GetJobStatusAsync));

        ViewerAgentCaptureActionResult result;
        TimeSpan? timeout = invocation.TimeoutSeconds.HasValue
            ? TimeSpan.FromSeconds(invocation.TimeoutSeconds.Value)
            : null;
        try
        {
            result = Kind switch
            {
                CliCommandKind.CaptureConfigurationShow =>
                    await actions.GetConfigurationAsync(session.CaptureTarget, cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.CaptureConfigurationCheck when invocation.FilePath != null =>
                    await actions.CheckConfigurationFileAsync(
                            session.CaptureTarget,
                            invocation.FilePath,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.CaptureConfigurationCheck =>
                    await actions.CheckConfigurationAsync(
                            session.CaptureTarget,
                            null,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.CaptureConfigurationSave =>
                    await actions.SaveConfigurationFileAsync(
                            session.CaptureTarget,
                            invocation.FilePath!,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.CaptureStart =>
                    await actions.StartConfiguredCaptureAsync(
                            session.CaptureTarget,
                            invocation.Wait,
                            timeout,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.CaptureStop =>
                    await actions.StopConfiguredCaptureAsync(
                            session.CaptureTarget,
                            invocation.Wait,
                            timeout,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.CaptureSourceStart =>
                    await actions.StartSourceAsync(
                            session.CaptureTarget,
                            invocation.Source!,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.CaptureSourceStop =>
                    await actions.StopSourceAsync(
                            session.CaptureTarget,
                            invocation.Source!,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.AgentJobList =>
                    await actions.ListJobsAsync(session.CaptureTarget, cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.AgentJobStatus =>
                    await actions.GetJobStatusAsync(
                            session.CaptureTarget,
                            invocation.JobId!.Value,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.AgentJobWait =>
                    await actions.WaitForJobAsync(
                            session.CaptureTarget,
                            invocation.JobId!.Value,
                            timeout,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.AgentJobCancel =>
                    await actions.CancelJobAsync(
                            session.CaptureTarget,
                            invocation.JobId!.Value,
                            cancellationToken)
                        .ConfigureAwait(false),
                _ => throw new InvalidOperationException("Unsupported capture action command.")
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }
        catch
        {
            return CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The capture action failed internally.");
        }

        return ToCliResult(invocation, result);
    }

    private static CliCommandResult ToCliResult(
        CliInvocation invocation,
        ViewerAgentCaptureActionResult result)
    {
        object? data;
        string text;
        if (result.Response?.CaptureConfiguration != null)
        {
            data = CliDtoMapper.FromCaptureConfiguration(result.Response.CaptureConfiguration);
            text = CliTextFormatter.CaptureConfiguration((CliCaptureConfigurationDto)data);
        }
        else if (result.Response?.ConfigurationCheck != null)
        {
            data = CliDtoMapper.FromConfigurationCheck(result.Response.ConfigurationCheck);
            text = CliTextFormatter.ConfigurationCheck((CliConfigurationCheckDto)data);
        }
        else if (result.Response?.CaptureLifecycle != null && !invocation.Wait)
        {
            data = CliDtoMapper.FromCaptureAction(invocation.CommandName, result);
            text = CliTextFormatter.CaptureAction((CliCaptureActionDto)data);
        }
        else if (result.ActiveJobs.Count > 0 || KindIsJobList(invocation.Kind))
        {
            data = new CliJobListDto(
                result.ActiveJobs.Select(CliDtoMapper.FromActiveJob).ToArray());
            text = CliTextFormatter.JobList((CliJobListDto)data);
        }
        else if (result.Job != null || result.Jobs.Count > 0)
        {
            var jobs = result.Jobs.Count > 0
                ? result.Jobs.Select(CliDtoMapper.FromJob).ToArray()
                : new[] { CliDtoMapper.FromJob(result.Job!) };
            data = new CliJobResultDto(jobs, CliValueSanitizer.OneLine(result.Diagnostic));
            text = CliTextFormatter.Jobs((CliJobResultDto)data);
        }
        else
        {
            data = CliDtoMapper.FromCaptureAction(invocation.CommandName, result);
            text = CliTextFormatter.CaptureAction((CliCaptureActionDto)data);
        }

        if (result.Succeeded)
        {
            return CliCommandResult.Succeeded(text, data);
        }

        var exitCode = result.Outcome switch
        {
            ViewerAgentCaptureActionOutcome.Canceled => CliExitCode.Canceled,
            ViewerAgentCaptureActionOutcome.TimedOut => CliExitCode.Timeout,
            ViewerAgentCaptureActionOutcome.Unavailable or
            ViewerAgentCaptureActionOutcome.Busy => CliExitCode.Unavailable,
            ViewerAgentCaptureActionOutcome.AgentRejected or
            ViewerAgentCaptureActionOutcome.JobCanceled or
            ViewerAgentCaptureActionOutcome.JobFailed => CliExitCode.AgentRejected,
            ViewerAgentCaptureActionOutcome.InternalFailure => CliExitCode.Failure,
            _ => CliExitCode.Rejected
        };
        exitCode = result.ErrorCode switch
        {
            "Canceled" => CliExitCode.Canceled,
            "AgentTimeout" => CliExitCode.Timeout,
            "AgentUnavailable" or "PairingUnavailable" => CliExitCode.Unavailable,
            "AuthenticationRejected" or "SessionSuperseded" => CliExitCode.Rejected,
            _ => exitCode
        };
        return CliCommandResult.Failed(
            exitCode,
            result.ErrorCode,
            result.Diagnostic,
            result.IsRetryable,
            text,
            data);
    }

    private static bool KindIsJobList(CliCommandKind kind) =>
        kind == CliCommandKind.AgentJobList;

    private static AgentIpcResponse ToCaptureActionResponse(
        ViewerAgentCommandResult result)
    {
        if (result.Success)
        {
            return result.ToAgentIpcResponse();
        }

        var mapped = CliAgentFailureMapper.FromViewerResult(result);
        return AgentIpcResponse.Failure(
            result.CommandId == Guid.Empty ? Guid.NewGuid() : result.CommandId,
            mapped.Error?.Code ?? "AgentRejected",
            mapped.Error?.Message ?? "The authenticated agent rejected the typed command.",
            mapped.Error?.Retryable ?? false);
    }
}

internal sealed class HostMonitoringCliCommandHandler : ICliCommandHandler
{
    private readonly IViewerCliAgentService _agentService;

    public HostMonitoringCliCommandHandler(
        CliCommandKind kind,
        IViewerCliAgentService agentService)
    {
        if (kind is not
            (CliCommandKind.HostMonitoringConfigurationShow or
             CliCommandKind.HostMonitoringConfigurationCheck or
             CliCommandKind.HostMonitoringConfigurationSave or
             CliCommandKind.HostMonitoringDeploy or
             CliCommandKind.HostMonitoringReverse))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        _agentService = agentService ?? throw new ArgumentNullException(nameof(agentService));
    }

    public CliCommandKind Kind { get; }

    public async Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }

        if (Kind is
                (CliCommandKind.HostMonitoringDeploy or
                 CliCommandKind.HostMonitoringReverse) &&
            !invocation.Confirmed)
        {
            return CliCommandResult.Failed(
                CliExitCode.Usage,
                "ConfirmationRequired",
                $"{invocation.CommandName} requires --yes before any session or service is opened.");
        }

        var opened = await _agentService.OpenSessionAsync(
                invocation.SessionTarget!,
                cancellationToken)
            .ConfigureAwait(false);
        if (!opened.Success)
        {
            return opened.Failure ?? CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The explicit local-agent session could not be opened.");
        }

        using var session = opened.Session!;
        var captureTarget = session.CaptureTarget;
        var target = new ViewerHostMonitoringActionTarget(
            captureTarget.AgentId,
            captureTarget.HostId,
            captureTarget.SessionId,
            captureTarget.SessionRoot,
            captureTarget.WorkspaceGeneration,
            RequireViewerConnection: false);
        var actions = new ViewerHostMonitoringActionService(
            new DelegateViewerHostMonitoringActionRuntime(
                candidate => candidate == target,
                async (command, _, _, token) => ToHostMonitoringResponse(
                    await session.ExecuteAsync(command, token).ConfigureAwait(false))));

        ViewerHostMonitoringActionResult result;
        try
        {
            result = Kind switch
            {
                CliCommandKind.HostMonitoringConfigurationShow =>
                    await actions.GetConfigurationAsync(target, cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.HostMonitoringConfigurationCheck when invocation.FilePath != null =>
                    await actions.CheckConfigurationFileAsync(
                            target,
                            invocation.FilePath,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.HostMonitoringConfigurationCheck =>
                    await actions.CheckSavedConfigurationAsync(target, cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.HostMonitoringConfigurationSave =>
                    await actions.SaveConfigurationFileAsync(
                            target,
                            invocation.FilePath!,
                            cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.HostMonitoringDeploy =>
                    await actions.DeploySavedConfigurationAsync(target, cancellationToken)
                        .ConfigureAwait(false),
                CliCommandKind.HostMonitoringReverse =>
                    await actions.ReverseSavedDeploymentAsync(target, cancellationToken)
                        .ConfigureAwait(false),
                _ => throw new InvalidOperationException(
                    "The selected host-monitoring handler has no matching action.")
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }
        catch
        {
            return CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The host-monitoring action failed internally.");
        }

        return ToCliResult(invocation, result);
    }

    private static CliCommandResult ToCliResult(
        CliInvocation invocation,
        ViewerHostMonitoringActionResult result)
    {
        object data;
        string text;
        if (result.Response?.HostMonitoringConfiguration != null)
        {
            data = CliDtoMapper.FromHostMonitoringConfiguration(
                result.Response.HostMonitoringConfiguration);
            text = CliTextFormatter.HostMonitoringConfiguration(
                (CliHostMonitoringConfigurationDto)data);
        }
        else if (result.Response?.ConfigurationCheck != null)
        {
            data = CliDtoMapper.FromConfigurationCheck(result.Response.ConfigurationCheck);
            text = CliTextFormatter.ConfigurationCheck((CliConfigurationCheckDto)data);
        }
        else if (result.Response?.MonitoringDeployment != null)
        {
            data = CliDtoMapper.FromMonitoringDeployment(result.Response.MonitoringDeployment);
            text = CliTextFormatter.MonitoringDeployment((CliMonitoringDeploymentDto)data);
        }
        else
        {
            data = new CliHostMonitoringActionDto(
                invocation.CommandName,
                result.Outcome.ToString(),
                CliValueSanitizer.OneLine(result.Diagnostic));
            text = CliTextFormatter.HostMonitoringAction((CliHostMonitoringActionDto)data);
        }

        if (result.Succeeded)
        {
            return CliCommandResult.Succeeded(text, data);
        }

        var exitCode = result.Outcome switch
        {
            ViewerHostMonitoringActionOutcome.Canceled => CliExitCode.Canceled,
            ViewerHostMonitoringActionOutcome.TimedOut => CliExitCode.Timeout,
            ViewerHostMonitoringActionOutcome.Unavailable => CliExitCode.Unavailable,
            ViewerHostMonitoringActionOutcome.AgentRejected => CliExitCode.AgentRejected,
            ViewerHostMonitoringActionOutcome.InternalFailure => CliExitCode.Failure,
            _ => CliExitCode.Rejected
        };
        exitCode = result.ErrorCode switch
        {
            "Canceled" => CliExitCode.Canceled,
            "AgentTimeout" => CliExitCode.Timeout,
            "AgentUnavailable" or "PairingUnavailable" => CliExitCode.Unavailable,
            _ => exitCode
        };
        return CliCommandResult.Failed(
            exitCode,
            result.ErrorCode,
            result.Diagnostic,
            result.IsRetryable,
            text,
            data);
    }

    private static AgentIpcResponse ToHostMonitoringResponse(ViewerAgentCommandResult result)
    {
        if (result.Success)
        {
            return result.ToAgentIpcResponse();
        }

        var mapped = CliAgentFailureMapper.FromViewerResult(result);
        return AgentIpcResponse.Failure(
            result.CommandId == Guid.Empty ? Guid.NewGuid() : result.CommandId,
            mapped.Error?.Code ?? "AgentRejected",
            mapped.Error?.Message ?? "The authenticated agent rejected the typed command.",
            mapped.Error?.Retryable ?? false);
    }
}

internal sealed class AgentEvidenceCliCommandHandler : ICliCommandHandler
{
    private readonly IViewerCliAgentService _agentService;

    public AgentEvidenceCliCommandHandler(
        CliCommandKind kind,
        IViewerCliAgentService agentService)
    {
        if (kind is not
            (CliCommandKind.AgentEvidenceEnrich or
             CliCommandKind.AgentProcessDump or
             CliCommandKind.AgentFilesystemImport))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        _agentService = agentService ?? throw new ArgumentNullException(nameof(agentService));
    }

    public CliCommandKind Kind { get; }

    public async Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }

        var opened = await _agentService.OpenSessionAsync(
                invocation.SessionTarget!,
                cancellationToken)
            .ConfigureAwait(false);
        if (!opened.Success)
        {
            return opened.Failure ?? CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The explicit local-agent session could not be opened.");
        }

        using var session = opened.Session!;
        var runtime = new DelegateViewerAgentCaptureActionRuntime(
            target => target == session.CaptureTarget,
            async (command, _, _, token) => ToEvidenceActionResponse(
                await session.ExecuteAsync(command, token).ConfigureAwait(false)),
            _ => Task.FromResult(new AgentIpcResponse
            {
                Success = true,
                Health = session.Health
            }),
            session.GetJobStatusAsync);
        using var actions = new ViewerAgentEvidenceActionService(runtime);
        TimeSpan? timeout = invocation.TimeoutSeconds.HasValue
            ? TimeSpan.FromSeconds(invocation.TimeoutSeconds.Value)
            : null;

        ViewerAgentEvidenceActionResult result;
        try
        {
            result = Kind switch
            {
                CliCommandKind.AgentEvidenceEnrich => await QueueEnrichmentAsync(
                        actions,
                        session,
                        invocation,
                        timeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentProcessDump => await actions.QueueProcessDumpAsync(
                        session.CaptureTarget,
                        new ViewerProcessDumpActionRequest(
                            invocation.ProcessKeys!.Single(),
                            invocation.DumpKind!.Value,
                            invocation.Confirmed),
                        invocation.Wait,
                        timeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentFilesystemImport => await actions.QueueFilesystemImportAsync(
                        session.CaptureTarget,
                        new ViewerFilesystemImportActionRequest(
                            invocation.SourcePath!,
                            invocation.Recurse,
                            invocation.IncludeNtfs,
                            invocation.IncludePrefetch,
                            invocation.MaxFiles ?? ViewerAgentEvidenceActionService.MaximumFilesystemImportFiles),
                        invocation.Wait,
                        timeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                _ => throw new InvalidOperationException("Unsupported evidence action command.")
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }
        catch
        {
            return CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The evidence action failed internally.");
        }

        var safeDiagnostic = EvidenceActionDiagnosticSanitizer.Sanitize(
            invocation,
            session.CaptureTarget,
            result);
        var data = CliDtoMapper.FromEvidenceAction(invocation, result, safeDiagnostic);
        var text = CliTextFormatter.EvidenceAction(data);
        if (result.Succeeded)
        {
            return CliCommandResult.Succeeded(text, data);
        }

        var exitCode = result.Outcome switch
        {
            ViewerAgentEvidenceActionOutcome.Canceled => CliExitCode.Canceled,
            ViewerAgentEvidenceActionOutcome.TimedOut => CliExitCode.Timeout,
            ViewerAgentEvidenceActionOutcome.Unavailable or
            ViewerAgentEvidenceActionOutcome.Busy => CliExitCode.Unavailable,
            ViewerAgentEvidenceActionOutcome.AgentRejected or
            ViewerAgentEvidenceActionOutcome.JobCanceled or
            ViewerAgentEvidenceActionOutcome.JobFailed => CliExitCode.AgentRejected,
            ViewerAgentEvidenceActionOutcome.InternalFailure => CliExitCode.Failure,
            _ => CliExitCode.Rejected
        };
        return CliCommandResult.Failed(
            exitCode,
            result.ErrorCode,
            safeDiagnostic,
            result.IsRetryable,
            text,
            data);
    }

    private static async Task<ViewerAgentEvidenceActionResult> QueueEnrichmentAsync(
        ViewerAgentEvidenceActionService actions,
        IViewerCliAgentSession session,
        CliInvocation invocation,
        TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        var scope = invocation.AllProcesses
            ? ArtifactEnrichmentQueueScope.ExplicitAll
            : invocation.ProcessEntityIds is { Count: > 0 }
                ? ArtifactEnrichmentQueueScope.ExplicitProcessEntities
                : ArtifactEnrichmentQueueScope.ExplicitProcessKeys;
        using var coordinator = new ArtifactEnrichmentWorkflowCoordinator(
            session.CaptureTarget.WorkspaceGeneration,
            new DelegateArtifactEnrichmentWorkflowRuntime(
                async (command, _, _, _, token) => ToEvidenceActionResponse(
                    await session.ExecuteAsync(command, token).ConfigureAwait(false)),
                session.GetJobStatusAsync,
                () => new AgentCaptureControlViewState
                {
                    SnapshotStatus = AgentControlSnapshotStatus.Current,
                    SnapshotAccepted = true
                },
                (_, _) => { }));
        return await actions.QueueEnrichmentAsync(
                session.CaptureTarget,
                coordinator,
                new ArtifactEnrichmentQueueRequest(
                    scope,
                    invocation.CaptureModules,
                    invocation.CaptureHandles,
                    invocation.CapturePe,
                    invocation.PeStringExtractionMode,
                    "queue explicit CLI evidence enrichment",
                    StartAgentIfNeeded: false,
                    RequireViewerConnection: false,
                    ProcessEntityIds: invocation.ProcessEntityIds,
                    ProcessKeys: invocation.ProcessKeys),
                invocation.Wait,
                timeout,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static AgentIpcResponse ToEvidenceActionResponse(ViewerAgentCommandResult result)
    {
        if (result.Success)
        {
            return result.ToAgentIpcResponse();
        }

        var mapped = CliAgentFailureMapper.FromViewerResult(result);
        return AgentIpcResponse.Failure(
            result.CommandId == Guid.Empty ? Guid.NewGuid() : result.CommandId,
            mapped.Error?.Code ?? "AgentRejected",
            mapped.Error?.Message ?? "The authenticated agent rejected the typed command.",
            mapped.Error?.Retryable ?? false);
    }
}

internal sealed class AgentToolCliCommandHandler : ICliCommandHandler
{
    private readonly IViewerCliAgentService _agentService;

    public AgentToolCliCommandHandler(
        CliCommandKind kind,
        IViewerCliAgentService agentService)
    {
        if (kind is not
            (CliCommandKind.AgentNetworkStart or
             CliCommandKind.AgentNetworkStop or
             CliCommandKind.AgentZeekRun or
             CliCommandKind.AgentProcessMonitorStart or
             CliCommandKind.AgentProcessMonitorStop or
             CliCommandKind.AgentProcessMonitorImport or
             CliCommandKind.AgentSqliteBenchmarkStart))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        _agentService = agentService ?? throw new ArgumentNullException(nameof(agentService));
    }

    public CliCommandKind Kind { get; }

    public async Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }

        var opened = await _agentService.OpenSessionAsync(
                invocation.SessionTarget!,
                cancellationToken)
            .ConfigureAwait(false);
        if (!opened.Success)
        {
            return opened.Failure ?? CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The explicit local-agent session could not be opened.");
        }

        using var session = opened.Session!;
        var runtime = new DelegateViewerAgentCaptureActionRuntime(
            target => target == session.CaptureTarget,
            async (command, _, _, token) => ToActionResponse(
                await session.ExecuteAsync(command, token).ConfigureAwait(false)),
            _ => Task.FromResult(new AgentIpcResponse
            {
                Success = true,
                Health = session.Health
            }),
            session.GetJobStatusAsync);
        using var actions = new ViewerAgentToolActionService(runtime);
        TimeSpan? timeout = invocation.TimeoutSeconds.HasValue
            ? TimeSpan.FromSeconds(invocation.TimeoutSeconds.Value)
            : null;

        ViewerAgentToolActionResult result;
        try
        {
            result = Kind switch
            {
                CliCommandKind.AgentNetworkStart => await actions.StartNetworkCaptureAsync(
                        session.CaptureTarget,
                        invocation.Wait,
                        timeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentNetworkStop => await actions.StopNetworkCaptureAsync(
                        session.CaptureTarget,
                        invocation.Wait,
                        timeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentZeekRun => await actions.QueueZeekAsync(
                        session.CaptureTarget,
                        new ViewerZeekActionRequest(
                            invocation.CaptureId ?? string.Empty,
                            invocation.PcapPath ?? string.Empty,
                            invocation.ZeekPath ?? string.Empty,
                            invocation.WslDistributionName ?? string.Empty,
                            invocation.WslZeekCommand ?? string.Empty),
                        invocation.Wait,
                        timeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentProcessMonitorStart => await actions.StartProcessMonitorCaptureAsync(
                        session.CaptureTarget,
                        new ViewerProcessMonitorStartActionRequest(
                            invocation.ProcmonPath ?? string.Empty,
                            invocation.AcceptEula,
                            invocation.MaxRows ?? AgentToolActionPolicy.MaximumProcessMonitorRows),
                        invocation.Wait,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentProcessMonitorStop => await actions.StopProcessMonitorCaptureAsync(
                        session.CaptureTarget,
                        new ViewerProcessMonitorStopActionRequest(invocation.ProcmonPath ?? string.Empty),
                        invocation.Wait,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentProcessMonitorImport => await actions.QueueProcessMonitorImportAsync(
                        session.CaptureTarget,
                        new ViewerProcessMonitorImportActionRequest(
                            invocation.InputPath!,
                            invocation.ProcmonPath ?? string.Empty,
                            invocation.MaxRows ?? AgentToolActionPolicy.MaximumProcessMonitorRows),
                        invocation.Wait,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentSqliteBenchmarkStart => await actions.StartSqliteBenchmarkAsync(
                        session.CaptureTarget,
                        new ViewerSqliteBenchmarkActionRequest(
                            invocation.PhaseDurationSeconds,
                            invocation.MaxPhaseCount,
                            invocation.InitialProcessBatchSize,
                            invocation.InitialEventsPerProcess,
                            invocation.MaxInFlightBatches,
                            invocation.MaxPendingWriterWorkItems),
                        invocation.Wait,
                        timeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                _ => throw new InvalidOperationException("Unsupported agent tool action command.")
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }
        catch
        {
            return CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The agent tool action failed internally.");
        }

        var safeDiagnostic = ToolActionDiagnosticSanitizer.Sanitize(invocation, result);
        var data = CliDtoMapper.FromToolAction(invocation, result, safeDiagnostic);
        var text = CliTextFormatter.ToolAction(data);
        if (result.Succeeded)
        {
            return CliCommandResult.Succeeded(text, data);
        }

        var exitCode = result.Outcome switch
        {
            ViewerAgentToolActionOutcome.Canceled => CliExitCode.Canceled,
            ViewerAgentToolActionOutcome.TimedOut => CliExitCode.Timeout,
            ViewerAgentToolActionOutcome.Unavailable or
            ViewerAgentToolActionOutcome.Busy => CliExitCode.Unavailable,
            ViewerAgentToolActionOutcome.AgentRejected or
            ViewerAgentToolActionOutcome.JobCanceled or
            ViewerAgentToolActionOutcome.JobFailed => CliExitCode.AgentRejected,
            ViewerAgentToolActionOutcome.InternalFailure => CliExitCode.Failure,
            _ => CliExitCode.Rejected
        };
        return CliCommandResult.Failed(
            exitCode,
            result.ErrorCode,
            safeDiagnostic,
            result.IsRetryable,
            text,
            data);
    }

    private static AgentIpcResponse ToActionResponse(ViewerAgentCommandResult result)
    {
        if (result.Success)
        {
            return result.ToAgentIpcResponse();
        }

        var mapped = CliAgentFailureMapper.FromViewerResult(result);
        return AgentIpcResponse.Failure(
            result.CommandId == Guid.Empty ? Guid.NewGuid() : result.CommandId,
            mapped.Error?.Code ?? "AgentRejected",
            mapped.Error?.Message ?? "The authenticated agent rejected the typed command.",
            mapped.Error?.Retryable ?? false);
    }
}

internal sealed class AgentMemoryCliCommandHandler : ICliCommandHandler
{
    private readonly IViewerCliAgentService _agentService;

    public AgentMemoryCliCommandHandler(CliCommandKind kind, IViewerCliAgentService agentService)
    {
        if (kind is not (CliCommandKind.AgentMemoryAcquire or
            CliCommandKind.AgentMemoryImport or
            CliCommandKind.AgentVolatilityRun))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        _agentService = agentService ?? throw new ArgumentNullException(nameof(agentService));
    }

    public CliCommandKind Kind { get; }

    public async Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(CliExitCode.Canceled, "Canceled", "The command was canceled.");
        }

        var opened = await _agentService.OpenSessionAsync(invocation.SessionTarget!, cancellationToken)
            .ConfigureAwait(false);
        if (!opened.Success)
        {
            return opened.Failure ?? CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The explicit local-agent session could not be opened.");
        }

        using var session = opened.Session!;
        var runtime = new DelegateViewerAgentCaptureActionRuntime(
            target => target == session.CaptureTarget,
            async (command, _, _, token) => ToActionResponse(
                await session.ExecuteAsync(command, token).ConfigureAwait(false)),
            _ => Task.FromResult(new AgentIpcResponse { Success = true, Health = session.Health }),
            session.GetJobStatusAsync);
        using var actions = new ViewerMemoryActionService(runtime);
        TimeSpan? waitTimeout = invocation.TimeoutSeconds.HasValue
            ? TimeSpan.FromSeconds(invocation.TimeoutSeconds.Value)
            : null;

        ViewerMemoryActionResult result;
        try
        {
            result = Kind switch
            {
                CliCommandKind.AgentMemoryAcquire => await actions.AcquireAsync(
                        session.CaptureTarget,
                        new ViewerMemoryAcquisitionRequest(
                            invocation.Confirmed,
                            invocation.OutputFileName ?? string.Empty,
                            invocation.AcquisitionTimeoutSeconds ?? AgentMemoryActionPolicy.DefaultAcquisitionTimeoutSeconds),
                        invocation.Wait,
                        waitTimeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentMemoryImport => await actions.ImportAsync(
                        session.CaptureTarget,
                        new ViewerMemoryImageImportRequest(
                            invocation.ImagePath!,
                            invocation.DisplayName ?? string.Empty,
                            invocation.HostName ?? string.Empty,
                            invocation.OsBuild ?? string.Empty,
                            invocation.AcquisitionTool ?? "Analyst import",
                            invocation.AcquisitionToolVersion ?? string.Empty,
                            invocation.AcquisitionCommandLine ?? string.Empty,
                            invocation.PrivilegeState ?? string.Empty),
                        invocation.Wait,
                        waitTimeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                CliCommandKind.AgentVolatilityRun => await actions.RunVolatilityAsync(
                        session.CaptureTarget,
                        new ViewerVolatilityActionRequest(
                            invocation.ImageId ?? string.Empty,
                            invocation.ImagePath ?? string.Empty,
                            invocation.PluginNames,
                            invocation.PluginTimeoutSeconds ?? AgentMemoryActionPolicy.DefaultPluginTimeoutSeconds),
                        invocation.Wait,
                        waitTimeout,
                        cancellationToken)
                    .ConfigureAwait(false),
                _ => throw new InvalidOperationException("Unsupported memory action command.")
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(CliExitCode.Canceled, "Canceled", "The command was canceled.");
        }
        catch
        {
            return CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The memory action failed internally.");
        }

        var safeDiagnostic = MemoryActionDiagnosticSanitizer.Sanitize(invocation, result);
        var data = CliDtoMapper.FromMemoryAction(invocation, result, safeDiagnostic);
        var output = CliTextFormatter.MemoryAction(data);
        if (result.Succeeded)
        {
            return CliCommandResult.Succeeded(output, data);
        }

        var exitCode = result.Outcome switch
        {
            ViewerMemoryActionOutcome.Canceled => CliExitCode.Canceled,
            ViewerMemoryActionOutcome.TimedOut => CliExitCode.Timeout,
            ViewerMemoryActionOutcome.Unavailable or ViewerMemoryActionOutcome.Busy => CliExitCode.Unavailable,
            ViewerMemoryActionOutcome.AgentRejected or
            ViewerMemoryActionOutcome.JobCanceled or
            ViewerMemoryActionOutcome.JobFailed => CliExitCode.AgentRejected,
            ViewerMemoryActionOutcome.InternalFailure => CliExitCode.Failure,
            _ => CliExitCode.Rejected
        };
        return CliCommandResult.Failed(
            exitCode,
            result.ErrorCode,
            safeDiagnostic,
            result.IsRetryable,
            output,
            data);
    }

    private static AgentIpcResponse ToActionResponse(ViewerAgentCommandResult result)
    {
        if (result.Success)
        {
            return result.ToAgentIpcResponse();
        }

        var mapped = CliAgentFailureMapper.FromViewerResult(result);
        return AgentIpcResponse.Failure(
            result.CommandId == Guid.Empty ? Guid.NewGuid() : result.CommandId,
            mapped.Error?.Code ?? "AgentRejected",
            mapped.Error?.Message ?? "The authenticated agent rejected the typed memory command.",
            mapped.Error?.Retryable ?? false);
    }
}

internal static class MemoryActionDiagnosticSanitizer
{
    public static string Sanitize(CliInvocation invocation, ViewerMemoryActionResult result)
    {
        if (result.Outcome == ViewerMemoryActionOutcome.JobFailed)
        {
            return "The agent memory job failed. Inspect bounded agent operational diagnostics for details.";
        }

        var diagnostic = CliValueSanitizer.OneLine(result.Diagnostic);
        foreach (var path in new[] { invocation.ImagePath, result.Memory?.Path, result.Memory?.OutputDirectory })
        {
            if (!string.IsNullOrWhiteSpace(path))
            {
                diagnostic = diagnostic.Replace(path, "[redacted]", StringComparison.OrdinalIgnoreCase);
            }
        }

        return diagnostic;
    }
}

internal static class ToolActionDiagnosticSanitizer
{
    private const string Redacted = "[redacted]";

    public static string Sanitize(CliInvocation invocation, ViewerAgentToolActionResult result)
    {
        if (result.Outcome == ViewerAgentToolActionOutcome.JobFailed)
        {
            return "The agent tool job failed. Inspect bounded agent operational diagnostics for details.";
        }

        var diagnostic = CliValueSanitizer.OneLine(result.Diagnostic);
        foreach (var sensitive in new[]
                 {
                     invocation.PcapPath,
                     invocation.ZeekPath,
                     invocation.ProcmonPath,
                     invocation.InputPath
                 })
        {
            if (!string.IsNullOrWhiteSpace(sensitive))
            {
                diagnostic = diagnostic.Replace(sensitive, Redacted, StringComparison.OrdinalIgnoreCase);
            }
        }

        return diagnostic;
    }
}

internal static class EvidenceActionDiagnosticSanitizer
{
    private const string Redacted = "[redacted]";

    public static string Sanitize(
        CliInvocation invocation,
        ViewerAgentCaptureActionTarget target,
        ViewerAgentEvidenceActionResult result)
    {
        if (result.Outcome == ViewerAgentEvidenceActionOutcome.JobFailed)
        {
            return "The evidence job failed. Inspect bounded agent operational diagnostics for details.";
        }

        var diagnostic = CliValueSanitizer.OneLine(result.Diagnostic);
        var sensitiveValues = new List<string>();
        sensitiveValues.AddRange(invocation.ProcessEntityIds ?? Array.Empty<string>());
        sensitiveValues.AddRange(invocation.ProcessKeys ?? Array.Empty<string>());
        AddPath(sensitiveValues, invocation.SourcePath);
        AddPath(sensitiveValues, target.DumpsDirectory);
        foreach (var sensitive in sensitiveValues
                     .Where(value => !string.IsNullOrWhiteSpace(value))
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(value => value.Length))
        {
            diagnostic = diagnostic.Replace(
                sensitive,
                Redacted,
                StringComparison.OrdinalIgnoreCase);
        }

        return diagnostic;
    }

    private static void AddPath(List<string> values, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        values.Add(path);
        try
        {
            values.Add(Path.GetFullPath(path));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
        }
    }
}

internal sealed class AgentControlCliCommandHandler : ICliCommandHandler
{
    private readonly IViewerCliAgentService _agentService;

    public AgentControlCliCommandHandler(
        CliCommandKind kind,
        IViewerCliAgentService agentService)
    {
        if (kind is not
            (CliCommandKind.AgentReconnect or
             CliCommandKind.AgentStart or
             CliCommandKind.AgentStop or
             CliCommandKind.AgentPairingStatus or
             CliCommandKind.AgentPairingRotate or
             CliCommandKind.AgentPairingRevoke))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        _agentService = agentService ?? throw new ArgumentNullException(nameof(agentService));
    }

    public CliCommandKind Kind { get; }

    public async Task<CliCommandResult> ExecuteAsync(
        CliInvocation invocation,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }

        ViewerCliAgentControlResult executed;
        try
        {
            executed = await _agentService.ExecuteControlAsync(invocation, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliCommandResult.Failed(
                CliExitCode.Canceled,
                "Canceled",
                "The command was canceled.");
        }
        catch
        {
            return CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The local-agent control action failed internally.");
        }

        if (!executed.Success)
        {
            return executed.Failure ?? CliCommandResult.Failed(
                CliExitCode.Failure,
                "InternalFailure",
                "The local-agent control action returned no result.");
        }

        var result = executed.Result!;
        var data = CliDtoMapper.FromAgentControl(invocation.CommandName, result);
        var text = CliTextFormatter.AgentControl(data);
        if (result.Succeeded)
        {
            return CliCommandResult.Succeeded(text, data);
        }

        var exitCode = result.Outcome switch
        {
            LocalAgentControlOutcome.Absent or
            LocalAgentControlOutcome.Unavailable or
            LocalAgentControlOutcome.Busy => CliExitCode.Unavailable,
            LocalAgentControlOutcome.Canceled => CliExitCode.Canceled,
            LocalAgentControlOutcome.TimedOut => CliExitCode.Timeout,
            LocalAgentControlOutcome.InternalFailure => CliExitCode.Failure,
            LocalAgentControlOutcome.Rejected when result.Response?.Success == false =>
                CliExitCode.AgentRejected,
            _ => CliExitCode.Rejected
        };
        var code = result.Outcome switch
        {
            LocalAgentControlOutcome.Absent => "AgentUnavailable",
            LocalAgentControlOutcome.Busy => "AgentControlBusy",
            LocalAgentControlOutcome.Canceled => "Canceled",
            LocalAgentControlOutcome.Superseded => "SessionSuperseded",
            LocalAgentControlOutcome.TimedOut => "AgentStopTimedOut",
            LocalAgentControlOutcome.InternalFailure => "InternalFailure",
            LocalAgentControlOutcome.Unavailable => "AgentUnavailable",
            _ when !string.IsNullOrWhiteSpace(result.Response?.ErrorCode) =>
                result.Response.ErrorCode,
            _ => "AgentControlRejected"
        };
        return CliCommandResult.Failed(
            exitCode,
            code,
            result.Diagnostic,
            retryable: result.Outcome is
                LocalAgentControlOutcome.Busy or
                LocalAgentControlOutcome.TimedOut,
            text: text,
            data: data);
    }
}

internal static class CliHelpFormatter
{
    public static IReadOnlyList<CliCommandDefinition> GetPublishedDefinitions(
        IFeatureCatalog featureCatalog)
    {
        var supportedCommands = AgentCommandFeaturePolicy
            .GetPublishedCommandCapabilities(featureCatalog)
            .Where(capability =>
                capability.OperationalAvailability == AgentCommandOperationalAvailability.Supported)
            .Select(capability => capability.CommandKind)
            .ToHashSet();
        return CliCommandRegistry.Definitions
            .Where(definition =>
                definition.DomainFeature is not { } domainFeature ||
                featureCatalog.IsPublished(domainFeature))
            .Where(definition =>
                definition.AgentCommand is not { } commandKind ||
                supportedCommands.Contains(commandKind))
            .ToArray();
    }

    public static string Format(
        IReadOnlyList<CliCommandDefinition> definitions,
        bool monitoringPublished)
    {
        var text = new StringBuilder();
        text.AppendLine(ProductIdentity.DisplayName);
        text.AppendLine(ProductIdentity.ShortDescription);
        text.AppendLine();
        text.AppendLine("Usage:");
        text.AppendLine("  dfiroscope <noun> <verb> [options]");
        text.AppendLine();
        text.AppendLine("Published commands:");
        foreach (var definition in definitions)
        {
            text.Append("  ").AppendLine(definition.Usage);
            text.Append("      ").AppendLine(definition.Summary);
        }

        text.AppendLine();
        text.AppendLine("Options:");
        text.AppendLine("  --output text|json");
        text.AppendLine("  --session <absolute-session-root-or-session.json>");
        text.AppendLine(monitoringPublished
            ? "  --yes (required for agent stop, pairing rotate/revoke, process dump, memory acquire, and monitoring deploy/reverse)"
            : "  --yes (required for agent stop, pairing rotate/revoke, process dump, and memory acquire)");
        text.AppendLine("  --live-buffer-memory-mb 500|1024|2048 (agent start only)");
        text.AppendLine("  --timeout-seconds 1..120 (agent stop only)");
        text.AppendLine("  --timeout-seconds 1..86400 (job wait or queued/capture action with --wait)");
        text.AppendLine(monitoringPublished
            ? "  --file <absolute-json> (capture or host-monitoring configuration check/save)"
            : "  --file <absolute-json> (capture configuration check/save)");
        text.AppendLine("  --source Runtime|ETW|Security|PowerShell|WindowsOther|Sysmon (capture source start/stop)");
        text.AppendLine("  --job-id <guid> (job status/wait/cancel)");
        text.AppendLine("  --wait (capture start/stop or queued evidence action)");
        text.AppendLine("  --all | --process-entity-id <id>... | --process-key <PID_StartTimeTicks>... (enrichment scope)");
        text.AppendLine("  --modules | --handles | --pe [--pe-strings deferred|immediate] (enrichment workload)");
        text.AppendLine("  --kind full|mini (process dump)");
        text.AppendLine("  --path <absolute-file-or-folder> [--recurse] [--include-ntfs] [--include-prefetch] [--max-files 1..10000]");
        text.AppendLine("  --no-prompt (shell entry only)");
        text.AppendLine();
        text.AppendLine("Shell built-ins:");
        foreach (var definition in CliShellBuiltInCatalog.Definitions)
        {
            text.Append("  ").AppendLine(definition.Usage);
            text.Append("      ").AppendLine(definition.Summary);
        }
        text.AppendLine();
        text.Append("No arguments launch the WPF viewer.");
        return text.ToString();
    }
}

internal sealed record CliHelpDto(
    string Grammar,
    IReadOnlyList<CliHelpCommandDto> Commands,
    IReadOnlyList<string> Options,
    IReadOnlyList<CliHelpCommandDto> ShellBuiltIns);

internal sealed record CliHelpCommandDto(string Command, string Usage, string Summary);

internal sealed record CliVersionDto(string Product, string Version, string ReleaseId);

internal sealed record CliDiscoveryDto(
    string Outcome,
    bool BlocksAdd,
    IReadOnlyList<CliDiscoveryCandidateDto> Candidates,
    IReadOnlyList<CliDiscoveryConflictDto> Conflicts);

internal sealed record CliDiscoveryCandidateDto(
    int ProcessId,
    string StartedAtUtc,
    string ExecutableName,
    string SessionId,
    string ReleaseId,
    string LastHeartbeatUtc);

internal sealed record CliDiscoveryConflictDto(
    string Kind,
    int? ProcessId,
    string Message);

internal sealed record CliAgentStatusDto(
    string AgentVersion,
    int ProcessId,
    string StartedAtUtc,
    string MachineName,
    string SessionId,
    string WorkspaceMode,
    bool CaptureSealed,
    string ReleaseId,
    string ReleaseMatch,
    string CaptureHealth,
    int KnownJobCount,
    int QueuedJobCount,
    int RunningJobCount,
    int WriterPendingWorkItemCount);

internal sealed record CliAgentCapabilitiesDto(
    string ReleaseId,
    string ReleaseMatch,
    IReadOnlyList<CliAgentCapabilityDto> Capabilities);

internal sealed record CliAgentCapabilityDto(
    string Command,
    bool CoreControl,
    bool PayloadSpecific,
    IReadOnlyList<string> PublishedFeatureIds,
    string Availability,
    string Reason);

internal sealed record CliCaptureConfigurationDto(
    string AgentId,
    string HostId,
    string ConfigurationVersion,
    string ConfigurationHash,
    string CreatedAtUtc,
    string UpdatedAtUtc,
    string Status,
    bool HasError,
    CliRuntimeCapturePolicyDto RuntimeProcessSnapshots,
    CliCaptureSourceTogglesDto Sources,
    CliEtwCapturePolicyDto Etw,
    CliNetworkCapturePolicyDto Network,
    CliZeekPolicyDto Zeek,
    CliArtifactCapturePolicyDto Artifacts,
    CliSourceHealthPolicyDto SourceHealth,
    CliGuardrailPolicyDto Guardrails);

internal sealed record CliHostMonitoringConfigurationDto(
    string AgentId,
    string HostId,
    string ConfigurationVersion,
    string ConfigurationHash,
    string UpdatedAtUtc,
    string Status,
    bool HasError,
    CliHostMonitoringSysmonDto Sysmon,
    CliHostMonitoringSecurityAuditDto SecurityAudit,
    CliHostMonitoringEventLogsDto EventLogs,
    CliHostMonitoringPowerShellDto PowerShell,
    CliHostMonitoringEtwDto Etw,
    CliHostMonitoringScheduledDumpsDto ScheduledDumps,
    CliMonitoringBaselineDto Baseline);

internal sealed record CliHostMonitoringSysmonDto(
    bool InstallOrUpdate,
    bool VerifyService,
    string ProfileId,
    string Status);

internal sealed record CliHostMonitoringSecurityAuditDto(
    bool ConfigureAuditPolicy,
    bool EnableProcessCommandLineLogging,
    string ProfileId,
    string Status);

internal sealed record CliHostMonitoringEventLogsDto(
    bool ConfigureChannels,
    bool ConfigureRetention,
    string ProfileId,
    int ChannelCount,
    string Status);

internal sealed record CliHostMonitoringPowerShellDto(
    bool EnableScriptBlockLogging,
    bool EnableModuleLogging,
    bool EnableTranscription,
    string ProfileId,
    string Status);

internal sealed record CliHostMonitoringEtwDto(
    bool ConfigureSession,
    string ProfileId,
    string Status);

internal sealed record CliHostMonitoringScheduledDumpsDto(
    bool Enabled,
    int IntervalSeconds,
    int OffsetCount,
    int MaxDumpsPerCapture,
    string Status);

internal sealed record CliMonitoringBaselineDto(
    bool Exists,
    string CapturedAtUtc,
    string LastRevertedAtUtc,
    string LastRevertStatus,
    int AreaCount);

internal sealed record CliMonitoringDeploymentDto(
    string AgentId,
    string HostId,
    string ConfigurationVersion,
    string ConfigurationHash,
    string Action,
    string StartedAtUtc,
    string CompletedAtUtc,
    string Status,
    IReadOnlyList<CliMonitoringDeploymentAreaDto> Areas,
    int WarningCount,
    bool HasError,
    CliMonitoringBaselineDto Baseline);

internal sealed record CliMonitoringDeploymentAreaDto(
    string Area,
    string Status,
    bool ReverseSupported,
    string Message,
    bool HasTechnicalDetail);

internal sealed record CliHostMonitoringActionDto(
    string Action,
    string Outcome,
    string Diagnostic);

internal sealed record CliConfigurationCheckDto(
    string Target,
    string AgentId,
    string HostId,
    string ConfigurationVersion,
    string ConfigurationHash,
    string CheckedAtUtc,
    string OverallState,
    IReadOnlyList<CliConfigurationFindingDto> Findings,
    bool HasError);

internal sealed record CliConfigurationFindingDto(
    string Area,
    string Severity,
    string Message,
    string SuggestedRemediation);

internal sealed record CliCaptureActionDto(
    string Command,
    string Outcome,
    string CaptureId,
    string ConfigurationVersion,
    string ConfigurationHash,
    string Status,
    string Message,
    IReadOnlyList<string> AcceptedJobIds,
    IReadOnlyList<string> AffectedJobIds,
    bool DatabaseChanged,
    int ApproximateNewRowCount);

internal sealed record CliActiveJobDto(
    string JobId,
    string JobKind,
    string State,
    string Ownership,
    string CaptureId,
    string SourceType,
    string SourceDisplayName,
    bool StopRequested,
    string AcceptedAtUtc,
    string UpdatedAtUtc);

internal sealed record CliJobListDto(IReadOnlyList<CliActiveJobDto> Jobs);

internal sealed record CliJobProgressDto(
    string JobId,
    string JobKind,
    string State,
    string SourceRunId,
    long ProcessedCount,
    long TotalCount,
    string StartedAtUtc,
    string FinishedAtUtc,
    string Progress,
    bool HasError);

internal sealed record CliJobResultDto(
    IReadOnlyList<CliJobProgressDto> Jobs,
    string Diagnostic);

internal sealed record CliEvidenceActionDto(
    string Action,
    string Outcome,
    string Scope,
    int TargetCount,
    IReadOnlyList<string> Workloads,
    string JobId,
    string JobKind,
    string JobState,
    bool Waited,
    bool RefreshNeeded,
    IReadOnlyList<CliEvidenceJobDto> Jobs,
    string Diagnostic);

internal sealed record CliEvidenceJobDto(
    string JobId,
    string JobKind,
    string State,
    long ProcessedCount,
    long TotalCount,
    string StartedAtUtc,
    string FinishedAtUtc,
    bool HasError);

internal sealed record CliToolActionDto(
    string Action,
    string Outcome,
    string JobId,
    string JobKind,
    string JobState,
    bool Waited,
    bool RefreshNeeded,
    CliSqliteBenchmarkDto? Benchmark,
    string Diagnostic);

internal sealed record CliMemoryActionDto(
    string Action,
    string Outcome,
    string JobId,
    string JobKind,
    string JobState,
    bool Waited,
    bool RefreshNeeded,
    CliMemoryResultDto? Result,
    string Diagnostic);

internal sealed record CliMemoryResultDto(
    string Action,
    string Status,
    string ImageId,
    IReadOnlyList<string> RunIds,
    string Sha256Hash,
    string Path,
    string OutputDirectory,
    long FileSizeBytes,
    string CleanupStatus,
    string QuarantinedPath,
    string Summary);

internal sealed record CliSqliteBenchmarkDto(
    string Status,
    string StartedAtUtc,
    string CompletedAtUtc,
    double DurationSeconds,
    long AttemptedRecords,
    long CommittedRecords,
    double CommittedRecordsPerSecond,
    string PerformanceProfile,
    string SourceMix,
    string ThresholdReason,
    string DatabasePath,
    string ReportPath,
    string JsonReportPath);

internal sealed record CliAgentControlDto(
    string Action,
    string Outcome,
    string Stage,
    string SessionId,
    int ProcessId,
    string ProcessStartedAtUtc,
    bool Started,
    bool Reused,
    bool Forced,
    string AuthenticatedEndpoint,
    string PairingState,
    long PairingGeneration,
    string Diagnostic);

internal sealed record CliRuntimeCapturePolicyDto(bool Enabled, int RefreshIntervalSeconds, string Status);

internal sealed record CliCaptureSourceTogglesDto(
    bool Runtime,
    bool Etw,
    bool Security,
    bool PowerShell,
    bool WindowsOther,
    bool Sysmon);

internal sealed record CliEtwCapturePolicyDto(bool ConfigureSession, string ProfileId, string Status);

internal sealed record CliNetworkCapturePolicyDto(
    bool Enabled,
    bool RecordMetadataOnly,
    int SegmentSeconds,
    long MaxSegmentBytes,
    string Status);

internal sealed record CliZeekPolicyDto(bool Enabled, bool RunAfterNetworkCapture, bool ImportLogs);

internal sealed record CliArtifactCapturePolicyDto(
    bool CaptureModules,
    bool CaptureHandles,
    bool CapturePeMetadata,
    bool CaptureDumpMetadata,
    int RefreshIntervalSeconds,
    string Status);

internal sealed record CliSourceHealthPolicyDto(
    bool TrackSourceHealth,
    bool PersistHealthSnapshots,
    int WarningAfterDroppedEvents,
    int WarningAfterSourceSilenceSeconds);

internal sealed record CliGuardrailPolicyDto(
    bool Enabled,
    int MaxEventsPerSecondWarning,
    long MaxLiveDatabaseBytesWarning,
    int RetentionDaysPlaceholder);

internal static class CliDtoMapper
{
    private const int MaxCollectionItems = 128;

    public static CliDiscoveryDto FromDiscovery(LocalAgentDiscoveryResult discovery) =>
        new(
            discovery.Outcome.ToString(),
            discovery.BlocksAdd,
            discovery.Candidates
                .OrderByDescending(candidate => candidate.Discovery.Lease.LastHeartbeatUtc)
                .ThenBy(candidate => candidate.Discovery.Lease.AgentProcessId)
                .ThenBy(candidate => candidate.Discovery.Lease.SessionId, StringComparer.Ordinal)
                .ThenBy(candidate => candidate.Discovery.Lease.ReleaseId, StringComparer.Ordinal)
                .ThenBy(candidate => candidate.Discovery.Lease.AgentStartedAtUtc)
                .ThenBy(candidate => candidate.Discovery.Lease.ExecutableName, StringComparer.Ordinal)
                .Take(MaxCollectionItems)
                .Select(candidate => new CliDiscoveryCandidateDto(
                    candidate.Discovery.Lease.AgentProcessId,
                    CliValueSanitizer.Timestamp(candidate.Discovery.Lease.AgentStartedAtUtc),
                    CliValueSanitizer.Value(candidate.Discovery.Lease.ExecutableName),
                    CliValueSanitizer.Value(candidate.Discovery.Lease.SessionId),
                    CliValueSanitizer.Value(candidate.Discovery.Lease.ReleaseId),
                    CliValueSanitizer.Timestamp(candidate.Discovery.Lease.LastHeartbeatUtc)))
                .ToArray(),
            discovery.Conflicts
                .OrderBy(conflict => (int)conflict.Kind)
                .ThenBy(conflict => conflict.Discovery?.Lease.AgentProcessId ?? int.MaxValue)
                .ThenBy(
                    conflict => conflict.Discovery?.Lease.SessionId ?? string.Empty,
                    StringComparer.Ordinal)
                .ThenBy(
                    conflict => conflict.Discovery?.Lease.ReleaseId ?? string.Empty,
                    StringComparer.Ordinal)
                .Take(MaxCollectionItems)
                .Select(conflict => new CliDiscoveryConflictDto(
                    conflict.Kind.ToString(),
                    conflict.Discovery?.Lease.AgentProcessId > 0
                        ? conflict.Discovery.Lease.AgentProcessId
                        : null,
                    DiscoveryConflictMessage(conflict.Kind)))
                .ToArray());

    public static string DiscoveryMessage(LocalAgentDiscoveryOutcome outcome) => outcome switch
    {
        LocalAgentDiscoveryOutcome.Absent => "No verified running local agent was discovered.",
        LocalAgentDiscoveryOutcome.DiscoveryUnavailable => "Local-agent discovery is unavailable.",
        LocalAgentDiscoveryOutcome.MultipleCandidates => "Multiple verified running local agents were discovered.",
        LocalAgentDiscoveryOutcome.AmbiguousCandidates => "Verified and unresolved local-agent candidates coexist.",
        LocalAgentDiscoveryOutcome.UnresolvedInspection => "A local-agent process identity could not be resolved safely.",
        _ => "Local-agent discovery failed."
    };

    public static CliAgentStatusDto FromHealth(AgentHealthSnapshot health) =>
        new(
            CliValueSanitizer.Value(health.AgentVersion),
            health.ProcessId,
            CliValueSanitizer.Timestamp(health.StartedAtUtc),
            CliValueSanitizer.Value(health.MachineName),
            CliValueSanitizer.Value(health.SessionId),
            health.WorkspaceMode.ToString(),
            health.CaptureSealed,
            CliValueSanitizer.Value(health.ReleaseProfile.ReleaseId),
            health.ReleaseProfile.Match.ToString(),
            health.CaptureHealth.Health.ToString(),
            health.KnownJobCount,
            health.Runtime.QueuedJobCount,
            health.Runtime.RunningJobCount,
            health.Runtime.WriterPendingWorkItemCount);

    public static CliAgentCapabilitiesDto FromCapabilities(
        AgentReleaseProfileSnapshot release,
        IFeatureCatalog featureCatalog)
    {
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(featureCatalog);
        var reported = release.PublishedCommandCapabilities ?? Array.Empty<AgentCommandCapability>();
        var locallySupported = AgentCommandFeaturePolicy
            .GetPublishedCommandCapabilities(featureCatalog)
            .Where(capability =>
                capability.OperationalAvailability == AgentCommandOperationalAvailability.Supported)
            .GroupBy(capability => capability.CommandKind)
            .Where(group => group.Count() == 1)
            .Select(group => group.Single())
            .Where(capability => ReportedCapabilityMatches(reported, capability))
            .OrderBy(capability => (int)capability.CommandKind)
            .Take(MaxCollectionItems)
            .Select(capability => new CliAgentCapabilityDto(
                capability.CommandKind.ToString(),
                capability.IsCoreControl,
                capability.HasPayloadSpecificRequirements,
                capability.PublishedFeatureIds
                    .Take(MaxCollectionItems)
                    .Select(CliValueSanitizer.Value)
                    .ToArray(),
                AgentCommandOperationalAvailability.Supported.ToString(),
                CliValueSanitizer.OneLine(
                    capability.AvailabilityReason,
                    AgentCommandCapability.MaxAvailabilityReasonLength)))
            .ToArray();
        return new CliAgentCapabilitiesDto(
            CliValueSanitizer.Value(release.ReleaseId),
            release.Match.ToString(),
            locallySupported);
    }

    public static CliCaptureConfigurationDto FromCaptureConfiguration(
        AgentCaptureConfiguration configuration) =>
        new(
            CliValueSanitizer.Value(configuration.AgentId),
            CliValueSanitizer.Value(configuration.HostId),
            CliValueSanitizer.Value(configuration.ConfigurationVersion),
            CliValueSanitizer.Value(configuration.ConfigurationHash),
            CliValueSanitizer.Timestamp(configuration.CreatedAtUtc),
            CliValueSanitizer.Timestamp(configuration.UpdatedAtUtc),
            configuration.Status.ToString(),
            !string.IsNullOrWhiteSpace(configuration.LastError),
            new CliRuntimeCapturePolicyDto(
                configuration.RuntimeProcessSnapshots.Enabled,
                configuration.RuntimeProcessSnapshots.RefreshIntervalSeconds,
                configuration.RuntimeProcessSnapshots.Status.ToString()),
            new CliCaptureSourceTogglesDto(
                configuration.SourceToggles.Runtime,
                configuration.SourceToggles.Etw,
                configuration.SourceToggles.Security,
                configuration.SourceToggles.PowerShell,
                configuration.SourceToggles.WindowsOther,
                configuration.SourceToggles.Sysmon),
            new CliEtwCapturePolicyDto(
                configuration.Etw.ConfigureSession,
                CliValueSanitizer.Value(configuration.Etw.ProfileId),
                configuration.Etw.Status.ToString()),
            new CliNetworkCapturePolicyDto(
                configuration.NetworkCapture.Enabled,
                configuration.NetworkCapture.RecordMetadataOnly,
                configuration.NetworkCapture.SegmentSeconds,
                configuration.NetworkCapture.MaxSegmentBytes,
                configuration.NetworkCapture.Status.ToString()),
            new CliZeekPolicyDto(
                configuration.Zeek.Enabled,
                configuration.Zeek.RunAfterNetworkCapture,
                configuration.Zeek.ImportLogs),
            new CliArtifactCapturePolicyDto(
                configuration.ArtifactCapture.CaptureModules,
                configuration.ArtifactCapture.CaptureHandles,
                configuration.ArtifactCapture.CapturePeMetadata,
                configuration.ArtifactCapture.CaptureDumpMetadata,
                configuration.ArtifactCapture.RefreshIntervalSeconds,
                configuration.ArtifactCapture.Status.ToString()),
            new CliSourceHealthPolicyDto(
                configuration.SourceHealth.TrackSourceHealth,
                configuration.SourceHealth.PersistHealthSnapshots,
                configuration.SourceHealth.WarningAfterDroppedEvents,
                configuration.SourceHealth.WarningAfterSourceSilenceSeconds),
            new CliGuardrailPolicyDto(
                configuration.Guardrails.Enabled,
                configuration.Guardrails.MaxEventsPerSecondWarning,
                configuration.Guardrails.MaxLiveDatabaseBytesWarning,
                configuration.Guardrails.RetentionDaysPlaceholder));

    public static CliHostMonitoringConfigurationDto FromHostMonitoringConfiguration(
        AgentHostMonitoringConfiguration configuration) =>
        new(
            CliValueSanitizer.Value(configuration.AgentId),
            CliValueSanitizer.Value(configuration.HostId),
            CliValueSanitizer.Value(configuration.ConfigurationVersion),
            CliValueSanitizer.Value(configuration.ConfigurationHash),
            CliValueSanitizer.Timestamp(configuration.UpdatedAtUtc),
            configuration.Status.ToString(),
            !string.IsNullOrWhiteSpace(configuration.LastError),
            new CliHostMonitoringSysmonDto(
                configuration.Sysmon.InstallOrUpdate,
                configuration.Sysmon.VerifyService,
                CliValueSanitizer.Value(configuration.Sysmon.ProfileId),
                configuration.Sysmon.Status.ToString()),
            new CliHostMonitoringSecurityAuditDto(
                configuration.SecurityAuditPolicy.ConfigureAuditPolicy,
                configuration.SecurityAuditPolicy.EnableProcessCommandLineLogging,
                CliValueSanitizer.Value(configuration.SecurityAuditPolicy.PolicyProfileId),
                configuration.SecurityAuditPolicy.Status.ToString()),
            new CliHostMonitoringEventLogsDto(
                configuration.EventLogs.ConfigureChannels,
                configuration.EventLogs.ConfigureRetention,
                CliValueSanitizer.Value(configuration.EventLogs.ProfileId),
                (configuration.EventLogs.ChannelNames ?? Array.Empty<string>())
                    .Take(MaxCollectionItems)
                    .Count(),
                configuration.EventLogs.Status.ToString()),
            new CliHostMonitoringPowerShellDto(
                configuration.PowerShellAuditing.EnableScriptBlockLogging,
                configuration.PowerShellAuditing.EnableModuleLogging,
                configuration.PowerShellAuditing.EnableTranscription,
                CliValueSanitizer.Value(configuration.PowerShellAuditing.ProfileId),
                configuration.PowerShellAuditing.Status.ToString()),
            new CliHostMonitoringEtwDto(
                configuration.Etw.ConfigureSession,
                CliValueSanitizer.Value(configuration.Etw.ProfileId),
                configuration.Etw.Status.ToString()),
            new CliHostMonitoringScheduledDumpsDto(
                configuration.ScheduledDumps.Enabled,
                configuration.ScheduledDumps.IntervalSeconds,
                string.IsNullOrWhiteSpace(configuration.ScheduledDumps.OffsetsFromCaptureStart)
                    ? 0
                    : configuration.ScheduledDumps.OffsetsFromCaptureStart
                        .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                        .Take(MaxCollectionItems)
                        .Count(),
                configuration.ScheduledDumps.MaxDumpsPerCapture,
                configuration.ScheduledDumps.Status.ToString()),
            FromMonitoringBaseline(configuration.OriginalState));

    public static CliMonitoringDeploymentDto FromMonitoringDeployment(
        AgentMonitoringDeploymentResult deployment) =>
        new(
            CliValueSanitizer.Value(deployment.AgentId),
            CliValueSanitizer.Value(deployment.HostId),
            CliValueSanitizer.Value(deployment.ConfigurationVersion),
            CliValueSanitizer.Value(deployment.ConfigurationHash),
            deployment.Action.ToString(),
            CliValueSanitizer.Timestamp(deployment.StartedAtUtc),
            deployment.CompletedAtUtc.HasValue
                ? CliValueSanitizer.Timestamp(deployment.CompletedAtUtc.Value)
                : string.Empty,
            deployment.Status.ToString(),
            (deployment.AreaResults ?? Array.Empty<AgentMonitoringDeploymentAreaResult>())
                .Take(MaxCollectionItems)
                .Select(area => new CliMonitoringDeploymentAreaDto(
                    area.Area.ToString(),
                    area.Status.ToString(),
                    area.ReverseSupported,
                    CliValueSanitizer.OneLine(area.Message),
                    !string.IsNullOrWhiteSpace(area.TechnicalDetail)))
                .ToArray(),
            (deployment.Warnings ?? Array.Empty<string>()).Take(MaxCollectionItems).Count(),
            !string.IsNullOrWhiteSpace(deployment.LastError),
            FromMonitoringBaseline(deployment.OriginalState));

    private static CliMonitoringBaselineDto FromMonitoringBaseline(
        AgentMonitoringOriginalStateSnapshot baseline) =>
        new(
            baseline.BaselineExists,
            baseline.CapturedAtUtc.HasValue
                ? CliValueSanitizer.Timestamp(baseline.CapturedAtUtc.Value)
                : string.Empty,
            baseline.LastRevertedUtc.HasValue
                ? CliValueSanitizer.Timestamp(baseline.LastRevertedUtc.Value)
                : string.Empty,
            baseline.LastRevertStatus.ToString(),
            (baseline.Areas ?? Array.Empty<AgentMonitoringOriginalStateArea>())
                .Take(MaxCollectionItems)
                .Count());

    public static CliConfigurationCheckDto FromConfigurationCheck(
        AgentConfigurationCheckResult check) =>
        new(
            check.TargetKind.ToString(),
            CliValueSanitizer.Value(check.AgentId),
            CliValueSanitizer.Value(check.HostId),
            CliValueSanitizer.Value(check.ConfigurationVersion),
            CliValueSanitizer.Value(check.ConfigurationHash),
            CliValueSanitizer.Timestamp(check.CheckedAtUtc),
            check.OverallState.ToString(),
            (check.Findings ?? Array.Empty<AgentConfigurationFinding>())
                .Take(MaxCollectionItems)
                .Select(finding => new CliConfigurationFindingDto(
                    finding.Area.ToString(),
                    finding.Severity.ToString(),
                    CliValueSanitizer.OneLine(finding.Message),
                    CliValueSanitizer.OneLine(finding.SuggestedRemediation)))
                .ToArray(),
            !string.IsNullOrWhiteSpace(check.LastError));

    public static CliCaptureActionDto FromCaptureAction(
        string command,
        ViewerAgentCaptureActionResult result)
    {
        var response = result.Response;
        var lifecycle = response?.CaptureLifecycle;
        return new CliCaptureActionDto(
            CliValueSanitizer.Value(command),
            result.Outcome.ToString(),
            CliValueSanitizer.Value(lifecycle?.CaptureId),
            CliValueSanitizer.Value(lifecycle?.ConfigurationVersion),
            CliValueSanitizer.Value(lifecycle?.ConfigurationHash),
            lifecycle?.Status.ToString() ?? string.Empty,
            CliValueSanitizer.OneLine(
                lifecycle?.Message ?? result.Diagnostic),
            (response == null
                    ? Array.Empty<AgentActiveWorkItem>()
                    : AgentIpcResponseJobProjection.GetAcceptedJobs(response))
                .Take(MaxCollectionItems)
                .Select(job => job.JobId.ToString("D", CultureInfo.InvariantCulture))
                .ToArray(),
            (response == null
                    ? Array.Empty<AgentActiveWorkItem>()
                    : AgentIpcResponseJobProjection.GetAffectedJobs(response))
                .Take(MaxCollectionItems)
                .Select(job => job.JobId.ToString("D", CultureInfo.InvariantCulture))
                .ToArray(),
            response?.DatabaseChanged != null,
            response?.DatabaseChanged?.ApproximateNewRowCount ?? 0);
    }

    public static CliActiveJobDto FromActiveJob(AgentActiveWorkItem job) =>
        new(
            job.JobId.ToString("D", CultureInfo.InvariantCulture),
            job.JobKind.ToString(),
            job.State.ToString(),
            job.Ownership.ToString(),
            CliValueSanitizer.Value(job.CaptureId),
            CliValueSanitizer.Value(job.SourceType),
            CliValueSanitizer.Value(job.SourceDisplayName),
            job.StopRequested,
            job.AcceptedAtUtc == default
                ? string.Empty
                : CliValueSanitizer.Timestamp(job.AcceptedAtUtc),
            job.UpdatedAtUtc == default
                ? string.Empty
                : CliValueSanitizer.Timestamp(job.UpdatedAtUtc));

    public static CliJobProgressDto FromJob(JobProgress job) =>
        new(
            job.JobId.ToString("D", CultureInfo.InvariantCulture),
            job.JobKind.ToString(),
            job.State.ToString(),
            CliValueSanitizer.Value(job.SourceRunId),
            job.ProcessedCount,
            job.TotalCount,
            job.StartedAtUtc.HasValue
                ? CliValueSanitizer.Timestamp(job.StartedAtUtc.Value)
                : string.Empty,
            job.FinishedAtUtc.HasValue
                ? CliValueSanitizer.Timestamp(job.FinishedAtUtc.Value)
                : string.Empty,
            CliValueSanitizer.OneLine(job.ProgressMessage),
            !string.IsNullOrWhiteSpace(job.ErrorText));

    public static CliEvidenceActionDto FromEvidenceAction(
        CliInvocation invocation,
        ViewerAgentEvidenceActionResult result,
        string safeDiagnostic)
    {
        var scope = invocation.Kind switch
        {
            CliCommandKind.AgentEvidenceEnrich when invocation.AllProcesses => "All",
            CliCommandKind.AgentEvidenceEnrich when invocation.ProcessEntityIds is { Count: > 0 } => "ProcessEntityId",
            CliCommandKind.AgentEvidenceEnrich => "ProcessKey",
            CliCommandKind.AgentProcessDump => "ExactProcessKey",
            CliCommandKind.AgentFilesystemImport => "AbsoluteSourcePath",
            _ => "Unknown"
        };
        var targetCount = invocation.Kind switch
        {
            CliCommandKind.AgentEvidenceEnrich when invocation.AllProcesses => 0,
            CliCommandKind.AgentEvidenceEnrich when invocation.ProcessEntityIds != null => invocation.ProcessEntityIds.Count,
            CliCommandKind.AgentEvidenceEnrich when invocation.ProcessKeys != null => invocation.ProcessKeys.Count,
            _ => 1
        };
        var workloads = new List<string>();
        if (invocation.CaptureModules)
        {
            workloads.Add("Modules");
        }

        if (invocation.CaptureHandles)
        {
            workloads.Add("Handles");
        }

        if (invocation.CapturePe)
        {
            workloads.Add($"PE:{invocation.PeStringExtractionMode}");
        }

        if (invocation.Kind == CliCommandKind.AgentProcessDump)
        {
            workloads.Add($"ProcessDump:{invocation.DumpKind}");
        }

        if (invocation.Kind == CliCommandKind.AgentFilesystemImport)
        {
            if (invocation.IncludeNtfs)
            {
                workloads.Add("NTFS");
            }

            if (invocation.IncludePrefetch)
            {
                workloads.Add("Prefetch");
            }
        }

        var job = result.Job ?? result.Response?.Job;
        return new CliEvidenceActionDto(
            invocation.CommandName,
            result.Outcome.ToString(),
            scope,
            targetCount,
            workloads,
            result.AcceptedJobId?.ToString("D", CultureInfo.InvariantCulture) ?? string.Empty,
            job?.JobKind.ToString() ?? string.Empty,
            job?.State.ToString() ?? string.Empty,
            result.Waited,
            result.RefreshNeeded,
            result.Jobs.Take(MaxCollectionItems).Select(FromEvidenceJob).ToArray(),
            CliValueSanitizer.OneLine(safeDiagnostic));
    }

    private static CliEvidenceJobDto FromEvidenceJob(JobProgress job) =>
        new(
            job.JobId.ToString("D", CultureInfo.InvariantCulture),
            job.JobKind.ToString(),
            job.State.ToString(),
            job.ProcessedCount,
            job.TotalCount,
            job.StartedAtUtc.HasValue
                ? CliValueSanitizer.Timestamp(job.StartedAtUtc.Value)
                : string.Empty,
            job.FinishedAtUtc.HasValue
                ? CliValueSanitizer.Timestamp(job.FinishedAtUtc.Value)
                : string.Empty,
            !string.IsNullOrWhiteSpace(job.ErrorText));

    public static CliToolActionDto FromToolAction(
        CliInvocation invocation,
        ViewerAgentToolActionResult result,
        string safeDiagnostic)
    {
        var job = result.Job ?? result.Response?.Job;
        var benchmark = job?.SqliteBenchmark;
        return new CliToolActionDto(
            invocation.CommandName,
            result.Outcome.ToString(),
            result.AcceptedJobId?.ToString("D", CultureInfo.InvariantCulture) ?? string.Empty,
            job?.JobKind.ToString() ?? string.Empty,
            job?.State.ToString() ?? string.Empty,
            result.Waited,
            result.RefreshNeeded,
            benchmark == null
                ? null
                : new CliSqliteBenchmarkDto(
                    CliValueSanitizer.Value(benchmark.Status),
                    benchmark.StartedAtUtc == default
                        ? string.Empty
                        : CliValueSanitizer.Timestamp(benchmark.StartedAtUtc),
                    benchmark.CompletedAtUtc.HasValue
                        ? CliValueSanitizer.Timestamp(benchmark.CompletedAtUtc.Value)
                        : string.Empty,
                    benchmark.DurationSeconds,
                    benchmark.AttemptedRecords,
                    benchmark.CommittedRecords,
                    benchmark.CommittedRecordsPerSecond,
                    CliValueSanitizer.Value(benchmark.PerformanceProfile),
                    CliValueSanitizer.Value(benchmark.SourceMix),
                    CliValueSanitizer.OneLine(benchmark.ThresholdReason),
                    CliValueSanitizer.Value(benchmark.DatabasePath),
                    CliValueSanitizer.Value(benchmark.ReportPath),
                    CliValueSanitizer.Value(benchmark.JsonReportPath)),
            CliValueSanitizer.OneLine(safeDiagnostic));
    }

    public static CliMemoryActionDto FromMemoryAction(
        CliInvocation invocation,
        ViewerMemoryActionResult result,
        string safeDiagnostic)
    {
        var job = result.Job ?? result.Response?.Job;
        var memory = result.Memory ?? job?.MemoryAction;
        return new CliMemoryActionDto(
            invocation.CommandName,
            result.Outcome.ToString(),
            result.AcceptedJobId?.ToString("D", CultureInfo.InvariantCulture) ?? string.Empty,
            job?.JobKind.ToString() ?? string.Empty,
            job?.State.ToString() ?? string.Empty,
            result.Waited,
            result.RefreshNeeded,
            memory == null
                ? null
                : new CliMemoryResultDto(
                    CliValueSanitizer.Value(memory.Action),
                    CliValueSanitizer.Value(memory.Status),
                    CliValueSanitizer.Value(memory.ImageId),
                    memory.RunIds.Take(MaxCollectionItems).Select(CliValueSanitizer.Value).ToArray(),
                    CliValueSanitizer.Value(memory.Sha256Hash),
                    CliValueSanitizer.Value(memory.Path),
                    CliValueSanitizer.Value(memory.OutputDirectory),
                    memory.FileSizeBytes,
                    CliValueSanitizer.Value(memory.CleanupStatus),
                    CliValueSanitizer.Value(memory.QuarantinedPath),
                    CliValueSanitizer.OneLine(memory.Summary)),
            CliValueSanitizer.OneLine(safeDiagnostic));
    }

    public static CliAgentControlDto FromAgentControl(
        string action,
        LocalAgentControlResult result)
    {
        var binding = result.Binding;
        var processId = binding?.Health.ProcessId ?? result.Process?.ProcessId ?? 0;
        var startedAtUtc = binding?.Health.StartedAtUtc ?? default;
        var pairing = result.Pairing ?? binding?.ProtectedPairing;
        return new CliAgentControlDto(
            CliValueSanitizer.Value(action),
            result.Outcome.ToString(),
            result.Stage.ToString(),
            CliValueSanitizer.Value(binding?.SessionPaths.SessionId),
            processId,
            startedAtUtc == default ? string.Empty : CliValueSanitizer.Timestamp(startedAtUtc),
            result.Outcome == LocalAgentControlOutcome.Started,
            result.Outcome == LocalAgentControlOutcome.Reused,
            result.Forced,
            EndpointAlias(binding?.AuthenticatedEndpoint),
            pairing?.State.ToString() ?? string.Empty,
            pairing?.PairingGeneration ?? binding?.PairingGeneration ?? 0,
            CliValueSanitizer.OneLine(result.Diagnostic));
    }

    private static string DiscoveryConflictMessage(LocalAgentRecoveryConflictKind kind) => kind switch
    {
        LocalAgentRecoveryConflictKind.DiscoveryUnavailable => "Discovery could not be completed safely.",
        LocalAgentRecoveryConflictKind.InvalidLeaseIdentity => "A lease lacks an inspectable process identity.",
        LocalAgentRecoveryConflictKind.ProcessExited => "The referenced process has exited.",
        LocalAgentRecoveryConflictKind.ProcessIdentityRejected => "The referenced process identity was rejected.",
        LocalAgentRecoveryConflictKind.ProcessInspectionUnresolved => "The referenced process could not be inspected exactly.",
        LocalAgentRecoveryConflictKind.MultipleVerifiedCandidates => "Multiple verified candidates exist.",
        LocalAgentRecoveryConflictKind.AmbiguousCandidates => "Verified and unresolved candidates coexist.",
        LocalAgentRecoveryConflictKind.IncompatibleLease => "The lease is incompatible with this release.",
        LocalAgentRecoveryConflictKind.ProtectedPairingRejected => "Protected pairing was rejected.",
        LocalAgentRecoveryConflictKind.WorkspaceRejected => "The referenced live workspace was rejected.",
        LocalAgentRecoveryConflictKind.AuthenticatedBindingRejected => "Authenticated binding was rejected.",
        LocalAgentRecoveryConflictKind.WorkspacePending => "The referenced live workspace is waiting for its Agent-owned evidence database.",
        _ => "The discovery record is unavailable."
    };

    private static bool ReportedCapabilityMatches(
        IReadOnlyList<AgentCommandCapability> reported,
        AgentCommandCapability local)
    {
        var matches = reported
            .Where(capability => capability != null && capability.CommandKind == local.CommandKind)
            .ToArray();
        if (matches.Length != 1)
        {
            return false;
        }

        var candidate = matches[0];
        var reportedFeatures = candidate.PublishedFeatureIds ?? Array.Empty<string>();
        var localFeatures = local.PublishedFeatureIds ?? Array.Empty<string>();
        return candidate.OperationalAvailability == AgentCommandOperationalAvailability.Supported &&
               candidate.IsCoreControl == local.IsCoreControl &&
               candidate.HasPayloadSpecificRequirements == local.HasPayloadSpecificRequirements &&
               reportedFeatures.Count == localFeatures.Count &&
               reportedFeatures.All(featureId => !string.IsNullOrWhiteSpace(featureId)) &&
               reportedFeatures.Distinct(StringComparer.Ordinal).Count() == reportedFeatures.Count &&
               !reportedFeatures.Except(localFeatures, StringComparer.Ordinal).Any();
    }

    private static string EndpointAlias(string? endpoint) => endpoint switch
    {
        AgentContracts.PipeName => "primary",
        AgentContracts.LegacyPipeName => "former",
        AgentContracts.ShutdownControlPipeName => "primary-control",
        AgentContracts.LegacyShutdownControlPipeName => "former-control",
        null or "" => string.Empty,
        _ => "verified-local"
    };
}

internal static class CliTextFormatter
{
    public static string Discovery(CliDiscoveryDto data)
    {
        var text = new StringBuilder();
        text.Append("Discovery: ").AppendLine(data.Outcome);
        text.Append("Candidates: ").AppendLine(data.Candidates.Count.ToString(CultureInfo.InvariantCulture));
        foreach (var candidate in data.Candidates)
        {
            text.Append("  PID ")
                .Append(candidate.ProcessId.ToString(CultureInfo.InvariantCulture))
                .Append(" | ")
                .Append(candidate.ExecutableName)
                .Append(" | session ")
                .Append(candidate.SessionId)
                .Append(" | release ")
                .AppendLine(candidate.ReleaseId);
        }

        foreach (var conflict in data.Conflicts)
        {
            text.Append("  Conflict ").Append(conflict.Kind).Append(": ").AppendLine(conflict.Message);
        }

        return text.ToString().TrimEnd();
    }

    public static string Status(CliAgentStatusDto data) =>
        string.Join(
            Environment.NewLine,
            $"Agent: {data.AgentVersion}",
            $"Process: PID {data.ProcessId.ToString(CultureInfo.InvariantCulture)}, started {data.StartedAtUtc}",
            $"Host: {data.MachineName}",
            $"Session: {data.SessionId}",
            $"Workspace: {data.WorkspaceMode}, sealed={data.CaptureSealed.ToString().ToLowerInvariant()}",
            $"Release: {data.ReleaseId} ({data.ReleaseMatch})",
            $"Capture: {data.CaptureHealth}",
            $"Jobs: known={data.KnownJobCount.ToString(CultureInfo.InvariantCulture)}, queued={data.QueuedJobCount.ToString(CultureInfo.InvariantCulture)}, running={data.RunningJobCount.ToString(CultureInfo.InvariantCulture)}");

    public static string Capabilities(CliAgentCapabilitiesDto data)
    {
        var text = new StringBuilder();
        text.Append("Release: ").Append(data.ReleaseId).Append(" (").Append(data.ReleaseMatch).AppendLine(")");
        text.Append("Capabilities: ").AppendLine(data.Capabilities.Count.ToString(CultureInfo.InvariantCulture));
        foreach (var capability in data.Capabilities)
        {
            text.Append("  ").Append(capability.Command).Append(": ").Append(capability.Availability);
            if (!string.IsNullOrWhiteSpace(capability.Reason))
            {
                text.Append(" - ").Append(capability.Reason);
            }

            text.AppendLine();
        }

        return text.ToString().TrimEnd();
    }

    public static string CaptureConfiguration(CliCaptureConfigurationDto data) =>
        string.Join(
            Environment.NewLine,
            $"Capture configuration: {data.ConfigurationVersion} ({data.Status})",
            $"Updated: {data.UpdatedAtUtc}",
            $"Runtime snapshots: {OnOff(data.RuntimeProcessSnapshots.Enabled)}, interval={data.RuntimeProcessSnapshots.RefreshIntervalSeconds.ToString(CultureInfo.InvariantCulture)}s",
            $"Sources: runtime={OnOff(data.Sources.Runtime)}, etw={OnOff(data.Sources.Etw)}, security={OnOff(data.Sources.Security)}, powershell={OnOff(data.Sources.PowerShell)}, windows-other={OnOff(data.Sources.WindowsOther)}, sysmon={OnOff(data.Sources.Sysmon)}",
            $"Artifacts: modules={OnOff(data.Artifacts.CaptureModules)}, handles={OnOff(data.Artifacts.CaptureHandles)}, pe={OnOff(data.Artifacts.CapturePeMetadata)}, dump-metadata={OnOff(data.Artifacts.CaptureDumpMetadata)}",
            $"Network metadata: {OnOff(data.Network.Enabled)} | Zeek: {OnOff(data.Zeek.Enabled)} | Guardrails: {OnOff(data.Guardrails.Enabled)}");

    public static string HostMonitoringConfiguration(CliHostMonitoringConfigurationDto data) =>
        string.Join(
            Environment.NewLine,
            $"Host monitoring configuration: {data.ConfigurationVersion} ({data.Status})",
            $"Updated: {data.UpdatedAtUtc}",
            $"Sysmon: install/update={OnOff(data.Sysmon.InstallOrUpdate)}, verify={OnOff(data.Sysmon.VerifyService)}, profile={data.Sysmon.ProfileId}",
            $"Security audit: policy={OnOff(data.SecurityAudit.ConfigureAuditPolicy)}, process-command-line={OnOff(data.SecurityAudit.EnableProcessCommandLineLogging)}, profile={data.SecurityAudit.ProfileId}",
            $"Event logs: channels={OnOff(data.EventLogs.ConfigureChannels)}, retention={OnOff(data.EventLogs.ConfigureRetention)}, count={data.EventLogs.ChannelCount.ToString(CultureInfo.InvariantCulture)}",
            $"PowerShell: script-block={OnOff(data.PowerShell.EnableScriptBlockLogging)}, module={OnOff(data.PowerShell.EnableModuleLogging)}, transcription={OnOff(data.PowerShell.EnableTranscription)}",
            $"ETW profile: {OnOff(data.Etw.ConfigureSession)} | Scheduled dumps: {OnOff(data.ScheduledDumps.Enabled)}",
            $"Original-state baseline: {(data.Baseline.Exists ? "available" : "absent")} ({data.Baseline.AreaCount.ToString(CultureInfo.InvariantCulture)} areas)");

    public static string MonitoringDeployment(CliMonitoringDeploymentDto data)
    {
        var text = new StringBuilder();
        text.Append("Host monitoring ")
            .Append(data.Action)
            .Append(": ")
            .Append(data.Status)
            .Append(" | baseline=")
            .AppendLine(data.Baseline.Exists ? "available" : "absent");
        foreach (var area in data.Areas)
        {
            text.Append("  ")
                .Append(area.Area)
                .Append(": ")
                .Append(area.Status)
                .Append(" | reverse=")
                .Append(area.ReverseSupported.ToString().ToLowerInvariant())
                .Append(" | ")
                .AppendLine(area.Message);
        }

        if (data.WarningCount > 0)
        {
            text.Append("Warnings: ")
                .Append(data.WarningCount.ToString(CultureInfo.InvariantCulture));
        }

        return text.ToString().TrimEnd();
    }

    public static string HostMonitoringAction(CliHostMonitoringActionDto data) =>
        $"{data.Action}: {data.Outcome}. {data.Diagnostic}".Trim();

    public static string ConfigurationCheck(CliConfigurationCheckDto data)
    {
        var text = new StringBuilder();
        text.Append(data.Target)
            .Append(" configuration check: ")
            .Append(data.OverallState)
            .Append(" at ")
            .AppendLine(data.CheckedAtUtc);
        foreach (var finding in data.Findings)
        {
            text.Append("  ")
                .Append(finding.Severity)
                .Append("/")
                .Append(finding.Area)
                .Append(": ")
                .AppendLine(finding.Message);
        }

        return text.ToString().TrimEnd();
    }

    public static string CaptureAction(CliCaptureActionDto data)
    {
        var capture = string.IsNullOrWhiteSpace(data.CaptureId)
            ? string.Empty
            : $" capture={data.CaptureId}";
        var jobs = data.AcceptedJobIds.Count + data.AffectedJobIds.Count;
        var refresh = data.DatabaseChanged
            ? $" refresh-needed=true rows~{data.ApproximateNewRowCount.ToString(CultureInfo.InvariantCulture)}"
            : string.Empty;
        return $"{data.Command}: {data.Outcome}{capture} jobs={jobs.ToString(CultureInfo.InvariantCulture)}{refresh}. {data.Message}".Trim();
    }

    public static string JobList(CliJobListDto data)
    {
        var text = new StringBuilder();
        text.Append("Active jobs: ")
            .AppendLine(data.Jobs.Count.ToString(CultureInfo.InvariantCulture));
        foreach (var job in data.Jobs)
        {
            text.Append("  ")
                .Append(job.JobId)
                .Append(" | ")
                .Append(job.JobKind)
                .Append(" | ")
                .Append(job.State)
                .Append(" | ")
                .AppendLine(job.Ownership);
        }

        return text.ToString().TrimEnd();
    }

    public static string Jobs(CliJobResultDto data)
    {
        var text = new StringBuilder();
        foreach (var job in data.Jobs)
        {
            text.Append(job.JobId)
                .Append(" | ")
                .Append(job.JobKind)
                .Append(" | ")
                .Append(job.State)
                .Append(" | ")
                .Append(job.ProcessedCount.ToString(CultureInfo.InvariantCulture))
                .Append("/")
                .Append(job.TotalCount.ToString(CultureInfo.InvariantCulture));
            if (!string.IsNullOrWhiteSpace(job.Progress))
            {
                text.Append(" | ").Append(job.Progress);
            }

            text.AppendLine();
        }

        if (!string.IsNullOrWhiteSpace(data.Diagnostic))
        {
            text.Append(data.Diagnostic);
        }

        return text.ToString().TrimEnd();
    }

    public static string AgentControl(CliAgentControlDto data)
    {
        var process = data.ProcessId > 0
            ? $" PID {data.ProcessId.ToString(CultureInfo.InvariantCulture)}"
            : string.Empty;
        var pairing = data.PairingGeneration > 0
            ? $" pairing={data.PairingState}/{data.PairingGeneration.ToString(CultureInfo.InvariantCulture)}"
            : string.IsNullOrWhiteSpace(data.PairingState)
                ? string.Empty
                : $" pairing={data.PairingState}";
        var flags = data.Forced
            ? " forced=true"
            : data.Reused
                ? " reused=true"
                : data.Started
                    ? " started=true"
                    : string.Empty;
        return $"{data.Action}: {data.Outcome} ({data.Stage}){process}{pairing}{flags}. {data.Diagnostic}".Trim();
    }

    public static string EvidenceAction(CliEvidenceActionDto data)
    {
        var job = string.IsNullOrWhiteSpace(data.JobId) ? "job=<none>" : $"job={data.JobId}";
        var state = string.IsNullOrWhiteSpace(data.JobState) ? string.Empty : $" state={data.JobState}";
        var refresh = data.RefreshNeeded ? " refresh-needed=true" : string.Empty;
        return $"{data.Action}: {data.Outcome} {job}{state}{refresh}. {data.Diagnostic}".Trim();
    }

    public static string ToolAction(CliToolActionDto data)
    {
        var job = string.IsNullOrWhiteSpace(data.JobId) ? "job=<none>" : $"job={data.JobId}";
        var state = string.IsNullOrWhiteSpace(data.JobState) ? string.Empty : $" state={data.JobState}";
        var refresh = data.RefreshNeeded ? " refresh-needed=true" : string.Empty;
        var benchmark = data.Benchmark == null
            ? string.Empty
            : $" committed={data.Benchmark.CommittedRecords.ToString(CultureInfo.InvariantCulture)} rate={data.Benchmark.CommittedRecordsPerSecond.ToString("F1", CultureInfo.InvariantCulture)}/s";
        return $"{data.Action}: {data.Outcome} {job}{state}{refresh}{benchmark}. {data.Diagnostic}".Trim();
    }

    public static string MemoryAction(CliMemoryActionDto data)
    {
        var job = string.IsNullOrWhiteSpace(data.JobId) ? "job=<none>" : $"job={data.JobId}";
        var state = string.IsNullOrWhiteSpace(data.JobState) ? string.Empty : $" state={data.JobState}";
        var refresh = data.RefreshNeeded ? " refresh-needed=true" : string.Empty;
        var image = string.IsNullOrWhiteSpace(data.Result?.ImageId) ? string.Empty : $" image={data.Result.ImageId}";
        var cleanup = string.IsNullOrWhiteSpace(data.Result?.CleanupStatus) ? string.Empty : $" cleanup={data.Result.CleanupStatus}";
        return $"{data.Action}: {data.Outcome} {job}{state}{image}{cleanup}{refresh}. {data.Diagnostic}".Trim();
    }

    private static string OnOff(bool value) => value ? "on" : "off";
}
