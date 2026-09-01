using System.IO;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Services.Features;

namespace ProcInsider.Services.AgentIpc;

public enum ViewerAgentCommandOutcome
{
    Unknown = 0,
    Succeeded = 1,
    InvalidContext = 2,
    FeatureRejected = 3,
    OperationallyUnavailable = 4,
    AccessRejected = 5,
    WorkspaceRejected = 6,
    HealthUnavailable = 7,
    PairingRejected = 8,
    ContractRejected = 9,
    ReleaseRejected = 10,
    SessionRejected = 11,
    ProcessRejected = 12,
    AgentRejected = 13,
    Superseded = 14,
    Canceled = 15,
    InternalFailure = 16
}

public enum ViewerAgentCommandAccessKind
{
    Unknown = 0,
    ViewerConnected = 1,
    VerifiedDeployedAgent = 2
}

public static class ViewerAgentCommandErrorCodes
{
    public const string InvalidContext = "InvalidCommandContext";
    public const string CommandNotAvailable = "CommandNotAvailable";
    public const string ViewerConnectionRequired = "ViewerConnectionRequired";
    public const string NoActiveWorkspace = "NoActiveCaptureWorkspace";
    public const string ArchivedCaptureSealed = "ArchivedCaptureSealed";
    public const string WriteCategoryMismatch = "WriteCategoryMismatch";
    public const string TargetUnavailable = "TargetUnavailable";
    public const string PairingContextMismatch = "PairingContextMismatch";
    public const string HealthMissing = "AgentHealthMissing";
    public const string HealthStale = "AgentHealthStale";
    public const string ContractMismatch = "AgentContractMismatch";
    public const string ReleaseMismatch = AgentFeaturePolicyErrorCodes.ReleaseProfileMismatch;
    public const string SessionMismatch = "SessionMismatch";
    public const string DatabaseMismatch = "DatabaseMismatch";
    public const string WorkspaceModeMismatch = "WorkspaceModeMismatch";
    public const string CaptureSealingMismatch = "CaptureSealingMismatch";
    public const string CaptureCompatibilityRejected = "CaptureCompatibilityRejected";
    public const string ProcessIdentityMismatch = "ProcessIdentityMismatch";
    public const string AuthenticatedContextRejected = "AuthenticatedAgentContextRejected";
    public const string AuthorizationRejected = "AgentCommandAuthorizationRejected";
    public const string WorkspaceSuperseded = "WorkspaceSuperseded";
    public const string Canceled = "Canceled";
    public const string CommandOutcomeUnknown = "CommandOutcomeUnknownAfterSubmission";
    public const string InternalFailure = "InternalFailure";
}

public sealed record ViewerAgentCommandAccessState(
    ViewerAgentCommandAccessKind Kind,
    bool RequiresViewerConnection);

public sealed record ViewerAgentCommandPackageIdentity(
    string FormatName,
    string SessionId,
    string SessionRoot,
    string DatabasePath,
    int ManifestSchemaVersion,
    int? EvidenceFormatVersion);

public sealed record ViewerAgentCommandTarget(
    string SessionId,
    string DatabasePath,
    CaptureWorkspaceMode WorkspaceMode,
    bool IsSealed,
    ViewerAgentCommandPackageIdentity PackageIdentity,
    int ExpectedProcessId,
    DateTime ExpectedProcessStartedAtUtc,
    IReadOnlyList<string> SupportedExecutablePaths);

public sealed record ViewerAgentCommandExecutionContext(
    InvestigationSessionPaths SessionPaths,
    ViewerAgentCommandTarget Target,
    IFeatureCatalog FeatureCatalog,
    string ViewerReleaseId,
    ViewerAgentCommandAccessState Access,
    CaptureWriteCategory WriteCategory,
    long WorkspaceGeneration);

public sealed record ViewerAgentCommandExecutionRequest(
    AgentCommand Command,
    ViewerAgentCommandExecutionContext Context);

public sealed record ViewerAgentCommandPreparation(
    ViewerAgentCommandExecutionRequest? Request,
    ViewerAgentCommandResult? Failure)
{
    public bool IsPrepared => Request != null && Failure == null;
}

public sealed record ViewerAgentCommandResult
{
    public const int MaxDiagnosticLength = 1024;
    public const int MaxErrorCodeLength = 128;

    public Guid CommandId { get; init; }

    public ViewerAgentCommandOutcome Outcome { get; init; }

    public bool Success => Outcome == ViewerAgentCommandOutcome.Succeeded;

    public string ErrorCode { get; init; } = string.Empty;

    public string Diagnostic { get; init; } = string.Empty;

    public bool IsRetryable { get; init; }

    public bool CommandSubmissionAttempted { get; init; }

    public bool PreflightVerified { get; init; }

    public bool AuthenticatedHealthVerified { get; init; }

    public int ContractVersion { get; init; } = AgentContracts.ContractVersion;

    public AgentHealthSnapshot? Health { get; init; }

    public AgentHealthSnapshot? VerifiedHealth { get; init; }

    public AgentPairingStatusSnapshot? VerifiedPairingStatus { get; init; }

    public string AuthenticatedEndpoint { get; init; } = string.Empty;

    public long PairingGeneration { get; init; }

    /// <summary>
    /// Transport-neutral identity produced only after the complete local pairing,
    /// release, target, compatibility, freshness, and exact-process preflight.
    /// It is viewer-local metadata and is never copied into the IPC response.
    /// </summary>
    public AuthenticatedAgentContext? AuthenticatedAgent { get; init; }

    /// <summary>
    /// Separate exact-command authorization decision bound to the authenticated
    /// credential epoch and connection generation.
    /// </summary>
    public AgentAuthorizationDecision? CommandAuthorization { get; init; }

    public AgentIpcResponse? Response { get; init; }

    public AgentIpcResponse? PreflightResponse { get; init; }

    public Guid? AcceptedJobId { get; init; }

    public JobProgress? Job { get; init; }

    public IReadOnlyList<AgentActiveWorkItem> AcceptedJobs { get; init; } =
        Array.Empty<AgentActiveWorkItem>();

    public IReadOnlyList<AgentActiveWorkItem> AffectedJobs { get; init; } =
        Array.Empty<AgentActiveWorkItem>();

    public DatabaseChangedNotification? DatabaseChanged { get; init; }

    public AgentHostMonitoringConfiguration? HostMonitoringConfiguration { get; init; }

    public AgentCaptureConfiguration? CaptureConfiguration { get; init; }

    public AgentConfigurationCheckResult? ConfigurationCheck { get; init; }

    public AgentMonitoringDeploymentResult? MonitoringDeployment { get; init; }

    public AgentCaptureLifecycleResult? CaptureLifecycle { get; init; }

    public AgentPairingStatusSnapshot? PairingStatus { get; init; }

    public AgentIpcResponse ToAgentIpcResponse() => Response ?? new AgentIpcResponse
    {
        ContractVersion = ContractVersion,
        RequestId = CommandId,
        Success = Success,
        ErrorCode = ErrorCode,
        ErrorMessage = Diagnostic,
        IsRetryable = IsRetryable,
        Health = Health,
        AcceptedJobId = AcceptedJobId,
        Job = Job,
        AcceptedJobs = AcceptedJobs,
        AffectedJobs = AffectedJobs,
        DatabaseChanged = DatabaseChanged,
        HostMonitoringConfiguration = HostMonitoringConfiguration,
        CaptureConfiguration = CaptureConfiguration,
        ConfigurationCheck = ConfigurationCheck,
        MonitoringDeployment = MonitoringDeployment,
        CaptureLifecycle = CaptureLifecycle,
        PairingStatus = PairingStatus
    };

    internal static ViewerAgentCommandResult Reject(
        Guid commandId,
        ViewerAgentCommandOutcome outcome,
        string errorCode,
        string diagnostic,
        bool isRetryable = false,
        AgentHealthSnapshot? health = null,
        bool commandSubmissionAttempted = false,
        bool preflightVerified = false,
        string authenticatedEndpoint = "",
        long pairingGeneration = 0,
        AgentPairingStatusSnapshot? verifiedPairingStatus = null) =>
        new()
        {
            CommandId = commandId,
            Outcome = outcome,
            ErrorCode = BoundCode(errorCode),
            Diagnostic = Bound(diagnostic),
            IsRetryable = isRetryable,
            Health = null,
            VerifiedHealth = health,
            VerifiedPairingStatus = verifiedPairingStatus,
            CommandSubmissionAttempted = commandSubmissionAttempted,
            PreflightVerified = preflightVerified,
            AuthenticatedEndpoint = authenticatedEndpoint,
            PairingGeneration = pairingGeneration
        };

    internal static ViewerAgentCommandResult FromResponse(
        Guid commandId,
        AgentIpcResponse response,
        AgentHealthSnapshot verifiedHealth,
        string authenticatedEndpoint,
        long pairingGeneration,
        AgentPairingStatusSnapshot? verifiedPairingStatus,
        bool commandSubmissionAttempted = true)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(verifiedHealth);
        var preservedResponse = response with
        {
            AcceptedJobs = Copy(response.AcceptedJobs),
            AffectedJobs = Copy(response.AffectedJobs)
        };
        return new ViewerAgentCommandResult
        {
            CommandId = commandId,
            Outcome = response.Success
                ? ViewerAgentCommandOutcome.Succeeded
                : ViewerAgentCommandOutcome.AgentRejected,
            ErrorCode = BoundCode(response.ErrorCode),
            Diagnostic = Bound(response.ErrorMessage),
            IsRetryable = response.IsRetryable,
            CommandSubmissionAttempted = commandSubmissionAttempted,
            PreflightVerified = true,
            ContractVersion = response.ContractVersion,
            Health = response.Health,
            VerifiedHealth = verifiedHealth,
            VerifiedPairingStatus = verifiedPairingStatus,
            AuthenticatedEndpoint = authenticatedEndpoint,
            PairingGeneration = pairingGeneration,
            Response = preservedResponse,
            AcceptedJobId = response.AcceptedJobId,
            Job = response.Job,
            AcceptedJobs = Copy(response.AcceptedJobs),
            AffectedJobs = Copy(response.AffectedJobs),
            DatabaseChanged = response.DatabaseChanged,
            HostMonitoringConfiguration = response.HostMonitoringConfiguration,
            CaptureConfiguration = response.CaptureConfiguration,
            ConfigurationCheck = response.ConfigurationCheck,
            MonitoringDeployment = response.MonitoringDeployment,
            CaptureLifecycle = response.CaptureLifecycle,
            PairingStatus = response.PairingStatus
        };
    }

    internal static ViewerAgentCommandResult VerifiedBinding(
        Guid commandId,
        AgentHealthSnapshot health,
        string authenticatedEndpoint,
        long pairingGeneration,
        AgentPairingStatusSnapshot? verifiedPairingStatus) =>
        new()
        {
            CommandId = commandId,
            Outcome = ViewerAgentCommandOutcome.Succeeded,
            ErrorCode = string.Empty,
            Diagnostic = "The authenticated viewer-agent binding passed the complete command preflight without submitting a command.",
            IsRetryable = false,
            CommandSubmissionAttempted = false,
            PreflightVerified = true,
            AuthenticatedHealthVerified = true,
            Health = health,
            VerifiedHealth = health,
            VerifiedPairingStatus = verifiedPairingStatus,
            AuthenticatedEndpoint = BoundCode(authenticatedEndpoint),
            PairingGeneration = pairingGeneration
        };

    private static IReadOnlyList<T> Copy<T>(IReadOnlyList<T>? values) =>
        values is { Count: > 0 }
            ? Array.AsReadOnly(values.ToArray())
            : Array.Empty<T>();

    private static string Bound(string? value)
    {
        var normalized = string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim();
        return normalized.Length <= MaxDiagnosticLength
            ? normalized
            : normalized[..MaxDiagnosticLength];
    }

    private static string BoundCode(string? value)
    {
        var normalized = string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim();
        return normalized.Length <= MaxErrorCodeLength
            ? normalized
            : normalized[..MaxErrorCodeLength];
    }
}

public interface IViewerAgentCommandRuntime
{
    bool IsContextCurrent(ViewerAgentCommandExecutionContext context);

    void BindSession(InvestigationSessionPaths sessionPaths);

    Task<AgentNamedPipeExchangeResult> GetHealthAsync(
        AgentCommandKind commandKind,
        CancellationToken cancellationToken);

    LocalAgentProcessResult VerifyRunning(LocalAgentProcessIdentity identity);

    bool IsSupportedExecutablePath(
        string executablePath,
        IReadOnlyList<string> supportedExecutablePaths);

    Task<AgentNamedPipeExchangeResult> SubmitCommandAsync(
        AgentCommand command,
        string expectedEndpoint,
        long expectedPairingGeneration,
        CancellationToken cancellationToken);
}

public sealed class DelegateViewerAgentCommandRuntime : IViewerAgentCommandRuntime
{
    private readonly Func<ViewerAgentCommandExecutionContext, bool> _isContextCurrent;
    private readonly Action<InvestigationSessionPaths> _bindSession;
    private readonly Func<AgentCommandKind, CancellationToken, Task<AgentNamedPipeExchangeResult>> _getHealthAsync;
    private readonly Func<LocalAgentProcessIdentity, LocalAgentProcessResult> _verifyRunning;
    private readonly Func<string, IReadOnlyList<string>, bool> _isSupportedExecutablePath;
    private readonly Func<AgentCommand, string, long, CancellationToken, Task<AgentNamedPipeExchangeResult>> _submitCommandAsync;

    public DelegateViewerAgentCommandRuntime(
        Func<ViewerAgentCommandExecutionContext, bool> isContextCurrent,
        Action<InvestigationSessionPaths> bindSession,
        Func<AgentCommandKind, CancellationToken, Task<AgentNamedPipeExchangeResult>> getHealthAsync,
        Func<LocalAgentProcessIdentity, LocalAgentProcessResult> verifyRunning,
        Func<string, IReadOnlyList<string>, bool> isSupportedExecutablePath,
        Func<AgentCommand, string, long, CancellationToken, Task<AgentNamedPipeExchangeResult>> submitCommandAsync)
    {
        _isContextCurrent = isContextCurrent ?? throw new ArgumentNullException(nameof(isContextCurrent));
        _bindSession = bindSession ?? throw new ArgumentNullException(nameof(bindSession));
        _getHealthAsync = getHealthAsync ?? throw new ArgumentNullException(nameof(getHealthAsync));
        _verifyRunning = verifyRunning ?? throw new ArgumentNullException(nameof(verifyRunning));
        _isSupportedExecutablePath = isSupportedExecutablePath ?? throw new ArgumentNullException(nameof(isSupportedExecutablePath));
        _submitCommandAsync = submitCommandAsync ?? throw new ArgumentNullException(nameof(submitCommandAsync));
    }

    public bool IsContextCurrent(ViewerAgentCommandExecutionContext context) =>
        _isContextCurrent(context);

    public void BindSession(InvestigationSessionPaths sessionPaths) =>
        _bindSession(sessionPaths);

    public Task<AgentNamedPipeExchangeResult> GetHealthAsync(
        AgentCommandKind commandKind,
        CancellationToken cancellationToken) =>
        _getHealthAsync(commandKind, cancellationToken);

    public LocalAgentProcessResult VerifyRunning(LocalAgentProcessIdentity identity) =>
        _verifyRunning(identity);

    public bool IsSupportedExecutablePath(
        string executablePath,
        IReadOnlyList<string> supportedExecutablePaths) =>
        _isSupportedExecutablePath(executablePath, supportedExecutablePaths);

    public Task<AgentNamedPipeExchangeResult> SubmitCommandAsync(
        AgentCommand command,
        string expectedEndpoint,
        long expectedPairingGeneration,
        CancellationToken cancellationToken) =>
        _submitCommandAsync(
            command,
            expectedEndpoint,
            expectedPairingGeneration,
            cancellationToken);
}

/// <summary>
/// Headless viewer-side application service that applies the complete reusable command
/// preflight and submits one typed command through an injected authenticated runtime.
/// It never starts, discovers, repairs, configures, or stops an agent.
/// </summary>
public sealed class ViewerAgentCommandExecutor
{
    private readonly IViewerAgentCommandRuntime _runtime;
    private readonly Func<DateTime> _utcNow;
    private readonly Func<Guid> _connectionGenerationFactory;

    public ViewerAgentCommandExecutor(
        IViewerAgentCommandRuntime runtime,
        Func<DateTime>? utcNow = null,
        Func<Guid>? connectionGenerationFactory = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
        _connectionGenerationFactory = connectionGenerationFactory ?? Guid.NewGuid;
    }

    public ViewerAgentCommandPreparation Prepare(ViewerAgentCommandExecutionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Command);
        ArgumentNullException.ThrowIfNull(request.Context);

        var command = request.Command;
        var context = request.Context;
        var contextFailure = ValidateContext(command.CommandId, context);
        if (contextFailure != null)
        {
            return new ViewerAgentCommandPreparation(null, contextFailure);
        }

        var featureDecision = AgentCommandFeaturePolicy.EvaluateCommand(
            context.FeatureCatalog,
            command);
        if (!featureDecision.Allowed)
        {
            return new ViewerAgentCommandPreparation(
                null,
                ViewerAgentCommandResult.Reject(
                    command.CommandId,
                    ViewerAgentCommandOutcome.FeatureRejected,
                    featureDecision.ErrorCode,
                    featureDecision.ErrorMessage,
                    featureDecision.IsRetryable));
        }

        var localCapabilities = AgentCommandFeaturePolicy
            .GetPublishedCommandCapabilities(context.FeatureCatalog)
            .Where(candidate => candidate.CommandKind == command.Kind)
            .ToArray();
        var capability = localCapabilities.Length == 1 ? localCapabilities[0] : null;
        if (capability == null ||
            capability.OperationalAvailability != AgentCommandOperationalAvailability.Supported)
        {
            var reason = capability == null || string.IsNullOrWhiteSpace(capability.AvailabilityReason)
                ? $"Agent command '{command.Kind}' is not operationally available."
                : capability.AvailabilityReason;
            return new ViewerAgentCommandPreparation(
                null,
                ViewerAgentCommandResult.Reject(
                    command.CommandId,
                    ViewerAgentCommandOutcome.OperationallyUnavailable,
                    ViewerAgentCommandErrorCodes.CommandNotAvailable,
                    reason));
        }

        CaptureWriteCategory actualCategory;
        try
        {
            actualCategory = CaptureWritePolicy.GetCategory(command.Kind);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            return new ViewerAgentCommandPreparation(
                null,
                ViewerAgentCommandResult.Reject(
                    command.CommandId,
                    ViewerAgentCommandOutcome.InvalidContext,
                    ViewerAgentCommandErrorCodes.WriteCategoryMismatch,
                    ex.Message));
        }

        if (context.WriteCategory != actualCategory)
        {
            return new ViewerAgentCommandPreparation(
                null,
                ViewerAgentCommandResult.Reject(
                    command.CommandId,
                    ViewerAgentCommandOutcome.InvalidContext,
                    ViewerAgentCommandErrorCodes.WriteCategoryMismatch,
                    $"Trusted command category '{context.WriteCategory}' does not match '{actualCategory}' for '{command.Kind}'."));
        }

        if (!CaptureWritePolicy.IsAllowed(context.Target.WorkspaceMode, actualCategory))
        {
            var archived = context.Target.WorkspaceMode == CaptureWorkspaceMode.ArchivedCapture;
            return new ViewerAgentCommandPreparation(
                null,
                ViewerAgentCommandResult.Reject(
                    command.CommandId,
                    ViewerAgentCommandOutcome.WorkspaceRejected,
                    archived
                        ? ViewerAgentCommandErrorCodes.ArchivedCaptureSealed
                        : ViewerAgentCommandErrorCodes.NoActiveWorkspace,
                    archived
                        ? $"{CaptureWritePolicy.ArchivedCaptureSealedMessage} '{command.Kind}' requests {actualCategory}."
                        : $"No active capture workspace can accept '{command.Kind}'."));
        }

        if (context.Access.RequiresViewerConnection &&
            context.Access.Kind != ViewerAgentCommandAccessKind.ViewerConnected)
        {
            return new ViewerAgentCommandPreparation(
                null,
                ViewerAgentCommandResult.Reject(
                    command.CommandId,
                    ViewerAgentCommandOutcome.AccessRejected,
                    ViewerAgentCommandErrorCodes.ViewerConnectionRequired,
                    "Connect to an agent before submitting this command."));
        }

        if (context.Access.Kind is not
            (ViewerAgentCommandAccessKind.ViewerConnected or
             ViewerAgentCommandAccessKind.VerifiedDeployedAgent))
        {
            return new ViewerAgentCommandPreparation(
                null,
                ViewerAgentCommandResult.Reject(
                    command.CommandId,
                    ViewerAgentCommandOutcome.AccessRejected,
                    ViewerAgentCommandErrorCodes.TargetUnavailable,
                    "The local agent is not available for this command."));
        }

        if (!_runtime.IsContextCurrent(context))
        {
            return new ViewerAgentCommandPreparation(
                null,
                RejectSuperseded(command.CommandId));
        }

        var canonicalSessionRoot = Path.GetFullPath(context.SessionPaths.SessionRoot);
        var canonicalDatabasePath = Path.GetFullPath(context.Target.DatabasePath);
        var trustedContext = context with
        {
            SessionPaths = context.SessionPaths with
            {
                SessionRoot = canonicalSessionRoot,
                LiveDatabasePath = canonicalDatabasePath
            },
            Target = context.Target with
            {
                DatabasePath = canonicalDatabasePath,
                PackageIdentity = context.Target.PackageIdentity with
                {
                    SessionRoot = canonicalSessionRoot,
                    DatabasePath = canonicalDatabasePath
                },
                SupportedExecutablePaths = Array.AsReadOnly(
                    context.Target.SupportedExecutablePaths
                        .Select(Path.GetFullPath)
                        .ToArray())
            }
        };
        var stamped = command with
        {
            TargetSessionId = trustedContext.Target.SessionId,
            TargetDatabasePath = canonicalDatabasePath,
            TargetWorkspaceMode = trustedContext.Target.WorkspaceMode,
            RequestedWriteCategory = actualCategory
        };
        if (stamped is ShutdownAgentCommand shutdown)
        {
            stamped = shutdown with { ExpectedDatabasePath = canonicalDatabasePath };
        }
        return new ViewerAgentCommandPreparation(
            new ViewerAgentCommandExecutionRequest(stamped, trustedContext),
            null);
    }

    public Task<ViewerAgentCommandResult> ValidateBindingAsync(
        ViewerAgentCommandExecutionRequest request,
        CancellationToken cancellationToken = default) =>
        ExecuteCoreAsync(request, submitCommand: false, cancellationToken);

    public Task<ViewerAgentCommandResult> ExecuteAsync(
        ViewerAgentCommandExecutionRequest request,
        CancellationToken cancellationToken = default) =>
        ExecuteCoreAsync(request, submitCommand: true, cancellationToken);

    private async Task<ViewerAgentCommandResult> ExecuteCoreAsync(
        ViewerAgentCommandExecutionRequest request,
        bool submitCommand,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Command);
        ArgumentNullException.ThrowIfNull(request.Context);

        if (cancellationToken.IsCancellationRequested)
        {
            return RejectCanceled(request.Command.CommandId);
        }

        var preparation = Prepare(request);
        if (!preparation.IsPrepared)
        {
            return preparation.Failure!;
        }

        var prepared = preparation.Request!;
        var command = prepared.Command;
        var context = prepared.Context;
        var contextFailure = ValidateContext(command.CommandId, context);
        if (contextFailure != null)
        {
            return contextFailure;
        }

        if (!_runtime.IsContextCurrent(context))
        {
            return RejectSuperseded(command.CommandId);
        }

        AgentNamedPipeExchangeResult healthExchange;
        try
        {
            _runtime.BindSession(context.SessionPaths);
            healthExchange = await _runtime.GetHealthAsync(command.Kind, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return RejectCanceled(command.CommandId);
        }
        catch (Exception ex)
        {
            return ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.InternalFailure,
                ViewerAgentCommandErrorCodes.InternalFailure,
                $"The authenticated agent health preflight failed: {ex.GetType().Name}: {ex.Message}",
                isRetryable: true);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return RejectCanceled(command.CommandId);
        }

        if (!_runtime.IsContextCurrent(context))
        {
            return RejectSuperseded(command.CommandId);
        }

        if (healthExchange == null || healthExchange.Response == null)
        {
            return ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.InternalFailure,
                ViewerAgentCommandErrorCodes.InternalFailure,
                "The authenticated health runtime returned no exchange result.",
                isRetryable: true);
        }

        var healthResponse = healthExchange.Response;
        if (healthExchange.ExpectedRequestId == Guid.Empty ||
            healthResponse.ContractVersion != AgentContracts.ContractVersion ||
            healthResponse.RequestId != healthExchange.ExpectedRequestId)
        {
            return ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.ContractRejected,
                ViewerAgentCommandErrorCodes.ContractMismatch,
                "The authenticated health response contract/request identity did not match its exact request envelope.",
                health: healthResponse.Health);
        }

        var authenticatedHealthVerified = false;
        ViewerAgentCommandResult WithPreflight(ViewerAgentCommandResult result) =>
            result with
            {
                PreflightResponse = healthResponse,
                AuthenticatedHealthVerified = authenticatedHealthVerified
            };

        if (healthResponse.Success && !healthExchange.ProtectedRequestSent)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.PairingRejected,
                ViewerAgentCommandErrorCodes.PairingContextMismatch,
                "The health runtime did not transmit an authenticated protected request."));
        }

        if (healthResponse.Success && !healthExchange.AuthoritativeResponseReceived)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.HealthUnavailable,
                ViewerAgentCommandErrorCodes.TargetUnavailable,
                "The health runtime did not receive an authoritative agent response.",
                isRetryable: true));
        }

        if (!healthResponse.Success)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                IsPairingFailure(healthResponse.ErrorCode)
                    ? ViewerAgentCommandOutcome.PairingRejected
                    : ViewerAgentCommandOutcome.HealthUnavailable,
                string.IsNullOrWhiteSpace(healthResponse.ErrorCode)
                    ? ViewerAgentCommandErrorCodes.TargetUnavailable
                    : healthResponse.ErrorCode,
                healthResponse.ErrorMessage,
                healthResponse.IsRetryable));
        }

        var health = healthResponse.Health;
        if (health == null)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.HealthUnavailable,
                ViewerAgentCommandErrorCodes.HealthMissing,
                "The authenticated health response did not contain an agent health snapshot."));
        }

        var healthFreshnessFailure = ValidateFreshHealthSnapshot(
            command.CommandId,
            health,
            _utcNow());
        if (healthFreshnessFailure != null)
        {
            return WithPreflight(healthFreshnessFailure);
        }

        if (health.ReleaseProfile == null)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.ReleaseRejected,
                ViewerAgentCommandErrorCodes.ReleaseMismatch,
                "Fresh agent health did not report a release profile.",
                health: health));
        }

        var transportFailure = ValidateAuthenticatedTransport(
            command.CommandId,
            context,
            health,
            healthExchange.ConnectedPipeName,
            healthExchange.PairingStatus);
        if (transportFailure != null)
        {
            return WithPreflight(transportFailure);
        }

        var authenticatedEndpoint = healthExchange.ConnectedPipeName;
        var pairingGeneration = healthExchange.PairingStatus.PairingGeneration;
        var verifiedPairingStatus = healthResponse.PairingStatus;

        if (health.ContractVersion != AgentContracts.ContractVersion)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.ContractRejected,
                ViewerAgentCommandErrorCodes.ContractMismatch,
                $"Agent contract version {health.ContractVersion} does not match viewer contract version {AgentContracts.ContractVersion}.",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        authenticatedHealthVerified = true;

        if (!IsReleaseProfileWellFormed(context, health) ||
            (!IsReleaseCompatible(context, health) && !AllowsReleaseMismatchCleanup(command.Kind)))
        {
            var agentRelease = string.IsNullOrWhiteSpace(health.ReleaseProfile?.ReleaseId)
                ? "<not reported>"
                : health.ReleaseProfile.ReleaseId;
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.ReleaseRejected,
                ViewerAgentCommandErrorCodes.ReleaseMismatch,
                $"Viewer release '{context.ViewerReleaseId}' does not match agent release '{agentRelease}'.",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        var capabilityFailure = ValidateFreshOperationalCapability(
            command.CommandId,
            command,
            context,
            health,
            authenticatedEndpoint,
            pairingGeneration,
            verifiedPairingStatus);
        if (capabilityFailure != null)
        {
            return WithPreflight(capabilityFailure);
        }

        var sessionFailure = ValidateHealthTarget(command.CommandId, context, health);
        if (sessionFailure != null)
        {
            return WithPreflight(sessionFailure with
            {
                AuthenticatedEndpoint = authenticatedEndpoint,
                PairingGeneration = pairingGeneration,
                VerifiedPairingStatus = verifiedPairingStatus
            });
        }

        var compatibility = health.CaptureCompatibility;
        if (compatibility == null)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.SessionRejected,
                ViewerAgentCommandErrorCodes.CaptureCompatibilityRejected,
                "Fresh agent health did not report capture compatibility; command submission is blocked.",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        var requiredCapability = context.Target.IsSealed
            ? CaptureOpenCapability.MaintainAnalysisState
            : CaptureOpenCapability.WritePrimaryEvidence;
        var expectedCompatibilityContext = context.Target.IsSealed
            ? CaptureOpenContext.ArchivedAnalysisMaintenance
            : CaptureOpenContext.AgentWritableLive;
        var expectedArtifactKind = context.Target.IsSealed
            ? CaptureArtifactKind.ArchivedSealedPackage
            : CaptureArtifactKind.LiveAuthoritativeDatabase;
        const CaptureOpenCapability knownCapabilities =
            CaptureOpenCapability.InspectMetadata |
            CaptureOpenCapability.ReadEvidence |
            CaptureOpenCapability.WritePrimaryEvidence |
            CaptureOpenCapability.MigratePrimaryEvidence |
            CaptureOpenCapability.MaintainAnalysisState;
        if (!Enum.IsDefined(compatibility.State) ||
            compatibility.State is not
                (CaptureCompatibilityState.CompatibleCurrent or
                 CaptureCompatibilityState.SupportedLegacy) ||
            !Enum.IsDefined(compatibility.AnalysisState) ||
            !Enum.IsDefined(compatibility.Context) ||
            !Enum.IsDefined(compatibility.ArtifactKind) ||
            (compatibility.Capabilities & ~knownCapabilities) != 0 ||
            !compatibility.Allows(requiredCapability) ||
            compatibility.Context != expectedCompatibilityContext ||
            compatibility.ArtifactKind != expectedArtifactKind ||
            compatibility.ManifestSchemaVersion !=
                context.Target.PackageIdentity.ManifestSchemaVersion ||
            compatibility.EvidenceFormatVersion !=
                context.Target.PackageIdentity.EvidenceFormatVersion ||
            compatibility.MinimumSupportedManifestSchemaVersion !=
                CaptureCompatibilityPolicy.MinimumSupportedManifestSchemaVersion ||
            compatibility.MaximumSupportedManifestSchemaVersion !=
                CaptureCompatibilityPolicy.CurrentManifestSchemaVersion ||
            compatibility.MinimumSupportedEvidenceFormatVersion !=
                CaptureCompatibilityPolicy.MinimumSupportedEvidenceFormatVersion ||
            compatibility.MaximumSupportedEvidenceFormatVersion !=
                CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion ||
            string.IsNullOrWhiteSpace(compatibility.StatusCode) ||
            string.IsNullOrWhiteSpace(compatibility.Message))
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.SessionRejected,
                ViewerAgentCommandErrorCodes.CaptureCompatibilityRejected,
                string.IsNullOrWhiteSpace(compatibility.Message)
                    ? $"The target capture does not allow {requiredCapability}."
                    : compatibility.Message,
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        LocalAgentProcessResult processVerification;
        try
        {
            _ = TryNormalize(
                healthExchange.PairingStatus.Lease!.ExecutablePath,
                out var verifiedExecutablePath);
            processVerification = _runtime.VerifyRunning(new LocalAgentProcessIdentity(
                health.ProcessId,
                health.StartedAtUtc,
                Array.AsReadOnly([verifiedExecutablePath])));
        }
        catch (Exception ex)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.ProcessRejected,
                ViewerAgentCommandErrorCodes.ProcessIdentityMismatch,
                $"Local-agent process inspection failed: {ex.GetType().Name}: {ex.Message}",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (processVerification == null ||
            processVerification.Outcome != LocalAgentProcessOutcome.VerifiedRunning ||
            processVerification.ProcessId != health.ProcessId ||
            !processVerification.IsRunning ||
            processVerification.IsStopped ||
            processVerification.Forced)
        {
            var processFailureDiagnostic = processVerification == null
                ? "Local-agent process verification returned no result."
                : processVerification.Outcome != LocalAgentProcessOutcome.VerifiedRunning
                    ? string.IsNullOrWhiteSpace(processVerification.Detail)
                        ? $"Local-agent process verification failed with {processVerification.Outcome}."
                        : $"{processVerification.Detail} (Outcome: {processVerification.Outcome}.)"
                    : "Local-agent process verification result did not match fresh health and the required running state.";
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.ProcessRejected,
                ViewerAgentCommandErrorCodes.ProcessIdentityMismatch,
                processFailureDiagnostic,
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        AuthenticatedAgentContext? authenticatedAgent = null;
        AgentAuthorizationDecision? commandAuthorization = null;
        ViewerAgentCommandResult WithVerifiedPreflight(ViewerAgentCommandResult result) =>
            result with
            {
                PreflightResponse = healthResponse,
                AuthenticatedHealthVerified = true,
                PreflightVerified = true,
                AuthenticatedAgent = authenticatedAgent,
                CommandAuthorization = commandAuthorization
            };

        if (cancellationToken.IsCancellationRequested)
        {
            return WithVerifiedPreflight(RejectCanceled(
                command.CommandId,
                health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (!_runtime.IsContextCurrent(context))
        {
            return WithVerifiedPreflight(RejectSuperseded(
                command.CommandId,
                health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        var finalHealthFreshnessFailure = ValidateFreshHealthSnapshot(
            command.CommandId,
            health,
            _utcNow());
        if (finalHealthFreshnessFailure != null)
        {
            return WithPreflight(finalHealthFreshnessFailure with
            {
                AuthenticatedEndpoint = authenticatedEndpoint,
                PairingGeneration = pairingGeneration,
                VerifiedPairingStatus = verifiedPairingStatus
            });
        }

        var authenticatedAtUtc = _utcNow();
        AgentAuthenticationDecision authentication;
        try
        {
            authentication = LocalAuthenticatedAgentContextAdapter.Authenticate(
                context,
                health,
                healthExchange.PairingStatus,
                authenticatedEndpoint,
                processVerification,
                authenticatedAtUtc,
                _connectionGenerationFactory());
        }
        catch (Exception ex)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.AccessRejected,
                ViewerAgentCommandErrorCodes.AuthenticatedContextRejected,
                $"The verified local-agent identity could not be normalized: {ex.GetType().Name}: {ex.Message}",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (!authentication.Allowed || authentication.Context == null)
        {
            return WithPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.AccessRejected,
                ViewerAgentCommandErrorCodes.AuthenticatedContextRejected,
                authentication.Diagnostic,
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        authenticatedAgent = authentication.Context;
        var exactCommandGrant = new AgentAuthorizationGrant
        {
            GrantId = $"local-command:{command.CommandId:N}",
            Role = "LocalInteractiveViewer",
            AgentId = authenticatedAgent.AgentId,
            HostId = authenticatedAgent.HostId,
            CredentialEpoch = authenticatedAgent.CredentialEpoch,
            ConnectionGeneration = authenticatedAgent.ConnectionGeneration,
            Scope = authenticatedAgent.Scope,
            IssuedAtUtc = authenticatedAtUtc,
            ExpiresAtUtc = authenticatedAgent.FreshUntilUtc,
            AllowCommandExecution = true,
            AllowedCommands = Array.AsReadOnly([command.Kind])
        };
        commandAuthorization = AgentAuthorizationPolicy.Evaluate(
            authenticatedAgent,
            exactCommandGrant,
            new AgentAuthorizationRequest
            {
                Action = AgentAuthorizationAction.ExecuteCommand,
                AgentId = authenticatedAgent.AgentId,
                HostId = authenticatedAgent.HostId,
                CredentialEpoch = authenticatedAgent.CredentialEpoch,
                ConnectionGeneration = authenticatedAgent.ConnectionGeneration,
                Scope = authenticatedAgent.Scope,
                CommandKind = command.Kind,
                WriteCategory = context.WriteCategory,
                FeaturePublished = true,
                CapabilityAvailable = true,
                ReleaseCompatible = true,
                ExactTargetValidated = true,
                CaptureCompatibilityAllowed = true
            },
            authenticatedAtUtc);
        if (!commandAuthorization.Allowed)
        {
            return WithVerifiedPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.AccessRejected,
                ViewerAgentCommandErrorCodes.AuthorizationRejected,
                commandAuthorization.Diagnostic,
                health: health,
                preflightVerified: true,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (!submitCommand)
        {
            return WithVerifiedPreflight(ViewerAgentCommandResult.VerifiedBinding(
                command.CommandId,
                health,
                authenticatedEndpoint,
                pairingGeneration,
                verifiedPairingStatus));
        }

        AgentNamedPipeExchangeResult commandExchange;
        try
        {
            commandExchange = await _runtime.SubmitCommandAsync(
                command,
                authenticatedEndpoint,
                pairingGeneration,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return WithVerifiedPreflight(RejectCommandOutcomeUnknown(
                command.CommandId,
                health,
                "Agent command submission was canceled after entering the command transport; no authenticated authoritative outcome could be confirmed.",
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }
        catch (Exception ex)
        {
            return WithVerifiedPreflight(RejectCommandOutcomeUnknown(
                command.CommandId,
                health,
                $"The command transport failed after submission began ({ex.GetType().Name}: {ex.Message}); no authenticated authoritative outcome could be confirmed.",
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (commandExchange == null || commandExchange.Response == null)
        {
            return WithVerifiedPreflight(RejectCommandOutcomeUnknown(
                command.CommandId,
                health,
                "The command transport returned no exchange result after submission began; no authenticated authoritative outcome could be confirmed.",
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        var response = commandExchange.Response;
        if (commandExchange.ProtectedRequestSent &&
            !commandExchange.AuthoritativeResponseReceived)
        {
            return WithVerifiedPreflight(RejectCommandOutcomeUnknown(
                command.CommandId,
                health,
                "The protected command transmission completed without an authenticated authoritative agent response.",
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (commandExchange.ExpectedRequestId == Guid.Empty ||
            response.ContractVersion != AgentContracts.ContractVersion ||
            response.RequestId != commandExchange.ExpectedRequestId)
        {
            if (commandExchange.ProtectedRequestSent)
            {
                return WithVerifiedPreflight(RejectCommandOutcomeUnknown(
                    command.CommandId,
                    health,
                    "The protected command response did not match its exact contract/request envelope; no authoritative outcome could be bound to this command.",
                    authenticatedEndpoint: authenticatedEndpoint,
                    pairingGeneration: pairingGeneration,
                    verifiedPairingStatus: verifiedPairingStatus));
            }

            return WithVerifiedPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                ViewerAgentCommandOutcome.ContractRejected,
                ViewerAgentCommandErrorCodes.ContractMismatch,
                "The agent command response contract/request identity did not match its exact request envelope.",
                health: health,
                commandSubmissionAttempted: commandExchange.ProtectedRequestSent,
                preflightVerified: true,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (!commandExchange.ProtectedRequestSent)
        {
            var pairingFailed = IsPairingFailure(response.ErrorCode) ||
                commandExchange.PairingStatus == null ||
                commandExchange.PairingStatus.State is not
                    (AgentPairingState.Ready or AgentPairingState.Connected);
            return WithVerifiedPreflight(ViewerAgentCommandResult.Reject(
                command.CommandId,
                pairingFailed
                    ? ViewerAgentCommandOutcome.PairingRejected
                    : ViewerAgentCommandOutcome.HealthUnavailable,
                string.IsNullOrWhiteSpace(response.ErrorCode)
                    ? pairingFailed
                        ? ViewerAgentCommandErrorCodes.PairingContextMismatch
                        : ViewerAgentCommandErrorCodes.TargetUnavailable
                    : response.ErrorCode,
                string.IsNullOrWhiteSpace(response.ErrorMessage)
                    ? "The protected agent command was not sent after authenticated preflight."
                    : response.ErrorMessage,
                response.IsRetryable,
                health,
                commandSubmissionAttempted: false,
                preflightVerified: true,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: commandExchange.PairingStatus?.PairingGeneration ?? 0,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (!response.Success &&
            string.IsNullOrWhiteSpace(commandExchange.ConnectedPipeName))
        {
            return WithVerifiedPreflight(RejectCommandOutcomeUnknown(
                command.CommandId,
                health,
                "The protected command returned no exact authenticated endpoint metadata, so its final outcome could not be trusted.",
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        var commandTransportFailure = ValidateAuthenticatedTransport(
            command.CommandId,
            context,
            health,
            commandExchange.ConnectedPipeName,
            commandExchange.PairingStatus);
        if (commandTransportFailure != null ||
            commandExchange.PairingStatus?.PairingGeneration != pairingGeneration)
        {
            return WithVerifiedPreflight(RejectCommandOutcomeUnknown(
                command.CommandId,
                health,
                "The protected command response did not match the authenticated endpoint and pairing generation established by fresh health; no authoritative outcome could be bound to this command.",
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        if (!_runtime.IsContextCurrent(context))
        {
            return WithVerifiedPreflight(RejectSuperseded(
                command.CommandId,
                health,
                commandSubmissionAttempted: true,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus));
        }

        return WithVerifiedPreflight(ViewerAgentCommandResult.FromResponse(
            command.CommandId,
            response,
            health,
            authenticatedEndpoint,
            pairingGeneration,
            verifiedPairingStatus,
            commandExchange.ProtectedRequestSent));
    }

    private static ViewerAgentCommandResult? ValidateFreshHealthSnapshot(
        Guid commandId,
        AgentHealthSnapshot health,
        DateTime nowUtc)
    {
        var control = health.Control;
        var age = control == null || control.EmittedAtUtc == default
            ? TimeSpan.MaxValue
            : nowUtc - control.EmittedAtUtc;
        if (control == null ||
            !control.IsAuthoritative ||
            control.Generation <= 0 ||
            control.EmittedAtUtc.Kind != DateTimeKind.Utc ||
            !Enum.IsDefined(control.CaptureState) ||
            control.CaptureState == AgentCaptureRunState.Unknown ||
            age > AgentCaptureControlProjectionService.DefaultFreshnessWindow ||
            age < -TimeSpan.FromMinutes(1))
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.HealthUnavailable,
                ViewerAgentCommandErrorCodes.HealthStale,
                "Fresh authenticated health did not contain a current authoritative agent control snapshot.",
                isRetryable: true,
                health: health);
        }

        return null;
    }

    private ViewerAgentCommandResult? ValidateAuthenticatedTransport(
        Guid commandId,
        ViewerAgentCommandExecutionContext context,
        AgentHealthSnapshot health,
        string endpoint,
        AgentPairingStoreResult? pairing)
    {
        var lease = pairing?.Lease;
        endpoint ??= string.Empty;
        var expectedEndpoints = AgentContracts.CompatiblePipeNames
            .Concat(AgentContracts.CompatibleShutdownControlPipeNames)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var endpointInventoryMatches = lease?.Endpoints != null &&
            lease.Endpoints.Count == expectedEndpoints.Length &&
            lease.Endpoints.All(endpointName => !string.IsNullOrWhiteSpace(endpointName)) &&
            lease.Endpoints.Distinct(StringComparer.Ordinal).Count() == expectedEndpoints.Length &&
            !lease.Endpoints.Except(expectedEndpoints, StringComparer.Ordinal).Any() &&
            !expectedEndpoints.Except(lease.Endpoints, StringComparer.Ordinal).Any();
        var databaseMatches = lease != null &&
            TryNormalize(lease.DatabaseIdentity, out var leaseDatabase) &&
            TryNormalize(context.Target.DatabasePath, out var targetDatabase) &&
            string.Equals(leaseDatabase, targetDatabase, StringComparison.OrdinalIgnoreCase);
        var healthReleaseId = health.ReleaseProfile?.ReleaseId ?? string.Empty;
        var releaseMatches = lease != null &&
            !string.IsNullOrWhiteSpace(healthReleaseId) &&
            string.Equals(lease.ReleaseId, healthReleaseId, StringComparison.Ordinal);
        var executableMatches = lease != null &&
            lease.AgentProcessId > 0 &&
            lease.AgentStartedAtUtc != default &&
            lease.AgentStartedAtUtc.Kind == DateTimeKind.Utc &&
            !string.IsNullOrWhiteSpace(lease.ExecutableName) &&
            ExecutableIdentity.IsSupportedAgentProcessName(lease.ExecutableName) &&
            string.Equals(
                Path.GetFileName(lease.ExecutablePath),
                lease.ExecutableName,
                StringComparison.OrdinalIgnoreCase) &&
            _runtime.IsSupportedExecutablePath(
                lease.ExecutablePath,
                context.Target.SupportedExecutablePaths);
        var valid = pairing != null &&
            pairing.State is AgentPairingState.Ready or AgentPairingState.Connected &&
            pairing.PairingGeneration > 0 &&
            pairing.ExpiresAtUtc > DateTime.UtcNow &&
            lease != null &&
            lease.State is AgentPairingState.Ready or AgentPairingState.Connected &&
            lease.PairingGeneration == pairing.PairingGeneration &&
            lease.PairingContractVersion == AgentContracts.PairingContractVersion &&
            lease.IpcContractVersion == AgentContracts.ContractVersion &&
            lease.ExpiresAtUtc > DateTime.UtcNow &&
            string.Equals(lease.SessionId, context.Target.SessionId, StringComparison.Ordinal) &&
            databaseMatches &&
            releaseMatches &&
            lease.WorkspaceMode == context.Target.WorkspaceMode &&
            lease.CaptureSealed == context.Target.IsSealed &&
            lease.AgentProcessId == health.ProcessId &&
            lease.AgentStartedAtUtc == health.StartedAtUtc &&
            executableMatches &&
            endpointInventoryMatches &&
            !string.IsNullOrWhiteSpace(endpoint) &&
            AgentContracts.CompatiblePipeNames.Contains(endpoint, StringComparer.Ordinal) &&
            lease.Endpoints.Contains(endpoint, StringComparer.Ordinal);
        if (valid)
        {
            return null;
        }

        return ViewerAgentCommandResult.Reject(
            commandId,
            ViewerAgentCommandOutcome.PairingRejected,
            ViewerAgentCommandErrorCodes.PairingContextMismatch,
            "The authenticated endpoint, pairing generation/contracts, lease target, or process identity did not match the exact command context.",
            health: health,
            authenticatedEndpoint: endpoint,
            pairingGeneration: pairing?.PairingGeneration ?? 0);
    }

    private static ViewerAgentCommandResult? ValidateFreshOperationalCapability(
        Guid commandId,
        AgentCommand command,
        ViewerAgentCommandExecutionContext context,
        AgentHealthSnapshot health,
        string authenticatedEndpoint,
        long pairingGeneration,
        AgentPairingStatusSnapshot? verifiedPairingStatus)
    {
        var publishedCapabilities = health.ReleaseProfile?.PublishedCommandCapabilities;
        if (publishedCapabilities == null ||
            publishedCapabilities.Any(capability => capability == null))
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.FeatureRejected,
                AgentFeaturePolicyErrorCodes.FeatureNotPublished,
                $"Fresh agent health reported an invalid capability collection for '{command.Kind}'.",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus);
        }

        var matches = publishedCapabilities
            .Where(capability => capability.CommandKind == command.Kind)
            .ToArray();
        if (matches.Length != 1)
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.FeatureRejected,
                AgentFeaturePolicyErrorCodes.FeatureNotPublished,
                $"Fresh agent health did not publish exactly one capability for '{command.Kind}'.",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus);
        }

        var capability = matches[0];
        if (capability.OperationalAvailability != AgentCommandOperationalAvailability.Supported)
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.OperationallyUnavailable,
                ViewerAgentCommandErrorCodes.CommandNotAvailable,
                string.IsNullOrWhiteSpace(capability.AvailabilityReason)
                    ? $"Fresh agent health reports '{command.Kind}' as {capability.OperationalAvailability}."
                    : capability.AvailabilityReason,
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus);
        }

        var localMatches = AgentCommandFeaturePolicy
            .GetPublishedCommandCapabilities(context.FeatureCatalog)
            .Where(candidate => candidate.CommandKind == command.Kind)
            .ToArray();
        if (localMatches.Length != 1 ||
            capability.IsCoreControl != localMatches[0].IsCoreControl ||
            capability.HasPayloadSpecificRequirements !=
                localMatches[0].HasPayloadSpecificRequirements)
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.FeatureRejected,
                AgentFeaturePolicyErrorCodes.FeatureNotPublished,
                $"Fresh agent capability identity for '{command.Kind}' does not match the viewer release catalog.",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus);
        }

        var featureDecision = AgentCommandFeaturePolicy.EvaluateCommand(
            context.FeatureCatalog,
            command);
        var publishedFeatureIds = capability.PublishedFeatureIds ?? Array.Empty<string>();
        var localPublishedFeatureIds = localMatches[0].PublishedFeatureIds ?? Array.Empty<string>();
        if (!featureDecision.Allowed ||
            publishedFeatureIds.Count != localPublishedFeatureIds.Count ||
            publishedFeatureIds.Any(string.IsNullOrWhiteSpace) ||
            publishedFeatureIds.Distinct(StringComparer.Ordinal).Count() != publishedFeatureIds.Count ||
            publishedFeatureIds.Except(localPublishedFeatureIds, StringComparer.Ordinal).Any() ||
            (!capability.IsCoreControl &&
             featureDecision.RequiredFeatures.Any(required =>
                 !publishedFeatureIds.Contains(required.Value, StringComparer.Ordinal))))
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.FeatureRejected,
                AgentFeaturePolicyErrorCodes.FeatureNotPublished,
                $"Fresh agent capability metadata does not publish every payload-specific feature required by '{command.Kind}'.",
                health: health,
                authenticatedEndpoint: authenticatedEndpoint,
                pairingGeneration: pairingGeneration,
                verifiedPairingStatus: verifiedPairingStatus);
        }

        return null;
    }

    private static ViewerAgentCommandResult? ValidateContext(
        Guid commandId,
        ViewerAgentCommandExecutionContext context)
    {
        if (commandId == Guid.Empty ||
            context.SessionPaths == null ||
            context.Target == null ||
            context.Target.PackageIdentity == null ||
            context.FeatureCatalog == null ||
            context.Access == null ||
            string.IsNullOrWhiteSpace(context.ViewerReleaseId) ||
            !string.Equals(
                context.ViewerReleaseId,
                context.FeatureCatalog.ReleaseId,
                StringComparison.Ordinal) ||
            context.WorkspaceGeneration < 0)
        {
            return Invalid(commandId, "The command execution context is incomplete or uses a different release catalog.");
        }

        var target = context.Target;
        var session = context.SessionPaths;
        var package = target.PackageIdentity;
        if (string.IsNullOrWhiteSpace(session.SessionId) ||
            string.IsNullOrWhiteSpace(target.SessionId) ||
            !string.Equals(session.SessionId, target.SessionId, StringComparison.Ordinal) ||
            !string.Equals(package.SessionId, target.SessionId, StringComparison.Ordinal) ||
            !string.Equals(
                package.FormatName,
                SessionPathService.CapturePackageFormatName,
                StringComparison.Ordinal) ||
            package.ManifestSchemaVersion <
                CaptureCompatibilityPolicy.MinimumSupportedManifestSchemaVersion ||
            package.ManifestSchemaVersion >
                CaptureCompatibilityPolicy.CurrentManifestSchemaVersion ||
            package.EvidenceFormatVersion is not int evidenceFormatVersion ||
            evidenceFormatVersion <
                CaptureCompatibilityPolicy.MinimumSupportedEvidenceFormatVersion ||
            evidenceFormatVersion >
                CaptureCompatibilityPolicy.CurrentEvidenceFormatVersion ||
            !Enum.IsDefined(context.Access.Kind) ||
            !Enum.IsDefined(context.WriteCategory) ||
            target.WorkspaceMode is not
                (CaptureWorkspaceMode.LiveCapture or CaptureWorkspaceMode.ArchivedCapture) ||
            target.IsSealed != (target.WorkspaceMode == CaptureWorkspaceMode.ArchivedCapture))
        {
            return Invalid(commandId, "The command target does not identify one validated live or sealed capture package.");
        }

        if (!TryNormalize(session.SessionRoot, out var sessionRoot) ||
            !TryNormalize(session.LiveDatabasePath, out var sessionDatabase) ||
            !TryNormalize(package.SessionRoot, out var packageRoot) ||
            !TryNormalize(package.DatabasePath, out var packageDatabase) ||
            !TryNormalize(target.DatabasePath, out var targetDatabase) ||
            !string.Equals(sessionRoot, packageRoot, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(sessionDatabase, packageDatabase, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(sessionDatabase, targetDatabase, StringComparison.OrdinalIgnoreCase))
        {
            return Invalid(commandId, "The command target paths do not match the validated active session package.");
        }

        var normalizedExecutablePaths = target.SupportedExecutablePaths?
            .Select(candidate =>
                TryNormalize(candidate, out var normalized)
                    ? normalized
                    : string.Empty)
            .ToArray() ?? Array.Empty<string>();
        if (normalizedExecutablePaths.Length == 0 ||
            normalizedExecutablePaths.Length > 16 ||
            normalizedExecutablePaths.Any(string.IsNullOrWhiteSpace) ||
            normalizedExecutablePaths.Any(candidate =>
                !ExecutableIdentity.IsSupportedAgentProcessName(Path.GetFileName(candidate))) ||
            normalizedExecutablePaths.Distinct(StringComparer.OrdinalIgnoreCase).Count() !=
                normalizedExecutablePaths.Length ||
            target.ExpectedProcessId < 0 ||
            (target.ExpectedProcessId > 0) !=
                (target.ExpectedProcessStartedAtUtc != default) ||
            (target.ExpectedProcessId > 0 &&
             target.ExpectedProcessStartedAtUtc.Kind != DateTimeKind.Utc))
        {
            return Invalid(commandId, "The command target does not include a valid local-agent identity allowlist or exact optional PID/start pair.");
        }

        return null;
    }

    private static ViewerAgentCommandResult? ValidateHealthTarget(
        Guid commandId,
        ViewerAgentCommandExecutionContext context,
        AgentHealthSnapshot health)
    {
        var target = context.Target;
        if (health.ProcessId <= 0 ||
            health.StartedAtUtc == default ||
            health.StartedAtUtc.Kind != DateTimeKind.Utc)
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.ProcessRejected,
                ViewerAgentCommandErrorCodes.ProcessIdentityMismatch,
                "Fresh agent health did not report a valid PID and UTC process start time.",
                health: health);
        }

        if (target.ExpectedProcessId > 0 &&
            (health.ProcessId != target.ExpectedProcessId ||
             health.StartedAtUtc != target.ExpectedProcessStartedAtUtc))
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.ProcessRejected,
                ViewerAgentCommandErrorCodes.ProcessIdentityMismatch,
                "Fresh agent health does not match the exact expected PID and start time.",
                health: health);
        }

        if (!string.Equals(health.SessionId, target.SessionId, StringComparison.Ordinal))
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.SessionRejected,
                ViewerAgentCommandErrorCodes.SessionMismatch,
                "Fresh agent health does not match the exact target session.",
                health: health);
        }

        if (string.IsNullOrWhiteSpace(health.DatabasePath) ||
            !TryNormalize(health.DatabasePath, out var healthDatabase) ||
            !TryNormalize(target.DatabasePath, out var targetDatabase) ||
            !string.Equals(healthDatabase, targetDatabase, StringComparison.OrdinalIgnoreCase))
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.SessionRejected,
                ViewerAgentCommandErrorCodes.DatabaseMismatch,
                "Fresh agent health does not match the exact target evidence database.",
                health: health);
        }

        if (health.WorkspaceMode != target.WorkspaceMode)
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.SessionRejected,
                ViewerAgentCommandErrorCodes.WorkspaceModeMismatch,
                $"Agent workspace mode '{health.WorkspaceMode}' does not match target mode '{target.WorkspaceMode}'.",
                health: health);
        }

        if (health.CaptureSealed != target.IsSealed)
        {
            return ViewerAgentCommandResult.Reject(
                commandId,
                ViewerAgentCommandOutcome.SessionRejected,
                ViewerAgentCommandErrorCodes.CaptureSealingMismatch,
                "Agent capture sealing state does not match the validated target package.",
                health: health);
        }

        return null;
    }

    private static bool IsReleaseCompatible(
        ViewerAgentCommandExecutionContext context,
        AgentHealthSnapshot health) =>
        health.ReleaseProfile is { } releaseProfile &&
        releaseProfile.Match == AgentReleaseProfileMatch.Match &&
        !string.IsNullOrWhiteSpace(releaseProfile.ReleaseId) &&
        string.Equals(
            releaseProfile.ViewerReleaseId,
            context.ViewerReleaseId,
            StringComparison.Ordinal) &&
        string.Equals(
            releaseProfile.ReleaseId,
            context.ViewerReleaseId,
            StringComparison.Ordinal);

    private static bool IsReleaseProfileWellFormed(
        ViewerAgentCommandExecutionContext context,
        AgentHealthSnapshot health)
    {
        if (health.ReleaseProfile is not { } releaseProfile ||
            string.IsNullOrWhiteSpace(releaseProfile.ReleaseId) ||
            string.IsNullOrWhiteSpace(releaseProfile.ViewerReleaseId) ||
            string.IsNullOrWhiteSpace(releaseProfile.Status) ||
            releaseProfile.Match is not
                (AgentReleaseProfileMatch.Match or AgentReleaseProfileMatch.Mismatch) ||
            !string.Equals(
                releaseProfile.ViewerReleaseId,
                context.ViewerReleaseId,
                StringComparison.Ordinal))
        {
            return false;
        }

        var releaseIdsMatch = string.Equals(
            releaseProfile.ReleaseId,
            releaseProfile.ViewerReleaseId,
            StringComparison.Ordinal);
        return releaseProfile.Match == AgentReleaseProfileMatch.Match
            ? releaseIdsMatch
            : !releaseIdsMatch;
    }

    private static bool AllowsReleaseMismatchCleanup(AgentCommandKind commandKind) =>
        commandKind is AgentCommandKind.ShutdownAgent or AgentCommandKind.CancelJob;

    private static bool IsPairingFailure(string? errorCode) =>
        !string.IsNullOrWhiteSpace(errorCode) &&
        (errorCode.Contains("Pairing", StringComparison.OrdinalIgnoreCase) ||
         errorCode.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase) ||
         errorCode.Contains("Authentication", StringComparison.OrdinalIgnoreCase));

    private static bool TryNormalize(string? path, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        try
        {
            normalized = Path.GetFullPath(path);
            return Path.IsPathFullyQualified(normalized);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static ViewerAgentCommandResult Invalid(Guid commandId, string diagnostic) =>
        ViewerAgentCommandResult.Reject(
            commandId,
            ViewerAgentCommandOutcome.InvalidContext,
            ViewerAgentCommandErrorCodes.InvalidContext,
            diagnostic);

    private static ViewerAgentCommandResult RejectSuperseded(
        Guid commandId,
        AgentHealthSnapshot? health = null,
        bool commandSubmissionAttempted = false,
        string authenticatedEndpoint = "",
        long pairingGeneration = 0,
        AgentPairingStatusSnapshot? verifiedPairingStatus = null) =>
        ViewerAgentCommandResult.Reject(
            commandId,
            ViewerAgentCommandOutcome.Superseded,
            ViewerAgentCommandErrorCodes.WorkspaceSuperseded,
            "The command result belongs to a superseded capture workspace and was not applied to the current workspace.",
            health: health,
            commandSubmissionAttempted: commandSubmissionAttempted,
            authenticatedEndpoint: authenticatedEndpoint,
            pairingGeneration: pairingGeneration,
            verifiedPairingStatus: verifiedPairingStatus);

    private static ViewerAgentCommandResult RejectCommandOutcomeUnknown(
        Guid commandId,
        AgentHealthSnapshot health,
        string diagnostic,
        string authenticatedEndpoint,
        long pairingGeneration,
        AgentPairingStatusSnapshot? verifiedPairingStatus) =>
        ViewerAgentCommandResult.Reject(
            commandId,
            ViewerAgentCommandOutcome.HealthUnavailable,
            ViewerAgentCommandErrorCodes.CommandOutcomeUnknown,
            diagnostic,
            isRetryable: false,
            health: health,
            commandSubmissionAttempted: true,
            preflightVerified: true,
            authenticatedEndpoint: authenticatedEndpoint,
            pairingGeneration: pairingGeneration,
            verifiedPairingStatus: verifiedPairingStatus);

    private static ViewerAgentCommandResult RejectCanceled(
        Guid commandId,
        AgentHealthSnapshot? health = null,
        bool commandSubmissionAttempted = false,
        string authenticatedEndpoint = "",
        long pairingGeneration = 0,
        AgentPairingStatusSnapshot? verifiedPairingStatus = null) =>
        ViewerAgentCommandResult.Reject(
            commandId,
            ViewerAgentCommandOutcome.Canceled,
            ViewerAgentCommandErrorCodes.Canceled,
            "Agent command execution was canceled.",
            health: health,
            commandSubmissionAttempted: commandSubmissionAttempted,
            authenticatedEndpoint: authenticatedEndpoint,
            pairingGeneration: pairingGeneration,
            verifiedPairingStatus: verifiedPairingStatus);
}
