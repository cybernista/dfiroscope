using System.Text.Json;
using System.Text;
using ProcInsider.Models.Agent;

namespace ProcInsider.Models.Infrastructure;

public enum InfrastructureCommandClass
{
    Unknown = 0,
    ConfigurationRead = 1,
    ConfigurationMutation = 2,
    CaptureLifecycle = 3,
    JobSubmission = 4,
    JobControl = 5,
    GracefulAgentShutdown = 6,
    Unsupported = 7
}

public enum InfrastructureCommandFailure
{
    None = 0,
    InvalidRequest = 1,
    ViewerAuthenticationStale = 2,
    ViewerIncompatible = 3,
    ViewerRoleDenied = 4,
    GrantNotFound = 5,
    GrantExpired = 6,
    CommandNotGranted = 7,
    CommandUnsupported = 8,
    IdempotencyMismatch = 9,
    ExactTargetRejected = 10,
    AgentSessionUnavailable = 11,
    AgentSessionStale = 12,
    FeatureUnavailable = 13,
    CapabilityUnavailable = 14,
    ReleaseIncompatible = 15,
    CaptureCompatibilityRejected = 16,
    CaptureWritePolicyRejected = 17,
    AgentAuthorizationRejected = 18,
    AuditUnavailable = 19,
    DuplicateRequest = 20,
    DispatchRejected = 21,
    TimedOut = 22,
    Canceled = 23,
    AgentRejected = 24,
    StaleResult = 25,
    TransportUnavailable = 26,
    ResponseSuperseded = 27
}

public sealed record InfrastructureCommandClassification(
    AgentCommandKind CommandKind,
    InfrastructureCommandClass CommandClass,
    InfrastructureSessionIdempotency Idempotency,
    bool Supported,
    bool AdministratorAllowed,
    bool OperatorAllowed);

public sealed record InfrastructureCommandTarget
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public long ServerSessionGeneration { get; init; }

    public Guid SessionId { get; init; }

    public AgentAuthorizationScope Scope { get; init; } = new();

    public string ReleaseId { get; init; } = string.Empty;

    public int ProtocolGeneration { get; init; }
}

public sealed record InfrastructureViewerCommandGrant
{
    public string GrantId { get; init; } = string.Empty;

    public string ViewerUserId { get; init; } = string.Empty;

    public string CaseId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public IReadOnlyList<AgentCommandKind> AllowedCommands { get; init; } =
        Array.Empty<AgentCommandKind>();

    public long AuthorizationRevision { get; init; }

    public DateTime IssuedAtUtc { get; init; }

    public DateTime ExpiresAtUtc { get; init; }
}

public sealed record InfrastructureCommandDispatchRequest
{
    public AuthenticatedInfrastructureViewerContext Viewer { get; init; } = new();

    public Guid RequestId { get; init; }

    public InfrastructureCommandTarget Target { get; init; } = new();

    public AgentCommandKind CommandKind { get; init; }

    public string CommandPayloadJson { get; init; } = string.Empty;

    public InfrastructureSessionIdempotency Idempotency { get; init; }

    public int Attempt { get; init; } = 1;

    public DateTime DeadlineUtc { get; init; }

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }
}

public sealed record InfrastructureCommandPolicyDecision
{
    public bool Allowed { get; init; }

    public InfrastructureCommandFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public InfrastructureCommandClassification? Classification { get; init; }

    public InfrastructureViewerCommandGrant? Grant { get; init; }
}

public sealed record InfrastructureCommandDispatchResult
{
    public Guid RequestId { get; init; }

    public bool Dispatched { get; init; }

    public InfrastructureSessionCommandOutcome Outcome { get; init; }

    public InfrastructureCommandFailure Failure { get; init; }

    public AgentAuthorizationFailure AgentAuthorizationFailure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string JobId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string CaseId { get; init; } = string.Empty;

    public Guid ConnectionGeneration { get; init; }

    public long ServerSessionGeneration { get; init; }

    public Guid SessionId { get; init; }

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public DateTime CompletedAtUtc { get; init; }
}

/// <summary>
/// Pure, dependency-light Viewer command policy. It classifies every current command,
/// intersects role and exact grants, and validates one fresh exact request. Server and
/// Agent owners still apply their independent publication, capability, target,
/// compatibility, write-policy, session, and audit gates.
/// </summary>
public static class InfrastructureCommandPolicy
{
    public const int MaximumCommandPayloadBytes = 256 * 1024;
    public const int MaximumGrantsPerRequest = 256;
    public const int MaximumIdempotentAttempts = 3;

    private static readonly IReadOnlyDictionary<AgentCommandKind, InfrastructureCommandClassification>
        Classifications = BuildClassifications();

    public static IReadOnlyList<AgentCommandKind> ClassifiedCommandKinds { get; } =
        Array.AsReadOnly(Classifications.Keys.OrderBy(kind => (int)kind).ToArray());

    public static InfrastructureCommandClassification Classify(AgentCommandKind commandKind) =>
        Classifications.TryGetValue(commandKind, out var classification)
            ? classification
            : new InfrastructureCommandClassification(
                commandKind,
                InfrastructureCommandClass.Unsupported,
                InfrastructureSessionIdempotency.Unknown,
                false,
                false,
                false);

    public static InfrastructureCommandPolicyDecision Evaluate(
        InfrastructureCommandDispatchRequest request,
        IReadOnlyList<InfrastructureViewerCommandGrant> grants,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(grants);
        var classification = Classify(request.CommandKind);
        if (!IsValidRequest(request, nowUtc))
        {
            return Deny(InfrastructureCommandFailure.InvalidRequest, "InfrastructureCommandRequestInvalid",
                "The bounded Infrastructure command request is malformed.", classification);
        }

        if (!classification.Supported)
        {
            return Deny(InfrastructureCommandFailure.CommandUnsupported, "InfrastructureCommandUnsupported",
                "The command is not eligible for remote Infrastructure routing.", classification);
        }

        if (request.Viewer.FreshUntilUtc < nowUtc || request.Viewer.AuthenticatedAtUtc > nowUtc)
        {
            return Deny(InfrastructureCommandFailure.ViewerAuthenticationStale,
                "ViewerAuthenticationGenerationStale",
                "The Viewer authentication generation is no longer fresh.", classification);
        }

        if (!string.Equals(request.Viewer.ReleaseId, request.Target.ReleaseId, StringComparison.Ordinal) ||
            request.Viewer.ProtocolGeneration != request.Target.ProtocolGeneration)
        {
            return Deny(InfrastructureCommandFailure.ViewerIncompatible, "ViewerCommandProfileMismatch",
                "The Viewer does not match the exact Agent release and protocol target.", classification);
        }

        var roleAllowed = request.Viewer.Role switch
        {
            InfrastructureViewerRole.Administrator => classification.AdministratorAllowed,
            InfrastructureViewerRole.Operator => classification.OperatorAllowed,
            _ => false
        };
        if (!roleAllowed)
        {
            return Deny(InfrastructureCommandFailure.ViewerRoleDenied, "ViewerRoleCommandDenied",
                "The Viewer role cannot issue this command class.", classification);
        }

        if (request.Idempotency != classification.Idempotency ||
            request.Idempotency == InfrastructureSessionIdempotency.NonIdempotent && request.Attempt != 1 ||
            request.Idempotency == InfrastructureSessionIdempotency.Idempotent &&
            request.Attempt > MaximumIdempotentAttempts)
        {
            return Deny(InfrastructureCommandFailure.IdempotencyMismatch, "CommandIdempotencyMismatch",
                "The declared attempt/idempotency does not match the exhaustive command classification.",
                classification);
        }

        if (grants.Count > MaximumGrantsPerRequest || grants.Any(grant => !IsValidGrant(grant)) ||
            grants.Select(grant => grant.GrantId).Distinct(StringComparer.Ordinal).Count() != grants.Count)
        {
            return Deny(InfrastructureCommandFailure.InvalidRequest, "ViewerCommandGrantSetInvalid",
                "The Viewer command-grant set is malformed or exceeds its bound.", classification);
        }

        var exact = grants.Where(grant =>
                string.Equals(grant.ViewerUserId, request.Viewer.ViewerUserId, StringComparison.Ordinal) &&
                string.Equals(grant.CaseId, request.Target.Scope.CaseId, StringComparison.Ordinal) &&
                string.Equals(grant.AgentId, request.Target.AgentId, StringComparison.Ordinal) &&
                string.Equals(grant.HostId, request.Target.HostId, StringComparison.Ordinal))
            .OrderByDescending(grant => grant.AuthorizationRevision)
            .ToArray();
        if (exact.Length == 0)
        {
            return Deny(InfrastructureCommandFailure.GrantNotFound, "ExactViewerCommandGrantMissing",
                "No exact case/Agent/Host command grant was found.", classification);
        }

        var current = exact[0];
        if (exact.Count(grant => grant.AuthorizationRevision == current.AuthorizationRevision) != 1)
        {
            return Deny(InfrastructureCommandFailure.InvalidRequest, "ViewerCommandGrantRevisionAmbiguous",
                "The highest exact Viewer command-grant revision is ambiguous.", classification);
        }

        if (current.IssuedAtUtc > nowUtc || current.ExpiresAtUtc < nowUtc)
        {
            return Deny(InfrastructureCommandFailure.GrantExpired, "ViewerCommandGrantExpired",
                "The exact Viewer command grant is outside its validity window.", classification);
        }

        if (!current.AllowedCommands.Contains(request.CommandKind))
        {
            return Deny(InfrastructureCommandFailure.CommandNotGranted, "ExactCommandNotGranted",
                "The exact command is absent from the current Viewer grant.", classification, current);
        }

        return new InfrastructureCommandPolicyDecision
        {
            Allowed = true,
            Message = "The fresh Viewer role and exact grant permit Server-side command authorization.",
            Classification = classification,
            Grant = current with { }
        };
    }

    public static bool IsValidTarget(InfrastructureCommandTarget? target) =>
        target != null &&
        !string.IsNullOrWhiteSpace(target.AgentId) && target.AgentId.Length <= 512 &&
        !string.IsNullOrWhiteSpace(target.HostId) && target.HostId.Length <= 512 &&
        target.CredentialEpoch > 0 && target.ConnectionGeneration != Guid.Empty &&
        target.ServerSessionGeneration > 0 && target.SessionId != Guid.Empty &&
        AgentAuthenticationPolicy.IsValidScope(target.Scope) &&
        !string.IsNullOrWhiteSpace(target.Scope.CaseId) &&
        !string.IsNullOrWhiteSpace(target.Scope.CaptureId) &&
        !string.IsNullOrWhiteSpace(target.Scope.SessionId) &&
        !string.IsNullOrWhiteSpace(target.Scope.DatabaseIdentity) &&
        !string.IsNullOrWhiteSpace(target.ReleaseId) && target.ReleaseId.Length <= 512 &&
        target.ProtocolGeneration > 0;

    private static bool IsValidRequest(InfrastructureCommandDispatchRequest request, DateTime nowUtc)
    {
        if (nowUtc.Kind != DateTimeKind.Utc || request.RequestId == Guid.Empty ||
            !IsValidViewer(request.Viewer) || !IsValidTarget(request.Target) ||
            request.CommandKind == AgentCommandKind.Unknown || !Enum.IsDefined(request.CommandKind) ||
            string.IsNullOrWhiteSpace(request.CommandPayloadJson) ||
            request.CommandPayloadJson.Length > MaximumCommandPayloadBytes ||
            Encoding.UTF8.GetByteCount(request.CommandPayloadJson) > MaximumCommandPayloadBytes ||
            request.Idempotency == InfrastructureSessionIdempotency.Unknown ||
            !Enum.IsDefined(request.Idempotency) || request.Attempt <= 0 ||
            request.DeadlineUtc.Kind != DateTimeKind.Utc || request.DeadlineUtc <= nowUtc ||
            request.DeadlineUtc - nowUtc > InfrastructureSessionLimits.CompiledRequestDeadline ||
            request.WorkspaceGeneration <= 0 || request.RequestGeneration <= 0)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(request.CommandPayloadJson);
            return document.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsValidViewer(AuthenticatedInfrastructureViewerContext? viewer) =>
        viewer != null &&
        !string.IsNullOrWhiteSpace(viewer.ViewerUserId) && viewer.ViewerUserId.Length <= 512 &&
        Enum.IsDefined(viewer.Role) && viewer.Role != InfrastructureViewerRole.Unknown &&
        viewer.CredentialEpoch > 0 && viewer.ConnectionGeneration != Guid.Empty &&
        viewer.ProtocolGeneration > 0 &&
        !string.IsNullOrWhiteSpace(viewer.ReleaseId) && viewer.ReleaseId.Length <= 512 &&
        viewer.AuthenticatedAtUtc.Kind == DateTimeKind.Utc && viewer.FreshUntilUtc.Kind == DateTimeKind.Utc &&
        viewer.FreshUntilUtc >= viewer.AuthenticatedAtUtc;

    private static bool IsValidGrant(InfrastructureViewerCommandGrant? grant) =>
        grant != null &&
        !string.IsNullOrWhiteSpace(grant.GrantId) && grant.GrantId.Length <= 512 &&
        !string.IsNullOrWhiteSpace(grant.ViewerUserId) && grant.ViewerUserId.Length <= 512 &&
        !string.IsNullOrWhiteSpace(grant.CaseId) && grant.CaseId.Length <= 512 &&
        !string.IsNullOrWhiteSpace(grant.AgentId) && grant.AgentId.Length <= 512 &&
        !string.IsNullOrWhiteSpace(grant.HostId) && grant.HostId.Length <= 512 &&
        grant.AuthorizationRevision > 0 &&
        grant.IssuedAtUtc.Kind == DateTimeKind.Utc && grant.ExpiresAtUtc.Kind == DateTimeKind.Utc &&
        grant.ExpiresAtUtc >= grant.IssuedAtUtc &&
        grant.AllowedCommands is { Count: <= 256 } &&
        grant.AllowedCommands.All(kind => kind != AgentCommandKind.Unknown && Enum.IsDefined(kind)) &&
        grant.AllowedCommands.Distinct().Count() == grant.AllowedCommands.Count;

    private static InfrastructureCommandPolicyDecision Deny(
        InfrastructureCommandFailure failure,
        string errorCode,
        string message,
        InfrastructureCommandClassification? classification = null,
        InfrastructureViewerCommandGrant? grant = null) =>
        new()
        {
            Failure = failure,
            ErrorCode = errorCode,
            Message = message,
            Classification = classification,
            Grant = grant
        };

    private static IReadOnlyDictionary<AgentCommandKind, InfrastructureCommandClassification>
        BuildClassifications()
    {
        var values = new Dictionary<AgentCommandKind, InfrastructureCommandClassification>();
        Add(AgentCommandKind.StartLiveCapture, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.StopLiveCapture, InfrastructureCommandClass.CaptureLifecycle);
        AddUnsupported(AgentCommandKind.QueueBackfill);
        AddUnsupported(AgentCommandKind.QueueImport);
        Add(AgentCommandKind.QueueEnrichment, InfrastructureCommandClass.JobSubmission);
        Add(AgentCommandKind.CancelJob, InfrastructureCommandClass.JobControl);
        Add(AgentCommandKind.PauseJob, InfrastructureCommandClass.JobControl);
        Add(AgentCommandKind.ResumeJob, InfrastructureCommandClass.JobControl);
        Add(AgentCommandKind.QueueProcessDump, InfrastructureCommandClass.JobSubmission);
        Add(AgentCommandKind.StartNetworkCapture, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.StopNetworkCapture, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.QueueZeekAnalysis, InfrastructureCommandClass.JobSubmission);
        Add(AgentCommandKind.QueueArtifactImport, InfrastructureCommandClass.JobSubmission);
        Add(AgentCommandKind.ShutdownAgent, InfrastructureCommandClass.GracefulAgentShutdown, false);
        Add(AgentCommandKind.QueueMemoryImageImport, InfrastructureCommandClass.JobSubmission);
        Add(AgentCommandKind.QueueVolatilityAnalysis, InfrastructureCommandClass.JobSubmission);
        Add(AgentCommandKind.GetHostMonitoringConfiguration, InfrastructureCommandClass.ConfigurationRead,
            false, InfrastructureSessionIdempotency.Idempotent);
        Add(AgentCommandKind.SaveHostMonitoringConfiguration, InfrastructureCommandClass.ConfigurationMutation, false);
        Add(AgentCommandKind.CheckHostMonitoringConfiguration, InfrastructureCommandClass.ConfigurationRead,
            false, InfrastructureSessionIdempotency.Idempotent);
        Add(AgentCommandKind.DeployHostMonitoringConfiguration, InfrastructureCommandClass.ConfigurationMutation, false);
        Add(AgentCommandKind.ReverseHostMonitoringDeployment, InfrastructureCommandClass.ConfigurationMutation, false);
        Add(AgentCommandKind.GetCaptureConfiguration, InfrastructureCommandClass.ConfigurationRead,
            false, InfrastructureSessionIdempotency.Idempotent);
        Add(AgentCommandKind.SaveCaptureConfiguration, InfrastructureCommandClass.ConfigurationMutation, false);
        Add(AgentCommandKind.CheckCaptureConfiguration, InfrastructureCommandClass.ConfigurationRead,
            false, InfrastructureSessionIdempotency.Idempotent);
        Add(AgentCommandKind.StartConfiguredCapture, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.StopConfiguredCapture, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.StartProcessMonitorCapture, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.StopProcessMonitorCapture, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.QueueProcessMonitorImport, InfrastructureCommandClass.JobSubmission);
        Add(AgentCommandKind.QueueSqliteBenchmark, InfrastructureCommandClass.JobSubmission);
        Add(AgentCommandKind.StopEtwCapture, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.StopLiveCaptureSource, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.StartLiveCaptureSource, InfrastructureCommandClass.CaptureLifecycle);
        Add(AgentCommandKind.QueueMemoryAcquisition, InfrastructureCommandClass.JobSubmission);

        var expected = Enum.GetValues<AgentCommandKind>().Where(kind => kind != AgentCommandKind.Unknown).ToArray();
        if (expected.Except(values.Keys).Any() || values.Keys.Except(expected).Any())
        {
            throw new InvalidOperationException(
                "Every AgentCommandKind must be explicitly classified for Infrastructure routing.");
        }

        return values;

        void Add(
            AgentCommandKind kind,
            InfrastructureCommandClass commandClass,
            bool operatorAllowed = true,
            InfrastructureSessionIdempotency idempotency = InfrastructureSessionIdempotency.NonIdempotent) =>
            values.Add(kind, new InfrastructureCommandClassification(
                kind, commandClass, idempotency, true, true, operatorAllowed));

        void AddUnsupported(AgentCommandKind kind) =>
            values.Add(kind, new InfrastructureCommandClassification(
                kind,
                InfrastructureCommandClass.Unsupported,
                InfrastructureSessionIdempotency.NonIdempotent,
                false,
                false,
                false));
    }
}
