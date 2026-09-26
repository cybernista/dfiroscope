using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Models.Infrastructure;
using ProcInsider.Services.Features;

namespace ProcInsider.Agent;

/// <summary>
/// Final Agent-side remote-command gate. The Server decision is necessary but not
/// sufficient: this adapter rechecks the exact authenticated connection, signed grant,
/// feature policy, local target, compatibility, and capture write policy before invoking
/// the existing typed Agent command runtime.
/// </summary>
internal sealed class AgentInfrastructureCommandDispatcher
{
    private readonly IFeatureCatalog _featureCatalog;
    private readonly Func<string, Guid, bool> _isAuthenticationCurrent;
    private readonly Func<InfrastructureCommandTarget, bool> _isExactLocalTarget;
    private readonly Func<InfrastructureCommandTarget, CaptureWriteCategory, bool> _isCaptureCompatible;
    private readonly Func<AgentIpcRequest, CancellationToken, Task<AgentIpcResponse>> _execute;

    public AgentInfrastructureCommandDispatcher(
        IFeatureCatalog featureCatalog,
        Func<string, Guid, bool> isAuthenticationCurrent,
        Func<InfrastructureCommandTarget, bool> isExactLocalTarget,
        Func<InfrastructureCommandTarget, CaptureWriteCategory, bool> isCaptureCompatible,
        Func<AgentIpcRequest, CancellationToken, Task<AgentIpcResponse>> execute)
    {
        _featureCatalog = featureCatalog ?? throw new ArgumentNullException(nameof(featureCatalog));
        _isAuthenticationCurrent = isAuthenticationCurrent ??
                                   throw new ArgumentNullException(nameof(isAuthenticationCurrent));
        _isExactLocalTarget = isExactLocalTarget ?? throw new ArgumentNullException(nameof(isExactLocalTarget));
        _isCaptureCompatible = isCaptureCompatible ?? throw new ArgumentNullException(nameof(isCaptureCompatible));
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
    }

    public async Task<InfrastructureSessionCommandResultPayload> ExecuteAsync(
        AuthenticatedAgentContext authenticated,
        InfrastructureSessionBinding binding,
        InfrastructureSessionCommandRequestPayload payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticated);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(payload);
        var nowUtc = DateTime.UtcNow;
        var classification = InfrastructureCommandPolicy.Classify(payload.CommandKind);
        if (payload.Target == null || payload.AuthorizationGrant == null ||
            !InfrastructureCommandPolicy.IsValidTarget(payload.Target) ||
            string.IsNullOrWhiteSpace(payload.ViewerUserId) ||
            string.IsNullOrWhiteSpace(payload.GrantId) ||
            payload.AuthorizationRevision <= 0 ||
            !string.Equals(payload.AuthorizationGrant.GrantId, payload.GrantId, StringComparison.Ordinal) ||
            !classification.Supported || payload.Idempotency != classification.Idempotency ||
            payload.Attempt <= 0 ||
            payload.Idempotency == InfrastructureSessionIdempotency.NonIdempotent && payload.Attempt != 1 ||
            payload.Idempotency == InfrastructureSessionIdempotency.Idempotent &&
            payload.Attempt > InfrastructureCommandPolicy.MaximumIdempotentAttempts ||
            payload.DeadlineUtc.Kind != DateTimeKind.Utc || payload.DeadlineUtc <= nowUtc ||
            payload.DeadlineUtc - nowUtc > InfrastructureSessionLimits.CompiledRequestDeadline)
        {
            return Rejected(payload.RequestId, "AgentCommandEnvelopeInvalid", nowUtc);
        }

        if (!_isAuthenticationCurrent(authenticated.AgentId, authenticated.ConnectionGeneration) ||
            !BindingMatches(authenticated, binding, payload.Target))
        {
            return Rejected(payload.RequestId, "AgentAuthenticationGenerationStale", nowUtc);
        }

        JsonElement commandJson;
        try
        {
            using var document = JsonDocument.Parse(payload.CommandPayloadJson);
            commandJson = document.RootElement.Clone();
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException)
        {
            return Rejected(payload.RequestId, "AgentCommandPayloadInvalid", nowUtc);
        }

        var ipcRequest = new AgentIpcRequest
        {
            RequestId = payload.RequestId,
            ViewerReleaseId = payload.Target.ReleaseId,
            Kind = AgentIpcRequestKind.SubmitCommand,
            CommandKind = payload.CommandKind,
            Payload = commandJson
        };
        var featureDecision = AgentCommandFeaturePolicy.EvaluateRequest(_featureCatalog, ipcRequest);
        CaptureWriteCategory expectedWriteCategory;
        try
        {
            expectedWriteCategory = CaptureWritePolicy.GetCategory(payload.CommandKind);
        }
        catch (ArgumentOutOfRangeException)
        {
            return Rejected(payload.RequestId, "AgentCommandClassificationMissing", nowUtc);
        }

        var request = new AgentAuthorizationRequest
        {
            Action = AgentAuthorizationAction.ExecuteCommand,
            AgentId = payload.Target.AgentId,
            HostId = payload.Target.HostId,
            CredentialEpoch = payload.Target.CredentialEpoch,
            ConnectionGeneration = payload.Target.ConnectionGeneration,
            Scope = payload.Target.Scope with { },
            CommandKind = payload.CommandKind,
            WriteCategory = payload.WriteCategory,
            FeaturePublished = featureDecision.Allowed,
            CapabilityAvailable = authenticated.CommandCapabilities.Contains(payload.CommandKind) &&
                                  payload.WriteCategory == expectedWriteCategory,
            ExactTargetValidated = _isExactLocalTarget(payload.Target),
            CaptureCompatibilityAllowed = _isCaptureCompatible(payload.Target, expectedWriteCategory),
            ReleaseCompatible = authenticated.ReleaseMatch == AgentReleaseProfileMatch.Match
        };
        var authorization = AgentAuthorizationPolicy.Evaluate(
            authenticated,
            payload.AuthorizationGrant,
            request,
            nowUtc);
        if (!authorization.Allowed)
        {
            return Rejected(payload.RequestId, $"AgentAuthorization{authorization.Failure}", nowUtc);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return new InfrastructureSessionCommandResultPayload
            {
                RequestId = payload.RequestId,
                Outcome = InfrastructureSessionCommandOutcome.Canceled,
                ErrorCode = "AgentCommandCanceled",
                CompletedAtUtc = nowUtc
            };
        }

        try
        {
            var response = await _execute(ipcRequest, cancellationToken).ConfigureAwait(false);
            if (response == null)
            {
                return new InfrastructureSessionCommandResultPayload
                {
                    RequestId = payload.RequestId,
                    Outcome = InfrastructureSessionCommandOutcome.Failed,
                    ErrorCode = "AgentCommandExecutionFailed",
                    CompletedAtUtc = DateTime.UtcNow
                };
            }

            var jobId = response.AcceptedJobId ?? response.Job?.JobId;
            return new InfrastructureSessionCommandResultPayload
            {
                RequestId = payload.RequestId,
                Outcome = response.Success
                    ? jobId.HasValue
                        ? InfrastructureSessionCommandOutcome.Accepted
                        : InfrastructureSessionCommandOutcome.Completed
                    : InfrastructureSessionCommandOutcome.Rejected,
                JobId = jobId?.ToString("D") ?? string.Empty,
                ErrorCode = Bound(response.ErrorCode),
                CompletedAtUtc = DateTime.UtcNow
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new InfrastructureSessionCommandResultPayload
            {
                RequestId = payload.RequestId,
                Outcome = InfrastructureSessionCommandOutcome.Canceled,
                ErrorCode = "AgentCommandCanceled",
                CompletedAtUtc = DateTime.UtcNow
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or IOException)
        {
            return new InfrastructureSessionCommandResultPayload
            {
                RequestId = payload.RequestId,
                Outcome = InfrastructureSessionCommandOutcome.Failed,
                ErrorCode = "AgentCommandExecutionFailed",
                CompletedAtUtc = DateTime.UtcNow
            };
        }
    }

    private static bool BindingMatches(
        AuthenticatedAgentContext authenticated,
        InfrastructureSessionBinding binding,
        InfrastructureCommandTarget target) =>
        string.Equals(authenticated.AgentId, binding.AgentId, StringComparison.Ordinal) &&
        string.Equals(authenticated.HostId, binding.HostId, StringComparison.Ordinal) &&
        authenticated.CredentialEpoch == binding.CredentialEpoch &&
        authenticated.ConnectionGeneration == binding.ConnectionGeneration &&
        string.Equals(target.AgentId, binding.AgentId, StringComparison.Ordinal) &&
        string.Equals(target.HostId, binding.HostId, StringComparison.Ordinal) &&
        target.CredentialEpoch == binding.CredentialEpoch &&
        target.ConnectionGeneration == binding.ConnectionGeneration &&
        target.ServerSessionGeneration == binding.ServerSessionGeneration &&
        target.SessionId == binding.SessionId &&
        target.ProtocolGeneration == binding.ProtocolGeneration &&
        string.Equals(target.ReleaseId, binding.ReleaseId, StringComparison.Ordinal) &&
        Equals(authenticated.Scope, target.Scope);

    private static InfrastructureSessionCommandResultPayload Rejected(
        Guid requestId,
        string errorCode,
        DateTime completedAtUtc) =>
        new()
        {
            RequestId = requestId,
            Outcome = InfrastructureSessionCommandOutcome.Rejected,
            ErrorCode = Bound(errorCode),
            CompletedAtUtc = completedAtUtc
        };

    private static string Bound(string? value) =>
        string.IsNullOrWhiteSpace(value) ? string.Empty : value.Length <= 128 ? value : value[..128];
}
