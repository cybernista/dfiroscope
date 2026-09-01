using System;
using System.Collections.Generic;
using System.Linq;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Transport that established an authenticated agent identity. The transport proves
/// identity only; command, health, and evidence authorization remain separate.
/// </summary>
public enum AgentAuthenticationKind
{
    Unknown = 0,
    LocalInteractiveNamedPipe = 1,
    EnrolledWindowsService = 2
}

/// <summary>Enrollment state used by a future service-to-case-server adapter.</summary>
public enum AgentEnrollmentState
{
    Unknown = 0,
    NotApplicableLocal = 1,
    Active = 2,
    Suspended = 3,
    Expired = 4,
    Revoked = 5,
    Compromised = 6
}

/// <summary>Eligibility of the credential epoch used for authentication.</summary>
public enum AgentCredentialStatus
{
    Unknown = 0,
    Active = 1,
    Rotated = 2,
    Expired = 3,
    Revoked = 4,
    Compromised = 5
}

/// <summary>Eligibility of one live authenticated connection generation.</summary>
public enum AgentConnectionStatus
{
    Unknown = 0,
    Current = 1,
    Stale = 2,
    Replayed = 3,
    Duplicate = 4,
    Closed = 5
}

public enum AgentAuthenticationFailure
{
    None = 0,
    InvalidContext = 1,
    UnknownAuthenticationKind = 2,
    EnrollmentNotActive = 3,
    CredentialUnknown = 4,
    CredentialRotated = 5,
    CredentialExpired = 6,
    CredentialRevoked = 7,
    CredentialCompromised = 8,
    CredentialProofInvalid = 9,
    ConnectionUnknown = 10,
    ConnectionStale = 11,
    ConnectionReplayed = 12,
    DuplicateConnection = 13,
    ConnectionClosed = 14,
    HostBindingMismatch = 15,
    ProtocolIncompatible = 16,
    AuthenticationExpired = 17
}

/// <summary>Separate authorization surfaces that consume an authenticated identity.</summary>
public enum AgentAuthorizationAction
{
    Unknown = 0,
    DiscloseHealth = 1,
    ExecuteCommand = 2,
    SubmitEvidence = 3
}

public enum AgentAuthorizationFailure
{
    None = 0,
    InvalidContext = 1,
    InvalidGrant = 2,
    InvalidRequest = 3,
    AuthenticationStale = 4,
    GrantExpired = 5,
    AgentMismatch = 6,
    HostMismatch = 7,
    CredentialEpochMismatch = 8,
    ConnectionGenerationMismatch = 9,
    WrongCase = 10,
    WrongCapture = 11,
    WrongSession = 12,
    WrongDatabase = 13,
    WorkspaceMismatch = 14,
    SealingMismatch = 15,
    HealthDisclosureNotGranted = 16,
    CommandExecutionNotGranted = 17,
    CommandNotGranted = 18,
    CommandCapabilityMissing = 19,
    FeatureNotPublished = 20,
    CapabilityUnavailable = 21,
    ExactTargetNotValidated = 22,
    CaptureCompatibilityRejected = 23,
    CaptureWritePolicyRejected = 24,
    EvidenceSubmissionNotGranted = 25,
    EvidenceWriterNotAuthoritative = 26,
    EvidenceWriterConflict = 27,
    UnsupportedAction = 28,
    ReleaseIncompatible = 29
}

/// <summary>
/// Exact case/capture assignment carried independently from transport identity.
/// CaseId and CaptureId may be empty only when that scope does not yet exist, as in
/// today's local single-session topology; empty values are still compared exactly.
/// </summary>
public sealed record AgentAuthorizationScope
{
    public string CaseId { get; init; } = string.Empty;

    public string CaptureId { get; init; } = string.Empty;

    public string SessionId { get; init; } = string.Empty;

    public string DatabaseIdentity { get; init; } = string.Empty;

    public CaptureWorkspaceMode WorkspaceMode { get; init; }

    public bool CaptureSealed { get; init; }
}

/// <summary>
/// Transport-neutral result of successful agent authentication. CredentialEpoch
/// changes on credential rotation/revocation; ConnectionGeneration changes on every
/// new live authentication window so stale health, grants, and results cannot be reused.
/// </summary>
public sealed record AuthenticatedAgentContext
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public AgentAuthenticationKind AuthenticationKind { get; init; }

    public AgentEnrollmentState EnrollmentState { get; init; }

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public int ProtocolContractVersion { get; init; }

    public string ReleaseId { get; init; } = string.Empty;

    public AgentReleaseProfileMatch ReleaseMatch { get; init; }

    public DateTime AuthenticatedAtUtc { get; init; }

    public DateTime FreshUntilUtc { get; init; }

    public IReadOnlyList<AgentCommandKind> CommandCapabilities { get; init; } =
        Array.Empty<AgentCommandKind>();

    public AgentAuthorizationScope Scope { get; init; } = new();

    /// <summary>
    /// True only for the agent identity that owns authoritative live-evidence writes.
    /// A viewer or case projection must never set this to gain writer authority.
    /// </summary>
    public bool IsAuthoritativeEvidenceWriter { get; init; }
}

/// <summary>
/// Transport-specific authentication evidence normalized before any authorization
/// grant is considered. A future service adapter must populate this only after mutual
/// authentication and enrollment/host binding; the local adapter uses the existing
/// DPAPI/HMAC, pipe, release, target, and exact process checks.
/// </summary>
public sealed record AgentAuthenticationCandidate
{
    public AuthenticatedAgentContext Context { get; init; } = new();

    public AgentCredentialStatus CredentialStatus { get; init; }

    public AgentConnectionStatus ConnectionStatus { get; init; }

    public bool CredentialProofVerified { get; init; }

    public bool HostBindingVerified { get; init; }

    public bool ProtocolCompatible { get; init; }
}

public sealed record AgentAuthenticationDecision
{
    public bool Allowed { get; init; }

    public AgentAuthenticationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public AuthenticatedAgentContext? Context { get; init; }
}

/// <summary>Pure fail-closed validation shared by local and future transport adapters.</summary>
public static class AgentAuthenticationPolicy
{
    public static AgentAuthenticationDecision Evaluate(
        AgentAuthenticationCandidate candidate,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        var context = candidate.Context;
        if (!IsValidContext(context) || nowUtc.Kind != DateTimeKind.Utc)
        {
            return Deny(AgentAuthenticationFailure.InvalidContext,
                "The authenticated-agent context is incomplete or malformed.");
        }

        if (context.AuthenticationKind == AgentAuthenticationKind.Unknown)
        {
            return Deny(AgentAuthenticationFailure.UnknownAuthenticationKind,
                "The authentication transport kind is unknown.");
        }

        if ((context.AuthenticationKind == AgentAuthenticationKind.LocalInteractiveNamedPipe &&
             context.EnrollmentState != AgentEnrollmentState.NotApplicableLocal) ||
            (context.AuthenticationKind == AgentAuthenticationKind.EnrolledWindowsService &&
             context.EnrollmentState != AgentEnrollmentState.Active))
        {
            return Deny(AgentAuthenticationFailure.EnrollmentNotActive,
                "The agent enrollment state is not eligible for this authentication kind.");
        }

        var credentialFailure = candidate.CredentialStatus switch
        {
            AgentCredentialStatus.Active => AgentAuthenticationFailure.None,
            AgentCredentialStatus.Rotated => AgentAuthenticationFailure.CredentialRotated,
            AgentCredentialStatus.Expired => AgentAuthenticationFailure.CredentialExpired,
            AgentCredentialStatus.Revoked => AgentAuthenticationFailure.CredentialRevoked,
            AgentCredentialStatus.Compromised => AgentAuthenticationFailure.CredentialCompromised,
            _ => AgentAuthenticationFailure.CredentialUnknown
        };
        if (credentialFailure != AgentAuthenticationFailure.None)
        {
            return Deny(credentialFailure,
                "The credential epoch is not currently eligible.");
        }

        if (!candidate.CredentialProofVerified)
        {
            return Deny(AgentAuthenticationFailure.CredentialProofInvalid,
                "Fresh credential proof was not verified.");
        }

        var connectionFailure = candidate.ConnectionStatus switch
        {
            AgentConnectionStatus.Current => AgentAuthenticationFailure.None,
            AgentConnectionStatus.Stale => AgentAuthenticationFailure.ConnectionStale,
            AgentConnectionStatus.Replayed => AgentAuthenticationFailure.ConnectionReplayed,
            AgentConnectionStatus.Duplicate => AgentAuthenticationFailure.DuplicateConnection,
            AgentConnectionStatus.Closed => AgentAuthenticationFailure.ConnectionClosed,
            _ => AgentAuthenticationFailure.ConnectionUnknown
        };
        if (connectionFailure != AgentAuthenticationFailure.None)
        {
            return Deny(connectionFailure,
                "The connection generation is not currently eligible.");
        }

        if (!candidate.HostBindingVerified)
        {
            return Deny(AgentAuthenticationFailure.HostBindingMismatch,
                "The credential was not bound to the expected host identity.");
        }

        if (!candidate.ProtocolCompatible)
        {
            return Deny(AgentAuthenticationFailure.ProtocolIncompatible,
                "The authenticated endpoint is not protocol/release compatible.");
        }

        if (nowUtc < context.AuthenticatedAtUtc || nowUtc > context.FreshUntilUtc)
        {
            return Deny(AgentAuthenticationFailure.AuthenticationExpired,
                "The authenticated connection generation is outside its freshness window.");
        }

        return new AgentAuthenticationDecision
        {
            Allowed = true,
            Failure = AgentAuthenticationFailure.None,
            Diagnostic = "The agent identity and current connection generation authenticated successfully.",
            Context = Copy(context)
        };
    }

    public static bool IsValidContext(AuthenticatedAgentContext? context)
    {
        if (context == null ||
            context.SchemaVersion != AuthenticatedAgentContext.CurrentSchemaVersion ||
            !IsValidIdentity(context.AgentId) ||
            !IsValidIdentity(context.HostId) ||
            !Enum.IsDefined(context.AuthenticationKind) ||
            !Enum.IsDefined(context.EnrollmentState) ||
            context.CredentialEpoch <= 0 ||
            context.ConnectionGeneration == Guid.Empty ||
            context.ProtocolContractVersion <= 0 ||
            !IsValidIdentity(context.ReleaseId) ||
            context.ReleaseMatch is not
                (AgentReleaseProfileMatch.Match or AgentReleaseProfileMatch.Mismatch) ||
            context.AuthenticatedAtUtc.Kind != DateTimeKind.Utc ||
            context.FreshUntilUtc.Kind != DateTimeKind.Utc ||
            context.FreshUntilUtc < context.AuthenticatedAtUtc ||
            !IsValidScope(context.Scope))
        {
            return false;
        }

        var capabilities = context.CommandCapabilities;
        return capabilities != null &&
               capabilities.Count <= 256 &&
               capabilities.All(kind => Enum.IsDefined(kind) && kind != AgentCommandKind.Unknown) &&
               capabilities.Distinct().Count() == capabilities.Count;
    }

    internal static bool IsValidScope(AgentAuthorizationScope? scope) =>
        scope != null &&
        IsValidOptionalIdentity(scope.CaseId) &&
        IsValidOptionalIdentity(scope.CaptureId) &&
        IsValidIdentity(scope.SessionId) &&
        IsValidIdentity(scope.DatabaseIdentity, 4096) &&
        scope.WorkspaceMode is CaptureWorkspaceMode.LiveCapture or CaptureWorkspaceMode.ArchivedCapture &&
        scope.CaptureSealed == (scope.WorkspaceMode == CaptureWorkspaceMode.ArchivedCapture);

    internal static AuthenticatedAgentContext Copy(AuthenticatedAgentContext context) =>
        context with
        {
            CommandCapabilities = Array.AsReadOnly(context.CommandCapabilities.ToArray()),
            Scope = context.Scope with { }
        };

    internal static bool IsValidIdentity(string? value, int maximumLength = 512) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static bool IsValidOptionalIdentity(string? value, int maximumLength = 512) =>
        value != null && value.Length <= maximumLength;

    private static AgentAuthenticationDecision Deny(
        AgentAuthenticationFailure failure,
        string diagnostic) =>
        new()
        {
            Failure = failure,
            Diagnostic = diagnostic
        };
}

/// <summary>
/// Server/local policy grant. It is bound to one credential epoch, one connection
/// generation, and one exact scope; possession of a credential does not create it.
/// </summary>
public sealed record AgentAuthorizationGrant
{
    public string GrantId { get; init; } = string.Empty;

    public string Role { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public AgentAuthorizationScope Scope { get; init; } = new();

    public DateTime IssuedAtUtc { get; init; }

    public DateTime ExpiresAtUtc { get; init; }

    public bool AllowHealthDisclosure { get; init; }

    public bool AllowCommandExecution { get; init; }

    public bool AllowEvidenceSubmission { get; init; }

    public IReadOnlyList<AgentCommandKind> AllowedCommands { get; init; } =
        Array.Empty<AgentCommandKind>();
}

/// <summary>
/// One exact requested action plus the independent publication, capability,
/// compatibility, target, and single-writer gates evaluated by their owners.
/// </summary>
public sealed record AgentAuthorizationRequest
{
    public AgentAuthorizationAction Action { get; init; }

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public AgentAuthorizationScope Scope { get; init; } = new();

    public AgentCommandKind CommandKind { get; init; }

    public CaptureWriteCategory WriteCategory { get; init; }

    public bool FeaturePublished { get; init; }

    public bool CapabilityAvailable { get; init; }

    public bool ExactTargetValidated { get; init; }

    public bool CaptureCompatibilityAllowed { get; init; }

    public bool ReleaseCompatible { get; init; }

    public bool ExistingAuthoritativeEvidenceWriter { get; init; }
}

public sealed record AgentAuthorizationDecision
{
    public bool Allowed { get; init; }

    public AgentAuthorizationAction Action { get; init; }

    public AgentAuthorizationFailure Failure { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public AuthenticatedAgentContext? AuthenticatedAgent { get; init; }

    public string GrantId { get; init; } = string.Empty;
}

/// <summary>
/// Pure authorization policy. Authentication, health disclosure, command
/// eligibility, and evidence routing remain separately typed decisions.
/// </summary>
public static class AgentAuthorizationPolicy
{
    public static AgentAuthorizationDecision Evaluate(
        AuthenticatedAgentContext context,
        AgentAuthorizationGrant grant,
        AgentAuthorizationRequest request,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(request);

        if (!AgentAuthenticationPolicy.IsValidContext(context) || nowUtc.Kind != DateTimeKind.Utc)
        {
            return Deny(request.Action, AgentAuthorizationFailure.InvalidContext,
                "The authenticated-agent context is invalid.");
        }

        if (!IsValidGrant(grant))
        {
            return Deny(request.Action, AgentAuthorizationFailure.InvalidGrant,
                "The authorization grant is incomplete or malformed.");
        }

        if (!IsValidRequest(request))
        {
            return Deny(request.Action, AgentAuthorizationFailure.InvalidRequest,
                "The authorization request is incomplete or malformed.");
        }

        if (nowUtc < context.AuthenticatedAtUtc || nowUtc > context.FreshUntilUtc)
        {
            return Deny(request.Action, AgentAuthorizationFailure.AuthenticationStale,
                "The authenticated connection generation is stale.");
        }

        if (nowUtc < grant.IssuedAtUtc || nowUtc > grant.ExpiresAtUtc)
        {
            return Deny(request.Action, AgentAuthorizationFailure.GrantExpired,
                "The authorization grant is outside its validity window.");
        }

        var bindingFailure = ValidateBinding(context, grant, request);
        if (bindingFailure != AgentAuthorizationFailure.None)
        {
            return Deny(request.Action, bindingFailure,
                "The authorization grant or request does not match the exact authenticated identity and scope.");
        }

        return request.Action switch
        {
            AgentAuthorizationAction.DiscloseHealth => EvaluateHealth(context, grant, request),

            AgentAuthorizationAction.ExecuteCommand => EvaluateCommand(context, grant, request),

            AgentAuthorizationAction.SubmitEvidence => EvaluateEvidence(context, grant, request),

            _ => Deny(request.Action, AgentAuthorizationFailure.UnsupportedAction,
                "The authorization action is unknown or unsupported.")
        };
    }

    private static AgentAuthorizationDecision EvaluateHealth(
        AuthenticatedAgentContext context,
        AgentAuthorizationGrant grant,
        AgentAuthorizationRequest request)
    {
        if (!grant.AllowHealthDisclosure)
        {
            return Deny(request.Action, AgentAuthorizationFailure.HealthDisclosureNotGranted,
                "The policy grant does not allow health disclosure.");
        }

        var availabilityFailure = EvaluatePublishedAvailability(request);
        return availabilityFailure ?? Allow(context, grant, request.Action,
            "Fresh authenticated identity and policy grant allow bounded health disclosure.");
    }

    private static AgentAuthorizationDecision EvaluateCommand(
        AuthenticatedAgentContext context,
        AgentAuthorizationGrant grant,
        AgentAuthorizationRequest request)
    {
        if (!grant.AllowCommandExecution)
        {
            return Deny(request.Action, AgentAuthorizationFailure.CommandExecutionNotGranted,
                "The policy grant does not allow command execution.");
        }

        if (!grant.AllowedCommands.Contains(request.CommandKind))
        {
            return Deny(request.Action, AgentAuthorizationFailure.CommandNotGranted,
                "The exact command is not present in the policy grant.");
        }

        if (!context.CommandCapabilities.Contains(request.CommandKind))
        {
            return Deny(request.Action, AgentAuthorizationFailure.CommandCapabilityMissing,
                "The authenticated agent did not advertise the exact command capability.");
        }

        if (!request.FeaturePublished)
        {
            return Deny(request.Action, AgentAuthorizationFailure.FeatureNotPublished,
                "The command's feature is not published.");
        }

        if (!request.CapabilityAvailable)
        {
            return Deny(request.Action, AgentAuthorizationFailure.CapabilityUnavailable,
                "The command capability is not operationally available.");
        }

        if (!request.ReleaseCompatible)
        {
            return Deny(request.Action, AgentAuthorizationFailure.ReleaseIncompatible,
                "The release policy does not allow this exact command.");
        }

        if (!request.ExactTargetValidated)
        {
            return Deny(request.Action, AgentAuthorizationFailure.ExactTargetNotValidated,
                "The exact command target was not validated.");
        }

        if (!request.CaptureCompatibilityAllowed)
        {
            return Deny(request.Action, AgentAuthorizationFailure.CaptureCompatibilityRejected,
                "Capture compatibility does not allow the requested command.");
        }

        if (!CaptureWritePolicy.IsAllowed(request.Scope.WorkspaceMode, request.WriteCategory))
        {
            return Deny(request.Action, AgentAuthorizationFailure.CaptureWritePolicyRejected,
                "Capture write policy rejects the command for the exact workspace.");
        }

        return Allow(context, grant, request.Action,
            "Fresh authentication and the exact command grant, capability, target, compatibility, and write policy allow execution.");
    }

    private static AgentAuthorizationDecision EvaluateEvidence(
        AuthenticatedAgentContext context,
        AgentAuthorizationGrant grant,
        AgentAuthorizationRequest request)
    {
        if (!grant.AllowEvidenceSubmission)
        {
            return Deny(request.Action, AgentAuthorizationFailure.EvidenceSubmissionNotGranted,
                "The policy grant does not allow evidence submission.");
        }

        var availabilityFailure = EvaluatePublishedAvailability(request);
        if (availabilityFailure != null)
        {
            return availabilityFailure;
        }

        if (!context.IsAuthoritativeEvidenceWriter)
        {
            return Deny(request.Action, AgentAuthorizationFailure.EvidenceWriterNotAuthoritative,
                "The authenticated identity is not the authoritative evidence writer.");
        }

        if (request.ExistingAuthoritativeEvidenceWriter)
        {
            return Deny(request.Action, AgentAuthorizationFailure.EvidenceWriterConflict,
                "Another authoritative evidence writer already owns the exact route.");
        }

        if (!request.ExactTargetValidated)
        {
            return Deny(request.Action, AgentAuthorizationFailure.ExactTargetNotValidated,
                "The exact evidence route was not validated.");
        }

        if (!request.CaptureCompatibilityAllowed)
        {
            return Deny(request.Action, AgentAuthorizationFailure.CaptureCompatibilityRejected,
                "Capture compatibility does not allow evidence submission.");
        }

        if (request.WriteCategory is not
                (CaptureWriteCategory.PrimaryAcquisition or CaptureWriteCategory.PrimaryImport) ||
            !CaptureWritePolicy.IsAllowed(request.Scope.WorkspaceMode, request.WriteCategory))
        {
            return Deny(request.Action, AgentAuthorizationFailure.CaptureWritePolicyRejected,
                "Evidence submission is not permitted for the exact workspace and write category.");
        }

        return Allow(context, grant, request.Action,
            "Fresh authentication and the exact evidence grant, route, compatibility, and single-writer policy allow submission.");
    }

    private static AgentAuthorizationDecision? EvaluatePublishedAvailability(
        AgentAuthorizationRequest request)
    {
        if (!request.FeaturePublished)
        {
            return Deny(request.Action, AgentAuthorizationFailure.FeatureNotPublished,
                "The requested surface is not published.");
        }

        if (!request.CapabilityAvailable)
        {
            return Deny(request.Action, AgentAuthorizationFailure.CapabilityUnavailable,
                "The requested surface is not operationally available.");
        }

        if (!request.ReleaseCompatible)
        {
            return Deny(request.Action, AgentAuthorizationFailure.ReleaseIncompatible,
                "The release policy does not allow the requested surface.");
        }

        return null;
    }

    private static AgentAuthorizationFailure ValidateBinding(
        AuthenticatedAgentContext context,
        AgentAuthorizationGrant grant,
        AgentAuthorizationRequest request)
    {
        if (!string.Equals(context.AgentId, grant.AgentId, StringComparison.Ordinal) ||
            !string.Equals(context.AgentId, request.AgentId, StringComparison.Ordinal))
        {
            return AgentAuthorizationFailure.AgentMismatch;
        }

        if (!string.Equals(context.HostId, grant.HostId, StringComparison.Ordinal) ||
            !string.Equals(context.HostId, request.HostId, StringComparison.Ordinal))
        {
            return AgentAuthorizationFailure.HostMismatch;
        }

        if (context.CredentialEpoch != grant.CredentialEpoch ||
            context.CredentialEpoch != request.CredentialEpoch)
        {
            return AgentAuthorizationFailure.CredentialEpochMismatch;
        }

        if (context.ConnectionGeneration != grant.ConnectionGeneration ||
            context.ConnectionGeneration != request.ConnectionGeneration)
        {
            return AgentAuthorizationFailure.ConnectionGenerationMismatch;
        }

        var contextScope = context.Scope;
        var grantScope = grant.Scope;
        var requestScope = request.Scope;
        if (!AllEqual(contextScope.CaseId, grantScope.CaseId, requestScope.CaseId))
        {
            return AgentAuthorizationFailure.WrongCase;
        }

        if (!AllEqual(contextScope.CaptureId, grantScope.CaptureId, requestScope.CaptureId))
        {
            return AgentAuthorizationFailure.WrongCapture;
        }

        if (!AllEqual(contextScope.SessionId, grantScope.SessionId, requestScope.SessionId))
        {
            return AgentAuthorizationFailure.WrongSession;
        }

        if (!AllEqual(
                contextScope.DatabaseIdentity,
                grantScope.DatabaseIdentity,
                requestScope.DatabaseIdentity,
                StringComparison.OrdinalIgnoreCase))
        {
            return AgentAuthorizationFailure.WrongDatabase;
        }

        if (contextScope.WorkspaceMode != grantScope.WorkspaceMode ||
            contextScope.WorkspaceMode != requestScope.WorkspaceMode)
        {
            return AgentAuthorizationFailure.WorkspaceMismatch;
        }

        if (contextScope.CaptureSealed != grantScope.CaptureSealed ||
            contextScope.CaptureSealed != requestScope.CaptureSealed)
        {
            return AgentAuthorizationFailure.SealingMismatch;
        }

        return AgentAuthorizationFailure.None;
    }

    private static bool IsValidGrant(AgentAuthorizationGrant grant) =>
        !string.IsNullOrWhiteSpace(grant.GrantId) &&
        grant.GrantId.Length <= 512 &&
        !string.IsNullOrWhiteSpace(grant.Role) &&
        grant.Role.Length <= 256 &&
        AgentAuthenticationPolicy.IsValidIdentity(grant.AgentId) &&
        AgentAuthenticationPolicy.IsValidIdentity(grant.HostId) &&
        grant.CredentialEpoch > 0 &&
        grant.ConnectionGeneration != Guid.Empty &&
        grant.IssuedAtUtc.Kind == DateTimeKind.Utc &&
        grant.ExpiresAtUtc.Kind == DateTimeKind.Utc &&
        grant.ExpiresAtUtc >= grant.IssuedAtUtc &&
        AgentAuthenticationPolicy.IsValidScope(grant.Scope) &&
        grant.AllowedCommands != null &&
        grant.AllowedCommands.Count <= 256 &&
        grant.AllowedCommands.All(kind => Enum.IsDefined(kind) && kind != AgentCommandKind.Unknown) &&
        grant.AllowedCommands.Distinct().Count() == grant.AllowedCommands.Count;

    private static bool IsValidRequest(AgentAuthorizationRequest request) =>
        Enum.IsDefined(request.Action) &&
        request.Action != AgentAuthorizationAction.Unknown &&
        AgentAuthenticationPolicy.IsValidIdentity(request.AgentId) &&
        AgentAuthenticationPolicy.IsValidIdentity(request.HostId) &&
        request.CredentialEpoch > 0 &&
        request.ConnectionGeneration != Guid.Empty &&
        AgentAuthenticationPolicy.IsValidScope(request.Scope) &&
        request.Action switch
        {
            AgentAuthorizationAction.DiscloseHealth =>
                request.CommandKind == AgentCommandKind.Unknown &&
                request.WriteCategory == CaptureWriteCategory.Unspecified &&
                !request.ExistingAuthoritativeEvidenceWriter,

            AgentAuthorizationAction.ExecuteCommand =>
                Enum.IsDefined(request.CommandKind) &&
                request.CommandKind != AgentCommandKind.Unknown &&
                Enum.IsDefined(request.WriteCategory) &&
                request.WriteCategory != CaptureWriteCategory.Unspecified &&
                !request.ExistingAuthoritativeEvidenceWriter,

            AgentAuthorizationAction.SubmitEvidence =>
                request.CommandKind == AgentCommandKind.Unknown &&
                request.WriteCategory is
                    CaptureWriteCategory.PrimaryAcquisition or CaptureWriteCategory.PrimaryImport,

            _ => false
        };

    private static AgentAuthorizationDecision Allow(
        AuthenticatedAgentContext context,
        AgentAuthorizationGrant grant,
        AgentAuthorizationAction action,
        string diagnostic) =>
        new()
        {
            Allowed = true,
            Action = action,
            Failure = AgentAuthorizationFailure.None,
            Diagnostic = diagnostic,
            AuthenticatedAgent = AgentAuthenticationPolicy.Copy(context),
            GrantId = grant.GrantId
        };

    private static AgentAuthorizationDecision Deny(
        AgentAuthorizationAction action,
        AgentAuthorizationFailure failure,
        string diagnostic) =>
        new()
        {
            Action = action,
            Failure = failure,
            Diagnostic = diagnostic
        };

    private static bool AllEqual(
        string first,
        string second,
        string third,
        StringComparison comparison = StringComparison.Ordinal) =>
        string.Equals(first, second, comparison) &&
        string.Equals(first, third, comparison);
}
