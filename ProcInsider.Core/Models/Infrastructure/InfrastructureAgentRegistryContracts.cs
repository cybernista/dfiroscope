namespace ProcInsider.Models.Infrastructure;

public enum InfrastructureAgentProjectionState
{
    Configured = 0,
    Connecting = 1,
    Authenticated = 2,
    Stale = 3,
    Disconnected = 4,
    Revoked = 5,
    Incompatible = 6,
    Duplicate = 7,
    Error = 8
}

public enum InfrastructureAgentEnrollmentState
{
    Unknown = 0,
    Active = 1,
    Revoked = 2,
    Expired = 3,
    Compromised = 4
}

public enum InfrastructureAgentTransportState
{
    Configured = 0,
    Connecting = 1,
    Active = 2,
    Disconnected = 3,
    Incompatible = 4,
    Duplicate = 5,
    Error = 6
}

public enum InfrastructureAgentProjectionFailure
{
    None = 0,
    InvalidRequest = 1,
    FeatureUnavailable = 2,
    ViewerAuthenticationStale = 3,
    ViewerIncompatible = 4,
    ViewerRoleDenied = 5,
    HealthDisclosureNotGranted = 6,
    AuditUnavailable = 7,
    AgentNotFound = 8,
    ResponseSuperseded = 9,
    Canceled = 10,
    TransportUnavailable = 11
}

public sealed record InfrastructureConfiguredAgent
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public long ConfigurationRevision { get; init; }

    public bool Enabled { get; init; }

    public InfrastructureAgentEnrollmentState EnrollmentState { get; init; }

    public long CredentialEpoch { get; init; }

    public string ReleaseId { get; init; } = string.Empty;

    public int ProtocolGeneration { get; init; }

    public IReadOnlyList<string> ApprovedCaseIds { get; init; } = Array.Empty<string>();

    public DateTime UpdatedAtUtc { get; init; }
}

public sealed record InfrastructureAgentSessionObservation
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public InfrastructureAgentTransportState TransportState { get; init; }

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public long ServerSessionGeneration { get; init; }

    public Guid SessionId { get; init; }

    public string ReleaseId { get; init; } = string.Empty;

    public int ProtocolGeneration { get; init; }

    public IReadOnlyList<string> Capabilities { get; init; } = Array.Empty<string>();

    public DateTime ObservedAtUtc { get; init; }

    public DateTime LastActivityUtc { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string ErrorMessage { get; init; } = string.Empty;
}

public sealed record InfrastructureAgentHealthObservation
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public long ServerSessionGeneration { get; init; }

    public Guid SessionId { get; init; }

    public long HealthRevision { get; init; }

    public DateTime ObservedAtUtc { get; init; }

    public string AvailabilityCode { get; init; } = string.Empty;

    public string ErrorCode { get; init; } = string.Empty;

    public string ErrorMessage { get; init; } = string.Empty;
}

public sealed record InfrastructureViewerHealthGrant
{
    public string GrantId { get; init; } = string.Empty;

    public string ViewerUserId { get; init; } = string.Empty;

    public string CaseId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public bool AllowReadHealth { get; init; }

    public long AuthorizationRevision { get; init; }

    public DateTime IssuedAtUtc { get; init; }

    public DateTime ExpiresAtUtc { get; init; }
}

public sealed record InfrastructureAgentProjectionRequest
{
    public AuthenticatedInfrastructureViewerContext Viewer { get; init; } = new();

    public string CaseId { get; init; } = string.Empty;

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public int MaximumRows { get; init; } = InfrastructureAgentProjectionPolicy.DefaultMaximumRows;

    public string ExpectedReleaseId { get; init; } = string.Empty;

    public int ExpectedProtocolGeneration { get; init; }
}

public sealed record InfrastructureAgentProjectionRow
{
    public string AgentId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public string CaseId { get; init; } = string.Empty;

    public InfrastructureAgentProjectionState State { get; init; }

    public InfrastructureAgentEnrollmentState EnrollmentState { get; init; }

    public long ConfigurationRevision { get; init; }

    public long CredentialEpoch { get; init; }

    public Guid ConnectionGeneration { get; init; }

    public long ServerSessionGeneration { get; init; }

    public Guid SessionId { get; init; }

    public string ReleaseId { get; init; } = string.Empty;

    public int ProtocolGeneration { get; init; }

    public IReadOnlyList<string> Capabilities { get; init; } = Array.Empty<string>();

    public long HealthRevision { get; init; }

    public DateTime? HealthObservedAtUtc { get; init; }

    public DateTime FreshUntilUtc { get; init; }

    public string AvailabilityCode { get; init; } = string.Empty;

    public string ErrorCode { get; init; } = string.Empty;

    public string ErrorMessage { get; init; } = string.Empty;

    public bool CountsAsConnected { get; init; }

    public bool CommandEligible { get; init; }
}

public sealed record InfrastructureAgentProjectionResponse
{
    public bool Allowed { get; init; }

    public InfrastructureAgentProjectionFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string CaseId { get; init; } = string.Empty;

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public long ProjectionRevision { get; init; }

    public DateTime GeneratedAtUtc { get; init; }

    public IReadOnlyList<InfrastructureAgentProjectionRow> Agents { get; init; } =
        Array.Empty<InfrastructureAgentProjectionRow>();

    public int ConnectedAgentCount { get; init; }
}

/// <summary>
/// Pure, transport-neutral policy for the authorized Infrastructure Agent roster. It never
/// treats configuration, selection, connectivity, or certificate possession as health authority.
/// </summary>
public static class InfrastructureAgentProjectionPolicy
{
    public const int DefaultMaximumRows = 256;
    public const int CompiledMaximumRows = 512;
    public const int CompiledMaximumConfiguredAgents = 4096;
    public const int CompiledMaximumSessionObservations = 4096;
    public const int CompiledMaximumHealthObservations = 4096;
    public const int CompiledMaximumGrants = 4096;
    public const int CompiledMaximumCasesPerAgent = 64;
    public static readonly TimeSpan MaximumHealthAge = TimeSpan.FromSeconds(90);

    public static InfrastructureAgentProjectionResponse Project(
        InfrastructureAgentProjectionRequest request,
        IReadOnlyList<InfrastructureViewerHealthGrant> grants,
        IReadOnlyList<InfrastructureConfiguredAgent> configuredAgents,
        IReadOnlyList<InfrastructureAgentSessionObservation> sessions,
        IReadOnlyList<InfrastructureAgentHealthObservation> health,
        long projectionRevision,
        bool featurePublished,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(configuredAgents);
        ArgumentNullException.ThrowIfNull(sessions);
        ArgumentNullException.ThrowIfNull(health);

        var malformed = !IsValidRequest(request, nowUtc) ||
                        projectionRevision < 0 ||
                        grants.Count > CompiledMaximumGrants ||
                        configuredAgents.Count > CompiledMaximumConfiguredAgents ||
                        sessions.Count > CompiledMaximumSessionObservations ||
                        health.Count > CompiledMaximumHealthObservations;
        if (malformed)
        {
            return Deny(request, InfrastructureAgentProjectionFailure.InvalidRequest,
                "InfrastructureProjectionRequestInvalid",
                "The bounded registry/health projection request is malformed.", nowUtc);
        }

        if (!featurePublished)
        {
            return Deny(request, InfrastructureAgentProjectionFailure.FeatureUnavailable,
                "InfrastructureAgentManagementUnavailable",
                "Infrastructure Agent Management is not published for this Server.", nowUtc);
        }

        if (request.Viewer.FreshUntilUtc < nowUtc || request.Viewer.AuthenticatedAtUtc > nowUtc)
        {
            return Deny(request, InfrastructureAgentProjectionFailure.ViewerAuthenticationStale,
                "ViewerAuthenticationStale",
                "The Viewer authentication generation is no longer fresh.", nowUtc);
        }

        if (!string.Equals(request.Viewer.ReleaseId, request.ExpectedReleaseId, StringComparison.Ordinal) ||
            request.Viewer.ProtocolGeneration != request.ExpectedProtocolGeneration)
        {
            return Deny(request, InfrastructureAgentProjectionFailure.ViewerIncompatible,
                "ViewerProfileIncompatible",
                "The Viewer release or protocol generation does not match the Server profile.", nowUtc);
        }

        if (request.Viewer.Role is InfrastructureViewerRole.Unknown or InfrastructureViewerRole.Reader)
        {
            return Deny(request, InfrastructureAgentProjectionFailure.ViewerRoleDenied,
                "ViewerRoleCannotReadHealth",
                "The Viewer role does not include live Agent health visibility.", nowUtc);
        }

        var currentGrants = grants
            .Where(grant => IsGrantCurrent(grant, request, nowUtc))
            .ToArray();
        if (currentGrants.Length == 0)
        {
            return Deny(request, InfrastructureAgentProjectionFailure.HealthDisclosureNotGranted,
                "ReadHealthGrantRequired",
                "An exact current case/Agent ReadHealth grant is required.", nowUtc);
        }

        var rows = new List<InfrastructureAgentProjectionRow>();
        foreach (var configured in configuredAgents
                     .Where(agent => agent.ApprovedCaseIds.Contains(request.CaseId, StringComparer.Ordinal))
                     .Where(agent => currentGrants.Any(grant => GrantMatches(grant, agent)))
                     .OrderBy(agent => agent.DisplayName, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(agent => agent.AgentId, StringComparer.Ordinal)
                     .ThenBy(agent => agent.HostId, StringComparer.Ordinal)
                     .Take(request.MaximumRows))
        {
            if (!IsValidConfigured(configured))
            {
                rows.Add(CreateMalformedRow(configured, request.CaseId, nowUtc));
                continue;
            }

            var session = sessions
                .Where(candidate => EqualIdentity(candidate.AgentId, candidate.HostId, configured.AgentId, configured.HostId))
                .OrderByDescending(candidate => candidate.ServerSessionGeneration)
                .ThenByDescending(candidate => candidate.ObservedAtUtc)
                .FirstOrDefault();
            var currentHealth = health
                .Where(candidate => EqualIdentity(candidate.AgentId, candidate.HostId, configured.AgentId, configured.HostId))
                .OrderByDescending(candidate => candidate.ServerSessionGeneration)
                .ThenByDescending(candidate => candidate.HealthRevision)
                .FirstOrDefault();
            rows.Add(ProjectRow(configured, request.CaseId, session, currentHealth, nowUtc));
        }

        var immutable = Array.AsReadOnly(rows.ToArray());
        return new InfrastructureAgentProjectionResponse
        {
            Allowed = true,
            Message = "The Server returned the authorized bounded Agent registry/health projection.",
            CaseId = request.CaseId,
            WorkspaceGeneration = request.WorkspaceGeneration,
            RequestGeneration = request.RequestGeneration,
            ProjectionRevision = projectionRevision,
            GeneratedAtUtc = nowUtc,
            Agents = immutable,
            ConnectedAgentCount = immutable
                .Where(row => row.CountsAsConnected)
                .Select(row => (row.AgentId, row.HostId))
                .Distinct()
                .Count()
        };
    }

    public static bool IsHealthBoundToSession(
        InfrastructureAgentHealthObservation health,
        InfrastructureAgentSessionObservation session) =>
        EqualIdentity(health.AgentId, health.HostId, session.AgentId, session.HostId) &&
        health.CredentialEpoch == session.CredentialEpoch &&
        health.ConnectionGeneration == session.ConnectionGeneration &&
        health.ServerSessionGeneration == session.ServerSessionGeneration &&
        health.SessionId == session.SessionId;

    public static bool IsValidConfigured(InfrastructureConfiguredAgent agent) =>
        IsIdentity(agent.AgentId) &&
        IsIdentity(agent.HostId) &&
        IsIdentity(agent.DisplayName) &&
        agent.ConfigurationRevision > 0 &&
        Enum.IsDefined(agent.EnrollmentState) &&
        agent.CredentialEpoch > 0 &&
        IsIdentity(agent.ReleaseId) &&
        agent.ProtocolGeneration > 0 &&
        agent.ApprovedCaseIds is { Count: > 0 and <= CompiledMaximumCasesPerAgent } &&
        agent.ApprovedCaseIds.All(IsIdentity) &&
        agent.ApprovedCaseIds.Distinct(StringComparer.Ordinal).Count() == agent.ApprovedCaseIds.Count &&
        agent.UpdatedAtUtc.Kind == DateTimeKind.Utc;

    private static InfrastructureAgentProjectionRow ProjectRow(
        InfrastructureConfiguredAgent configured,
        string caseId,
        InfrastructureAgentSessionObservation? session,
        InfrastructureAgentHealthObservation? health,
        DateTime nowUtc)
    {
        var state = ResolveState(configured, session, health, nowUtc);
        var healthBound = session != null && health != null && IsHealthBoundToSession(health, session);
        var freshUntil = healthBound ? health!.ObservedAtUtc + MaximumHealthAge : DateTime.MinValue;
        var compatible = session != null &&
                         string.Equals(session.ReleaseId, configured.ReleaseId, StringComparison.Ordinal) &&
                         session.ProtocolGeneration == configured.ProtocolGeneration;
        var counts = state == InfrastructureAgentProjectionState.Authenticated &&
                     configured.Enabled &&
                     configured.EnrollmentState == InfrastructureAgentEnrollmentState.Active &&
                     compatible &&
                     healthBound &&
                     freshUntil >= nowUtc;
        return new InfrastructureAgentProjectionRow
        {
            AgentId = configured.AgentId,
            HostId = configured.HostId,
            DisplayName = configured.DisplayName,
            CaseId = caseId,
            State = state,
            EnrollmentState = configured.EnrollmentState,
            ConfigurationRevision = configured.ConfigurationRevision,
            CredentialEpoch = session?.CredentialEpoch ?? configured.CredentialEpoch,
            ConnectionGeneration = session?.ConnectionGeneration ?? Guid.Empty,
            ServerSessionGeneration = session?.ServerSessionGeneration ?? 0,
            SessionId = session?.SessionId ?? Guid.Empty,
            ReleaseId = session?.ReleaseId ?? configured.ReleaseId,
            ProtocolGeneration = session?.ProtocolGeneration ?? configured.ProtocolGeneration,
            Capabilities = session?.Capabilities ?? Array.Empty<string>(),
            HealthRevision = healthBound ? health!.HealthRevision : 0,
            HealthObservedAtUtc = healthBound ? health!.ObservedAtUtc : null,
            FreshUntilUtc = freshUntil,
            AvailabilityCode = healthBound ? health!.AvailabilityCode : string.Empty,
            ErrorCode = FirstNonEmpty(healthBound ? health!.ErrorCode : string.Empty, session?.ErrorCode),
            ErrorMessage = FirstNonEmpty(healthBound ? health!.ErrorMessage : string.Empty, session?.ErrorMessage),
            CountsAsConnected = counts,
            CommandEligible = false
        };
    }

    private static InfrastructureAgentProjectionState ResolveState(
        InfrastructureConfiguredAgent configured,
        InfrastructureAgentSessionObservation? session,
        InfrastructureAgentHealthObservation? health,
        DateTime nowUtc)
    {
        if (!configured.Enabled)
        {
            return InfrastructureAgentProjectionState.Configured;
        }

        if (configured.EnrollmentState is InfrastructureAgentEnrollmentState.Revoked or
            InfrastructureAgentEnrollmentState.Expired or InfrastructureAgentEnrollmentState.Compromised)
        {
            return InfrastructureAgentProjectionState.Revoked;
        }

        if (session == null)
        {
            return InfrastructureAgentProjectionState.Configured;
        }

        if (session.TransportState == InfrastructureAgentTransportState.Duplicate)
        {
            return InfrastructureAgentProjectionState.Duplicate;
        }

        if (session.TransportState == InfrastructureAgentTransportState.Incompatible ||
            !string.Equals(session.ReleaseId, configured.ReleaseId, StringComparison.Ordinal) ||
            session.ProtocolGeneration != configured.ProtocolGeneration)
        {
            return InfrastructureAgentProjectionState.Incompatible;
        }

        if (session.TransportState == InfrastructureAgentTransportState.Error)
        {
            return InfrastructureAgentProjectionState.Error;
        }

        if (session.TransportState == InfrastructureAgentTransportState.Disconnected)
        {
            return InfrastructureAgentProjectionState.Disconnected;
        }

        if (session.TransportState is InfrastructureAgentTransportState.Configured or
            InfrastructureAgentTransportState.Connecting)
        {
            return InfrastructureAgentProjectionState.Connecting;
        }

        if (nowUtc - session.LastActivityUtc > MaximumHealthAge ||
            health == null ||
            !IsHealthBoundToSession(health, session) ||
            nowUtc - health.ObservedAtUtc > MaximumHealthAge)
        {
            return health == null ? InfrastructureAgentProjectionState.Connecting : InfrastructureAgentProjectionState.Stale;
        }

        return string.IsNullOrWhiteSpace(health.ErrorCode)
            ? InfrastructureAgentProjectionState.Authenticated
            : InfrastructureAgentProjectionState.Error;
    }

    private static bool IsValidRequest(InfrastructureAgentProjectionRequest request, DateTime nowUtc) =>
        nowUtc.Kind == DateTimeKind.Utc &&
        IsValidViewer(request.Viewer) &&
        IsIdentity(request.CaseId) &&
        request.WorkspaceGeneration > 0 &&
        request.RequestGeneration > 0 &&
        request.MaximumRows is > 0 and <= CompiledMaximumRows &&
        IsIdentity(request.ExpectedReleaseId) &&
        request.ExpectedProtocolGeneration > 0;

    private static bool IsValidViewer(AuthenticatedInfrastructureViewerContext viewer) =>
        IsIdentity(viewer.ViewerUserId) &&
        Enum.IsDefined(viewer.Role) && viewer.Role != InfrastructureViewerRole.Unknown &&
        viewer.CredentialEpoch > 0 &&
        viewer.ConnectionGeneration != Guid.Empty &&
        viewer.ProtocolGeneration > 0 &&
        IsIdentity(viewer.ReleaseId) &&
        viewer.AuthenticatedAtUtc.Kind == DateTimeKind.Utc &&
        viewer.FreshUntilUtc.Kind == DateTimeKind.Utc &&
        viewer.FreshUntilUtc >= viewer.AuthenticatedAtUtc;

    private static bool IsGrantCurrent(
        InfrastructureViewerHealthGrant grant,
        InfrastructureAgentProjectionRequest request,
        DateTime nowUtc) =>
        IsIdentity(grant.GrantId) &&
        string.Equals(grant.ViewerUserId, request.Viewer.ViewerUserId, StringComparison.Ordinal) &&
        string.Equals(grant.CaseId, request.CaseId, StringComparison.Ordinal) &&
        IsIdentity(grant.AgentId) &&
        IsIdentity(grant.HostId) &&
        grant.AllowReadHealth &&
        grant.AuthorizationRevision > 0 &&
        grant.IssuedAtUtc.Kind == DateTimeKind.Utc &&
        grant.ExpiresAtUtc.Kind == DateTimeKind.Utc &&
        grant.IssuedAtUtc <= nowUtc &&
        grant.ExpiresAtUtc >= nowUtc;

    private static bool GrantMatches(
        InfrastructureViewerHealthGrant grant,
        InfrastructureConfiguredAgent agent) =>
        EqualIdentity(grant.AgentId, grant.HostId, agent.AgentId, agent.HostId);

    private static InfrastructureAgentProjectionRow CreateMalformedRow(
        InfrastructureConfiguredAgent configured,
        string caseId,
        DateTime nowUtc) =>
        new()
        {
            AgentId = configured.AgentId,
            HostId = configured.HostId,
            DisplayName = configured.DisplayName,
            CaseId = caseId,
            State = InfrastructureAgentProjectionState.Error,
            EnrollmentState = configured.EnrollmentState,
            ConfigurationRevision = configured.ConfigurationRevision,
            CredentialEpoch = configured.CredentialEpoch,
            ReleaseId = configured.ReleaseId,
            ProtocolGeneration = configured.ProtocolGeneration,
            FreshUntilUtc = DateTime.MinValue,
            ErrorCode = "ConfiguredAgentInvalid",
            ErrorMessage = "The configured Agent record is malformed and contributes no eligibility.",
            CountsAsConnected = false,
            CommandEligible = false
        };

    private static InfrastructureAgentProjectionResponse Deny(
        InfrastructureAgentProjectionRequest request,
        InfrastructureAgentProjectionFailure failure,
        string errorCode,
        string message,
        DateTime nowUtc) =>
        new()
        {
            Failure = failure,
            ErrorCode = errorCode,
            Message = message,
            CaseId = request.CaseId,
            WorkspaceGeneration = request.WorkspaceGeneration,
            RequestGeneration = request.RequestGeneration,
            GeneratedAtUtc = nowUtc
        };

    private static bool EqualIdentity(
        string leftAgent,
        string leftHost,
        string rightAgent,
        string rightHost) =>
        string.Equals(leftAgent, rightAgent, StringComparison.Ordinal) &&
        string.Equals(leftHost, rightHost, StringComparison.Ordinal);

    private static bool IsIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512;

    private static string FirstNonEmpty(string? first, string? second) =>
        !string.IsNullOrWhiteSpace(first) ? first : second ?? string.Empty;
}
