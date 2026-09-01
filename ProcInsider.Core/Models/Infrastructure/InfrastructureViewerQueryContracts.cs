using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;

namespace ProcInsider.Models.Infrastructure;

public enum InfrastructureViewerQueryKind
{
    Unknown = 0,
    CaseInventory = 1,
    ProcessListing = 2,
    ExplorerSummary = 3,
    SelectedProcessEvidence = 4,
    Timeline = 5,
    Search = 6,
    SigmaFindings = 7,
    RiskProjection = 8,
    Artifacts = 9,
    Diagnostics = 10,
    Annotations = 11
}

public enum InfrastructureViewerSortField
{
    Unknown = 0,
    DurableIdentity = 1,
    NativeTimestamp = 2,
    DisplayName = 3,
    Severity = 4,
    RiskScore = 5
}

public enum InfrastructureViewerSortDirection
{
    Unknown = 0,
    Ascending = 1,
    Descending = 2
}

public enum InfrastructureViewerWorkspaceFailure
{
    None = 0,
    InvalidRequest = 1,
    FeatureUnavailable = 2,
    ViewerAuthenticationStale = 3,
    ViewerIncompatible = 4,
    ViewerRoleDenied = 5,
    CaseGrantRequired = 6,
    CaseNotFound = 7,
    RevisionUnavailable = 8,
    RevisionIncompatible = 9,
    QueryUnsupported = 10,
    CursorInvalid = 11,
    AuditUnavailable = 12,
    AnnotationDenied = 13,
    AnnotationConflict = 14,
    TransportUnavailable = 15,
    Canceled = 16,
    ResponseSuperseded = 17,
    ServerUnavailable = 18
}

public enum InfrastructureAnnotationMutationKind
{
    Unknown = 0,
    Bookmark = 1,
    Note = 2,
    AnalystReview = 3
}

public static class InfrastructureViewerQueryContract
{
    public const int CurrentApiVersion = 1;
    public const int DefaultPageSize = 100;
    public const int MaximumPageSize = 512;
    public const int MaximumProjectionRowsPerPublication = 4096;
    public const int MaximumFieldCount = 64;
    public const int MaximumFieldNameCharacters = 128;
    public const int MaximumFieldValueCharacters = 4096;
    public const int MaximumSearchCharacters = 1024;
    public const int MaximumFilterCharacters = 2048;
    public const int MaximumCursorCharacters = 4096;
    public const int MaximumAnnotationBodyCharacters = 64 * 1024;
    public const int MaximumErrorCodeCharacters = 128;
    public const int MaximumMessageCharacters = 2048;
}

/// <summary>
/// Immutable Server-issued identity for one stable case projection cut. The hash detects
/// accidental or malicious field changes but is not an authorization grant; every request
/// still requires a fresh Viewer context and an exact current case grant.
/// </summary>
public sealed record InfrastructureCaseRevisionToken
{
    public int ApiVersion { get; init; } = InfrastructureViewerQueryContract.CurrentApiVersion;

    public string CaseId { get; init; } = string.Empty;

    public long Revision { get; init; }

    public string SourceCommitId { get; init; } = string.Empty;

    public string ServerInstanceId { get; init; } = string.Empty;

    public long RestoreGeneration { get; init; }

    public int EvidenceSchemaVersion { get; init; }

    public DateTime IssuedAtUtc { get; init; }

    public string TokenSha256 { get; init; } = string.Empty;
}

public static class InfrastructureCaseRevisionTokenCodec
{
    public static InfrastructureCaseRevisionToken Stamp(InfrastructureCaseRevisionToken draft)
    {
        ArgumentNullException.ThrowIfNull(draft);
        var normalized = draft with { TokenSha256 = string.Empty };
        if (!ValidateShape(normalized, requireHash: false))
        {
            throw new InvalidDataException("InfrastructureCaseRevisionTokenInvalid");
        }

        return normalized with { TokenSha256 = Hash(Canonical(normalized)) };
    }

    public static bool Validate(InfrastructureCaseRevisionToken? token) =>
        token != null && ValidateShape(token, requireHash: true) &&
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(token.TokenSha256),
            Encoding.ASCII.GetBytes(Hash(Canonical(token with { TokenSha256 = string.Empty }))));

    private static bool ValidateShape(InfrastructureCaseRevisionToken token, bool requireHash) =>
        token.ApiVersion == InfrastructureViewerQueryContract.CurrentApiVersion &&
        InfrastructureViewerQueryPolicy.IsIdentifier(token.CaseId) &&
        token.Revision > 0 &&
        InfrastructureViewerQueryPolicy.IsIdentifier(token.SourceCommitId) &&
        InfrastructureViewerQueryPolicy.IsIdentifier(token.ServerInstanceId) &&
        token.RestoreGeneration >= 0 &&
        token.EvidenceSchemaVersion > 0 &&
        token.IssuedAtUtc.Kind == DateTimeKind.Utc &&
        (!requireHash || IsSha256(token.TokenSha256));

    private static string Canonical(InfrastructureCaseRevisionToken token) => string.Join('\n',
        token.ApiVersion,
        token.CaseId,
        token.Revision,
        token.SourceCommitId,
        token.ServerInstanceId,
        token.RestoreGeneration,
        token.EvidenceSchemaVersion,
        token.IssuedAtUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture));

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public sealed record InfrastructureViewerCaseGrant
{
    public string GrantId { get; init; } = string.Empty;

    public string ViewerUserId { get; init; } = string.Empty;

    public string CaseId { get; init; } = string.Empty;

    public bool AllowReadEvidence { get; init; }

    public bool AllowAnnotations { get; init; }

    public bool AllowExport { get; init; }

    public long AuthorizationRevision { get; init; }

    public DateTime IssuedAtUtc { get; init; }

    public DateTime ExpiresAtUtc { get; init; }
}

public sealed record InfrastructureCaseQueryScope
{
    public string CaseId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string CaptureId { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public string ProcessEntityId { get; init; } = string.Empty;
}

public sealed record InfrastructureCaseRevisionRequest
{
    public AuthenticatedInfrastructureViewerContext Viewer { get; init; } = new();

    public string CaseId { get; init; } = string.Empty;

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public string ExpectedReleaseId { get; init; } = string.Empty;

    public int ExpectedProtocolGeneration { get; init; }
}

public sealed record InfrastructureCaseRevisionResponse
{
    public bool Allowed { get; init; }

    public InfrastructureViewerWorkspaceFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string CaseId { get; init; } = string.Empty;

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public InfrastructureCaseRevisionToken? Revision { get; init; }

    public DateTime RespondedAtUtc { get; init; }
}

public sealed record InfrastructureViewerQueryRequest
{
    public AuthenticatedInfrastructureViewerContext Viewer { get; init; } = new();

    public InfrastructureCaseRevisionToken Revision { get; init; } = new();

    public InfrastructureCaseQueryScope Scope { get; init; } = new();

    public InfrastructureViewerQueryKind Kind { get; init; }

    public string SearchText { get; init; } = string.Empty;

    public string FilterExpression { get; init; } = string.Empty;

    public InfrastructureViewerSortField SortField { get; init; } =
        InfrastructureViewerSortField.DurableIdentity;

    public InfrastructureViewerSortDirection SortDirection { get; init; } =
        InfrastructureViewerSortDirection.Ascending;

    public string ContinuationToken { get; init; } = string.Empty;

    public int MaximumRows { get; init; } = InfrastructureViewerQueryContract.DefaultPageSize;

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public string ExpectedReleaseId { get; init; } = string.Empty;

    public int ExpectedProtocolGeneration { get; init; }
}

public sealed record InfrastructureViewerQueryRow
{
    public string RowId { get; init; } = string.Empty;

    public InfrastructureViewerQueryKind Kind { get; init; }

    public string CaseId { get; init; } = string.Empty;

    public string HostId { get; init; } = string.Empty;

    public string AgentId { get; init; } = string.Empty;

    public string CaptureId { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public int? ProcessId { get; init; }

    public string DisplayName { get; init; } = string.Empty;

    public string Category { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;

    public DateTime? NativeTimestampUtc { get; init; }

    public DateTime? ServerReceiptTimeUtc { get; init; }

    public long ClockUncertaintyMilliseconds { get; init; }

    public int Severity { get; init; }

    public double? RiskScore { get; init; }

    public bool RelationshipAmbiguous { get; init; }

    public IReadOnlyDictionary<string, string> Fields { get; init; } =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>());
}

public sealed record InfrastructureViewerQueryResponse
{
    public bool Allowed { get; init; }

    public InfrastructureViewerWorkspaceFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public InfrastructureCaseRevisionToken? Revision { get; init; }

    public InfrastructureViewerQueryKind Kind { get; init; }

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public IReadOnlyList<InfrastructureViewerQueryRow> Rows { get; init; } =
        Array.Empty<InfrastructureViewerQueryRow>();

    public bool HasMore { get; init; }

    public string NextContinuationToken { get; init; } = string.Empty;

    public long? TotalCount { get; init; }

    public DateTime RespondedAtUtc { get; init; }
}

public sealed record InfrastructureAnnotationMutationRequest
{
    public AuthenticatedInfrastructureViewerContext Viewer { get; init; } = new();

    public InfrastructureCaseRevisionToken Revision { get; init; } = new();

    public InfrastructureAnnotationMutationKind Kind { get; init; }

    public string AnnotationId { get; init; } = string.Empty;

    public string TargetIdentity { get; init; } = string.Empty;

    public string BodyJson { get; init; } = string.Empty;

    public long ExpectedAnnotationRevision { get; init; }

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public string ExpectedReleaseId { get; init; } = string.Empty;

    public int ExpectedProtocolGeneration { get; init; }
}

public sealed record InfrastructureAnnotationMutationResponse
{
    public bool Allowed { get; init; }

    public InfrastructureViewerWorkspaceFailure Failure { get; init; }

    public string ErrorCode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string AnnotationId { get; init; } = string.Empty;

    public long AnnotationRevision { get; init; }

    public InfrastructureCaseRevisionToken? CaseRevision { get; init; }

    public long WorkspaceGeneration { get; init; }

    public long RequestGeneration { get; init; }

    public DateTime RespondedAtUtc { get; init; }
}

public sealed record InfrastructureViewerAuthorizationDecision(
    bool Allowed,
    InfrastructureViewerWorkspaceFailure Failure,
    string ErrorCode,
    string Message,
    InfrastructureViewerCaseGrant? Grant = null)
{
    public static InfrastructureViewerAuthorizationDecision Permit(InfrastructureViewerCaseGrant grant) =>
        new(true, InfrastructureViewerWorkspaceFailure.None, string.Empty,
            "The Viewer has one current exact case grant.", grant);

    public static InfrastructureViewerAuthorizationDecision Deny(
        InfrastructureViewerWorkspaceFailure failure,
        string code,
        string message) => new(false, failure, code, message);
}

public static class InfrastructureViewerQueryPolicy
{
    public static InfrastructureViewerAuthorizationDecision AuthorizeRead(
        AuthenticatedInfrastructureViewerContext viewer,
        string caseId,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        string expectedReleaseId,
        int expectedProtocolGeneration,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(viewer);
        ArgumentNullException.ThrowIfNull(grants);
        if (!IsValidViewer(viewer) || !IsIdentifier(caseId) || !IsIdentifier(expectedReleaseId) ||
            expectedProtocolGeneration <= 0 || nowUtc.Kind != DateTimeKind.Utc)
        {
            return InfrastructureViewerAuthorizationDecision.Deny(
                InfrastructureViewerWorkspaceFailure.InvalidRequest,
                "InfrastructureViewerRequestInvalid",
                "The bounded Viewer case request is malformed.");
        }

        if (viewer.FreshUntilUtc < nowUtc || viewer.AuthenticatedAtUtc > nowUtc)
        {
            return InfrastructureViewerAuthorizationDecision.Deny(
                InfrastructureViewerWorkspaceFailure.ViewerAuthenticationStale,
                "ViewerAuthenticationStale",
                "The Viewer authentication generation is no longer fresh.");
        }

        if (!string.Equals(viewer.ReleaseId, expectedReleaseId, StringComparison.Ordinal) ||
            viewer.ProtocolGeneration != expectedProtocolGeneration)
        {
            return InfrastructureViewerAuthorizationDecision.Deny(
                InfrastructureViewerWorkspaceFailure.ViewerIncompatible,
                "ViewerProfileIncompatible",
                "The Viewer release or protocol generation does not match the Server profile.");
        }

        if (viewer.Role is InfrastructureViewerRole.Unknown or InfrastructureViewerRole.Operator)
        {
            return InfrastructureViewerAuthorizationDecision.Deny(
                InfrastructureViewerWorkspaceFailure.ViewerRoleDenied,
                "ViewerRoleCannotReadCaseEvidence",
                "The Viewer role does not include case-evidence query authority.");
        }

        var grant = grants
            .Where(item => IsCurrentGrant(item, viewer.ViewerUserId, caseId, nowUtc) && item.AllowReadEvidence)
            .OrderByDescending(item => item.AuthorizationRevision)
            .ThenBy(item => item.GrantId, StringComparer.Ordinal)
            .FirstOrDefault();
        return grant == null
            ? InfrastructureViewerAuthorizationDecision.Deny(
                InfrastructureViewerWorkspaceFailure.CaseGrantRequired,
                "ReadCaseEvidenceGrantRequired",
                "An exact current Read Evidence grant is required for this case.")
            : InfrastructureViewerAuthorizationDecision.Permit(grant);
    }

    public static InfrastructureViewerAuthorizationDecision AuthorizeAnnotation(
        AuthenticatedInfrastructureViewerContext viewer,
        string caseId,
        IReadOnlyList<InfrastructureViewerCaseGrant> grants,
        string expectedReleaseId,
        int expectedProtocolGeneration,
        DateTime nowUtc)
    {
        var read = AuthorizeRead(
            viewer, caseId, grants, expectedReleaseId, expectedProtocolGeneration, nowUtc);
        if (!read.Allowed)
        {
            return read;
        }

        if (viewer.Role is InfrastructureViewerRole.Reader || read.Grant?.AllowAnnotations != true)
        {
            return InfrastructureViewerAuthorizationDecision.Deny(
                InfrastructureViewerWorkspaceFailure.AnnotationDenied,
                "CaseAnnotationGrantRequired",
                "Annotations require an Analyst or Administrator role and an exact annotation grant.");
        }

        return read;
    }

    public static bool IsValidRevisionRequest(InfrastructureCaseRevisionRequest request) =>
        request != null && IsIdentifier(request.CaseId) && request.WorkspaceGeneration > 0 &&
        request.RequestGeneration > 0 && IsIdentifier(request.ExpectedReleaseId) &&
        request.ExpectedProtocolGeneration > 0;

    public static bool IsValidQueryRequest(InfrastructureViewerQueryRequest request) =>
        request != null && InfrastructureCaseRevisionTokenCodec.Validate(request.Revision) &&
        IsValidScope(request.Scope) && request.Scope.CaseId == request.Revision.CaseId &&
        Enum.IsDefined(request.Kind) && request.Kind != InfrastructureViewerQueryKind.Unknown &&
        Enum.IsDefined(request.SortField) && request.SortField != InfrastructureViewerSortField.Unknown &&
        Enum.IsDefined(request.SortDirection) && request.SortDirection != InfrastructureViewerSortDirection.Unknown &&
        request.SearchText is { Length: <= InfrastructureViewerQueryContract.MaximumSearchCharacters } &&
        request.FilterExpression is { Length: <= InfrastructureViewerQueryContract.MaximumFilterCharacters } &&
        request.ContinuationToken is { Length: <= InfrastructureViewerQueryContract.MaximumCursorCharacters } &&
        request.MaximumRows is > 0 and <= InfrastructureViewerQueryContract.MaximumPageSize &&
        request.WorkspaceGeneration > 0 && request.RequestGeneration > 0 &&
        IsIdentifier(request.ExpectedReleaseId) && request.ExpectedProtocolGeneration > 0;

    public static bool IsValidAnnotationRequest(InfrastructureAnnotationMutationRequest request) =>
        request != null && InfrastructureCaseRevisionTokenCodec.Validate(request.Revision) &&
        Enum.IsDefined(request.Kind) && request.Kind != InfrastructureAnnotationMutationKind.Unknown &&
        IsIdentifier(request.AnnotationId) && IsIdentifier(request.TargetIdentity) &&
        request.BodyJson is { Length: > 1 and <= InfrastructureViewerQueryContract.MaximumAnnotationBodyCharacters } &&
        request.ExpectedAnnotationRevision >= 0 && request.WorkspaceGeneration > 0 &&
        request.RequestGeneration > 0 && IsIdentifier(request.ExpectedReleaseId) &&
        request.ExpectedProtocolGeneration > 0;

    public static bool IsValidRow(InfrastructureViewerQueryRow? row, string caseId) =>
        row != null && IsIdentifier(row.RowId) && Enum.IsDefined(row.Kind) &&
        row.Kind != InfrastructureViewerQueryKind.Unknown && row.CaseId == caseId &&
        OptionalIdentifier(row.HostId) && OptionalIdentifier(row.AgentId) &&
        OptionalIdentifier(row.CaptureId) && OptionalIdentifier(row.SourceRunId) &&
        OptionalIdentifier(row.ProcessEntityId) && OptionalIdentifier(row.ProcessKey) &&
        row.ProcessId is null or >= 0 && OptionalText(row.DisplayName) && OptionalText(row.Category) &&
        OptionalText(row.Status) && IsOptionalUtc(row.NativeTimestampUtc) &&
        IsOptionalUtc(row.ServerReceiptTimeUtc) && row.ClockUncertaintyMilliseconds >= 0 &&
        row.Severity is >= 0 and <= 100 && row.RiskScore is null or >= 0 and <= 100 &&
        row.Fields is { Count: <= InfrastructureViewerQueryContract.MaximumFieldCount } &&
        row.Fields.All(pair => !string.IsNullOrWhiteSpace(pair.Key) &&
            pair.Key.Length <= InfrastructureViewerQueryContract.MaximumFieldNameCharacters &&
            pair.Value != null && pair.Value.Length <= InfrastructureViewerQueryContract.MaximumFieldValueCharacters);

    public static IReadOnlyDictionary<string, string> FreezeFields(
        IEnumerable<KeyValuePair<string, string>>? fields) =>
        new ReadOnlyDictionary<string, string>((fields ?? [])
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));

    public static bool IsIdentifier(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= InfrastructureEvidenceInterchange.MaximumIdentifierCharacters;

    private static bool IsCurrentGrant(
        InfrastructureViewerCaseGrant grant,
        string viewerUserId,
        string caseId,
        DateTime nowUtc) =>
        IsIdentifier(grant.GrantId) && grant.ViewerUserId == viewerUserId && grant.CaseId == caseId &&
        grant.AuthorizationRevision > 0 && grant.IssuedAtUtc.Kind == DateTimeKind.Utc &&
        grant.ExpiresAtUtc.Kind == DateTimeKind.Utc && grant.IssuedAtUtc <= nowUtc &&
        grant.ExpiresAtUtc >= nowUtc;

    private static bool IsValidViewer(AuthenticatedInfrastructureViewerContext viewer) =>
        IsIdentifier(viewer.ViewerUserId) && Enum.IsDefined(viewer.Role) &&
        viewer.Role != InfrastructureViewerRole.Unknown && viewer.CredentialEpoch > 0 &&
        viewer.ConnectionGeneration != Guid.Empty && viewer.ProtocolGeneration > 0 &&
        IsIdentifier(viewer.ReleaseId) && viewer.AuthenticatedAtUtc.Kind == DateTimeKind.Utc &&
        viewer.FreshUntilUtc.Kind == DateTimeKind.Utc &&
        viewer.FreshUntilUtc >= viewer.AuthenticatedAtUtc;

    private static bool IsValidScope(InfrastructureCaseQueryScope scope) =>
        scope != null && IsIdentifier(scope.CaseId) && OptionalIdentifier(scope.HostId) &&
        OptionalIdentifier(scope.AgentId) && OptionalIdentifier(scope.CaptureId) &&
        OptionalIdentifier(scope.SourceRunId) && OptionalIdentifier(scope.ProcessEntityId);

    private static bool OptionalIdentifier(string? value) =>
        string.IsNullOrEmpty(value) || IsIdentifier(value);

    private static bool OptionalText(string? value) =>
        value != null && value.Length <= InfrastructureViewerQueryContract.MaximumFieldValueCharacters;

    private static bool IsOptionalUtc(DateTime? value) => value is null || value.Value.Kind == DateTimeKind.Utc;
}
