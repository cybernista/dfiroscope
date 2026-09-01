namespace ProcInsider.Models.Infrastructure;

/// <summary>
/// Authenticated Viewer HTTP/2 routes. Identity and grants are deliberately absent from every
/// wire request: the Server derives both from the current mutually authenticated connection.
/// </summary>
public static class InfrastructureViewerTransportContract
{
    public const int CurrentVersion = 1;
    public const string OpenCaseRevisionPath = "/api/infrastructure/v1/viewer/case-revision/open";
    public const string QueryPath = "/api/infrastructure/v1/viewer/query";
    public const string AnnotationPath = "/api/infrastructure/v1/viewer/annotation";
    public const int MaximumRequestBytes = 1024 * 1024;
    public const int MaximumResponseBytes = 32 * 1024 * 1024;
}

public sealed record InfrastructureCaseRevisionWireRequest
{
    public int TransportVersion { get; init; } = InfrastructureViewerTransportContract.CurrentVersion;
    public string CaseId { get; init; } = string.Empty;
    public long WorkspaceGeneration { get; init; }
    public long RequestGeneration { get; init; }
    public string ExpectedReleaseId { get; init; } = string.Empty;
    public int ExpectedProtocolGeneration { get; init; }
}

public sealed record InfrastructureViewerQueryWireRequest
{
    public int TransportVersion { get; init; } = InfrastructureViewerTransportContract.CurrentVersion;
    public InfrastructureCaseRevisionToken Revision { get; init; } = new();
    public InfrastructureCaseQueryScope Scope { get; init; } = new();
    public InfrastructureViewerQueryKind Kind { get; init; }
    public string SearchText { get; init; } = string.Empty;
    public string FilterExpression { get; init; } = string.Empty;
    public InfrastructureViewerSortField SortField { get; init; } = InfrastructureViewerSortField.DurableIdentity;
    public InfrastructureViewerSortDirection SortDirection { get; init; } = InfrastructureViewerSortDirection.Ascending;
    public string ContinuationToken { get; init; } = string.Empty;
    public int MaximumRows { get; init; } = InfrastructureViewerQueryContract.DefaultPageSize;
    public long WorkspaceGeneration { get; init; }
    public long RequestGeneration { get; init; }
    public string ExpectedReleaseId { get; init; } = string.Empty;
    public int ExpectedProtocolGeneration { get; init; }
}

public sealed record InfrastructureAnnotationMutationWireRequest
{
    public int TransportVersion { get; init; } = InfrastructureViewerTransportContract.CurrentVersion;
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
