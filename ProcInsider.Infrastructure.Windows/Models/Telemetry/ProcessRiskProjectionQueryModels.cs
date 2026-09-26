using ProcInsider.Models.Analysis;

namespace ProcInsider.Models;

public enum ProcessRiskProjectionReadState
{
    NotReady = 0,
    Available = 1,
    Unsupported = 2,
    Stale = 3,
    Failed = 4,
    AmbiguousLegacyKey = 5
}

/// <summary>
/// Bounded listing-page projection. It carries only persisted summary columns and
/// never contributor detail or a primary-evidence payload.
/// </summary>
public sealed record ProcessRiskProjectionSummaryRecord
{
    public ProcessRiskProjectionReadState ReadState { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public ProcessRiskProjectionState ProjectionState { get; init; }

    public int? Score { get; init; }

    public ProcessRiskBand Band { get; init; }

    public double Confidence { get; init; }

    public double Coverage { get; init; }

    public DateTime? ProjectedUtc { get; init; }

    public static ProcessRiskProjectionSummaryRecord Unavailable(
        ProcessRiskProjectionReadState state,
        string diagnostic,
        string processEntityId = "") => new()
    {
        ReadState = state,
        Diagnostic = diagnostic ?? string.Empty,
        ProcessEntityId = processEntityId?.Trim() ?? string.Empty
    };
}

/// <summary>
/// Bounded read model for one current rebuildable process-risk projection.
/// The portable projection remains distinct from persistence/rebuild metadata.
/// </summary>
public sealed record ProcessRiskProjectionRecord
{
    public ProcessRiskProjectionReadState ReadState { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public string ProcessEntityId { get; init; } = string.Empty;

    public string ProcessKey { get; init; } = string.Empty;

    public string EvaluationId { get; init; } = string.Empty;

    public string InputIdentityHash { get; init; } = string.Empty;

    public string MapperId { get; init; } = string.Empty;

    public string MapperVersion { get; init; } = string.Empty;

    public string AggregationVersion { get; init; } = string.Empty;

    public string ObservationId { get; init; } = string.Empty;

    public string PeAnalysisId { get; init; } = string.Empty;

    public string AuthenticodeVerificationId { get; init; } = string.Empty;

    public IReadOnlyList<ProcessRiskSourceCoverage> Sources { get; init; } = [];

    public ProcessRiskScoreProjection? Projection { get; init; }
}

/// <summary>
/// One exact selected-process explanation. Contributor detail remains bounded by
/// the query owner and is omitted for every non-available or malformed state.
/// </summary>
public sealed record ProcessRiskProjectionDetailsRecord
{
    public ProcessRiskProjectionRecord Current { get; init; } = new();

    public IReadOnlyList<ProcessRiskContribution> Contributors { get; init; } = [];
}
