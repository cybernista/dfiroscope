using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public interface IProcessRiskProjectionQueryService
{
    IReadOnlyList<ProcessRiskProjectionSummaryRecord> GetCurrentSummaries(
        IReadOnlyList<string> processEntityIds,
        CancellationToken cancellationToken = default);

    ProcessRiskProjectionRecord GetCurrentProjection(
        string processEntityId,
        string processKey = "",
        CancellationToken cancellationToken = default);

    ProcessRiskProjectionDetailsRecord GetCurrentDetails(
        string processEntityId,
        string processKey = "",
        int maxContributors = 512,
        CancellationToken cancellationToken = default);

    IReadOnlyList<ProcessRiskContribution> GetContributors(
        string processEntityId,
        string processKey = "",
        int maxCount = 100,
        CancellationToken cancellationToken = default);
}

internal sealed class ProcessRiskProjectionQueryService : IProcessRiskProjectionQueryService
{
    private const int MaximumBatchEntities = 512;
    private const int MaximumContributors = 512;
    private readonly SqliteReadQueryContext _readContext;

    internal ProcessRiskProjectionQueryService(SqliteReadQueryContext readContext)
    {
        _readContext = readContext ?? throw new ArgumentNullException(nameof(readContext));
    }

    public IReadOnlyList<ProcessRiskProjectionSummaryRecord> GetCurrentSummaries(
        IReadOnlyList<string> processEntityIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(processEntityIds);
        if (processEntityIds.Count == 0)
        {
            return [];
        }

        if (processEntityIds.Count > MaximumBatchEntities)
        {
            throw new ArgumentOutOfRangeException(
                nameof(processEntityIds),
                processEntityIds.Count,
                $"A process-risk summary batch cannot exceed {MaximumBatchEntities} exact entities.");
        }

        var normalizedIds = new string[processEntityIds.Count];
        var uniqueIds = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < processEntityIds.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalized = processEntityIds[index]?.Trim() ?? string.Empty;
            if (normalized.Length == 0)
            {
                throw new ArgumentException(
                    "Process-risk summary batches require non-empty durable ProcessEntityId values.",
                    nameof(processEntityIds));
            }

            if (!uniqueIds.Add(normalized))
            {
                throw new ArgumentException(
                    "Process-risk summary batches cannot contain duplicate ProcessEntityId values.",
                    nameof(processEntityIds));
            }

            normalizedIds[index] = normalized;
        }

        using var connection = _readContext.OpenReadOnlyConnection();
        cancellationToken.ThrowIfCancellationRequested();
        if (!TableExists(connection, "ProcessRiskProjections"))
        {
            return normalizedIds
                .Select(processEntityId => ProcessRiskProjectionSummaryRecord.Unavailable(
                    ProcessRiskProjectionReadState.Unsupported,
                    "This supported capture revision has no process-risk projection schema. Explicit analysis maintenance is required when the catalog prerequisite is available.",
                    processEntityId))
                .ToArray();
        }

        if (!TableExists(connection, "ProcessRiskProjectionSources"))
        {
            return normalizedIds
                .Select(processEntityId => ProcessRiskProjectionSummaryRecord.Unavailable(
                    ProcessRiskProjectionReadState.Failed,
                    "The process-risk projection source-coverage table is missing.",
                    processEntityId))
                .ToArray();
        }

        using var command = connection.CreateCommand();
        var parameterNames = new string[normalizedIds.Length];
        for (var index = 0; index < normalizedIds.Length; index++)
        {
            parameterNames[index] = $"$Entity{index}";
            command.Parameters.AddWithValue(parameterNames[index], normalizedIds[index]);
        }

        command.CommandText = $"""
            SELECT p.ProcessEntityId, p.ProcessKey, p.RebuildStatus, p.Diagnostic,
                   p.MapperId, p.MapperVersion, p.AggregationVersion,
                   p.EvaluationId, p.InputIdentityHash, p.ProjectionState,
                   p.Score, p.Band, p.Confidence, p.Coverage, p.ProjectedUtc,
                   p.PolicyId, p.PolicyVersion,
                   s.SourceOrder, s.SourceKind, s.SourceId, s.Availability
            FROM ProcessRiskProjections p
            LEFT JOIN ProcessRiskProjectionSources s
              ON s.ProcessEntityId = p.ProcessEntityId
            WHERE p.ProcessEntityId IN ({string.Join(", ", parameterNames)})
            ORDER BY p.ProcessEntityId, s.SourceOrder;
            """;

        var candidates = new Dictionary<string, PersistedSummaryCandidate>(StringComparer.Ordinal);
        using var cancellationRegistration = cancellationToken.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var processEntityId = GetString(reader, 0);
            if (!candidates.TryGetValue(processEntityId, out var candidate))
            {
                candidate = new PersistedSummaryCandidate(
                    processEntityId,
                    GetString(reader, 1),
                    GetString(reader, 2),
                    GetString(reader, 3),
                    GetString(reader, 4),
                    GetString(reader, 5),
                    GetString(reader, 6),
                    GetString(reader, 7),
                    GetString(reader, 8),
                    GetString(reader, 9),
                    reader.IsDBNull(10) ? null : reader.GetInt32(10),
                    GetString(reader, 11),
                    reader.IsDBNull(12) ? double.NaN : reader.GetDouble(12),
                    reader.IsDBNull(13) ? double.NaN : reader.GetDouble(13),
                    GetString(reader, 14),
                    GetString(reader, 15),
                    GetString(reader, 16));
                candidates.Add(processEntityId, candidate);
            }

            if (!reader.IsDBNull(17))
            {
                candidate.Sources.Add(new PersistedSummarySource(
                    reader.GetInt32(17),
                    GetString(reader, 18),
                    GetString(reader, 19),
                    GetString(reader, 20)));
            }
        }

        return normalizedIds
            .Select(processEntityId => candidates.TryGetValue(processEntityId, out var candidate)
                ? MaterializeSummary(candidate)
                : ProcessRiskProjectionSummaryRecord.Unavailable(
                    ProcessRiskProjectionReadState.NotReady,
                    "No current process-risk projection has been rebuilt for this exact process entity.",
                    processEntityId))
            .ToArray();
    }

    public ProcessRiskProjectionRecord GetCurrentProjection(
        string processEntityId,
        string processKey = "",
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var connection = _readContext.OpenReadOnlyConnection();
        if (!TableExists(connection, "ProcessRiskProjections"))
        {
            return Unavailable(
                ProcessRiskProjectionReadState.Unsupported,
                "This supported capture revision has no process-risk projection schema. Explicit analysis maintenance is required when the catalog prerequisite is available.",
                processEntityId,
                processKey);
        }

        var identity = ResolveIdentity(connection, processEntityId, processKey, cancellationToken);
        if (identity.State != ProcessRiskProjectionReadState.Available)
        {
            return Unavailable(identity.State, identity.Diagnostic, processEntityId, processKey);
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ProcessEntityId, ProcessKey, RebuildStatus, Diagnostic,
                   MapperId, MapperVersion, AggregationVersion, EvaluationId, InputIdentityHash,
                   ObservationId, COALESCE(PeAnalysisId, ''), COALESCE(AuthenticodeVerificationId, ''),
                   ProjectionJson, PolicyId, PolicyVersion
            FROM ProcessRiskProjections
            WHERE ProcessEntityId = $ProcessEntityId
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$ProcessEntityId", identity.ProcessEntityId);
        using var cancellationRegistration = cancellationToken.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return Unavailable(
                ProcessRiskProjectionReadState.NotReady,
                "No current process-risk projection has been rebuilt for this exact process entity.",
                identity.ProcessEntityId,
                processKey);
        }

        var rebuildStatus = GetString(reader, 2);
        var diagnostic = GetString(reader, 3);
        var mapperId = GetString(reader, 4);
        var mapperVersion = GetString(reader, 5);
        var aggregationVersion = GetString(reader, 6);
        var evaluationId = GetString(reader, 7);
        var inputIdentityHash = GetString(reader, 8);
        var observationId = GetString(reader, 9);
        var peAnalysisId = GetString(reader, 10);
        var authenticodeVerificationId = GetString(reader, 11);
        var projectionJson = GetString(reader, 12);
        var selectedEntityId = GetString(reader, 0);
        var selectedProcessKey = GetString(reader, 1);
        var policyId = GetString(reader, 13);
        var policyVersion = GetString(reader, 14);
        reader.Close();
        cancellationToken.ThrowIfCancellationRequested();
        if (!TryReadSources(connection, selectedEntityId, cancellationToken, out var sources))
        {
            return Unavailable(
                ProcessRiskProjectionReadState.Failed,
                "The persisted process-risk source coverage is malformed and was not returned.",
                selectedEntityId,
                selectedProcessKey);
        }

        var policy = ProcessRiskProjectionReadPolicy.GetSupportedPolicy(policyId, policyVersion) ??
                     ProcessRiskProjectionReadPolicy.CurrentPolicy;
        var staleContract = ProcessRiskProjectionReadPolicy.HasStaleContract(
            mapperId,
            mapperVersion,
            aggregationVersion,
            policyId,
            policyVersion);

        ProcessRiskScoreProjection? projection = null;
        if (!string.IsNullOrWhiteSpace(projectionJson))
        {
            try
            {
                projection = JsonSerializer.Deserialize<ProcessRiskScoreProjection>(projectionJson);
            }
            catch (JsonException)
            {
                return Unavailable(
                    ProcessRiskProjectionReadState.Failed,
                    "The persisted process-risk projection payload is malformed and was not returned.",
                    selectedEntityId,
                    selectedProcessKey);
            }
        }

        var stale = staleContract ||
                    projection is { SchemaVersion: not ProcessRiskScoreProjection.CurrentSchemaVersion };
        var incompleteSources = !SourcesMatchPolicy(sources, policy);
        var malformedIdentity = !ProcessRiskProjectionReadPolicy.HasValidEvaluationIdentity(
            evaluationId,
            inputIdentityHash,
            mapperId,
            mapperVersion,
            aggregationVersion,
            policyId,
            policyVersion);
        var missingReadyProjection =
            string.Equals(rebuildStatus, "Ready", StringComparison.Ordinal) && projection == null;
        var malformedProjection =
            projection != null && !IsValidProjection(projection, selectedEntityId, selectedProcessKey, sources);
        var readState = stale
            ? ProcessRiskProjectionReadState.Stale
            : incompleteSources || malformedIdentity || missingReadyProjection || malformedProjection
                ? ProcessRiskProjectionReadState.Failed
                : string.Equals(rebuildStatus, "Ready", StringComparison.Ordinal)
                    ? ProcessRiskProjectionReadState.Available
                    : ProcessRiskProjectionReadState.Failed;

        return new ProcessRiskProjectionRecord
        {
            ReadState = readState,
            Diagnostic = stale
                ? "The persisted projection version differs from the current mapper, policy, or aggregation contract and must be rebuilt."
                : incompleteSources || malformedIdentity || missingReadyProjection || malformedProjection
                    ? "The persisted process-risk projection or source coverage is incomplete or malformed and must be rebuilt."
                    : diagnostic,
            ProcessEntityId = selectedEntityId,
            ProcessKey = selectedProcessKey,
            MapperId = mapperId,
            MapperVersion = mapperVersion,
            AggregationVersion = aggregationVersion,
            EvaluationId = evaluationId,
            InputIdentityHash = inputIdentityHash,
            ObservationId = observationId,
            PeAnalysisId = peAnalysisId,
            AuthenticodeVerificationId = authenticodeVerificationId,
            Sources = sources,
            Projection = readState == ProcessRiskProjectionReadState.Available ? projection : null
        };
    }

    public ProcessRiskProjectionDetailsRecord GetCurrentDetails(
        string processEntityId,
        string processKey = "",
        int maxContributors = MaximumContributors,
        CancellationToken cancellationToken = default)
    {
        var current = GetCurrentProjection(processEntityId, processKey, cancellationToken);
        if (current.ReadState != ProcessRiskProjectionReadState.Available)
        {
            return new ProcessRiskProjectionDetailsRecord { Current = current };
        }

        using var connection = _readContext.OpenReadOnlyConnection();
        if (!TableExists(connection, "ProcessRiskProjectionContributors"))
        {
            return FailedDetails(
                current,
                "The process-risk contributor table is missing.");
        }

        if (!TryReadContributors(
                connection,
                current.ProcessEntityId,
                Math.Clamp(maxContributors, 1, MaximumContributors),
                ProcessRiskProjectionReadPolicy.GetSupportedPolicy(
                    current.Projection?.PolicyId,
                    current.Projection?.PolicyVersion) ?? ProcessRiskProjectionReadPolicy.CurrentPolicy,
                cancellationToken,
                out var contributors))
        {
            return FailedDetails(
                current,
                "The persisted process-risk contributor detail is malformed and was not returned.");
        }

        return new ProcessRiskProjectionDetailsRecord
        {
            Current = current,
            Contributors = contributors
        };
    }

    public IReadOnlyList<ProcessRiskContribution> GetContributors(
        string processEntityId,
        string processKey = "",
        int maxCount = 100,
        CancellationToken cancellationToken = default) =>
        GetCurrentDetails(processEntityId, processKey, maxCount, cancellationToken).Contributors;

    private static ProcessRiskProjectionSummaryRecord MaterializeSummary(
        PersistedSummaryCandidate candidate)
    {
        if (ProcessRiskProjectionReadPolicy.HasStaleContract(
                candidate.MapperId,
                candidate.MapperVersion,
                candidate.AggregationVersion,
                candidate.PolicyId,
                candidate.PolicyVersion))
        {
            return ProcessRiskProjectionSummaryRecord.Unavailable(
                ProcessRiskProjectionReadState.Stale,
                "The persisted projection version differs from the current mapper, policy, or aggregation contract and must be rebuilt.",
                candidate.ProcessEntityId);
        }

        if (!string.Equals(candidate.RebuildStatus, "Ready", StringComparison.Ordinal))
        {
            return ProcessRiskProjectionSummaryRecord.Unavailable(
                ProcessRiskProjectionReadState.Failed,
                string.IsNullOrWhiteSpace(candidate.Diagnostic)
                    ? "The process-risk projection rebuild did not complete successfully."
                    : candidate.Diagnostic,
                candidate.ProcessEntityId);
        }

        var policy = ProcessRiskProjectionReadPolicy.GetSupportedPolicy(
                         candidate.PolicyId,
                         candidate.PolicyVersion) ?? ProcessRiskProjectionReadPolicy.CurrentPolicy;
        if (!ProcessRiskProjectionReadPolicy.HasValidEvaluationIdentity(
                candidate.EvaluationId,
                candidate.InputIdentityHash,
                candidate.MapperId,
                candidate.MapperVersion,
                candidate.AggregationVersion,
                candidate.PolicyId,
                candidate.PolicyVersion) ||
            !TryValidatePersistedSources(candidate.Sources, policy) ||
            !Enum.TryParse<ProcessRiskProjectionState>(
                candidate.ProjectionState,
                out var projectionState) ||
            !Enum.IsDefined(projectionState) ||
            !Enum.TryParse<ProcessRiskBand>(candidate.Band, out var band) ||
            !Enum.IsDefined(band) ||
            !ProcessRiskProjectionReadPolicy.IsValidSummaryValues(
                projectionState,
                candidate.Score,
                band,
                candidate.Confidence,
                candidate.Coverage,
                policy) ||
            !DateTime.TryParse(
                candidate.ProjectedUtc,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var projectedUtc) ||
            projectedUtc.Kind != DateTimeKind.Utc)
        {
            return ProcessRiskProjectionSummaryRecord.Unavailable(
                ProcessRiskProjectionReadState.Failed,
                "The persisted process-risk summary is incomplete or malformed and must be rebuilt.",
                candidate.ProcessEntityId);
        }

        return new ProcessRiskProjectionSummaryRecord
        {
            ReadState = ProcessRiskProjectionReadState.Available,
            Diagnostic = candidate.Diagnostic,
            ProcessEntityId = candidate.ProcessEntityId,
            ProcessKey = candidate.ProcessKey,
            ProjectionState = projectionState,
            Score = candidate.Score,
            Band = band,
            Confidence = candidate.Confidence,
            Coverage = candidate.Coverage,
            ProjectedUtc = projectedUtc
        };
    }

    private static bool TryReadSources(
        SqliteConnection connection,
        string processEntityId,
        CancellationToken cancellationToken,
        out IReadOnlyList<ProcessRiskSourceCoverage> sources)
    {
        if (!TableExists(connection, "ProcessRiskProjectionSources"))
        {
            sources = [];
            return false;
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT SourceKind, SourceId, Availability, ConfidenceWeight, Confidence,
                   FindingCount, SignalCount, Diagnostic
            FROM ProcessRiskProjectionSources
            WHERE ProcessEntityId = $ProcessEntityId
            ORDER BY SourceOrder;
            """;
        command.Parameters.AddWithValue("$ProcessEntityId", processEntityId);
        var results = new List<ProcessRiskSourceCoverage>();
        using var cancellationRegistration = cancellationToken.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Enum.TryParse<ProcessRiskSourceKind>(GetString(reader, 0), out var sourceKind) ||
                !Enum.IsDefined(sourceKind) ||
                sourceKind == ProcessRiskSourceKind.Unknown ||
                !Enum.TryParse<AnalysisSourceAvailability>(GetString(reader, 2), out var availability) ||
                !Enum.IsDefined(availability) ||
                availability == AnalysisSourceAvailability.Unknown)
            {
                sources = [];
                return false;
            }

            results.Add(new ProcessRiskSourceCoverage
            {
                SourceKind = sourceKind,
                SourceId = GetString(reader, 1),
                Availability = availability,
                ConfidenceWeight = reader.GetInt32(3),
                Confidence = reader.GetDouble(4),
                FindingCount = reader.GetInt32(5),
                SignalCount = reader.GetInt32(6),
                Diagnostic = GetString(reader, 7)
            });
        }

        sources = results;
        return true;
    }

    private static bool TryReadContributors(
        SqliteConnection connection,
        string processEntityId,
        int maxCount,
        ProcessRiskAggregationPolicy policy,
        CancellationToken cancellationToken,
        out IReadOnlyList<ProcessRiskContribution> contributors)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ContributorOrder, ContributionJson
            FROM ProcessRiskProjectionContributors
            WHERE ProcessEntityId = $ProcessEntityId
            ORDER BY ContributorOrder
            LIMIT $MaxCount;
            """;
        command.Parameters.AddWithValue("$ProcessEntityId", processEntityId);
        command.Parameters.AddWithValue("$MaxCount", maxCount);
        var results = new List<ProcessRiskContribution>();
        using var cancellationRegistration = cancellationToken.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reader.GetInt32(0) != results.Count)
            {
                contributors = [];
                return false;
            }

            ProcessRiskContribution? contribution;
            try
            {
                contribution = JsonSerializer.Deserialize<ProcessRiskContribution>(GetString(reader, 1));
            }
            catch (JsonException)
            {
                contributors = [];
                return false;
            }

            if (contribution == null ||
                contribution.SourceKind == ProcessRiskSourceKind.Unknown ||
                !Enum.IsDefined(contribution.SourceKind) ||
                !string.Equals(contribution.Finding.ProcessEntityId, processEntityId, StringComparison.Ordinal) ||
                !string.Equals(contribution.Signal.ProcessEntityId, processEntityId, StringComparison.Ordinal) ||
                !AnalysisContractPolicy.ValidateFinding(contribution.Finding).Accepted ||
                !AnalysisContractPolicy.ValidateSignal(contribution.Finding, contribution.Signal).Accepted)
            {
                contributors = [];
                return false;
            }

            var sourcePolicy = policy.Sources
                .SingleOrDefault(source => source.SourceKind == contribution.SourceKind);
            if (sourcePolicy == null ||
                !string.Equals(sourcePolicy.SourceId, contribution.SourceId, StringComparison.Ordinal))
            {
                contributors = [];
                return false;
            }

            results.Add(contribution);
        }

        contributors = results;
        return true;
    }

    private static IdentityResolution ResolveIdentity(
        SqliteConnection connection,
        string processEntityId,
        string processKey,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(processEntityId))
        {
            return new IdentityResolution(
                ProcessRiskProjectionReadState.Available,
                processEntityId.Trim(),
                string.Empty);
        }

        if (string.IsNullOrWhiteSpace(processKey))
        {
            return new IdentityResolution(
                ProcessRiskProjectionReadState.NotReady,
                string.Empty,
                "A ProcessEntityId or exact legacy ProcessKey is required; PID-only lookup is unsupported.");
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ProcessEntityId
            FROM ProcessRiskProjections
            WHERE ProcessKey = $ProcessKey
            ORDER BY ProcessEntityId
            LIMIT 2;
            """;
        command.Parameters.AddWithValue("$ProcessKey", processKey.Trim());
        var ids = new List<string>(2);
        using var cancellationRegistration = cancellationToken.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            ids.Add(GetString(reader, 0));
        }

        return ids.Count switch
        {
            1 => new IdentityResolution(ProcessRiskProjectionReadState.Available, ids[0], string.Empty),
            > 1 => new IdentityResolution(
                ProcessRiskProjectionReadState.AmbiguousLegacyKey,
                string.Empty,
                "The exact legacy ProcessKey maps to multiple durable process entities; no projection was selected."),
            _ => new IdentityResolution(
                ProcessRiskProjectionReadState.NotReady,
                string.Empty,
                "No current process-risk projection matches the exact legacy ProcessKey.")
        };
    }

    private static bool IsValidProjection(
        ProcessRiskScoreProjection projection,
        string processEntityId,
        string processKey,
        IReadOnlyList<ProcessRiskSourceCoverage> sources)
    {
        var policy = ProcessRiskProjectionReadPolicy.GetSupportedPolicy(
            projection.PolicyId,
            projection.PolicyVersion);
        if (projection.SchemaVersion != ProcessRiskScoreProjection.CurrentSchemaVersion ||
            !Enum.IsDefined(projection.State) ||
            !Enum.IsDefined(projection.Band) ||
            !string.Equals(projection.ProcessEntityId, processEntityId, StringComparison.Ordinal) ||
            !string.Equals(projection.ProcessKey, processKey, StringComparison.Ordinal) ||
            policy == null ||
            projection.ProjectedUtc.Kind != DateTimeKind.Utc ||
            !ProcessRiskProjectionReadPolicy.IsValidSummaryValues(
                projection.State,
                projection.Score,
                projection.Band,
                projection.Confidence,
                projection.Coverage,
                policy) ||
            !SourcesMatchPolicy(projection.Sources, policy) ||
            projection.Sources.Count != sources.Count)
        {
            return false;
        }

        for (var index = 0; index < sources.Count; index++)
        {
            if (projection.Sources[index] != sources[index])
            {
                return false;
            }
        }

        if (projection.Contributors.Count > MaximumContributors)
        {
            return false;
        }

        foreach (var contribution in projection.Contributors)
        {
            if (contribution.SourceKind == ProcessRiskSourceKind.Unknown ||
                !Enum.IsDefined(contribution.SourceKind) ||
                !string.Equals(contribution.Finding.ProcessEntityId, processEntityId, StringComparison.Ordinal) ||
                !string.Equals(contribution.Signal.ProcessEntityId, processEntityId, StringComparison.Ordinal) ||
                !AnalysisContractPolicy.ValidateFinding(contribution.Finding).Accepted ||
                !AnalysisContractPolicy.ValidateSignal(contribution.Finding, contribution.Signal).Accepted)
            {
                return false;
            }
        }

        return true;
    }

    private static bool SourcesMatchPolicy(
        IReadOnlyList<ProcessRiskSourceCoverage>? sources,
        ProcessRiskAggregationPolicy policy)
    {
        if (sources == null || sources.Count != policy.Sources.Count)
        {
            return false;
        }

        var expected = policy.Sources.OrderBy(source => source.SourceKind).ToArray();
        for (var index = 0; index < expected.Length; index++)
        {
            var source = sources[index];
            if (source.SourceKind != expected[index].SourceKind ||
                !string.Equals(source.SourceId, expected[index].SourceId, StringComparison.Ordinal) ||
                source.Availability == AnalysisSourceAvailability.Unknown ||
                !Enum.IsDefined(source.Availability) ||
                source.ConfidenceWeight != expected[index].ConfidenceWeight ||
                !double.IsFinite(source.Confidence) ||
                source.Confidence < 0 ||
                source.Confidence > 1 ||
                source.FindingCount < 0 ||
                source.SignalCount < 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryValidatePersistedSources(
        IReadOnlyList<PersistedSummarySource> sources,
        ProcessRiskAggregationPolicy policy)
    {
        if (sources.Count != policy.Sources.Count)
        {
            return false;
        }

        var expected = policy.Sources.OrderBy(source => source.SourceKind).ToArray();
        for (var index = 0; index < expected.Length; index++)
        {
            var source = sources[index];
            if (source.Order != index ||
                !Enum.TryParse<ProcessRiskSourceKind>(source.Kind, out var kind) ||
                kind != expected[index].SourceKind ||
                !string.Equals(source.Id, expected[index].SourceId, StringComparison.Ordinal) ||
                !Enum.TryParse<AnalysisSourceAvailability>(source.Availability, out var availability) ||
                availability == AnalysisSourceAvailability.Unknown ||
                !Enum.IsDefined(availability))
            {
                return false;
            }
        }

        return true;
    }

    private static ProcessRiskProjectionDetailsRecord FailedDetails(
        ProcessRiskProjectionRecord current,
        string diagnostic) => new()
    {
        Current = Unavailable(
            ProcessRiskProjectionReadState.Failed,
            diagnostic,
            current.ProcessEntityId,
            current.ProcessKey)
    };

    private static ProcessRiskProjectionRecord Unavailable(
        ProcessRiskProjectionReadState state,
        string diagnostic,
        string processEntityId,
        string processKey) => new()
    {
        ReadState = state,
        Diagnostic = diagnostic,
        ProcessEntityId = processEntityId?.Trim() ?? string.Empty,
        ProcessKey = processKey?.Trim() ?? string.Empty
    };

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $Name LIMIT 1;";
        command.Parameters.AddWithValue("$Name", tableName);
        return command.ExecuteScalar() != null;
    }

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private sealed record IdentityResolution(
        ProcessRiskProjectionReadState State,
        string ProcessEntityId,
        string Diagnostic);

    private sealed record PersistedSummarySource(
        int Order,
        string Kind,
        string Id,
        string Availability);

    private sealed class PersistedSummaryCandidate(
        string processEntityId,
        string processKey,
        string rebuildStatus,
        string diagnostic,
        string mapperId,
        string mapperVersion,
        string aggregationVersion,
        string evaluationId,
        string inputIdentityHash,
        string projectionState,
        int? score,
        string band,
        double confidence,
        double coverage,
        string projectedUtc,
        string policyId,
        string policyVersion)
    {
        public string ProcessEntityId { get; } = processEntityId;
        public string ProcessKey { get; } = processKey;
        public string RebuildStatus { get; } = rebuildStatus;
        public string Diagnostic { get; } = diagnostic;
        public string MapperId { get; } = mapperId;
        public string MapperVersion { get; } = mapperVersion;
        public string AggregationVersion { get; } = aggregationVersion;
        public string EvaluationId { get; } = evaluationId;
        public string InputIdentityHash { get; } = inputIdentityHash;
        public string ProjectionState { get; } = projectionState;
        public int? Score { get; } = score;
        public string Band { get; } = band;
        public double Confidence { get; } = confidence;
        public double Coverage { get; } = coverage;
        public string ProjectedUtc { get; } = projectedUtc;
        public string PolicyId { get; } = policyId;
        public string PolicyVersion { get; } = policyVersion;
        public List<PersistedSummarySource> Sources { get; } = [];
    }
}
