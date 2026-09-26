using ProcInsider.Models;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services;

public enum SigmaRiskEvidenceMaterializationFailure
{
    None = 0,
    InvalidRequest = 1,
    InputLimitExceeded = 2,
    InvalidRuleIdentity = 3,
    DuplicateRuleIdentity = 4,
    MissingRuleIdentity = 5,
    UnsupportedSourceKind = 6,
    InvalidFindingIdentity = 7,
    SourceNotFound = 8,
    AmbiguousSource = 9,
    NormalizationRejected = 10,
    DuplicateMatchIdentity = 11,
    ProcessMatchLimitExceeded = 12
}

public sealed record SigmaRiskRuleIdentity
{
    public string RuleId { get; init; } = string.Empty;

    public string RuleVersion { get; init; } = string.Empty;

    public string RuleContentHashSha256 { get; init; } = string.Empty;
}

public sealed record SigmaRiskEvidenceMaterializationRequest
{
    public DateTime EvaluatedUtc { get; init; }

    public IReadOnlyList<SigmaRiskRuleIdentity> RuleIdentities { get; init; } = [];

    public IReadOnlyList<SigmaFinding> Findings { get; init; } = [];

    public IReadOnlyList<TelemetryEventRecord> Events { get; init; } = [];

    public IReadOnlyList<ProcessObservation> ProcessObservations { get; init; } = [];

    public IReadOnlyList<ModuleObservationRecord> ModuleObservations { get; init; } = [];

    public IReadOnlyList<HandleObservationRecord> HandleObservations { get; init; } = [];
}

public sealed record SigmaRiskEvidenceMaterializationDiagnostic
{
    public SigmaRiskEvidenceMaterializationFailure Failure { get; init; }

    public SigmaRiskEvidenceNormalizationFailure NormalizationFailure { get; init; }

    public string RuleId { get; init; } = string.Empty;

    public string SourceKind { get; init; } = string.Empty;

    public string ProcessEntityId { get; init; } = string.Empty;

    public string SourceEvidenceId { get; init; } = string.Empty;

    public string SourceRunId { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;
}

public sealed record SigmaRiskEvidenceMaterializationResult
{
    public IReadOnlyList<LocalProcessSigmaEvidence> Evidence { get; init; } = [];

    public IReadOnlyList<SigmaRiskEvidenceMaterializationDiagnostic> Diagnostics { get; init; } = [];

    public int AcceptedFindingCount { get; init; }

    public int RejectedFindingCount { get; init; }
}

/// <summary>
/// Resolves a bounded completed Sigma run to exact persisted sources and delegates
/// one-row conversion to <see cref="SigmaRiskEvidenceNormalizer"/>. The returned
/// rows are in-memory mapper inputs only; this owner does not persist or schedule them.
/// </summary>
public static class SigmaRiskEvidenceMaterializer
{
    public const int MaximumRuleIdentities = 1000;
    public const int MaximumFindings = 1000;
    public const int MaximumSourceRecordsPerKind = 10000;

    private const int MaximumIdentityLength = 512;
    private const string EventSourceKind = "Event";
    private const string ProcessSourceKind = "Process";
    private const string ModuleSourceKind = "Module";
    private const string HandleSourceKind = "Handle";

    public static SigmaRiskEvidenceMaterializationResult Materialize(
        SigmaRiskEvidenceMaterializationRequest? request)
    {
        if (request == null ||
            request.RuleIdentities == null ||
            request.Findings == null ||
            request.Events == null ||
            request.ProcessObservations == null ||
            request.ModuleObservations == null ||
            request.HandleObservations == null ||
            request.EvaluatedUtc.Kind != DateTimeKind.Utc)
        {
            return FailRequest(
                request?.Findings?.Count ?? 0,
                SigmaRiskEvidenceMaterializationFailure.InvalidRequest,
                "A UTC evaluation boundary and non-null bounded Sigma/source collections are required.");
        }

        if (request.RuleIdentities.Count > MaximumRuleIdentities ||
            request.Findings.Count > MaximumFindings ||
            request.Events.Count > MaximumSourceRecordsPerKind ||
            request.ProcessObservations.Count > MaximumSourceRecordsPerKind ||
            request.ModuleObservations.Count > MaximumSourceRecordsPerKind ||
            request.HandleObservations.Count > MaximumSourceRecordsPerKind)
        {
            return FailRequest(
                request.Findings.Count,
                SigmaRiskEvidenceMaterializationFailure.InputLimitExceeded,
                "The Sigma materialization input exceeds a fixed rule, finding, or per-source bound.");
        }

        var diagnostics = new List<SigmaRiskEvidenceMaterializationDiagnostic>();
        var rules = BuildRuleIndex(request.RuleIdentities, diagnostics);
        var events = BuildIndex(
            request.Events,
            source => new EventSourceKey(
                source.ProcessEntityId,
                source.ProcessKey,
                source.TimestampUtc.Ticks,
                source.CorrelationState,
                source.CorrelationMethod,
                source.CorrelationCandidateCount));
        var processes = BuildIndex(
            request.ProcessObservations.Where(source => source?.Fields != null),
            source => new ProcessSourceKey(
                source.ProcessEntityId,
                source.Fields.ProcessKey,
                source.ObservedUtc.Ticks));
        var modules = BuildIndex(
            request.ModuleObservations,
            source => new ArtifactSourceKey(
                source.ModuleKey,
                source.SourceRunId,
                source.ProcessEntityId,
                source.ProcessKey,
                source.LastSeenUtc.Ticks));
        var handles = BuildIndex(
            request.HandleObservations,
            source => new ArtifactSourceKey(
                source.HandleKey,
                source.SourceRunId,
                source.ProcessEntityId,
                source.ProcessKey,
                source.LastSeenUtc.Ticks));

        var accepted = new List<MaterializedFinding>();
        foreach (var finding in request.Findings
                     .OrderBy(FindingSortKey, StringComparer.Ordinal))
        {
            if (finding == null)
            {
                diagnostics.Add(Diagnostic(
                    SigmaRiskEvidenceMaterializationFailure.InvalidFindingIdentity,
                    null,
                    "A null Sigma finding cannot be materialized."));
                continue;
            }

            if (!Required(finding.RuleId))
            {
                diagnostics.Add(Diagnostic(
                    SigmaRiskEvidenceMaterializationFailure.InvalidFindingIdentity,
                    finding,
                    "A Sigma finding requires one bounded rule ID."));
                continue;
            }

            if (!rules.TryGetValue(finding.RuleId, out var rule))
            {
                diagnostics.Add(Diagnostic(
                    SigmaRiskEvidenceMaterializationFailure.MissingRuleIdentity,
                    finding,
                    "The finding does not have one unique valid versioned rule identity."));
                continue;
            }

            var decision = ResolveAndNormalize(
                request.EvaluatedUtc,
                rule,
                finding,
                events,
                processes,
                modules,
                handles,
                diagnostics);
            if (decision is { Accepted: true, Evidence: not null })
            {
                accepted.Add(new MaterializedFinding(finding, decision.Evidence));
            }
        }

        var evidence = new List<LocalProcessSigmaEvidence>();
        foreach (var processGroup in accepted
                     .GroupBy(item => item.Evidence.ProcessEntityId, StringComparer.Ordinal)
                     .OrderBy(group => group.Key, StringComparer.Ordinal))
        {
            var duplicateMatchIds = processGroup
                .GroupBy(item => item.Evidence.MatchId, StringComparer.Ordinal)
                .Where(group => group.Count() > 1)
                .Select(group => group.Key)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();
            if (duplicateMatchIds.Length > 0)
            {
                foreach (var matchId in duplicateMatchIds)
                {
                    var duplicate = processGroup
                        .Where(item => string.Equals(item.Evidence.MatchId, matchId, StringComparison.Ordinal))
                        .OrderBy(item => FindingSortKey(item.Finding), StringComparer.Ordinal)
                        .First();
                    diagnostics.Add(Diagnostic(
                        SigmaRiskEvidenceMaterializationFailure.DuplicateMatchIdentity,
                        duplicate.Finding,
                        "Duplicate normalized Sigma match identity suppressed the complete process group."));
                }

                continue;
            }

            if (processGroup.Count() > LocalProcessRiskMapper.MaximumSigmaEvidence)
            {
                var first = processGroup
                    .OrderBy(item => item.Evidence.MatchId, StringComparer.Ordinal)
                    .First();
                diagnostics.Add(Diagnostic(
                    SigmaRiskEvidenceMaterializationFailure.ProcessMatchLimitExceeded,
                    first.Finding,
                    $"More than {LocalProcessRiskMapper.MaximumSigmaEvidence} normalized Sigma matches suppressed the complete process group."));
                continue;
            }

            evidence.AddRange(processGroup
                .Select(item => item.Evidence)
                .OrderBy(item => item.MatchId, StringComparer.Ordinal));
        }

        var orderedEvidence = evidence
            .OrderBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ThenBy(item => item.MatchId, StringComparer.Ordinal)
            .ToArray();
        var orderedDiagnostics = diagnostics
            .OrderBy(item => item.Failure)
            .ThenBy(item => item.RuleId, StringComparer.Ordinal)
            .ThenBy(item => item.SourceKind, StringComparer.Ordinal)
            .ThenBy(item => item.ProcessEntityId, StringComparer.Ordinal)
            .ThenBy(item => item.SourceEvidenceId, StringComparer.Ordinal)
            .ThenBy(item => item.SourceRunId, StringComparer.Ordinal)
            .ThenBy(item => item.NormalizationFailure)
            .ThenBy(item => item.Message, StringComparer.Ordinal)
            .ToArray();
        return new SigmaRiskEvidenceMaterializationResult
        {
            Evidence = orderedEvidence,
            Diagnostics = orderedDiagnostics,
            AcceptedFindingCount = orderedEvidence.Length,
            RejectedFindingCount = request.Findings.Count - orderedEvidence.Length
        };
    }

    private static Dictionary<string, SigmaRiskRuleIdentity> BuildRuleIndex(
        IReadOnlyList<SigmaRiskRuleIdentity> identities,
        List<SigmaRiskEvidenceMaterializationDiagnostic> diagnostics)
    {
        var rules = new Dictionary<string, SigmaRiskRuleIdentity>(StringComparer.Ordinal);
        var validIdentities = new List<SigmaRiskRuleIdentity>();
        foreach (var identity in identities)
        {
            if (identity == null ||
                !Required(identity.RuleId) ||
                !Required(identity.RuleVersion) ||
                !ValidSha256(identity.RuleContentHashSha256))
            {
                diagnostics.Add(new SigmaRiskEvidenceMaterializationDiagnostic
                {
                    Failure = SigmaRiskEvidenceMaterializationFailure.InvalidRuleIdentity,
                    RuleId = identity?.RuleId ?? string.Empty,
                    Message = "Rule ID, explicit version, and SHA-256 content identity are required."
                });
                continue;
            }

            validIdentities.Add(identity);
        }

        foreach (var group in validIdentities
                     .OrderBy(identity => identity.RuleId, StringComparer.Ordinal)
                     .ThenBy(identity => identity.RuleVersion, StringComparer.Ordinal)
                     .ThenBy(identity => identity.RuleContentHashSha256, StringComparer.Ordinal)
                     .GroupBy(identity => identity.RuleId, StringComparer.Ordinal))
        {
            if (group.Count() != 1)
            {
                diagnostics.Add(new SigmaRiskEvidenceMaterializationDiagnostic
                {
                    Failure = SigmaRiskEvidenceMaterializationFailure.DuplicateRuleIdentity,
                    RuleId = group.Key,
                    Message = "Each Sigma rule ID must have exactly one version and content hash in a materialization run."
                });
                continue;
            }

            var identity = group.Single();
            rules.Add(identity.RuleId, identity);
        }

        return rules;
    }

    private static SigmaRiskEvidenceNormalizationDecision? ResolveAndNormalize(
        DateTime evaluatedUtc,
        SigmaRiskRuleIdentity rule,
        SigmaFinding finding,
        IReadOnlyDictionary<EventSourceKey, List<TelemetryEventRecord>> events,
        IReadOnlyDictionary<ProcessSourceKey, List<ProcessObservation>> processes,
        IReadOnlyDictionary<ArtifactSourceKey, List<ModuleObservationRecord>> modules,
        IReadOnlyDictionary<ArtifactSourceKey, List<HandleObservationRecord>> handles,
        List<SigmaRiskEvidenceMaterializationDiagnostic> diagnostics)
    {
        SigmaRiskEvidenceNormalizationRequest normalization;
        switch (finding.SourceKind)
        {
            case EventSourceKind:
                if (finding.TimestampUtc == null)
                {
                    diagnostics.Add(Diagnostic(
                        SigmaRiskEvidenceMaterializationFailure.InvalidFindingIdentity,
                        finding,
                        "An Event finding requires an exact UTC source timestamp."));
                    return null;
                }

                var eventKey = new EventSourceKey(
                    finding.ProcessEntityId,
                    finding.ProcessKey,
                    finding.TimestampUtc.Value.Ticks,
                    finding.CorrelationState,
                    finding.CorrelationMethod,
                    finding.CorrelationCandidateCount);
                if (!TryResolve(events, eventKey, finding, diagnostics, out TelemetryEventRecord? sourceEvent))
                {
                    return null;
                }

                normalization = CreateNormalization(evaluatedUtc, rule, finding) with { Event = sourceEvent };
                break;

            case ProcessSourceKind:
                if (finding.TimestampUtc == null)
                {
                    diagnostics.Add(Diagnostic(
                        SigmaRiskEvidenceMaterializationFailure.InvalidFindingIdentity,
                        finding,
                        "A Process finding requires an exact UTC observation timestamp."));
                    return null;
                }

                var processKey = new ProcessSourceKey(
                    finding.ProcessEntityId,
                    finding.ProcessKey,
                    finding.TimestampUtc.Value.Ticks);
                if (!TryResolve(processes, processKey, finding, diagnostics, out ProcessObservation? observation))
                {
                    return null;
                }

                normalization = CreateNormalization(evaluatedUtc, rule, finding) with
                {
                    ProcessObservation = observation
                };
                break;

            case ModuleSourceKind:
            case HandleSourceKind:
                if (finding.TimestampUtc == null ||
                    !Required(finding.SourceEvidenceId) ||
                    !Required(finding.SourceRunId))
                {
                    diagnostics.Add(Diagnostic(
                        SigmaRiskEvidenceMaterializationFailure.InvalidFindingIdentity,
                        finding,
                        "A Module or Handle finding requires exact source-evidence, source-run, process, and UTC identity."));
                    return null;
                }

                var artifactKey = new ArtifactSourceKey(
                    finding.SourceEvidenceId,
                    finding.SourceRunId,
                    finding.ProcessEntityId,
                    finding.ProcessKey,
                    finding.TimestampUtc.Value.Ticks);
                if (string.Equals(finding.SourceKind, ModuleSourceKind, StringComparison.Ordinal))
                {
                    if (!TryResolve(modules, artifactKey, finding, diagnostics, out ModuleObservationRecord? module))
                    {
                        return null;
                    }

                    normalization = CreateNormalization(evaluatedUtc, rule, finding) with
                    {
                        ModuleObservation = module
                    };
                }
                else
                {
                    if (!TryResolve(handles, artifactKey, finding, diagnostics, out HandleObservationRecord? handle))
                    {
                        return null;
                    }

                    normalization = CreateNormalization(evaluatedUtc, rule, finding) with
                    {
                        HandleObservation = handle
                    };
                }

                break;

            default:
                diagnostics.Add(Diagnostic(
                    SigmaRiskEvidenceMaterializationFailure.UnsupportedSourceKind,
                    finding,
                    "Only persisted Event, Process, Module, and Handle findings can be materialized."));
                return null;
        }

        var decision = SigmaRiskEvidenceNormalizer.Normalize(normalization);
        if (!decision.Accepted || decision.Evidence == null)
        {
            diagnostics.Add(Diagnostic(
                SigmaRiskEvidenceMaterializationFailure.NormalizationRejected,
                finding,
                decision.Diagnostic,
                decision.Failure));
        }

        return decision;
    }

    private static SigmaRiskEvidenceNormalizationRequest CreateNormalization(
        DateTime evaluatedUtc,
        SigmaRiskRuleIdentity rule,
        SigmaFinding finding) =>
        new()
        {
            Finding = finding,
            RuleId = rule.RuleId,
            RuleVersion = rule.RuleVersion,
            RuleContentHashSha256 = rule.RuleContentHashSha256,
            EvaluatedUtc = evaluatedUtc
        };

    private static bool TryResolve<TKey, TSource>(
        IReadOnlyDictionary<TKey, List<TSource>> index,
        TKey key,
        SigmaFinding finding,
        List<SigmaRiskEvidenceMaterializationDiagnostic> diagnostics,
        out TSource? source)
        where TKey : notnull
        where TSource : class
    {
        source = null;
        if (!index.TryGetValue(key, out var candidates) || candidates.Count == 0)
        {
            diagnostics.Add(Diagnostic(
                SigmaRiskEvidenceMaterializationFailure.SourceNotFound,
                finding,
                "No exact persisted source matches the Sigma finding identity."));
            return false;
        }

        if (candidates.Count != 1)
        {
            diagnostics.Add(Diagnostic(
                SigmaRiskEvidenceMaterializationFailure.AmbiguousSource,
                finding,
                "More than one persisted source matches the Sigma finding identity."));
            return false;
        }

        source = candidates[0];
        return true;
    }

    private static Dictionary<TKey, List<TSource>> BuildIndex<TKey, TSource>(
        IEnumerable<TSource> sources,
        Func<TSource, TKey> keySelector)
        where TKey : notnull
        where TSource : class
    {
        var index = new Dictionary<TKey, List<TSource>>();
        foreach (var source in sources)
        {
            if (source == null)
            {
                continue;
            }

            var key = keySelector(source);
            if (!index.TryGetValue(key, out var matches))
            {
                matches = [];
                index.Add(key, matches);
            }

            matches.Add(source);
        }

        return index;
    }

    private static SigmaRiskEvidenceMaterializationResult FailRequest(
        int rejectedFindingCount,
        SigmaRiskEvidenceMaterializationFailure failure,
        string message) =>
        new()
        {
            Diagnostics =
            [
                new SigmaRiskEvidenceMaterializationDiagnostic
                {
                    Failure = failure,
                    Message = message
                }
            ],
            RejectedFindingCount = rejectedFindingCount
        };

    private static SigmaRiskEvidenceMaterializationDiagnostic Diagnostic(
        SigmaRiskEvidenceMaterializationFailure failure,
        SigmaFinding? finding,
        string message,
        SigmaRiskEvidenceNormalizationFailure normalizationFailure =
            SigmaRiskEvidenceNormalizationFailure.None) =>
        new()
        {
            Failure = failure,
            NormalizationFailure = normalizationFailure,
            RuleId = finding?.RuleId ?? string.Empty,
            SourceKind = finding?.SourceKind ?? string.Empty,
            ProcessEntityId = finding?.ProcessEntityId ?? string.Empty,
            SourceEvidenceId = finding?.SourceEvidenceId ?? string.Empty,
            SourceRunId = finding?.SourceRunId ?? string.Empty,
            Message = message
        };

    private static string FindingSortKey(SigmaFinding? finding) =>
        finding == null
            ? string.Empty
            : string.Join(
                "\u001f",
                finding.RuleId,
                finding.SourceKind,
                finding.ProcessEntityId,
                finding.ProcessKey,
                finding.TimestampUtc?.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
                ((int)finding.CorrelationState).ToString(System.Globalization.CultureInfo.InvariantCulture),
                finding.CorrelationMethod,
                finding.CorrelationCandidateCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                finding.SourceEvidenceId,
                finding.SourceRunId);

    private static bool Required(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= MaximumIdentityLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal);

    private static bool ValidSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private sealed record MaterializedFinding(
        SigmaFinding Finding,
        LocalProcessSigmaEvidence Evidence);

    private readonly record struct EventSourceKey(
        string ProcessEntityId,
        string ProcessKey,
        long TimestampTicks,
        EvidenceCorrelationState CorrelationState,
        string CorrelationMethod,
        int CorrelationCandidateCount);

    private readonly record struct ProcessSourceKey(
        string ProcessEntityId,
        string ProcessKey,
        long TimestampTicks);

    private readonly record struct ArtifactSourceKey(
        string SourceEvidenceId,
        string SourceRunId,
        string ProcessEntityId,
        string ProcessKey,
        long TimestampTicks);
}
