namespace ProcInsider.Services;

/// <summary>
/// Builds the shared read-side event-to-process attachment predicate used by
/// process Listing summaries, event-count sorting, and selected-process detail.
/// Exact durable identity wins. The compatibility route is available only for
/// a uniquely resolved scoped ProcessKey and never associates by PID.
/// </summary>
internal static class ProcessEventAttachmentSql
{
    internal static string Build(
        string eventAlias,
        string processAlias,
        string canonicalProcessTable,
        bool eventHasProcessEntityId,
        bool supportsScopedFallback)
    {
        var (exact, fallback) = BuildBranches(eventAlias, processAlias, canonicalProcessTable,
            eventHasProcessEntityId, supportsScopedFallback);
        return $"(({exact}) OR ({fallback}))";
    }

    // Disjoint branches allow the planner to seek by entity and by key independently.
    // Keeping the legacy scope/uniqueness predicate intact is essential for evidence integrity.
    internal static (string Exact, string Fallback) BuildBranches(
        string eventAlias, string processAlias, string canonicalProcessTable,
        bool eventHasProcessEntityId, bool supportsScopedFallback)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventAlias);
        ArgumentException.ThrowIfNullOrWhiteSpace(processAlias);

        var eventEntityExpression = eventHasProcessEntityId
            ? $"COALESCE({eventAlias}.ProcessEntityId, '')"
            : "''";
        var exactEntityPredicate = eventHasProcessEntityId
            ? $"COALESCE({processAlias}.ProcessEntityId, '') <> '' " +
              $"AND {eventAlias}.ProcessEntityId = {processAlias}.ProcessEntityId"
            : "1 = 0";
        var scopedKeyPredicate = supportsScopedFallback
            ? BuildUniqueScopedKeyPredicate(eventAlias, processAlias, canonicalProcessTable)
            : "1 = 0";

        return (exactEntityPredicate, $"""
                (
                    (COALESCE({processAlias}.ProcessEntityId, '') = ''
                     OR {eventEntityExpression} = '')
                    AND ({scopedKeyPredicate})
                )
            """);
    }

    private static string BuildUniqueScopedKeyPredicate(
        string eventAlias,
        string processAlias,
        string canonicalProcessTable)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalProcessTable);

        return $"""
            COALESCE({processAlias}.ProcessKey, '') <> ''
            AND {eventAlias}.ProcessKey = {processAlias}.ProcessKey
            AND (COALESCE({eventAlias}.CaseId, '') = COALESCE({processAlias}.CaseId, '')
                 OR COALESCE({eventAlias}.CaseId, '') = ''
                 OR COALESCE({processAlias}.CaseId, '') = '')
            AND COALESCE({processAlias}.EvidenceSessionId, '') <> ''
            AND COALESCE({eventAlias}.EvidenceSessionId, '') = COALESCE({processAlias}.EvidenceSessionId, '')
            AND COALESCE({eventAlias}.CaptureId, '') = COALESCE({processAlias}.CaptureId, '')
            AND COALESCE({processAlias}.HostId, '') <> ''
            AND COALESCE({eventAlias}.HostId, '') = COALESCE({processAlias}.HostId, '')
            AND (
                COALESCE({eventAlias}.ExecutionRootId, '') = COALESCE({processAlias}.ExecutionRootId, '')
                OR COALESCE({eventAlias}.ExecutionRootId, '') = ''
                OR COALESCE({processAlias}.ExecutionRootId, '') = ''
                OR (
                    COALESCE({processAlias}.ExecutionRootId, '') = COALESCE({processAlias}.EvidenceSessionId, '')
                    AND instr(
                        COALESCE({eventAlias}.ExecutionRootId, ''),
                        COALESCE({processAlias}.EvidenceSessionId, '') || '-execution-') = 1
                )
                OR (
                    COALESCE({eventAlias}.ExecutionRootId, '') = COALESCE({processAlias}.EvidenceSessionId, '')
                    AND instr(
                        COALESCE({processAlias}.ExecutionRootId, ''),
                        COALESCE({processAlias}.EvidenceSessionId, '') || '-execution-') = 1
                )
            )
            AND (
                SELECT COUNT(*)
                FROM {canonicalProcessTable} candidate
                WHERE candidate.ProcessKey = {eventAlias}.ProcessKey
                  AND (COALESCE(candidate.CaseId, '') = COALESCE({eventAlias}.CaseId, '')
                       OR COALESCE(candidate.CaseId, '') = ''
                       OR COALESCE({eventAlias}.CaseId, '') = '')
                  AND COALESCE(candidate.EvidenceSessionId, '') <> ''
                  AND COALESCE(candidate.EvidenceSessionId, '') = COALESCE({eventAlias}.EvidenceSessionId, '')
                  AND COALESCE(candidate.CaptureId, '') = COALESCE({eventAlias}.CaptureId, '')
                  AND COALESCE(candidate.HostId, '') <> ''
                  AND COALESCE(candidate.HostId, '') = COALESCE({eventAlias}.HostId, '')
                  AND (
                      COALESCE(candidate.ExecutionRootId, '') = COALESCE({eventAlias}.ExecutionRootId, '')
                      OR COALESCE(candidate.ExecutionRootId, '') = ''
                      OR COALESCE({eventAlias}.ExecutionRootId, '') = ''
                      OR (
                          COALESCE(candidate.ExecutionRootId, '') = COALESCE(candidate.EvidenceSessionId, '')
                          AND instr(
                              COALESCE({eventAlias}.ExecutionRootId, ''),
                              COALESCE(candidate.EvidenceSessionId, '') || '-execution-') = 1
                      )
                      OR (
                          COALESCE({eventAlias}.ExecutionRootId, '') = COALESCE(candidate.EvidenceSessionId, '')
                          AND instr(
                              COALESCE(candidate.ExecutionRootId, ''),
                              COALESCE(candidate.EvidenceSessionId, '') || '-execution-') = 1
                      )
                  )
            ) = 1
            """;
    }
}
