using System;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Narrow read contract for selected-process event, module, and handle details
/// plus their process-row count summaries.
/// </summary>
public interface ISelectedProcessEvidenceQueryService
{
    ProcessArtifactCounts GetArtifactCounts(string processKey, string processEntityId = "");

    ProcessSourceEventCounts GetEventCounts(string processKey, string processEntityId = "");

    IReadOnlyDictionary<string, ProcessSourceEventCounts> CountEventsByProcessAndSource();

    IReadOnlyDictionary<string, int> CountModulesByProcess(bool includeUnloaded);

    IReadOnlyDictionary<string, int> CountHandlesByProcess(bool includeClosed);

    IReadOnlyList<TelemetryEventRecord> GetEventsForProcess(
        string processKey,
        string? source,
        int maxCount,
        string processEntityId = "");

    IReadOnlyList<ModuleObservationRecord> GetModulesForProcess(
        string processKey,
        bool includeUnloaded,
        int maxCount = 10000,
        string processEntityId = "");

    IReadOnlyList<HandleObservationRecord> GetHandlesForProcess(
        string processKey,
        bool includeClosed,
        int maxCount = 10000,
        string processEntityId = "");

    IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeQueryPlans();
}

/// <summary>
/// Focused SQLite owner for process-attached event/module/handle detail and
/// count reads. The validated <see cref="SqliteStagingQueryService"/> remains
/// the compatibility facade and database-open authority.
/// </summary>
internal sealed class SelectedProcessEvidenceQueryService : ISelectedProcessEvidenceQueryService
{
    private const int MaxProcessDetailArtifactRows = 10000;
    private readonly SqliteReadQueryContext _readContext;

    internal SelectedProcessEvidenceQueryService(SqliteReadQueryContext readContext)
    {
        _readContext = readContext;
    }

    public ProcessArtifactCounts GetArtifactCounts(string processKey, string processEntityId = "")
    {
        if (!HasProcessIdentity(processKey, processEntityId))
        {
            return new ProcessArtifactCounts();
        }

        return _readContext.MeasureRead(
            "GetArtifactCounts",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                var modulePredicate = BuildProcessAttachmentPredicate(
                    connection,
                    "Modules",
                    "m",
                    processEntityId,
                    processKey);
                var handlePredicate = BuildProcessAttachmentPredicate(
                    connection,
                    "Handles",
                    "h",
                    processEntityId,
                    processKey);
                command.CommandText = $"""
                    SELECT
                        (SELECT COUNT(*) FROM Modules m WHERE {modulePredicate}),
                        (SELECT COUNT(*) FROM Handles h WHERE {handlePredicate});
                    """;
                AddIdentityParameters(command, processKey, processEntityId);
                using var reader = command.ExecuteReader();
                if (!reader.Read())
                {
                    return new ProcessArtifactCounts();
                }

                return new ProcessArtifactCounts
                {
                    ModuleCount = GetInt(reader, 0),
                    HandleCount = GetInt(reader, 1)
                };
            },
            IdentityDiagnostic(processKey, processEntityId),
            counts => counts.ModuleCount + counts.HandleCount);
    }

    public ProcessSourceEventCounts GetEventCounts(string processKey, string processEntityId = "")
    {
        if (!HasProcessIdentity(processKey, processEntityId))
        {
            return new ProcessSourceEventCounts();
        }

        return _readContext.MeasureRead(
            "GetEventCounts",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                var predicate = BuildProcessAttachmentPredicate(
                    connection,
                    "ProcessEvents",
                    "e",
                    processEntityId,
                    processKey);
                command.CommandText = $"""
                    SELECT Source, COUNT(*)
                    FROM ProcessEvents e
                    WHERE {predicate}
                    GROUP BY Source;
                    """;
                AddIdentityParameters(command, processKey, processEntityId);

                var counts = new ProcessSourceEventCounts();
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    ApplyEventCount(counts, GetString(reader, 0), GetInt(reader, 1));
                }

                return counts;
            },
            IdentityDiagnostic(processKey, processEntityId),
            CountEventRows);
    }

    public IReadOnlyDictionary<string, ProcessSourceEventCounts> CountEventsByProcessAndSource()
    {
        return _readContext.MeasureRead(
            "CountEventsByProcessAndSource",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                command.CommandText = BuildAllProcessEventCountSql(connection);

                var countsByProcess = new Dictionary<string, ProcessSourceEventCounts>(StringComparer.Ordinal);
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    var processKey = GetString(reader, 0);
                    if (!countsByProcess.TryGetValue(processKey, out var counts))
                    {
                        counts = new ProcessSourceEventCounts();
                        countsByProcess[processKey] = counts;
                    }

                    ApplyEventCount(counts, GetString(reader, 1), GetInt(reader, 2));
                }

                return (IReadOnlyDictionary<string, ProcessSourceEventCounts>)countsByProcess;
            },
            "canonical ProcessEntityId-to-ProcessKey recovery with legacy fallback",
            counts => counts.Count);
    }

    public IReadOnlyDictionary<string, int> CountModulesByProcess(bool includeUnloaded)
    {
        return _readContext.MeasureRead(
            "CountModulesByProcess",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                command.CommandText = BuildAllProcessModuleCountSql(connection, includeUnloaded);
                return ReadProcessCountDictionary(command);
            },
            $"include_unloaded={includeUnloaded}",
            counts => counts.Count);
    }

    public IReadOnlyDictionary<string, int> CountHandlesByProcess(bool includeClosed)
    {
        return _readContext.MeasureRead(
            "CountHandlesByProcess",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                command.CommandText = BuildAllProcessHandleCountSql(connection, includeClosed);
                return ReadProcessCountDictionary(command);
            },
            $"include_closed={includeClosed}",
            counts => counts.Count);
    }

    public IReadOnlyList<TelemetryEventRecord> GetEventsForProcess(
        string processKey,
        string? source,
        int maxCount,
        string processEntityId = "")
    {
        if (maxCount <= 0 || !HasProcessIdentity(processKey, processEntityId))
        {
            return Array.Empty<TelemetryEventRecord>();
        }

        return _readContext.MeasureRead(
            "GetEventsForProcess",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                var entity = SelectOptionalColumn(connection, "ProcessEvents", "e", "ProcessEntityId", "''");
                var entityValue = ColumnExists(connection, "ProcessEvents", "ProcessEntityId")
                    ? "e.ProcessEntityId"
                    : "''";
                var sourceRun = SelectOptionalColumn(connection, "ProcessEvents", "e", "SourceRunId", "''");
                var ingestionJob = SelectOptionalColumn(connection, "ProcessEvents", "e", "IngestionJobId", "''");
                var processPredicate = BuildProcessAttachmentPredicate(
                    connection,
                    "ProcessEvents",
                    "e",
                    processEntityId,
                    processKey);
                var sourcePredicate = string.IsNullOrWhiteSpace(source)
                    ? string.Empty
                    : "AND e.Source = $Source";
                command.CommandText = $"""
                    SELECT e.SequenceId, e.TimestampUtc, e.Source, e.ProcessKey, e.ProcessId, e.ProcessGuid,
                           e.ProcessStartTimeUtc, e.ProcessName, e.ParentProcessId, e.EventCode, e.Category,
                           e.Action, e.Target, e.Summary, e.Details, e.RiskFlags, e.IsInteresting, e.RepeatCount,
                           e.RawProvider, e.RawLogName, e.RawRecordIdText, e.CorrelationMethod,
                           e.CaseId, e.EvidenceSessionId, e.CaptureId, e.SourceIdentityId, e.HostId, e.ExecutionRootId,
                           {entity},
                           CASE WHEN {entityValue} <> '' THEN 'Asserted' ELSE 'Unresolved' END AS CorrelationState,
                           e.CorrelationMethod, 0 AS CandidateCount,
                           CASE WHEN {entityValue} <> '' THEN 'Entity-first selected-process query.' ELSE 'Legacy ProcessKey compatibility query.' END AS CorrelationDiagnostics,
                           {sourceRun}, {ingestionJob}
                    FROM ProcessEvents e
                    WHERE {processPredicate} {sourcePredicate}
                    ORDER BY e.TimestampUtc DESC, e.SequenceId DESC
                    LIMIT $MaxCount;
                    """;
                AddIdentityParameters(command, processKey, processEntityId);
                if (!string.IsNullOrWhiteSpace(source))
                {
                    command.Parameters.AddWithValue("$Source", source);
                }

                command.Parameters.AddWithValue("$MaxCount", Math.Clamp(maxCount, 1, 100000));
                return ReadEvents(command);
            },
            $"{IdentityDiagnostic(processKey, processEntityId)}; source={source ?? "all"}; max={maxCount}",
            events => events.Count);
    }

    public IReadOnlyList<ModuleObservationRecord> GetModulesForProcess(
        string processKey,
        bool includeUnloaded,
        int maxCount = MaxProcessDetailArtifactRows,
        string processEntityId = "")
    {
        if (!HasProcessIdentity(processKey, processEntityId) || maxCount <= 0)
        {
            return Array.Empty<ModuleObservationRecord>();
        }

        return _readContext.MeasureRead(
            "GetModulesForProcess",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                var entity = SelectOptionalColumn(connection, "Modules", "m", "ProcessEntityId", "''");
                var sourceRun = SelectOptionalColumn(connection, "Modules", "m", "SourceRunId", "''");
                var ingestionJob = SelectOptionalColumn(connection, "Modules", "m", "IngestionJobId", "''");
                var processPredicate = BuildProcessAttachmentPredicate(
                    connection,
                    "Modules",
                    "m",
                    processEntityId,
                    processKey);
                var statePredicate = includeUnloaded ? string.Empty : "AND m.State <> 'Unloaded'";
                command.CommandText = $"""
                    SELECT m.SequenceId, m.ProcessKey, m.ProcessId, m.ProcessGuid, m.ModuleKey, m.ModuleName,
                           m.FullPath, m.BaseAddress, m.ModuleMemorySize, m.FileVersion, m.CompanyName,
                           m.Description, m.Sha256Hash, m.FirstSeenUtc, m.LastSeenUtc, m.UnloadedUtc,
                           m.State, m.Sources, m.LastSource, m.CaseId, m.EvidenceSessionId, m.CaptureId,
                           m.SourceIdentityId, m.HostId, m.ExecutionRootId,
                           {entity}, {sourceRun}, {ingestionJob}
                    FROM Modules m
                    WHERE {processPredicate} {statePredicate}
                    ORDER BY m.ModuleName, m.FullPath
                    LIMIT $MaxCount;
                    """;
                AddIdentityParameters(command, processKey, processEntityId);
                command.Parameters.AddWithValue(
                    "$MaxCount",
                    Math.Clamp(maxCount, 1, MaxProcessDetailArtifactRows));
                return ReadModules(command);
            },
            $"{IdentityDiagnostic(processKey, processEntityId)}; include_unloaded={includeUnloaded}; max={maxCount}",
            modules => modules.Count);
    }

    public IReadOnlyList<HandleObservationRecord> GetHandlesForProcess(
        string processKey,
        bool includeClosed,
        int maxCount = MaxProcessDetailArtifactRows,
        string processEntityId = "")
    {
        if (!HasProcessIdentity(processKey, processEntityId) || maxCount <= 0)
        {
            return Array.Empty<HandleObservationRecord>();
        }

        return _readContext.MeasureRead(
            "GetHandlesForProcess",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                using var command = connection.CreateCommand();
                var entity = SelectOptionalColumn(connection, "Handles", "h", "ProcessEntityId", "''");
                var sourceRun = SelectOptionalColumn(connection, "Handles", "h", "SourceRunId", "''");
                var ingestionJob = SelectOptionalColumn(connection, "Handles", "h", "IngestionJobId", "''");
                var processPredicate = BuildProcessAttachmentPredicate(
                    connection,
                    "Handles",
                    "h",
                    processEntityId,
                    processKey);
                var statePredicate = includeClosed ? string.Empty : "AND h.State <> 'Closed'";
                command.CommandText = $"""
                    SELECT h.SequenceId, h.ProcessKey, h.ProcessId, h.HandleKey, h.HandleValue, h.HandleValueNumeric,
                           h.ObjectType, h.ObjectName, h.GrantedAccess, h.GrantedAccessValue, h.HandleAttributes,
                           h.HandleAttributesValue, h.ObjectAddress, h.FirstSeenUtc, h.LastSeenUtc, h.ClosedUtc,
                           h.State, h.LastSource, h.CaseId, h.EvidenceSessionId, h.CaptureId,
                           h.SourceIdentityId, h.HostId, h.ExecutionRootId,
                           {entity}, {sourceRun}, {ingestionJob}
                    FROM Handles h
                    WHERE {processPredicate} {statePredicate}
                    ORDER BY CASE h.State WHEN 'Closed' THEN 1 ELSE 0 END, h.ObjectType, h.ObjectName
                    LIMIT $MaxCount;
                    """;
                AddIdentityParameters(command, processKey, processEntityId);
                command.Parameters.AddWithValue(
                    "$MaxCount",
                    Math.Clamp(maxCount, 1, MaxProcessDetailArtifactRows));
                return ReadHandles(command);
            },
            $"{IdentityDiagnostic(processKey, processEntityId)}; include_closed={includeClosed}; max={maxCount}",
            handles => handles.Count);
    }

    public IReadOnlyList<SqliteQueryPlanRecord> GetRepresentativeQueryPlans()
    {
        return _readContext.MeasureRead(
            "GetSelectedProcessEvidenceRepresentativeQueryPlans",
            () =>
            {
                using var connection = _readContext.OpenReadOnlyConnection();
                var plans = new List<SqliteQueryPlanRecord>();
                var identity = ReadFirstProcessIdentity(connection);

                if (HasProcessIdentity(identity.ProcessKey, identity.ProcessEntityId))
                {
                    var eventPredicate = BuildProcessAttachmentPredicate(
                        connection,
                        "ProcessEvents",
                        "e",
                        identity.ProcessEntityId,
                        identity.ProcessKey);
                    var modulePredicate = BuildProcessAttachmentPredicate(
                        connection,
                        "Modules",
                        "m",
                        identity.ProcessEntityId,
                        identity.ProcessKey);
                    var handlePredicate = BuildProcessAttachmentPredicate(
                        connection,
                        "Handles",
                        "h",
                        identity.ProcessEntityId,
                        identity.ProcessKey);

                    AddIdentityPlan(
                        plans,
                        connection,
                        "selected-process events",
                        $"""
                        SELECT e.SequenceId
                        FROM ProcessEvents e
                        WHERE {eventPredicate}
                        ORDER BY e.TimestampUtc DESC, e.SequenceId DESC
                        LIMIT $MaxCount;
                        """,
                        identity,
                        addLimit: true);
                    AddIdentityPlan(
                        plans,
                        connection,
                        "selected-process modules",
                        $"""
                        SELECT m.SequenceId
                        FROM Modules m
                        WHERE {modulePredicate} AND m.State <> 'Unloaded'
                        ORDER BY m.ModuleName, m.FullPath
                        LIMIT $MaxCount;
                        """,
                        identity,
                        addLimit: true);
                    AddIdentityPlan(
                        plans,
                        connection,
                        "selected-process handles",
                        $"""
                        SELECT h.SequenceId
                        FROM Handles h
                        WHERE {handlePredicate} AND h.State <> 'Closed'
                        ORDER BY CASE h.State WHEN 'Closed' THEN 1 ELSE 0 END, h.ObjectType, h.ObjectName
                        LIMIT $MaxCount;
                        """,
                        identity,
                        addLimit: true);
                    AddIdentityPlan(
                        plans,
                        connection,
                        "selected-process event counts",
                        $"""
                        SELECT e.Source, COUNT(*)
                        FROM ProcessEvents e
                        WHERE {eventPredicate}
                        GROUP BY e.Source;
                        """,
                        identity);
                    AddIdentityPlan(
                        plans,
                        connection,
                        "selected-process artifact counts",
                        $"""
                        SELECT
                            (SELECT COUNT(*) FROM Modules m WHERE {modulePredicate}),
                            (SELECT COUNT(*) FROM Handles h WHERE {handlePredicate});
                        """,
                        identity);
                }

                AddQueryPlan(
                    plans,
                    connection,
                    "all-process event counts",
                    BuildAllProcessEventCountSql(connection));
                AddQueryPlan(
                    plans,
                    connection,
                    "all-process module counts",
                    BuildAllProcessModuleCountSql(connection, includeUnloaded: true));
                AddQueryPlan(
                    plans,
                    connection,
                    "all-process handle counts",
                    BuildAllProcessHandleCountSql(connection, includeClosed: true));

                return (IReadOnlyList<SqliteQueryPlanRecord>)plans;
            },
            "selected-process event/module/handle detail and count plans",
            plans => plans.Count);
    }

    internal static IReadOnlyList<TelemetryEventRecord> ReadEvents(SqliteCommand command)
    {
        var events = new List<TelemetryEventRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var record = new TelemetryEventRecord
            {
                SequenceId = GetLong(reader, 0),
                TimestampUtc = GetDateTime(reader, 1) ?? DateTime.UtcNow,
                Source = GetString(reader, 2),
                ProcessKey = GetString(reader, 3),
                ProcessId = GetInt(reader, 4),
                ProcessGuid = GetString(reader, 5),
                ProcessStartTimeUtc = GetDateTime(reader, 6),
                ProcessName = GetString(reader, 7),
                ParentProcessId = GetInt(reader, 8),
                EventCode = GetNullableInt(reader, 9),
                Category = GetEnum(reader, 10, ProcessEventCategory.Windows),
                Action = GetEnum(reader, 11, ProcessEventAction.WindowsEvent),
                Target = GetString(reader, 12),
                Summary = GetString(reader, 13),
                Details = GetString(reader, 14),
                RiskFlags = GetString(reader, 15),
                IsInteresting = GetInt(reader, 16) != 0,
                RepeatCount = GetInt(reader, 17),
                RawProvider = GetString(reader, 18),
                RawLogName = GetString(reader, 19),
                RawRecordId = GetString(reader, 20),
                CorrelationMethod = GetString(reader, 21)
            };
            if (reader.FieldCount >= 28)
            {
                record.CaseId = GetString(reader, 22);
                record.EvidenceSessionId = GetString(reader, 23);
                record.CaptureId = GetString(reader, 24);
                record.SourceIdentityId = GetString(reader, 25);
                record.HostId = GetString(reader, 26);
                record.ExecutionRootId = GetString(reader, 27);
            }
            if (reader.FieldCount >= 33)
            {
                record.ProcessEntityId = GetString(reader, 28);
                record.CorrelationState = GetEnum(reader, 29, EvidenceCorrelationState.Unresolved);
                record.CorrelationMethod = GetString(reader, 30);
                record.CorrelationCandidateCount = GetInt(reader, 31);
                record.CorrelationDiagnostics = GetString(reader, 32);
            }
            if (reader.FieldCount >= 35)
            {
                record.SourceRunId = GetString(reader, 33);
                record.IngestionJobId = GetString(reader, 34);
            }

            events.Add(record);
        }

        return events;
    }

    internal static IReadOnlyList<ModuleObservationRecord> ReadModules(SqliteCommand command)
    {
        var modules = new List<ModuleObservationRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var record = new ModuleObservationRecord
            {
                SequenceId = GetLong(reader, 0),
                ProcessKey = GetString(reader, 1),
                ProcessId = GetInt(reader, 2),
                ProcessGuid = GetString(reader, 3),
                ModuleKey = GetString(reader, 4),
                ModuleName = GetString(reader, 5),
                FullPath = GetString(reader, 6),
                BaseAddress = GetString(reader, 7),
                ModuleMemorySize = GetLong(reader, 8),
                FileVersion = GetString(reader, 9),
                CompanyName = GetString(reader, 10),
                Description = GetString(reader, 11),
                Sha256Hash = GetString(reader, 12),
                FirstSeenUtc = GetDateTime(reader, 13) ?? DateTime.UtcNow,
                LastSeenUtc = GetDateTime(reader, 14) ?? DateTime.UtcNow,
                UnloadedUtc = GetDateTime(reader, 15),
                State = GetEnum(reader, 16, ModuleObservationState.Loaded),
                Sources = GetString(reader, 17),
                LastSource = GetString(reader, 18)
            };
            if (reader.FieldCount >= 25)
            {
                record.CaseId = GetString(reader, 19);
                record.EvidenceSessionId = GetString(reader, 20);
                record.CaptureId = GetString(reader, 21);
                record.SourceIdentityId = GetString(reader, 22);
                record.HostId = GetString(reader, 23);
                record.ExecutionRootId = GetString(reader, 24);
            }
            if (reader.FieldCount >= 28)
            {
                record.ProcessEntityId = GetString(reader, 25);
                record.SourceRunId = GetString(reader, 26);
                record.IngestionJobId = GetString(reader, 27);
            }

            modules.Add(record);
        }

        return modules;
    }

    internal static IReadOnlyList<HandleObservationRecord> ReadHandles(SqliteCommand command)
    {
        var handles = new List<HandleObservationRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var record = new HandleObservationRecord
            {
                SequenceId = GetLong(reader, 0),
                ProcessKey = GetString(reader, 1),
                ProcessId = GetInt(reader, 2),
                HandleKey = GetString(reader, 3),
                HandleValue = GetString(reader, 4),
                HandleValueNumeric = GetUInt64(reader, 5),
                ObjectType = GetString(reader, 6),
                ObjectName = GetString(reader, 7),
                GrantedAccess = GetString(reader, 8),
                GrantedAccessValue = GetUInt32(reader, 9),
                HandleAttributes = GetString(reader, 10),
                HandleAttributesValue = GetUInt32(reader, 11),
                ObjectAddress = GetString(reader, 12),
                FirstSeenUtc = GetDateTime(reader, 13) ?? DateTime.UtcNow,
                LastSeenUtc = GetDateTime(reader, 14) ?? DateTime.UtcNow,
                ClosedUtc = GetDateTime(reader, 15),
                State = GetEnum(reader, 16, HandleObservationState.Open),
                LastSource = GetString(reader, 17)
            };
            if (reader.FieldCount >= 24)
            {
                record.CaseId = GetString(reader, 18);
                record.EvidenceSessionId = GetString(reader, 19);
                record.CaptureId = GetString(reader, 20);
                record.SourceIdentityId = GetString(reader, 21);
                record.HostId = GetString(reader, 22);
                record.ExecutionRootId = GetString(reader, 23);
            }
            if (reader.FieldCount >= 27)
            {
                record.ProcessEntityId = GetString(reader, 24);
                record.SourceRunId = GetString(reader, 25);
                record.IngestionJobId = GetString(reader, 26);
            }

            handles.Add(record);
        }

        return handles;
    }

    private static string BuildAllProcessEventCountSql(SqliteConnection connection)
    {
        var hasEntities = TableExists(connection, "ProcessEntities") &&
                          ColumnExists(connection, "ProcessEvents", "ProcessEntityId");
        return hasEntities
            ? """
              SELECT COALESCE(NULLIF(pe.ProcessKey, ''), e.ProcessKey), e.Source, COUNT(*)
              FROM ProcessEvents e
              LEFT JOIN ProcessEntities pe ON pe.ProcessEntityId = e.ProcessEntityId
              WHERE COALESCE(NULLIF(pe.ProcessKey, ''), e.ProcessKey) <> ''
              GROUP BY COALESCE(NULLIF(pe.ProcessKey, ''), e.ProcessKey), e.Source;
              """
            : """
              SELECT ProcessKey, Source, COUNT(*)
              FROM ProcessEvents
              WHERE ProcessKey IS NOT NULL AND ProcessKey <> ''
              GROUP BY ProcessKey, Source;
              """;
    }

    private static string BuildAllProcessModuleCountSql(SqliteConnection connection, bool includeUnloaded)
    {
        var hasEntities = TableExists(connection, "ProcessEntities") &&
                          ColumnExists(connection, "Modules", "ProcessEntityId");
        return hasEntities
            ? includeUnloaded
                ? """
                  SELECT COALESCE(NULLIF(pe.ProcessKey, ''), m.ProcessKey), COUNT(*)
                  FROM Modules m
                  LEFT JOIN ProcessEntities pe ON pe.ProcessEntityId = m.ProcessEntityId
                  WHERE COALESCE(NULLIF(pe.ProcessKey, ''), m.ProcessKey) <> ''
                  GROUP BY COALESCE(NULLIF(pe.ProcessKey, ''), m.ProcessKey);
                  """
                : """
                  SELECT COALESCE(NULLIF(pe.ProcessKey, ''), m.ProcessKey), COUNT(*)
                  FROM Modules m
                  LEFT JOIN ProcessEntities pe ON pe.ProcessEntityId = m.ProcessEntityId
                  WHERE COALESCE(NULLIF(pe.ProcessKey, ''), m.ProcessKey) <> '' AND m.State <> 'Unloaded'
                  GROUP BY COALESCE(NULLIF(pe.ProcessKey, ''), m.ProcessKey);
                  """
            : includeUnloaded
                ? """
                  SELECT ProcessKey, COUNT(*)
                  FROM Modules
                  WHERE ProcessKey IS NOT NULL AND ProcessKey <> ''
                  GROUP BY ProcessKey;
                  """
                : """
                  SELECT ProcessKey, COUNT(*)
                  FROM Modules
                  WHERE ProcessKey IS NOT NULL AND ProcessKey <> '' AND State <> 'Unloaded'
                  GROUP BY ProcessKey;
                  """;
    }

    private static string BuildAllProcessHandleCountSql(SqliteConnection connection, bool includeClosed)
    {
        var hasEntities = TableExists(connection, "ProcessEntities") &&
                          ColumnExists(connection, "Handles", "ProcessEntityId");
        return hasEntities
            ? includeClosed
                ? """
                  SELECT COALESCE(NULLIF(pe.ProcessKey, ''), h.ProcessKey), COUNT(*)
                  FROM Handles h
                  LEFT JOIN ProcessEntities pe ON pe.ProcessEntityId = h.ProcessEntityId
                  WHERE COALESCE(NULLIF(pe.ProcessKey, ''), h.ProcessKey) <> ''
                  GROUP BY COALESCE(NULLIF(pe.ProcessKey, ''), h.ProcessKey);
                  """
                : """
                  SELECT COALESCE(NULLIF(pe.ProcessKey, ''), h.ProcessKey), COUNT(*)
                  FROM Handles h
                  LEFT JOIN ProcessEntities pe ON pe.ProcessEntityId = h.ProcessEntityId
                  WHERE COALESCE(NULLIF(pe.ProcessKey, ''), h.ProcessKey) <> '' AND h.State <> 'Closed'
                  GROUP BY COALESCE(NULLIF(pe.ProcessKey, ''), h.ProcessKey);
                  """
            : includeClosed
                ? """
                  SELECT ProcessKey, COUNT(*)
                  FROM Handles
                  WHERE ProcessKey IS NOT NULL AND ProcessKey <> ''
                  GROUP BY ProcessKey;
                  """
                : """
                  SELECT ProcessKey, COUNT(*)
                  FROM Handles
                  WHERE ProcessKey IS NOT NULL AND ProcessKey <> '' AND State <> 'Closed'
                  GROUP BY ProcessKey;
                  """;
    }

    private static IReadOnlyDictionary<string, int> ReadProcessCountDictionary(SqliteCommand command)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            counts[GetString(reader, 0)] = GetInt(reader, 1);
        }

        return counts;
    }

    private static void ApplyEventCount(ProcessSourceEventCounts counts, string source, int value)
    {
        switch (source)
        {
            case "Runtime":
                counts.RuntimeEventCount = value;
                break;
            case "ETW":
                counts.EtwEventCount = value;
                break;
            case "Security":
                counts.SecurityEventCount = value;
                break;
            case "PowerShell":
                counts.PowerShellEventCount = value;
                break;
            case "WindowsOther":
                counts.OtherWindowsEventCount = value;
                break;
            case "Sysmon":
                counts.SysmonEventCount = value;
                break;
        }
    }

    private static long CountEventRows(ProcessSourceEventCounts counts)
        => counts.RuntimeEventCount +
           counts.EtwEventCount +
           counts.SecurityEventCount +
           counts.PowerShellEventCount +
           counts.OtherWindowsEventCount +
           counts.SysmonEventCount;

    private static bool HasProcessIdentity(string processKey, string processEntityId)
        => !string.IsNullOrWhiteSpace(processKey) || !string.IsNullOrWhiteSpace(processEntityId);

    private static string IdentityDiagnostic(string processKey, string processEntityId)
        => !string.IsNullOrWhiteSpace(processEntityId)
            ? $"process_entity_id={processEntityId}"
            : $"process_key={processKey}";

    private static void AddIdentityParameters(
        SqliteCommand command,
        string processKey,
        string processEntityId)
    {
        command.Parameters.AddWithValue("$ProcessKey", processKey ?? string.Empty);
        command.Parameters.AddWithValue("$ProcessEntityId", processEntityId ?? string.Empty);
    }

    private static string BuildProcessAttachmentPredicate(
        SqliteConnection connection,
        string tableName,
        string alias,
        string processEntityId,
        string processKey)
    {
        return !string.IsNullOrWhiteSpace(processEntityId) &&
               ColumnExists(connection, tableName, "ProcessEntityId")
            ? $"{alias}.ProcessEntityId = $ProcessEntityId"
            : !string.IsNullOrWhiteSpace(processKey)
                ? $"{alias}.ProcessKey = $ProcessKey"
                : "1 = 0";
    }

    private static string SelectOptionalColumn(
        SqliteConnection connection,
        string tableName,
        string alias,
        string columnName,
        string fallbackExpression)
    {
        return ColumnExists(connection, tableName, columnName)
            ? $"{alias}.{columnName}"
            : $"{fallbackExpression} AS {columnName}";
    }

    private static bool ColumnExists(SqliteConnection connection, string tableName, string columnName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({tableName});";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (string.Equals(GetString(reader, 1), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TableExists(SqliteConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM sqlite_master
            WHERE name = $TableName
              AND type IN ('table', 'view')
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$TableName", tableName);
        return command.ExecuteScalar() != null;
    }

    private static (string ProcessKey, string ProcessEntityId) ReadFirstProcessIdentity(
        SqliteConnection connection)
    {
        var processTable = TableExists(connection, "ProcessEntities")
            ? "ProcessEntities"
            : "Processes";
        var entityColumn = ColumnExists(connection, processTable, "ProcessEntityId")
            ? "ProcessEntityId"
            : "'' AS ProcessEntityId";
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT ProcessKey, {entityColumn}
            FROM {processTable}
            WHERE COALESCE(ProcessKey, '') <> ''
            ORDER BY ProcessKey
            LIMIT 1;
            """;
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? (GetString(reader, 0), GetString(reader, 1))
            : (string.Empty, string.Empty);
    }

    private static void AddIdentityPlan(
        ICollection<SqliteQueryPlanRecord> plans,
        SqliteConnection connection,
        string operation,
        string sql,
        (string ProcessKey, string ProcessEntityId) identity,
        bool addLimit = false)
    {
        AddQueryPlan(
            plans,
            connection,
            operation,
            sql,
            command =>
            {
                AddIdentityParameters(command, identity.ProcessKey, identity.ProcessEntityId);
                if (addLimit)
                {
                    command.Parameters.AddWithValue("$MaxCount", 250);
                }
            });
    }

    private static void AddQueryPlan(
        ICollection<SqliteQueryPlanRecord> plans,
        SqliteConnection connection,
        string operation,
        string sql,
        Action<SqliteCommand>? configure = null)
    {
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"EXPLAIN QUERY PLAN {sql.Trim().TrimEnd(';')};";
            configure?.Invoke(command);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                plans.Add(new SqliteQueryPlanRecord(
                    operation,
                    GetInt(reader, 0),
                    GetInt(reader, 1),
                    GetInt(reader, 2),
                    GetString(reader, 3)));
            }
        }
        catch (Exception ex) when (ex is SqliteException or InvalidOperationException)
        {
            plans.Add(new SqliteQueryPlanRecord(
                operation,
                -1,
                -1,
                -1,
                $"query plan unavailable: {ex.Message}"));
        }
    }

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static int GetInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt32(ordinal);

    private static int? GetNullableInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);

    private static long GetLong(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt64(ordinal);

    private static uint GetUInt32(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : unchecked((uint)reader.GetInt64(ordinal));

    private static ulong GetUInt64(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : unchecked((ulong)reader.GetInt64(ordinal));

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ||
               !DateTimeOffset.TryParse(reader.GetString(ordinal), out var value)
            ? null
            : value.UtcDateTime;
    }

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum fallback)
        where TEnum : struct
    {
        return !reader.IsDBNull(ordinal) &&
               Enum.TryParse<TEnum>(reader.GetString(ordinal), out var value)
            ? value
            : fallback;
    }
}
