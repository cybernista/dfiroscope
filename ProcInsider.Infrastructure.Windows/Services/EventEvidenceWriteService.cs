using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal interface IEventEvidenceWriteService
{
    void AddEvent(TelemetryEventRecord processEvent);
    void AddEvents(IEnumerable<TelemetryEventRecord> events);
}

internal sealed class EventEvidenceWriteService : IEventEvidenceWriteService
{
    private readonly SqliteWriteTransactionContext _context;

    internal EventEvidenceWriteService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public void AddEvent(TelemetryEventRecord processEvent)
    {
        ArgumentNullException.ThrowIfNull(processEvent);
        _context.Execute(() =>
        {
            var sourceId = _context.EnsureTelemetrySource(processEvent.Source, "Event");
            using var command = CreateEventInsertCommand();
            WriteEventCore(command, processEvent, sourceId, processEvent.Source);
        });
    }

    public void AddEvents(IEnumerable<TelemetryEventRecord> events)
    {
        ArgumentNullException.ThrowIfNull(events);
        var snapshot = events.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            var sourceIds = new Dictionary<string, int?>(StringComparer.OrdinalIgnoreCase);
            using var command = CreateEventInsertCommand();
            command.Prepare();
            foreach (var processEvent in snapshot)
            {
                ArgumentNullException.ThrowIfNull(processEvent);
                var sourceName = processEvent.Source ?? string.Empty;
                if (!sourceIds.TryGetValue(sourceName, out var sourceId))
                {
                    sourceId = _context.EnsureTelemetrySource(sourceName, "Event");
                    sourceIds[sourceName] = sourceId;
                }

                WriteEventCore(command, processEvent, sourceId, sourceName);
            }
        });
    }

    private void WriteEventCore(
        SqliteCommand command,
        TelemetryEventRecord processEvent,
        int? sourceId,
        string sourceName)
    {
        var identity = _context.ResolveEvidenceIdentity(processEvent, "Event", sourceName);
        ApplyEvidenceIdentity(processEvent, identity);
        var evidenceId = processEvent.SequenceId.ToString(CultureInfo.InvariantCulture);
        var attachment = _context.PrepareProcessAttachedEvidence(
            processEvent,
            EvidenceReferenceKind.Event,
            evidenceId,
            processEvent.ProcessId,
            processEvent.ProcessGuid,
            processEvent.ProcessStartTimeUtc,
            processEvent.ProcessName,
            processEvent.TimestampUtc);
        ApplyEventAttachment(processEvent, attachment);
        SetEventInsertParameters(command, processEvent, sourceId, identity);
        command.ExecuteNonQuery();
        _context.UpsertSearchIndex(CreateSearchIndexRow(processEvent));
        var input = CreateEventCorrelationInput(processEvent);
        _context.ApplyPersistedEventCorrelationProvenance(input, processEvent.SequenceId);
        _context.UpsertEvidenceCorrelationInput(input);
        _context.EnsureInitialCorrelationDecision(input);
        _context.PersistProcessAttachedRelation(
            processEvent,
            EvidenceReferenceKind.Event,
            evidenceId,
            EvidenceRelationType.OwnedBy,
            attachment,
            processEvent.TimestampUtc,
            rawInputId: processEvent.RawRecordId);
    }

    private SqliteCommand CreateEventInsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT OR REPLACE INTO ProcessEvents (
                SequenceId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceId, ProcessEntityId, SourceRunId, IngestionJobId,
                TimestampUtc, Source, ProcessKey, ProcessId, ProcessGuid,
                ProcessStartTimeUtc, ProcessName, ParentProcessId, EventCode, Category, Action,
                Target, Summary, Details, RiskFlags, IsInteresting, RepeatCount, RawProvider,
                RawLogName, RawRecordIdText, CorrelationMethod, DedupKey)
            VALUES (
                $SequenceId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceId, $ProcessEntityId, $SourceRunId, $IngestionJobId,
                $TimestampUtc, $Source, $ProcessKey, $ProcessId, $ProcessGuid,
                $ProcessStartTimeUtc, $ProcessName, $ParentProcessId, $EventCode, $Category, $Action,
                $Target, $Summary, $Details, $RiskFlags, $IsInteresting, $RepeatCount, $RawProvider,
                $RawLogName, $RawRecordIdText, $CorrelationMethod, $DedupKey);
            """);
        foreach (var parameterName in new[]
        {
            "$SequenceId", "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId", "$ExecutionRootId",
            "$SourceId", "$ProcessEntityId", "$SourceRunId", "$IngestionJobId",
            "$TimestampUtc", "$Source", "$ProcessKey", "$ProcessId", "$ProcessGuid",
            "$ProcessStartTimeUtc", "$ProcessName", "$ParentProcessId", "$EventCode", "$Category", "$Action",
            "$Target", "$Summary", "$Details", "$RiskFlags", "$IsInteresting", "$RepeatCount", "$RawProvider",
            "$RawLogName", "$RawRecordIdText", "$CorrelationMethod", "$DedupKey"
        })
        {
            SqliteWriteTransactionContext.Add(command, parameterName, null);
        }

        return command;
    }

    private static void SetEventInsertParameters(
        SqliteCommand command,
        TelemetryEventRecord processEvent,
        int? sourceId,
        EvidenceIdentity identity)
    {
        Set(command, "$SequenceId", processEvent.SequenceId);
        Set(command, "$CaseId", identity.CaseId);
        Set(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Set(command, "$CaptureId", identity.CaptureId);
        Set(command, "$SourceIdentityId", identity.SourceIdentityId);
        Set(command, "$HostId", identity.HostId);
        Set(command, "$ExecutionRootId", identity.ExecutionRootId);
        Set(command, "$SourceId", sourceId);
        Set(command, "$ProcessEntityId", processEvent.ProcessEntityId);
        Set(command, "$SourceRunId", EmptyToNull(processEvent.SourceRunId));
        Set(command, "$IngestionJobId", processEvent.IngestionJobId);
        Set(command, "$TimestampUtc", processEvent.TimestampUtc);
        Set(command, "$Source", processEvent.Source);
        Set(command, "$ProcessKey", processEvent.ProcessKey);
        Set(command, "$ProcessId", processEvent.ProcessId);
        Set(command, "$ProcessGuid", processEvent.ProcessGuid);
        Set(command, "$ProcessStartTimeUtc", processEvent.ProcessStartTimeUtc);
        Set(command, "$ProcessName", processEvent.ProcessName);
        Set(command, "$ParentProcessId", processEvent.ParentProcessId);
        Set(command, "$EventCode", processEvent.EventCode);
        Set(command, "$Category", processEvent.Category.ToString());
        Set(command, "$Action", processEvent.Action.ToString());
        Set(command, "$Target", processEvent.Target);
        Set(command, "$Summary", processEvent.Summary);
        Set(command, "$Details", processEvent.Details);
        Set(command, "$RiskFlags", processEvent.RiskFlags);
        Set(command, "$IsInteresting", processEvent.IsInteresting ? 1 : 0);
        Set(command, "$RepeatCount", processEvent.RepeatCount);
        Set(command, "$RawProvider", processEvent.RawProvider);
        Set(command, "$RawLogName", processEvent.RawLogName);
        Set(command, "$RawRecordIdText", processEvent.RawRecordId);
        Set(command, "$CorrelationMethod", processEvent.CorrelationMethod);
        Set(command, "$DedupKey", BuildEventDedupKey(processEvent));
    }

    internal static SearchIndexRow CreateSearchIndexRow(TelemetryEventRecord processEvent)
        => new SearchIndexRow
        {
            Kind = "Event",
            RecordKey = processEvent.SequenceId.ToString(),
            ProcessKey = processEvent.ProcessKey,
            ProcessId = processEvent.ProcessId.ToString(),
            ProcessName = processEvent.ProcessName,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(processEvent.TimestampUtc),
            Source = processEvent.Source,
            Title = $"{processEvent.Category} | {processEvent.Action}",
            Subtitle = string.IsNullOrWhiteSpace(processEvent.Summary) ? processEvent.Target : processEvent.Summary,
            ProcessNameText = processEvent.ProcessName,
            TargetText = processEvent.Target,
            SummaryText = processEvent.Summary,
            DetailsText = processEvent.Details,
            RiskFlagsText = processEvent.RiskFlags,
            EventCodeText = processEvent.EventCode?.ToString() ?? string.Empty,
            ActionText = processEvent.Action.ToString(),
            CategoryText = processEvent.Category.ToString(),
            ProcessGuidText = processEvent.ProcessGuid
        }.WithSearchText();

    private static EvidenceCorrelationInput CreateEventCorrelationInput(TelemetryEventRecord processEvent)
        => new()
        {
            InputId = $"event:{processEvent.SequenceId}",
            EvidenceKind = EvidenceReferenceKind.Event,
            EvidenceId = processEvent.SequenceId.ToString(CultureInfo.InvariantCulture),
            EvidenceType = $"{processEvent.Category}/{processEvent.Action}",
            Source = processEvent.Source,
            RelationType = EvidenceRelationType.ObservedProcess,
            CaseId = processEvent.CaseId,
            EvidenceSessionId = processEvent.EvidenceSessionId,
            CaptureId = processEvent.CaptureId,
            SourceIdentityId = processEvent.SourceIdentityId,
            HostId = processEvent.HostId,
            ExecutionRootId = processEvent.ExecutionRootId,
            RawInputId = processEvent.RawRecordId,
            ProcessId = processEvent.ProcessId,
            ProcessStartTimeUtc = processEvent.ProcessStartTimeUtc,
            ProcessGuid = processEvent.ProcessGuid,
            ProcessName = processEvent.ProcessName,
            ProcessPath = processEvent.Action == ProcessEventAction.ProcessStart ? processEvent.Target : string.Empty,
            SourceNativeId = processEvent.ProcessKey,
            ObservedUtc = processEvent.TimestampUtc,
            CreatedUtc = processEvent.TimestampUtc
        };

    private static void ApplyEvidenceIdentity(IHasEvidenceIdentity record, EvidenceIdentity identity)
    {
        record.CaseId = identity.CaseId;
        record.EvidenceSessionId = identity.EvidenceSessionId;
        record.CaptureId = identity.CaptureId;
        record.SourceIdentityId = identity.SourceIdentityId;
        record.HostId = identity.HostId;
        record.ExecutionRootId = identity.ExecutionRootId;
    }

    private static void ApplyEventAttachment(
        TelemetryEventRecord processEvent,
        ProcessEvidenceAttachmentResolution resolution)
    {
        processEvent.CorrelationState = resolution.State;
        processEvent.CorrelationMethod = resolution.Method;
        processEvent.CorrelationCandidateCount = resolution.CandidateCount;
        processEvent.CorrelationDiagnostics = resolution.Diagnostics;
    }

    private static object? EmptyToNull(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    private static void Set(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = SqliteWriteTransactionContext.FormatDate(dateTime);
        }

        command.Parameters[name].Value = value ?? DBNull.Value;
    }

    private static string BuildEventDedupKey(TelemetryEventRecord processEvent)
        => string.Join(
            "|",
            processEvent.Source,
            processEvent.RawProvider,
            processEvent.RawLogName,
            processEvent.RawRecordId,
            processEvent.TimestampUtc.ToString("O"),
            processEvent.ProcessKey,
            processEvent.EventCode?.ToString() ?? string.Empty,
            processEvent.Action,
            processEvent.Target);
}
