using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal interface IProcessEvidenceWriteService
{
    void UpsertProcess(ProcessRecord process);
    void UpsertProcesses(IEnumerable<ProcessRecord> processes);
    void UpsertProcessStatistic(ProcessStatisticsRecord sample);
    void UpsertProcessStatistics(IEnumerable<ProcessStatisticsRecord> samples);
    void UpsertProcessBatch(
        IEnumerable<ProcessRecord> processes,
        IEnumerable<ProcessStatisticsRecord> samples);
    ProcessObservationWriteResult AppendProcessObservationBatch(
        IEnumerable<ProcessObservation> observations,
        IEnumerable<ProcessAlias> aliases,
        IEnumerable<ProcessStatisticsRecord>? statistics = null);
    void RebuildProcessProjection();
    void BackfillMissingProcessObservationsAndRebuild();
}

internal sealed class ProcessEvidenceWriteService : IProcessEvidenceWriteService
{
    private readonly SqliteWriteTransactionContext _context;

    internal ProcessEvidenceWriteService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public void UpsertProcess(ProcessRecord process)
    {
        ArgumentNullException.ThrowIfNull(process);
        _context.Execute(() => UpsertProcessCore(process));
    }

    public void UpsertProcesses(IEnumerable<ProcessRecord> processes)
    {
        ArgumentNullException.ThrowIfNull(processes);
        var snapshot = processes.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            foreach (var process in snapshot)
            {
                ArgumentNullException.ThrowIfNull(process);
                UpsertProcessCore(process);
            }
        });
    }

    public void UpsertProcessStatistic(ProcessStatisticsRecord sample)
    {
        ArgumentNullException.ThrowIfNull(sample);
        _context.Execute(() => UpsertProcessStatisticCore(sample));
    }

    public void UpsertProcessStatistics(IEnumerable<ProcessStatisticsRecord> samples)
    {
        ArgumentNullException.ThrowIfNull(samples);
        var snapshot = samples.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            foreach (var sample in snapshot)
            {
                ArgumentNullException.ThrowIfNull(sample);
                UpsertProcessStatisticCore(sample);
            }
        });
    }

    public void UpsertProcessBatch(
        IEnumerable<ProcessRecord> processes,
        IEnumerable<ProcessStatisticsRecord> samples)
    {
        ArgumentNullException.ThrowIfNull(processes);
        ArgumentNullException.ThrowIfNull(samples);
        var processSnapshot = processes.ToList();
        var sampleSnapshot = samples.ToList();
        if (processSnapshot.Count == 0 && sampleSnapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            foreach (var process in processSnapshot)
            {
                ArgumentNullException.ThrowIfNull(process);
                UpsertProcessCore(process);
            }

            foreach (var sample in sampleSnapshot)
            {
                ArgumentNullException.ThrowIfNull(sample);
                UpsertProcessStatisticCore(sample);
            }
        });
    }

    private void UpsertProcessCore(ProcessRecord process)
    {
        var sourceId = _context.EnsureTelemetrySource(process.LastSource, "Process");
        var identity = _context.ResolveEvidenceIdentity(process, "Process", process.LastSource);
        ApplyEvidenceIdentity(process, identity);
        process.ProcessEntityId = ResolveOrCreateProcessEntityId(process);
        process.ParentProcessEntityId = ResolveProcessAlias(
            process.ParentProcessKey,
            ProcessAliasKind.LegacyProcessKey,
            process);
        using var command = CreateCommand("""
            INSERT INTO Processes (
                ProcessKey, ProcessEntityId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceId, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                ParentProcessId, ParentProcessKey, ParentProcessEntityId, ParentProcessName, ProcessName, ProcessPath,
                CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc, LastObservedUtc,
                LastSource, ModuleCaptureStatus, ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError,
                HandleCaptureStatus, HandleCount, HandleLastCapturedUtc, HandleCaptureError)
            VALUES (
                $ProcessKey, $ProcessEntityId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceId, $ProcessId, $ProcessGuid, $StartTimeUtc, $EndTimeUtc, $Status,
                $ParentProcessId, $ParentProcessKey, $ParentProcessEntityId, $ParentProcessName, $ProcessName, $ProcessPath,
                $CommandLine, $UserName, $SessionId, $Architecture, $CpuUsage, $MemoryUsageBytes,
                $CompanyName, $FileDescription, $Sha256Hash, $TreeDepth, $FirstObservedUtc, $LastObservedUtc,
                $LastSource, $ModuleCaptureStatus, $ModuleCount, $ModuleLastCapturedUtc, $ModuleCaptureError,
                $HandleCaptureStatus, $HandleCount, $HandleLastCapturedUtc, $HandleCaptureError)
            ON CONFLICT(ProcessKey) DO UPDATE SET
                ProcessEntityId = excluded.ProcessEntityId,
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceId = excluded.SourceId,
                ProcessId = excluded.ProcessId,
                ProcessGuid = excluded.ProcessGuid,
                StartTimeUtc = excluded.StartTimeUtc,
                EndTimeUtc = excluded.EndTimeUtc,
                Status = excluded.Status,
                ParentProcessId = excluded.ParentProcessId,
                ParentProcessKey = excluded.ParentProcessKey,
                ParentProcessEntityId = excluded.ParentProcessEntityId,
                ParentProcessName = excluded.ParentProcessName,
                ProcessName = excluded.ProcessName,
                ProcessPath = excluded.ProcessPath,
                CommandLine = excluded.CommandLine,
                UserName = excluded.UserName,
                SessionId = excluded.SessionId,
                Architecture = excluded.Architecture,
                CpuUsage = excluded.CpuUsage,
                MemoryUsageBytes = excluded.MemoryUsageBytes,
                CompanyName = excluded.CompanyName,
                FileDescription = excluded.FileDescription,
                Sha256Hash = excluded.Sha256Hash,
                TreeDepth = excluded.TreeDepth,
                FirstObservedUtc = CASE
                    WHEN Processes.FirstObservedUtc IS NULL OR Processes.FirstObservedUtc = ''
                    THEN excluded.FirstObservedUtc
                    ELSE Processes.FirstObservedUtc
                END,
                LastObservedUtc = excluded.LastObservedUtc,
                LastSource = excluded.LastSource,
                ModuleCaptureStatus = CASE
                    WHEN excluded.ModuleCaptureStatus = 'Pending'
                         AND excluded.ModuleCount = 0
                         AND excluded.ModuleLastCapturedUtc IS NULL
                         AND COALESCE(excluded.ModuleCaptureError, '') = ''
                    THEN Processes.ModuleCaptureStatus
                    ELSE excluded.ModuleCaptureStatus
                END,
                ModuleCount = CASE
                    WHEN excluded.ModuleCaptureStatus = 'Pending'
                         AND excluded.ModuleCount = 0
                         AND excluded.ModuleLastCapturedUtc IS NULL
                         AND COALESCE(excluded.ModuleCaptureError, '') = ''
                    THEN Processes.ModuleCount
                    ELSE excluded.ModuleCount
                END,
                ModuleLastCapturedUtc = CASE
                    WHEN excluded.ModuleCaptureStatus = 'Pending'
                         AND excluded.ModuleCount = 0
                         AND excluded.ModuleLastCapturedUtc IS NULL
                         AND COALESCE(excluded.ModuleCaptureError, '') = ''
                    THEN Processes.ModuleLastCapturedUtc
                    ELSE excluded.ModuleLastCapturedUtc
                END,
                ModuleCaptureError = CASE
                    WHEN excluded.ModuleCaptureStatus = 'Pending'
                         AND excluded.ModuleCount = 0
                         AND excluded.ModuleLastCapturedUtc IS NULL
                         AND COALESCE(excluded.ModuleCaptureError, '') = ''
                    THEN Processes.ModuleCaptureError
                    ELSE excluded.ModuleCaptureError
                END,
                HandleCaptureStatus = CASE
                    WHEN excluded.HandleCaptureStatus = 'Pending'
                         AND excluded.HandleCount = 0
                         AND excluded.HandleLastCapturedUtc IS NULL
                         AND COALESCE(excluded.HandleCaptureError, '') = ''
                    THEN Processes.HandleCaptureStatus
                    ELSE excluded.HandleCaptureStatus
                END,
                HandleCount = CASE
                    WHEN excluded.HandleCaptureStatus = 'Pending'
                         AND excluded.HandleCount = 0
                         AND excluded.HandleLastCapturedUtc IS NULL
                         AND COALESCE(excluded.HandleCaptureError, '') = ''
                    THEN Processes.HandleCount
                    ELSE excluded.HandleCount
                END,
                HandleLastCapturedUtc = CASE
                    WHEN excluded.HandleCaptureStatus = 'Pending'
                         AND excluded.HandleCount = 0
                         AND excluded.HandleLastCapturedUtc IS NULL
                         AND COALESCE(excluded.HandleCaptureError, '') = ''
                    THEN Processes.HandleLastCapturedUtc
                    ELSE excluded.HandleLastCapturedUtc
                END,
                HandleCaptureError = CASE
                    WHEN excluded.HandleCaptureStatus = 'Pending'
                         AND excluded.HandleCount = 0
                         AND excluded.HandleLastCapturedUtc IS NULL
                         AND COALESCE(excluded.HandleCaptureError, '') = ''
                    THEN Processes.HandleCaptureError
                    ELSE excluded.HandleCaptureError
                END;
            """);
        Add(command, "$ProcessKey", process.ProcessKey);
        Add(command, "$ProcessEntityId", process.ProcessEntityId);
        AddEvidenceIdentityParameters(command, identity);
        Add(command, "$SourceId", sourceId);
        AddProcessPayloadParameters(command, process, includeCaptureSummaries: true);
        command.ExecuteNonQuery();
        UpsertCanonicalProcessEntity(process, sourceId);
        UpsertProcessAlias(process, ProcessAliasKind.LegacyProcessKey, process.ProcessKey);
        UpsertProcessAlias(process, ProcessAliasKind.SysmonProcessGuid, process.ProcessGuid);
        var observation = AppendCompatibilityProcessObservation(process, sourceId);
        var projected = ReprojectProcessEntityCore(observation.ProcessEntityId);
        _context.RefreshProcessDerivedState(projected);
    }

    private void UpsertProcessStatisticCore(ProcessStatisticsRecord sample)
    {
        var observedUtc = sample.ObservedUtc == default ? DateTime.UtcNow : sample.ObservedUtc;
        sample.ObservedUtc = observedUtc;
        var sourceId = _context.EnsureTelemetrySource(sample.Source, "ProcessStatistics");
        var identity = _context.ResolveEvidenceIdentity(sample, "ProcessStatistics", sample.Source);
        ApplyEvidenceIdentity(sample, identity);
        var attachment = _context.PrepareProcessAttachedEvidence(
            sample,
            EvidenceReferenceKind.ProcessStatistic,
            sample.SampleId,
            sample.ProcessId,
            sample.ProcessGuid,
            processStartTimeUtc: null,
            sample.ProcessName,
            observedUtc);
        if (string.IsNullOrWhiteSpace(sample.SampleId))
        {
            sample.SampleId = BuildProcessStatisticsSampleId(
                string.IsNullOrWhiteSpace(sample.ProcessEntityId) ? sample.ProcessKey : sample.ProcessEntityId,
                observedUtc);
        }

        using var command = CreateCommand("""
            INSERT OR REPLACE INTO ProcessStatistics (
                SampleId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceId, ProcessEntityId, SourceRunId, IngestionJobId,
                ProcessKey, ProcessId, ProcessGuid, ProcessName, Status, ObservedUtc,
                TotalProcessorTimeTicks, UserProcessorTimeTicks, PrivilegedProcessorTimeTicks,
                ReadBytes, WrittenBytes, CollectionError, Source)
            VALUES (
                $SampleId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceId, $ProcessEntityId, $SourceRunId, $IngestionJobId,
                $ProcessKey, $ProcessId, $ProcessGuid, $ProcessName, $Status, $ObservedUtc,
                $TotalProcessorTimeTicks, $UserProcessorTimeTicks, $PrivilegedProcessorTimeTicks,
                $ReadBytes, $WrittenBytes, $CollectionError, $Source);
            """);
        Add(command, "$SampleId", sample.SampleId);
        AddEvidenceIdentityParameters(command, identity);
        Add(command, "$SourceId", sourceId);
        Add(command, "$ProcessEntityId", sample.ProcessEntityId);
        Add(command, "$SourceRunId", EmptyToNull(sample.SourceRunId));
        Add(command, "$IngestionJobId", sample.IngestionJobId);
        Add(command, "$ProcessKey", sample.ProcessKey);
        Add(command, "$ProcessId", sample.ProcessId);
        Add(command, "$ProcessGuid", sample.ProcessGuid);
        Add(command, "$ProcessName", sample.ProcessName);
        Add(command, "$Status", sample.Status.ToString());
        Add(command, "$ObservedUtc", observedUtc);
        Add(command, "$TotalProcessorTimeTicks", sample.TotalProcessorTimeTicks);
        Add(command, "$UserProcessorTimeTicks", sample.UserProcessorTimeTicks);
        Add(command, "$PrivilegedProcessorTimeTicks", sample.PrivilegedProcessorTimeTicks);
        Add(command, "$ReadBytes", sample.ReadBytes);
        Add(command, "$WrittenBytes", sample.WrittenBytes);
        Add(command, "$CollectionError", sample.CollectionError);
        Add(command, "$Source", sample.Source);
        command.ExecuteNonQuery();
        _context.PersistProcessAttachedRelation(
            sample,
            EvidenceReferenceKind.ProcessStatistic,
            sample.SampleId,
            EvidenceRelationType.OwnedBy,
            attachment,
            observedUtc,
            rawInputId: sample.SampleId);
    }

    public ProcessObservationWriteResult AppendProcessObservationBatch(
        IEnumerable<ProcessObservation> observations,
        IEnumerable<ProcessAlias> aliases,
        IEnumerable<ProcessStatisticsRecord>? statistics = null)
    {
        ArgumentNullException.ThrowIfNull(observations);
        ArgumentNullException.ThrowIfNull(aliases);
        var observationRows = observations.ToList();
        var aliasRows = aliases.ToList();
        var statisticRows = statistics?.ToList() ?? [];
        var result = new ProcessObservationWriteResult(0, 0, 0, 0, 0);
        if (observationRows.Count == 0 && statisticRows.Count == 0)
        {
            return result;
        }

        _context.Execute(() =>
        {
            using var commands = new ReusableCommandCache(this);
            foreach (var observation in observationRows)
            {
                ValidateNormalizedProcessObservation(observation);
                observation.Fields.ProcessEntityId = observation.ProcessEntityId;
                EnsureProcessEntitySeed(observation.Fields, commands);
            }

            var allAliases = aliasRows
                .Concat(observationRows.SelectMany(CreateBuiltInProcessAliases))
                .Where(alias => !string.IsNullOrWhiteSpace(alias.ProcessEntityId) && !string.IsNullOrWhiteSpace(alias.Value))
                .GroupBy(
                    alias => $"{alias.ProcessEntityId}\u001f{alias.Kind}\u001f{alias.Value}\u001f{alias.SourceIdentityId}",
                    StringComparer.Ordinal)
                .Select(group => group.First())
                .ToList();
            var persistedAliases = 0;
            var duplicateAliases = 0;
            foreach (var alias in allAliases)
            {
                if (InsertProcessAliasCore(alias, commands))
                {
                    persistedAliases++;
                }
                else
                {
                    duplicateAliases++;
                }
            }

            var persistedObservations = 0;
            var duplicateObservations = 0;
            var changedEntityIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var observation in observationRows)
            {
                var process = observation.Fields;
                if (string.IsNullOrWhiteSpace(process.ParentProcessEntityId))
                {
                    process.ParentProcessEntityId = ResolveProcessAlias(
                        process.ParentProcessKey,
                        ProcessAliasKind.LegacyProcessKey,
                        process,
                        commands);
                }

                if (InsertProcessObservationCore(observation, commands))
                {
                    persistedObservations++;
                    changedEntityIds.Add(observation.ProcessEntityId);
                }
                else
                {
                    duplicateObservations++;
                }
            }

            var observationOwnership = observationRows
                .Where(observation => !string.IsNullOrWhiteSpace(observation.Fields.ProcessKey))
                .GroupBy(observation => observation.Fields.ProcessKey, StringComparer.Ordinal)
                .Where(group => group.Select(item => item.ProcessEntityId).Distinct(StringComparer.Ordinal).Count() == 1)
                .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
            foreach (var sample in statisticRows)
            {
                ArgumentNullException.ThrowIfNull(sample);
                if (observationOwnership.TryGetValue(sample.ProcessKey, out var owner))
                {
                    sample.ProcessEntityId = string.IsNullOrWhiteSpace(sample.ProcessEntityId)
                        ? owner.ProcessEntityId
                        : sample.ProcessEntityId;
                    sample.SourceRunId = string.IsNullOrWhiteSpace(sample.SourceRunId)
                        ? owner.SourceRunId
                        : sample.SourceRunId;
                    sample.IngestionJobId = string.IsNullOrWhiteSpace(sample.IngestionJobId)
                        ? owner.IngestionJobId?.ToString("D") ?? string.Empty
                        : sample.IngestionJobId;
                }

                UpsertProcessStatisticCore(sample);
            }

            var projections = new List<ProcessProjectionBatchRow>(changedEntityIds.Count);
            var projectionObservations = ReadProcessObservationsForAppend(
                changedEntityIds,
                observationRows);
            foreach (var processEntityId in changedEntityIds)
            {
                ReprojectProcessEntityCore(
                    processEntityId,
                    commands,
                    projections,
                    projectionObservations[processEntityId]);
            }
            PersistProcessProjections(projections);
            var projectedProcesses = projections.Select(projection => projection.Process).ToList();
            _context.RefreshProcessDerivedStates(projectedProcesses);

            result = new ProcessObservationWriteResult(
                persistedObservations,
                duplicateObservations,
                persistedAliases,
                duplicateAliases,
                statisticRows.Count);
        });
        return result;
    }

    private static void ValidateNormalizedProcessObservation(ProcessObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(observation.Fields);
        if (string.IsNullOrWhiteSpace(observation.ObservationId) ||
            string.IsNullOrWhiteSpace(observation.AdapterId) ||
            string.IsNullOrWhiteSpace(observation.ProcessEntityId) ||
            string.IsNullOrWhiteSpace(observation.SourceRunId) ||
            string.IsNullOrWhiteSpace(observation.SourceNativeAlias) ||
            string.IsNullOrWhiteSpace(observation.Fields.ProcessKey))
        {
            throw new InvalidOperationException(
                "Normalized process observations require observation, adapter, entity, source-run, source-native, and ProcessKey identity.");
        }

        if (observation.ObservedUtc == default)
        {
            throw new InvalidOperationException("Normalized process observations require ObservedUtc.");
        }
    }

    private void EnsureProcessEntitySeed(
        ProcessRecord process,
        ReusableCommandCache? commands = null)
    {
        using var lease = LeaseCommand(commands, """
            INSERT OR IGNORE INTO ProcessEntities(
                ProcessEntityId, ProcessKey, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                HostId, ExecutionRootId, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                ParentProcessId, ParentProcessKey, ParentProcessEntityId, ParentProcessName,
                ProcessName, ProcessPath, CommandLine, UserName, SessionId, Architecture,
                FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus, ModuleCount,
                HandleCaptureStatus, HandleCount)
            VALUES(
                $ProcessEntityId, $ProcessKey, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId,
                $HostId, $ExecutionRootId, $ProcessId, $ProcessGuid, $StartTimeUtc, $EndTimeUtc, $Status,
                $ParentProcessId, $ParentProcessKey, $ParentProcessEntityId, $ParentProcessName,
                $ProcessName, $ProcessPath, $CommandLine, $UserName, $SessionId, $Architecture,
                $FirstObservedUtc, $LastObservedUtc, $LastSource, $ModuleCaptureStatus, $ModuleCount,
                $HandleCaptureStatus, $HandleCount);
            """);
        var command = lease.Command;
        Add(command, "$ProcessEntityId", process.ProcessEntityId);
        Add(command, "$ProcessKey", process.ProcessKey);
        Add(command, "$CaseId", process.CaseId);
        Add(command, "$EvidenceSessionId", process.EvidenceSessionId);
        Add(command, "$CaptureId", process.CaptureId);
        Add(command, "$SourceIdentityId", process.SourceIdentityId);
        Add(command, "$HostId", process.HostId);
        Add(command, "$ExecutionRootId", process.ExecutionRootId);
        AddProcessPayloadParameters(command, process, includeCaptureSummaries: false);
        command.ExecuteNonQuery();
    }

    private bool InsertProcessAliasCore(
        ProcessAlias alias,
        ReusableCommandCache? commands = null)
    {
        using var lease = LeaseCommand(commands, """
            INSERT OR IGNORE INTO ProcessAliases(
                ProcessEntityId, AliasKind, AliasValue, CaseId, EvidenceSessionId,
                HostId, ExecutionRootId, SourceIdentityId, CreatedUtc)
            VALUES($ProcessEntityId, $AliasKind, $AliasValue, $CaseId, $EvidenceSessionId,
                   $HostId, $ExecutionRootId, $SourceIdentityId, $CreatedUtc);
            """);
        var command = lease.Command;
        Add(command, "$ProcessEntityId", alias.ProcessEntityId);
        Add(command, "$AliasKind", alias.Kind.ToString());
        Add(command, "$AliasValue", alias.Value);
        Add(command, "$CaseId", alias.CaseId);
        Add(command, "$EvidenceSessionId", alias.EvidenceSessionId);
        Add(command, "$HostId", alias.HostId);
        Add(command, "$ExecutionRootId", alias.ExecutionRootId);
        Add(command, "$SourceIdentityId", alias.SourceIdentityId);
        Add(command, "$CreatedUtc", DateTime.UtcNow);
        return command.ExecuteNonQuery() > 0;
    }

    private bool InsertProcessObservationCore(
        ProcessObservation observation,
        ReusableCommandCache? commands = null)
    {
        using var insertLease = LeaseCommand(commands, """
            INSERT OR IGNORE INTO ProcessObservations(
                ObservationId, AdapterId, ObservationKind, ProcessEntityId, CaseId, EvidenceSessionId,
                CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc, ValidToUtc,
                StatusAssertion, CorrelationMethod, CorrelationConfidence, ParserVersion,
                FieldStatesJson, MetadataJson, PayloadJson, CreatedUtc)
            VALUES(
                $ObservationId, $AdapterId, $ObservationKind, $ProcessEntityId, $CaseId, $EvidenceSessionId,
                $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId, $SourceRunId, $IngestionJobId,
                $RawRecordId, $SourceNativeAlias, $ObservedUtc, $ValidFromUtc, $ValidToUtc,
                $StatusAssertion, $CorrelationMethod, $CorrelationConfidence, $ParserVersion,
                $FieldStatesJson, $MetadataJson, $PayloadJson, $CreatedUtc);
            """);
        var command = insertLease.Command;
        Add(command, "$ObservationId", observation.ObservationId);
        Add(command, "$AdapterId", observation.AdapterId);
        Add(command, "$ObservationKind", observation.ObservationKind.ToString());
        Add(command, "$ProcessEntityId", observation.ProcessEntityId);
        Add(command, "$CaseId", observation.Fields.CaseId);
        Add(command, "$EvidenceSessionId", observation.Fields.EvidenceSessionId);
        Add(command, "$CaptureId", observation.Fields.CaptureId);
        Add(command, "$SourceIdentityId", observation.Fields.SourceIdentityId);
        Add(command, "$HostId", observation.Fields.HostId);
        Add(command, "$ExecutionRootId", observation.Fields.ExecutionRootId);
        Add(command, "$SourceRunId", observation.SourceRunId);
        Add(command, "$IngestionJobId", observation.IngestionJobId?.ToString("D"));
        Add(command, "$RawRecordId", observation.RawRecordId);
        Add(command, "$SourceNativeAlias", observation.SourceNativeAlias);
        Add(command, "$ObservedUtc", observation.ObservedUtc);
        Add(command, "$ValidFromUtc", observation.ValidFromUtc);
        Add(command, "$ValidToUtc", observation.ValidToUtc);
        Add(command, "$StatusAssertion", observation.StatusAssertion.ToString());
        Add(command, "$CorrelationMethod", observation.CorrelationMethod.ToString());
        Add(command, "$CorrelationConfidence", observation.CorrelationConfidence);
        Add(command, "$ParserVersion", observation.ParserVersion);
        Add(command, "$FieldStatesJson", JsonSerializer.Serialize(observation.FieldStates));
        Add(command, "$MetadataJson", observation.MetadataJson);
        var payloadJson = JsonSerializer.Serialize(observation.Fields);
        Add(command, "$PayloadJson", payloadJson);
        Add(command, "$CreatedUtc", DateTime.UtcNow);
        if (command.ExecuteNonQuery() > 0)
        {
            return true;
        }

        using var existingLease = LeaseCommand(commands, """
            SELECT ProcessEntityId, SourceRunId, PayloadJson
            FROM ProcessObservations WHERE ObservationId = $ObservationId;
            """);
        var existing = existingLease.Command;
        Add(existing, "$ObservationId", observation.ObservationId);
        using var reader = existing.ExecuteReader();
        if (!reader.Read() ||
            !string.Equals(GetString(reader, 0), observation.ProcessEntityId, StringComparison.Ordinal) ||
            !string.Equals(GetString(reader, 1), observation.SourceRunId, StringComparison.Ordinal) ||
            !string.Equals(GetString(reader, 2), payloadJson, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Process observation id '{observation.ObservationId}' was reused with different immutable content.");
        }

        return false;
    }

    private static IEnumerable<ProcessAlias> CreateBuiltInProcessAliases(ProcessObservation observation)
    {
        var process = observation.Fields;
        if (!string.IsNullOrWhiteSpace(process.ProcessKey))
        {
            yield return CreateAlias(
                process.ProcessKey.StartsWith("procmon:", StringComparison.OrdinalIgnoreCase)
                    ? ProcessAliasKind.ProcmonSyntheticKey
                    : ProcessAliasKind.LegacyProcessKey,
                process.ProcessKey);
        }

        if (!string.IsNullOrWhiteSpace(process.ProcessGuid))
        {
            yield return CreateAlias(ProcessAliasKind.SysmonProcessGuid, process.ProcessGuid);
        }

        ProcessAlias CreateAlias(ProcessAliasKind kind, string value)
            => new()
            {
                ProcessEntityId = observation.ProcessEntityId,
                Kind = kind,
                Value = value,
                CaseId = process.CaseId,
                EvidenceSessionId = process.EvidenceSessionId,
                HostId = process.HostId,
                ExecutionRootId = process.ExecutionRootId,
                SourceIdentityId = process.SourceIdentityId
            };
    }

    private Dictionary<string, List<ProcessObservation>> ReadProcessObservationsForAppend(
        IReadOnlyCollection<string> processEntityIds,
        IReadOnlyList<ProcessObservation> currentBatch)
    {
        var result = processEntityIds.ToDictionary(
            processEntityId => processEntityId,
            _ => new List<ProcessObservation>(),
            StringComparer.Ordinal);
        if (result.Count == 0)
        {
            return result;
        }

        var currentById = currentBatch
            .GroupBy(observation => observation.ObservationId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
        using var command = CreateCommand("""
            SELECT ProcessEntityId, ObservationId, AdapterId, ObservationKind, SourceRunId, IngestionJobId,
                   RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc, ValidToUtc, StatusAssertion,
                   CorrelationMethod, CorrelationConfidence, ParserVersion, FieldStatesJson, MetadataJson, PayloadJson
            FROM ProcessObservations
            WHERE ProcessEntityId IN (SELECT value FROM json_each($ProcessEntityIdsJson))
            ORDER BY ProcessEntityId, ObservationId;
            """);
        Add(command, "$ProcessEntityIdsJson", JsonSerializer.Serialize(processEntityIds));
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var processEntityId = GetString(reader, 0);
            var observationId = GetString(reader, 1);
            result[processEntityId].Add(
                currentById.TryGetValue(observationId, out var current)
                    ? current
                    : ReadProcessObservation(reader, processEntityId, firstColumnOffset: 1));
        }

        return result;
    }

    private static ProcessObservation ReadProcessObservation(
        SqliteDataReader reader,
        string processEntityId,
        int firstColumnOffset)
    {
        var fields = JsonSerializer.Deserialize<ProcessRecord>(GetString(reader, firstColumnOffset + 16)) ?? new ProcessRecord();
        return new ProcessObservation
        {
            ObservationId = GetString(reader, firstColumnOffset),
            ProcessEntityId = processEntityId,
            AdapterId = GetString(reader, firstColumnOffset + 1),
            ObservationKind = GetEnum(reader, firstColumnOffset + 2, ProcessObservationKind.LegacyCompatibility),
            SourceRunId = GetString(reader, firstColumnOffset + 3),
            IngestionJobId = Guid.TryParse(GetString(reader, firstColumnOffset + 4), out var jobId) ? jobId : null,
            RawRecordId = GetString(reader, firstColumnOffset + 5),
            SourceNativeAlias = GetString(reader, firstColumnOffset + 6),
            ObservedUtc = GetDateTime(reader, firstColumnOffset + 7) ?? DateTime.MinValue,
            ValidFromUtc = GetDateTime(reader, firstColumnOffset + 8),
            ValidToUtc = GetDateTime(reader, firstColumnOffset + 9),
            StatusAssertion = GetEnum(reader, firstColumnOffset + 10, ProcessStatus.Running),
            CorrelationMethod = GetEnum(reader, firstColumnOffset + 11, ProcessCorrelationMethod.LegacyCompatibility),
            CorrelationConfidence = GetDouble(reader, firstColumnOffset + 12),
            ParserVersion = GetString(reader, firstColumnOffset + 13),
            FieldStates = JsonSerializer.Deserialize<Dictionary<string, ProcessObservationValueState>>(
                              GetString(reader, firstColumnOffset + 14)) ?? new(StringComparer.Ordinal),
            MetadataJson = GetString(reader, firstColumnOffset + 15),
            Fields = fields
        };
    }

    private IReadOnlyList<ProcessObservationGroup> ReadAllProcessObservationGroups()
    {
        var groups = new List<ProcessObservationGroup>();
        using var command = CreateCommand("""
            SELECT ProcessEntityId, ObservationId, AdapterId, ObservationKind, SourceRunId, IngestionJobId,
                   RawRecordId, SourceNativeAlias, ObservedUtc, ValidFromUtc, ValidToUtc, StatusAssertion,
                   CorrelationMethod, CorrelationConfidence, ParserVersion, FieldStatesJson, MetadataJson, PayloadJson
            FROM ProcessObservations
            WHERE ProcessEntityId <> ''
            ORDER BY ProcessEntityId, ObservationId;
            """);
        using var reader = command.ExecuteReader();
        ProcessObservationGroup? current = null;
        while (reader.Read())
        {
            var processEntityId = GetString(reader, 0);
            if (current == null ||
                !string.Equals(current.ProcessEntityId, processEntityId, StringComparison.Ordinal))
            {
                current = new ProcessObservationGroup(processEntityId, []);
                groups.Add(current);
            }

            current.Observations.Add(
                ReadProcessObservation(reader, processEntityId, firstColumnOffset: 1));
        }

        return groups;
    }

    public void RebuildProcessProjection()
    {
        _context.Execute(() =>
        {
            var observationGroups = ReadAllProcessObservationGroups();
            var projections = new List<ProcessProjectionBatchRow>(observationGroups.Count);
            foreach (var group in observationGroups)
            {
                ReprojectProcessEntityCore(
                    group.ProcessEntityId,
                    projectionBatch: projections,
                    suppliedObservations: group.Observations);
            }

            PersistProcessProjections(projections);
            RecordProjectionRebuild();
        });
    }

    public void BackfillMissingProcessObservationsAndRebuild()
        => _context.Execute(() =>
        {
            BackfillProcessObservations();
            RecordProjectionRebuild();
        });

    internal void BackfillProcessObservations()
    {
        var processes = ReadProcessesForObservationBackfill();
        foreach (var process in processes)
        {
            if (string.IsNullOrWhiteSpace(process.ProcessEntityId))
            {
                process.ProcessEntityId = ResolveOrCreateProcessEntityId(process);
            }

            process.ParentProcessEntityId = ResolveProcessAlias(
                process.ParentProcessKey,
                ProcessAliasKind.LegacyProcessKey,
                process);
            var sourceId = _context.EnsureTelemetrySource(process.LastSource, "Process");
            UpsertCanonicalProcessEntity(process, sourceId);
            UpsertProcessAlias(process, ProcessAliasKind.LegacyProcessKey, process.ProcessKey);
            UpsertProcessAlias(process, ProcessAliasKind.SysmonProcessGuid, process.ProcessGuid);
            using var exists = CreateCommand(
                "SELECT 1 FROM ProcessObservations WHERE ProcessEntityId=$ProcessEntityId LIMIT 1;");
            Add(exists, "$ProcessEntityId", process.ProcessEntityId);
            if (exists.ExecuteScalar() != null)
            {
                continue;
            }

            AppendCompatibilityProcessObservation(process, sourceId);
        }

        foreach (var entityId in processes
                     .Select(process => process.ProcessEntityId)
                     .Where(entityId => !string.IsNullOrWhiteSpace(entityId))
                     .Distinct(StringComparer.Ordinal))
        {
            ReprojectProcessEntityCore(entityId);
        }
    }

    private ProcessObservation AppendCompatibilityProcessObservation(ProcessRecord process, int? sourceId)
    {
        var sourceRunId = EnsureCompatibilitySourceRun(sourceId, process);
        var ingestionJobId = ReadWriterIngestionJobId();
        var observedUtc = process.LastObservedUtc == default
            ? process.FirstObservedUtc == default ? DateTime.UtcNow : process.FirstObservedUtc
            : process.LastObservedUtc;
        var observation = new ProcessObservation
        {
            ObservationId = "pobs-" + Guid.NewGuid().ToString("N"),
            AdapterId = "procinsider.legacy-process-compatibility",
            ObservationKind = ProcessObservationKind.LegacyCompatibility,
            ProcessEntityId = process.ProcessEntityId,
            SourceRunId = sourceRunId,
            IngestionJobId = ingestionJobId,
            SourceNativeAlias = process.ProcessKey,
            ObservedUtc = observedUtc,
            ValidFromUtc = process.StartTimeUtc,
            ValidToUtc = process.EndTimeUtc,
            StatusAssertion = process.Status,
            CorrelationMethod = process.StartTimeUtc.HasValue
                ? ProcessCorrelationMethod.ExactScopedPidStartTime
                : process.ProcessKey.StartsWith("procmon:", StringComparison.OrdinalIgnoreCase)
                    ? ProcessCorrelationMethod.SourceNativeAlias
                    : ProcessCorrelationMethod.LegacyCompatibility,
            CorrelationConfidence = process.StartTimeUtc.HasValue ? 1.0 : 0.65,
            FieldStates = BuildProcessFieldStates(process),
            Fields = process
        };
        using var command = CreateCommand("""
            INSERT INTO ProcessObservations(
                ObservationId, AdapterId, ObservationKind, ProcessEntityId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                HostId, ExecutionRootId, SourceRunId, IngestionJobId, RawRecordId,
                SourceNativeAlias, ObservedUtc, ValidFromUtc, ValidToUtc, StatusAssertion,
                CorrelationMethod, CorrelationConfidence, ParserVersion, FieldStatesJson,
                MetadataJson, PayloadJson, CreatedUtc)
            VALUES($ObservationId, $AdapterId, $ObservationKind, $ProcessEntityId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId,
                   $HostId, $ExecutionRootId, $SourceRunId, $IngestionJobId, $RawRecordId,
                   $SourceNativeAlias, $ObservedUtc, $ValidFromUtc, $ValidToUtc, $StatusAssertion,
                   $CorrelationMethod, $CorrelationConfidence, $ParserVersion, $FieldStatesJson,
                   $MetadataJson, $PayloadJson, $CreatedUtc);
            """);
        Add(command, "$ObservationId", observation.ObservationId);
        Add(command, "$AdapterId", observation.AdapterId);
        Add(command, "$ObservationKind", observation.ObservationKind.ToString());
        Add(command, "$ProcessEntityId", observation.ProcessEntityId);
        Add(command, "$CaseId", process.CaseId);
        Add(command, "$EvidenceSessionId", process.EvidenceSessionId);
        Add(command, "$CaptureId", process.CaptureId);
        Add(command, "$SourceIdentityId", process.SourceIdentityId);
        Add(command, "$HostId", process.HostId);
        Add(command, "$ExecutionRootId", process.ExecutionRootId);
        Add(command, "$SourceRunId", observation.SourceRunId);
        Add(command, "$IngestionJobId", observation.IngestionJobId?.ToString("D"));
        Add(command, "$RawRecordId", observation.RawRecordId);
        Add(command, "$SourceNativeAlias", observation.SourceNativeAlias);
        Add(command, "$ObservedUtc", observation.ObservedUtc);
        Add(command, "$ValidFromUtc", observation.ValidFromUtc);
        Add(command, "$ValidToUtc", observation.ValidToUtc);
        Add(command, "$StatusAssertion", observation.StatusAssertion.ToString());
        Add(command, "$CorrelationMethod", observation.CorrelationMethod.ToString());
        Add(command, "$CorrelationConfidence", observation.CorrelationConfidence);
        Add(command, "$ParserVersion", observation.ParserVersion);
        Add(command, "$FieldStatesJson", JsonSerializer.Serialize(observation.FieldStates));
        Add(command, "$MetadataJson", observation.MetadataJson);
        Add(command, "$PayloadJson", JsonSerializer.Serialize(process));
        Add(command, "$CreatedUtc", DateTime.UtcNow);
        command.ExecuteNonQuery();
        return observation;
    }

    private string EnsureCompatibilitySourceRun(int? sourceId, ProcessRecord process)
    {
        using (var context = CreateCommand(
                   "SELECT SourceRunId FROM WriterProvenanceContext WHERE SingletonId = 1 LIMIT 1;"))
        {
            var current = context.ExecuteScalar()?.ToString();
            if (!string.IsNullOrWhiteSpace(current))
            {
                return current;
            }
        }

        var resolvedSourceId = sourceId ?? _context.EnsureTelemetrySource(process.LastSource, "Process");
        var sourceRunId = $"legacy-srun-{resolvedSourceId:x16}";
        using var command = CreateCommand("""
            INSERT OR IGNORE INTO SourceRuns(
                SourceRunId, SourceId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                HostId, ExecutionRootId, SourceType, DisplayName, IsLive, Status, StartedUtc,
                MetadataJson, CreatedUtc, UpdatedUtc)
            SELECT $SourceRunId, SourceId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId,
                   $HostId, $ExecutionRootId, SourceType, DisplayName, 0, 'Compatibility', $StartedUtc,
                   '{}', $StartedUtc, $StartedUtc
            FROM Sources WHERE SourceId = $SourceId;
            """);
        Add(command, "$SourceRunId", sourceRunId);
        Add(command, "$SourceId", resolvedSourceId);
        Add(command, "$CaseId", process.CaseId);
        Add(command, "$EvidenceSessionId", process.EvidenceSessionId);
        Add(command, "$CaptureId", process.CaptureId);
        Add(command, "$SourceIdentityId", process.SourceIdentityId);
        Add(command, "$HostId", process.HostId);
        Add(command, "$ExecutionRootId", process.ExecutionRootId);
        Add(command, "$StartedUtc", process.FirstObservedUtc == default ? DateTime.UtcNow : process.FirstObservedUtc);
        command.ExecuteNonQuery();
        return sourceRunId;
    }

    private Guid? ReadWriterIngestionJobId()
    {
        using var command = CreateCommand(
            "SELECT IngestionJobId FROM WriterProvenanceContext WHERE SingletonId = 1 LIMIT 1;");
        return Guid.TryParse(command.ExecuteScalar()?.ToString(), out var value) ? value : null;
    }

    private static Dictionary<string, ProcessObservationValueState> BuildProcessFieldStates(ProcessRecord process)
    {
        var result = new Dictionary<string, ProcessObservationValueState>(StringComparer.Ordinal);
        foreach (var pair in new Dictionary<string, string?>
                 {
                     ["ProcessKey"] = process.ProcessKey,
                     ["ProcessGuid"] = process.ProcessGuid,
                     ["ProcessName"] = process.ProcessName,
                     ["ProcessPath"] = process.ProcessPath,
                     ["CommandLine"] = process.CommandLine,
                     ["UserName"] = process.UserName,
                     ["ParentProcessKey"] = process.ParentProcessKey,
                     ["ParentProcessEntityId"] = process.ParentProcessEntityId,
                     ["ParentProcessName"] = process.ParentProcessName,
                     ["Architecture"] = process.Architecture,
                     ["CompanyName"] = process.CompanyName,
                     ["FileDescription"] = process.FileDescription,
                     ["Sha256Hash"] = process.Sha256Hash
                 })
        {
            result[pair.Key] = pair.Value?.Contains("access denied", StringComparison.OrdinalIgnoreCase) == true
                ? ProcessObservationValueState.AccessDenied
                : ProcessProjectionPolicy.IsKnown(pair.Value)
                    ? ProcessObservationValueState.Available
                    : ProcessObservationValueState.NotCollected;
        }

        return result;
    }

    private ProcessRecord ReprojectProcessEntityCore(
        string processEntityId,
        ReusableCommandCache? commands = null,
        ICollection<ProcessProjectionBatchRow>? projectionBatch = null,
        IReadOnlyList<ProcessObservation>? suppliedObservations = null)
    {
        var observations = suppliedObservations?.ToList() ?? [];
        if (suppliedObservations == null)
        {
            using var lease = LeaseCommand(commands, """
                SELECT ObservationId, AdapterId, ObservationKind, SourceRunId, IngestionJobId, RawRecordId, SourceNativeAlias,
                       ObservedUtc, ValidFromUtc, ValidToUtc, StatusAssertion, CorrelationMethod,
                       CorrelationConfidence, ParserVersion, FieldStatesJson, MetadataJson, PayloadJson
                FROM ProcessObservations WHERE ProcessEntityId = $ProcessEntityId
                ORDER BY ObservationId;
                """);
            var command = lease.Command;
            Add(command, "$ProcessEntityId", processEntityId);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                observations.Add(ReadProcessObservation(reader, processEntityId, firstColumnOffset: 0));
            }
        }

        var resolution = ProcessProjectionPolicy.Resolve(observations);
        var process = resolution.Process;
        process.ProcessEntityId = processEntityId;

        if (projectionBatch != null)
        {
            projectionBatch.Add(new ProcessProjectionBatchRow(
                process,
                resolution.Winners,
                resolution.ConflictCount));
            return process;
        }

        using (var lease = LeaseCommand(commands, """
                   INSERT OR IGNORE INTO Processes(
                       ProcessKey, ProcessEntityId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                       HostId, ExecutionRootId, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                       ParentProcessId, ParentProcessKey, ParentProcessEntityId, ParentProcessName,
                       ProcessName, ProcessPath, CommandLine, UserName, SessionId, Architecture,
                       CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash, TreeDepth,
                       FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus, ModuleCount,
                       HandleCaptureStatus, HandleCount)
                   VALUES(
                       $ProcessKey, $ProcessEntityId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId,
                       $HostId, $ExecutionRootId, $ProcessId, $ProcessGuid, $StartTimeUtc, $EndTimeUtc, $Status,
                       $ParentProcessId, $ParentProcessKey, $ParentProcessEntityId, $ParentProcessName,
                       $ProcessName, $ProcessPath, $CommandLine, $UserName, $SessionId, $Architecture,
                       $CpuUsage, $MemoryUsageBytes, $CompanyName, $FileDescription, $Sha256Hash, $TreeDepth,
                       $FirstObservedUtc, $LastObservedUtc, $LastSource, $ModuleCaptureStatus, $ModuleCount,
                       $HandleCaptureStatus, $HandleCount);
                   """))
        {
            var insert = lease.Command;
            AddProcessProjectionParameters(insert, process, processEntityId);
            insert.ExecuteNonQuery();
        }

        using (var lease = LeaseCommand(
                   commands,
                   "DELETE FROM Processes WHERE ProcessEntityId = $ProcessEntityId AND ProcessKey <> $ProcessKey;"))
        {
            var delete = lease.Command;
            Add(delete, "$ProcessEntityId", processEntityId);
            Add(delete, "$ProcessKey", process.ProcessKey);
            delete.ExecuteNonQuery();
        }

        using (var lease = LeaseCommand(commands, """
                   UPDATE Processes SET ProcessEntityId=$ProcessEntityId, CaseId=$CaseId,
                       EvidenceSessionId=$EvidenceSessionId, CaptureId=$CaptureId, SourceIdentityId=$SourceIdentityId,
                       HostId=$HostId, ExecutionRootId=$ExecutionRootId, ProcessId=$ProcessId, ProcessGuid=$ProcessGuid,
                       StartTimeUtc=$StartTimeUtc, EndTimeUtc=$EndTimeUtc, Status=$Status,
                       ParentProcessId=$ParentProcessId, ParentProcessKey=$ParentProcessKey,
                       ParentProcessEntityId=$ParentProcessEntityId, ParentProcessName=$ParentProcessName,
                       ProcessName=$ProcessName, ProcessPath=$ProcessPath, CommandLine=$CommandLine,
                       UserName=$UserName, SessionId=$SessionId, Architecture=$Architecture,
                       CpuUsage=$CpuUsage, MemoryUsageBytes=$MemoryUsageBytes, CompanyName=$CompanyName,
                       FileDescription=$FileDescription, Sha256Hash=$Sha256Hash, TreeDepth=$TreeDepth,
                       FirstObservedUtc=$FirstObservedUtc, LastObservedUtc=$LastObservedUtc, LastSource=$LastSource,
                       ModuleCaptureStatus=$ModuleCaptureStatus, ModuleCount=$ModuleCount,
                       HandleCaptureStatus=$HandleCaptureStatus, HandleCount=$HandleCount
                   WHERE ProcessKey=$ProcessKey;
                   """))
        {
            var update = lease.Command;
            AddProcessProjectionParameters(update, process, processEntityId);
            update.ExecuteNonQuery();
        }

        using (var lease = LeaseCommand(
                   commands,
                   "DELETE FROM ProcessProjectionFields WHERE ProcessEntityId = $ProcessEntityId;"))
        {
            var clear = lease.Command;
            Add(clear, "$ProcessEntityId", processEntityId);
            clear.ExecuteNonQuery();
        }

        foreach (var winner in resolution.Winners)
        {
            using var lease = LeaseCommand(commands, """
                INSERT INTO ProcessProjectionFields(ProcessEntityId, FieldName, ObservationId, SourceRunId,
                    ValueQuality, ResolutionReason, ProjectionVersion, UpdatedUtc)
                VALUES($ProcessEntityId, $FieldName, $ObservationId, $SourceRunId,
                    $ValueQuality, $ResolutionReason, $ProjectionVersion, $UpdatedUtc);
                """);
            var command = lease.Command;
            Add(command, "$ProcessEntityId", processEntityId);
            Add(command, "$FieldName", winner.FieldName);
            Add(command, "$ObservationId", winner.ObservationId);
            Add(command, "$SourceRunId", winner.SourceRunId);
            Add(command, "$ValueQuality", winner.ValueQuality);
            Add(command, "$ResolutionReason", winner.ResolutionReason);
            Add(command, "$ProjectionVersion", ProcessProjectionPolicy.Version);
            Add(command, "$UpdatedUtc", DateTime.UtcNow);
            command.ExecuteNonQuery();
        }

        using (var lease = LeaseCommand(
                   commands,
                   "INSERT OR REPLACE INTO SchemaInfo(Key, Value) VALUES($Key, $Value);"))
        {
            var diagnostic = lease.Command;
            Add(diagnostic, "$Key", "ProcessProjectionConflicts." + processEntityId);
            Add(diagnostic, "$Value", resolution.ConflictCount.ToString(CultureInfo.InvariantCulture));
            diagnostic.ExecuteNonQuery();
        }

        UpsertCanonicalProcessEntity(process, null, commands);
        return process;
    }

    private void PersistProcessProjections(
        IReadOnlyList<ProcessProjectionBatchRow> projections)
    {
        if (projections.Count == 0)
        {
            return;
        }

        using (var initialize = CreateCommand("""
                   CREATE TEMP TABLE IF NOT EXISTS ProcessProjectionAppendRows (
                       ProcessKey TEXT NOT NULL,
                       ProcessEntityId TEXT NOT NULL,
                       CaseId TEXT,
                       EvidenceSessionId TEXT,
                       CaptureId TEXT,
                       SourceIdentityId TEXT,
                       HostId TEXT,
                       ExecutionRootId TEXT,
                       ProcessId INTEGER,
                       ProcessGuid TEXT,
                       StartTimeUtc TEXT,
                       EndTimeUtc TEXT,
                       Status TEXT,
                       ParentProcessId INTEGER,
                       ParentProcessKey TEXT,
                       ParentProcessEntityId TEXT,
                       ParentProcessName TEXT,
                       ProcessName TEXT,
                       ProcessPath TEXT,
                       CommandLine TEXT,
                       UserName TEXT,
                       SessionId INTEGER,
                       Architecture TEXT,
                       CpuUsage REAL,
                       MemoryUsageBytes INTEGER,
                       CompanyName TEXT,
                       FileDescription TEXT,
                       Sha256Hash TEXT,
                       TreeDepth INTEGER,
                       FirstObservedUtc TEXT,
                       LastObservedUtc TEXT,
                       LastSource TEXT,
                       ModuleCaptureStatus TEXT,
                       ModuleCount INTEGER,
                       HandleCaptureStatus TEXT,
                       HandleCount INTEGER,
                       ConflictCount INTEGER NOT NULL
                   );
                   CREATE UNIQUE INDEX IF NOT EXISTS temp.IX_ProcessProjectionAppendRows_Entity
                       ON ProcessProjectionAppendRows(ProcessEntityId);
                   DELETE FROM ProcessProjectionAppendRows;
                   """))
        {
            initialize.ExecuteNonQuery();
        }

        using (var stage = CreateCommand("""
                   INSERT INTO ProcessProjectionAppendRows(
                       ProcessKey, ProcessEntityId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                       HostId, ExecutionRootId, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                       ParentProcessId, ParentProcessKey, ParentProcessEntityId, ParentProcessName,
                       ProcessName, ProcessPath, CommandLine, UserName, SessionId, Architecture,
                       CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash, TreeDepth,
                       FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus, ModuleCount,
                       HandleCaptureStatus, HandleCount, ConflictCount)
                   VALUES(
                       $ProcessKey, $ProcessEntityId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId,
                       $HostId, $ExecutionRootId, $ProcessId, $ProcessGuid, $StartTimeUtc, $EndTimeUtc, $Status,
                       $ParentProcessId, $ParentProcessKey, $ParentProcessEntityId, $ParentProcessName,
                       $ProcessName, $ProcessPath, $CommandLine, $UserName, $SessionId, $Architecture,
                       $CpuUsage, $MemoryUsageBytes, $CompanyName, $FileDescription, $Sha256Hash, $TreeDepth,
                       $FirstObservedUtc, $LastObservedUtc, $LastSource, $ModuleCaptureStatus, $ModuleCount,
                       $HandleCaptureStatus, $HandleCount, $ConflictCount);
                   """))
        {
            foreach (var projection in projections)
            {
                AddProcessProjectionParameters(
                    stage,
                    projection.Process,
                    projection.Process.ProcessEntityId);
                Add(stage, "$ConflictCount", projection.ConflictCount);
                stage.ExecuteNonQuery();
            }
        }

        using (var upsertProcesses = CreateCommand("""
                   INSERT INTO Processes(
                       ProcessKey, ProcessEntityId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                       HostId, ExecutionRootId, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                       ParentProcessId, ParentProcessKey, ParentProcessEntityId, ParentProcessName,
                       ProcessName, ProcessPath, CommandLine, UserName, SessionId, Architecture,
                       CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash, TreeDepth,
                       FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus, ModuleCount,
                       HandleCaptureStatus, HandleCount)
                   SELECT
                       ProcessKey, ProcessEntityId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                       HostId, ExecutionRootId, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                       ParentProcessId, ParentProcessKey, ParentProcessEntityId, ParentProcessName,
                       ProcessName, ProcessPath, CommandLine, UserName, SessionId, Architecture,
                       CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash, TreeDepth,
                       FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus, ModuleCount,
                       HandleCaptureStatus, HandleCount
                   FROM ProcessProjectionAppendRows
                   WHERE true
                   ON CONFLICT(ProcessKey) DO UPDATE SET
                       ProcessEntityId=excluded.ProcessEntityId, CaseId=excluded.CaseId,
                       EvidenceSessionId=excluded.EvidenceSessionId, CaptureId=excluded.CaptureId,
                       SourceIdentityId=excluded.SourceIdentityId, HostId=excluded.HostId,
                       ExecutionRootId=excluded.ExecutionRootId, ProcessId=excluded.ProcessId,
                       ProcessGuid=excluded.ProcessGuid, StartTimeUtc=excluded.StartTimeUtc,
                       EndTimeUtc=excluded.EndTimeUtc, Status=excluded.Status,
                       ParentProcessId=excluded.ParentProcessId, ParentProcessKey=excluded.ParentProcessKey,
                       ParentProcessEntityId=excluded.ParentProcessEntityId,
                       ParentProcessName=excluded.ParentProcessName, ProcessName=excluded.ProcessName,
                       ProcessPath=excluded.ProcessPath, CommandLine=excluded.CommandLine,
                       UserName=excluded.UserName, SessionId=excluded.SessionId,
                       Architecture=excluded.Architecture, CpuUsage=excluded.CpuUsage,
                       MemoryUsageBytes=excluded.MemoryUsageBytes, CompanyName=excluded.CompanyName,
                       FileDescription=excluded.FileDescription, Sha256Hash=excluded.Sha256Hash,
                       TreeDepth=excluded.TreeDepth, FirstObservedUtc=excluded.FirstObservedUtc,
                       LastObservedUtc=excluded.LastObservedUtc, LastSource=excluded.LastSource,
                       ModuleCaptureStatus=excluded.ModuleCaptureStatus, ModuleCount=excluded.ModuleCount,
                       HandleCaptureStatus=excluded.HandleCaptureStatus, HandleCount=excluded.HandleCount;
                   """))
        {
            upsertProcesses.ExecuteNonQuery();
        }

        using (var deleteObsolete = CreateCommand("""
                   DELETE FROM Processes
                   WHERE ProcessEntityId IN (
                       SELECT ProcessEntityId FROM ProcessProjectionAppendRows)
                     AND NOT EXISTS (
                       SELECT 1 FROM ProcessProjectionAppendRows staged
                       WHERE staged.ProcessEntityId = Processes.ProcessEntityId
                         AND staged.ProcessKey = Processes.ProcessKey);
                   """))
        {
            deleteObsolete.ExecuteNonQuery();
        }

        using (var clearFields = CreateCommand("""
                   DELETE FROM ProcessProjectionFields
                   WHERE ProcessEntityId IN (
                       SELECT ProcessEntityId FROM ProcessProjectionAppendRows);
                   """))
        {
            clearFields.ExecuteNonQuery();
        }

        var projectionFields = new List<ProjectionFieldBatchRow>(projections.Count * 20);
        foreach (var projection in projections)
        {
            foreach (var winner in projection.Winners)
            {
                projectionFields.Add(new ProjectionFieldBatchRow(
                    projection.Process.ProcessEntityId,
                    winner.FieldName,
                    winner.ObservationId,
                    winner.SourceRunId,
                    winner.ValueQuality,
                    winner.ResolutionReason,
                    DateTime.UtcNow));
            }
        }

        if (projectionFields.Count > 0)
        {
            using var insertFields = CreateCommand("""
                INSERT INTO ProcessProjectionFields(ProcessEntityId, FieldName, ObservationId, SourceRunId,
                    ValueQuality, ResolutionReason, ProjectionVersion, UpdatedUtc)
                SELECT
                    json_extract(value, '$.ProcessEntityId'),
                    json_extract(value, '$.FieldName'),
                    json_extract(value, '$.ObservationId'),
                    json_extract(value, '$.SourceRunId'),
                    CAST(json_extract(value, '$.ValueQuality') AS INTEGER),
                    json_extract(value, '$.ResolutionReason'),
                    $ProjectionVersion,
                    json_extract(value, '$.UpdatedUtc')
                FROM json_each($ProjectionFieldsJson);
                """);
            Add(insertFields, "$ProjectionVersion", ProcessProjectionPolicy.Version);
            Add(insertFields, "$ProjectionFieldsJson", JsonSerializer.Serialize(projectionFields));
            insertFields.ExecuteNonQuery();
        }

        using (var diagnostics = CreateCommand("""
                   INSERT OR REPLACE INTO SchemaInfo(Key, Value)
                   SELECT 'ProcessProjectionConflicts.' || ProcessEntityId, CAST(ConflictCount AS TEXT)
                   FROM ProcessProjectionAppendRows;
                   """))
        {
            diagnostics.ExecuteNonQuery();
        }

        using var upsertEntities = CreateCommand("""
            INSERT INTO ProcessEntities (
                ProcessEntityId, ProcessKey, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                HostId, ExecutionRootId, ArtifactId, SourceId, ProcessId, ProcessGuid, StartTimeUtc,
                EndTimeUtc, Status, ParentProcessId, ParentProcessKey, ParentProcessEntityId,
                ParentProcessName, ProcessName, ProcessPath, CommandLine, UserName, SessionId,
                Architecture, CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash,
                TreeDepth, FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus,
                ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError, HandleCaptureStatus,
                HandleCount, HandleLastCapturedUtc, HandleCaptureError)
            SELECT p.ProcessEntityId, p.ProcessKey, p.CaseId, p.EvidenceSessionId, p.CaptureId, p.SourceIdentityId,
                   p.HostId, p.ExecutionRootId, p.ArtifactId, NULL, p.ProcessId, p.ProcessGuid, p.StartTimeUtc,
                   p.EndTimeUtc, p.Status, p.ParentProcessId, p.ParentProcessKey, p.ParentProcessEntityId,
                   p.ParentProcessName, p.ProcessName, p.ProcessPath, p.CommandLine, p.UserName, p.SessionId,
                   p.Architecture, p.CpuUsage, p.MemoryUsageBytes, p.CompanyName, p.FileDescription, p.Sha256Hash,
                   p.TreeDepth, p.FirstObservedUtc, p.LastObservedUtc, p.LastSource, p.ModuleCaptureStatus,
                   p.ModuleCount, p.ModuleLastCapturedUtc, p.ModuleCaptureError, p.HandleCaptureStatus,
                   p.HandleCount, p.HandleLastCapturedUtc, p.HandleCaptureError
            FROM Processes p
            INNER JOIN ProcessProjectionAppendRows staged
                ON staged.ProcessKey = p.ProcessKey AND staged.ProcessEntityId = p.ProcessEntityId
            WHERE true
            ON CONFLICT(ProcessEntityId) DO UPDATE SET
                ProcessKey = excluded.ProcessKey, CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId, SourceId = excluded.SourceId,
                ProcessId = excluded.ProcessId, ProcessGuid = excluded.ProcessGuid,
                StartTimeUtc = excluded.StartTimeUtc, EndTimeUtc = excluded.EndTimeUtc,
                Status = excluded.Status, ParentProcessId = excluded.ParentProcessId,
                ParentProcessKey = excluded.ParentProcessKey,
                ParentProcessEntityId = excluded.ParentProcessEntityId,
                ParentProcessName = excluded.ParentProcessName, ProcessName = excluded.ProcessName,
                ProcessPath = excluded.ProcessPath, CommandLine = excluded.CommandLine,
                UserName = excluded.UserName, SessionId = excluded.SessionId,
                Architecture = excluded.Architecture, CpuUsage = excluded.CpuUsage,
                MemoryUsageBytes = excluded.MemoryUsageBytes, CompanyName = excluded.CompanyName,
                FileDescription = excluded.FileDescription, Sha256Hash = excluded.Sha256Hash,
                TreeDepth = excluded.TreeDepth,
                FirstObservedUtc = CASE
                    WHEN ProcessEntities.FirstObservedUtc IS NULL OR ProcessEntities.FirstObservedUtc = ''
                    THEN excluded.FirstObservedUtc ELSE ProcessEntities.FirstObservedUtc END,
                LastObservedUtc = excluded.LastObservedUtc, LastSource = excluded.LastSource,
                ModuleCaptureStatus = excluded.ModuleCaptureStatus, ModuleCount = excluded.ModuleCount,
                ModuleLastCapturedUtc = excluded.ModuleLastCapturedUtc,
                ModuleCaptureError = excluded.ModuleCaptureError,
                HandleCaptureStatus = excluded.HandleCaptureStatus, HandleCount = excluded.HandleCount,
                HandleLastCapturedUtc = excluded.HandleLastCapturedUtc,
                HandleCaptureError = excluded.HandleCaptureError;
            """);
        upsertEntities.ExecuteNonQuery();
    }

    private IReadOnlyList<ProcessRecord> ReadProcessesForObservationBackfill()
    {
        var rows = new List<ProcessRecord>();
        using var command = CreateCommand("""
            SELECT ProcessKey, ProcessEntityId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                   HostId, ExecutionRootId, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                   ParentProcessId, ParentProcessKey, ParentProcessEntityId, ParentProcessName, ProcessName,
                   ProcessPath, CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                   CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc, LastObservedUtc, LastSource
            FROM Processes;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new ProcessRecord
            {
                ProcessKey = GetString(reader, 0),
                ProcessEntityId = GetString(reader, 1),
                CaseId = GetString(reader, 2),
                EvidenceSessionId = GetString(reader, 3),
                CaptureId = GetString(reader, 4),
                SourceIdentityId = GetString(reader, 5),
                HostId = GetString(reader, 6),
                ExecutionRootId = GetString(reader, 7),
                ProcessId = GetInt(reader, 8),
                ProcessGuid = GetString(reader, 9),
                StartTimeUtc = GetDateTime(reader, 10),
                EndTimeUtc = GetDateTime(reader, 11),
                Status = GetEnum(reader, 12, ProcessStatus.Running),
                ParentProcessId = GetInt(reader, 13),
                ParentProcessKey = GetString(reader, 14),
                ParentProcessEntityId = GetString(reader, 15),
                ParentProcessName = GetString(reader, 16),
                ProcessName = GetString(reader, 17),
                ProcessPath = GetString(reader, 18),
                CommandLine = GetString(reader, 19),
                UserName = GetString(reader, 20),
                SessionId = GetInt(reader, 21),
                Architecture = GetString(reader, 22),
                CpuUsage = GetDouble(reader, 23),
                MemoryUsageBytes = GetLong(reader, 24),
                CompanyName = GetString(reader, 25),
                FileDescription = GetString(reader, 26),
                Sha256Hash = GetString(reader, 27),
                TreeDepth = GetInt(reader, 28),
                FirstObservedUtc = GetDateTime(reader, 29) ?? DateTime.UtcNow,
                LastObservedUtc = GetDateTime(reader, 30) ?? DateTime.UtcNow,
                LastSource = GetString(reader, 31)
            });
        }

        return rows;
    }

    private string ResolveOrCreateProcessEntityId(ProcessRecord process)
    {
        if (!string.IsNullOrWhiteSpace(process.ProcessEntityId))
        {
            return process.ProcessEntityId;
        }

        if (process.StartTimeUtc.HasValue)
        {
            return ProcessEntityIdentity.CreateExact(
                process.CaseId,
                process.EvidenceSessionId,
                process.HostId,
                process.ExecutionRootId,
                process.ProcessId,
                process.StartTimeUtc.Value);
        }

        var aliasKind = process.ProcessKey.StartsWith("procmon:", StringComparison.OrdinalIgnoreCase)
            ? ProcessAliasKind.ProcmonSyntheticKey
            : ProcessAliasKind.LegacyProcessKey;
        var resolved = ResolveProcessAlias(process.ProcessKey, aliasKind, process);
        return string.IsNullOrWhiteSpace(resolved) ? ProcessEntityIdentity.CreateOpaque() : resolved;
    }

    private string ResolveProcessAlias(
        string aliasValue,
        ProcessAliasKind aliasKind,
        ProcessRecord scope,
        ReusableCommandCache? commands = null)
    {
        if (string.IsNullOrWhiteSpace(aliasValue))
        {
            return string.Empty;
        }

        var cacheKey = string.Join(
            '\u001f',
            aliasKind.ToString(),
            aliasValue,
            scope.CaseId,
            scope.EvidenceSessionId,
            scope.HostId,
            scope.ExecutionRootId);
        if (commands != null && commands.TryGetAliasResolution(cacheKey, out var cached))
        {
            return cached;
        }

        using var lease = LeaseCommand(commands, """
            SELECT MIN(ProcessEntityId)
            FROM ProcessAliases
            WHERE AliasKind = $AliasKind AND AliasValue = $AliasValue
              AND COALESCE(CaseId, '') = $CaseId
              AND COALESCE(EvidenceSessionId, '') = $EvidenceSessionId
              AND COALESCE(HostId, '') = $HostId
              AND COALESCE(ExecutionRootId, '') = $ExecutionRootId
            HAVING COUNT(DISTINCT ProcessEntityId) = 1;
            """);
        var command = lease.Command;
        Add(command, "$AliasKind", aliasKind.ToString());
        Add(command, "$AliasValue", aliasValue);
        Add(command, "$CaseId", scope.CaseId);
        Add(command, "$EvidenceSessionId", scope.EvidenceSessionId);
        Add(command, "$HostId", scope.HostId);
        Add(command, "$ExecutionRootId", scope.ExecutionRootId);
        var resolved = command.ExecuteScalar()?.ToString() ?? string.Empty;
        commands?.SetAliasResolution(cacheKey, resolved);
        return resolved;
    }

    private void UpsertCanonicalProcessEntity(
        ProcessRecord process,
        int? sourceId,
        ReusableCommandCache? commands = null)
    {
        using var lease = LeaseCommand(commands, """
            INSERT INTO ProcessEntities (
                ProcessEntityId, ProcessKey, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                HostId, ExecutionRootId, ArtifactId, SourceId, ProcessId, ProcessGuid, StartTimeUtc,
                EndTimeUtc, Status, ParentProcessId, ParentProcessKey, ParentProcessEntityId,
                ParentProcessName, ProcessName, ProcessPath, CommandLine, UserName, SessionId,
                Architecture, CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash,
                TreeDepth, FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus,
                ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError, HandleCaptureStatus,
                HandleCount, HandleLastCapturedUtc, HandleCaptureError)
            SELECT $ProcessEntityId, ProcessKey, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId,
                   HostId, ExecutionRootId, ArtifactId, $SourceId, ProcessId, ProcessGuid, StartTimeUtc,
                   EndTimeUtc, Status, ParentProcessId, ParentProcessKey, $ParentProcessEntityId,
                   ParentProcessName, ProcessName, ProcessPath, CommandLine, UserName, SessionId,
                   Architecture, CpuUsage, MemoryUsageBytes, CompanyName, FileDescription, Sha256Hash,
                   TreeDepth, FirstObservedUtc, LastObservedUtc, LastSource, ModuleCaptureStatus,
                   ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError, HandleCaptureStatus,
                   HandleCount, HandleLastCapturedUtc, HandleCaptureError
            FROM Processes WHERE ProcessKey = $ProcessKey
            ON CONFLICT(ProcessEntityId) DO UPDATE SET
                ProcessKey = excluded.ProcessKey, CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId, SourceId = excluded.SourceId,
                ProcessId = excluded.ProcessId, ProcessGuid = excluded.ProcessGuid,
                StartTimeUtc = excluded.StartTimeUtc, EndTimeUtc = excluded.EndTimeUtc,
                Status = excluded.Status, ParentProcessId = excluded.ParentProcessId,
                ParentProcessKey = excluded.ParentProcessKey,
                ParentProcessEntityId = excluded.ParentProcessEntityId,
                ParentProcessName = excluded.ParentProcessName, ProcessName = excluded.ProcessName,
                ProcessPath = excluded.ProcessPath, CommandLine = excluded.CommandLine,
                UserName = excluded.UserName, SessionId = excluded.SessionId,
                Architecture = excluded.Architecture, CpuUsage = excluded.CpuUsage,
                MemoryUsageBytes = excluded.MemoryUsageBytes, CompanyName = excluded.CompanyName,
                FileDescription = excluded.FileDescription, Sha256Hash = excluded.Sha256Hash,
                TreeDepth = excluded.TreeDepth,
                FirstObservedUtc = CASE
                    WHEN ProcessEntities.FirstObservedUtc IS NULL OR ProcessEntities.FirstObservedUtc = ''
                    THEN excluded.FirstObservedUtc ELSE ProcessEntities.FirstObservedUtc END,
                LastObservedUtc = excluded.LastObservedUtc, LastSource = excluded.LastSource,
                ModuleCaptureStatus = excluded.ModuleCaptureStatus, ModuleCount = excluded.ModuleCount,
                ModuleLastCapturedUtc = excluded.ModuleLastCapturedUtc,
                ModuleCaptureError = excluded.ModuleCaptureError,
                HandleCaptureStatus = excluded.HandleCaptureStatus, HandleCount = excluded.HandleCount,
                HandleLastCapturedUtc = excluded.HandleLastCapturedUtc,
                HandleCaptureError = excluded.HandleCaptureError;
            """);
        var command = lease.Command;
        Add(command, "$ProcessEntityId", process.ProcessEntityId);
        Add(command, "$ParentProcessEntityId", process.ParentProcessEntityId);
        Add(command, "$SourceId", sourceId);
        Add(command, "$ProcessKey", process.ProcessKey);
        command.ExecuteNonQuery();
    }

    private void UpsertProcessAlias(ProcessRecord process, ProcessAliasKind kind, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (kind == ProcessAliasKind.LegacyProcessKey &&
            value.StartsWith("procmon:", StringComparison.OrdinalIgnoreCase))
        {
            kind = ProcessAliasKind.ProcmonSyntheticKey;
        }

        using var command = CreateCommand("""
            INSERT OR IGNORE INTO ProcessAliases (
                ProcessEntityId, AliasKind, AliasValue, CaseId, EvidenceSessionId,
                HostId, ExecutionRootId, SourceIdentityId, CreatedUtc)
            VALUES ($ProcessEntityId, $AliasKind, $AliasValue, $CaseId, $EvidenceSessionId,
                    $HostId, $ExecutionRootId, $SourceIdentityId, $CreatedUtc);
            """);
        Add(command, "$ProcessEntityId", process.ProcessEntityId);
        Add(command, "$AliasKind", kind.ToString());
        Add(command, "$AliasValue", value);
        Add(command, "$CaseId", process.CaseId);
        Add(command, "$EvidenceSessionId", process.EvidenceSessionId);
        Add(command, "$HostId", process.HostId);
        Add(command, "$ExecutionRootId", process.ExecutionRootId);
        Add(command, "$SourceIdentityId", process.SourceIdentityId);
        Add(command, "$CreatedUtc", DateTime.UtcNow);
        command.ExecuteNonQuery();
    }

    private void RecordProjectionRebuild()
    {
        using (var version = CreateCommand("""
                   INSERT INTO SchemaInfo(Key, Value) VALUES($Key, $Value)
                   ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value;
                   """))
        {
            Add(version, "$Key", "ProcessProjectionVersion");
            Add(version, "$Value", ProcessProjectionPolicy.Version);
            version.ExecuteNonQuery();
        }

        using var rebuilt = CreateCommand("""
            INSERT INTO SchemaInfo(Key, Value) VALUES($Key, $Value)
            ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value;
            """);
        Add(rebuilt, "$Key", "ProcessProjectionLastRebuildUtc");
        Add(rebuilt, "$Value", DateTime.UtcNow);
        rebuilt.ExecuteNonQuery();
    }

    private static void ApplyEvidenceIdentity(IHasEvidenceIdentity record, EvidenceIdentity identity)
    {
        record.CaseId = identity.CaseId;
        record.EvidenceSessionId = identity.EvidenceSessionId;
        record.CaptureId = identity.CaptureId;
        record.SourceIdentityId = identity.SourceIdentityId;
        record.HostId = identity.HostId;
        record.ExecutionRootId = identity.ExecutionRootId;
    }

    private static void AddEvidenceIdentityParameters(SqliteCommand command, EvidenceIdentity identity)
    {
        Add(command, "$CaseId", identity.CaseId);
        Add(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Add(command, "$CaptureId", identity.CaptureId);
        Add(command, "$SourceIdentityId", identity.SourceIdentityId);
        Add(command, "$HostId", identity.HostId);
        Add(command, "$ExecutionRootId", identity.ExecutionRootId);
    }

    private static void AddProcessPayloadParameters(
        SqliteCommand command,
        ProcessRecord process,
        bool includeCaptureSummaries)
    {
        Add(command, "$ProcessId", process.ProcessId);
        Add(command, "$ProcessGuid", process.ProcessGuid);
        Add(command, "$StartTimeUtc", process.StartTimeUtc);
        Add(command, "$EndTimeUtc", process.EndTimeUtc);
        Add(command, "$Status", process.Status.ToString());
        Add(command, "$ParentProcessId", process.ParentProcessId);
        Add(command, "$ParentProcessKey", process.ParentProcessKey);
        Add(command, "$ParentProcessEntityId", process.ParentProcessEntityId);
        Add(command, "$ParentProcessName", process.ParentProcessName);
        Add(command, "$ProcessName", process.ProcessName);
        Add(command, "$ProcessPath", process.ProcessPath);
        Add(command, "$CommandLine", process.CommandLine);
        Add(command, "$UserName", process.UserName);
        Add(command, "$SessionId", process.SessionId);
        Add(command, "$Architecture", process.Architecture);
        Add(command, "$CpuUsage", process.CpuUsage);
        Add(command, "$MemoryUsageBytes", process.MemoryUsageBytes);
        Add(command, "$CompanyName", process.CompanyName);
        Add(command, "$FileDescription", process.FileDescription);
        Add(command, "$Sha256Hash", process.Sha256Hash);
        Add(command, "$TreeDepth", process.TreeDepth);
        Add(command, "$FirstObservedUtc", process.FirstObservedUtc == default ? DateTime.UtcNow : process.FirstObservedUtc);
        Add(command, "$LastObservedUtc", process.LastObservedUtc == default ? DateTime.UtcNow : process.LastObservedUtc);
        Add(command, "$LastSource", process.LastSource);
        Add(command, "$ModuleCaptureStatus", process.ModuleCaptureStatus.ToString());
        Add(command, "$ModuleCount", process.ModuleCount);
        Add(command, "$HandleCaptureStatus", process.HandleCaptureStatus.ToString());
        Add(command, "$HandleCount", process.HandleCount);
        if (!includeCaptureSummaries)
        {
            return;
        }

        Add(command, "$ModuleLastCapturedUtc", process.ModuleLastCapturedUtc);
        Add(command, "$ModuleCaptureError", process.ModuleCaptureError);
        Add(command, "$HandleLastCapturedUtc", process.HandleLastCapturedUtc);
        Add(command, "$HandleCaptureError", process.HandleCaptureError);
    }

    private static void AddProcessProjectionParameters(
        SqliteCommand command,
        ProcessRecord process,
        string processEntityId)
    {
        Add(command, "$ProcessEntityId", processEntityId);
        Add(command, "$ProcessKey", process.ProcessKey);
        Add(command, "$CaseId", process.CaseId);
        Add(command, "$EvidenceSessionId", process.EvidenceSessionId);
        Add(command, "$CaptureId", process.CaptureId);
        Add(command, "$SourceIdentityId", process.SourceIdentityId);
        Add(command, "$HostId", process.HostId);
        Add(command, "$ExecutionRootId", process.ExecutionRootId);
        AddProcessPayloadParameters(command, process, includeCaptureSummaries: false);
    }

    private SqliteCommand CreateCommand(string sql) => _context.CreateCommand(sql);

    private CommandLease LeaseCommand(ReusableCommandCache? cache, string sql)
        => cache == null
            ? new CommandLease(CreateCommand(sql), ownsCommand: true)
            : new CommandLease(cache.GetOrCreate(sql), ownsCommand: false);

    private static void Add(SqliteCommand command, string name, object? value)
    {
        if (!command.Parameters.Contains(name))
        {
            SqliteWriteTransactionContext.Add(command, name, value);
            return;
        }

        if (value is DateTime dateTime)
        {
            value = SqliteWriteTransactionContext.FormatDate(dateTime);
        }

        command.Parameters[name].Value = value ?? DBNull.Value;
    }

    private static object? EmptyToNull(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string BuildProcessStatisticsSampleId(string processKey, DateTime observedUtc)
    {
        var normalizedProcessKey = string.IsNullOrWhiteSpace(processKey) ? "unknown" : processKey;
        var normalizedObservedUtc = observedUtc == default ? DateTime.UtcNow : observedUtc;
        return $"{normalizedProcessKey}_{normalizedObservedUtc.ToUniversalTime().Ticks}";
    }

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static int GetInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt32(ordinal);

    private static long GetLong(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt64(ordinal);

    private static double GetDouble(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetDouble(ordinal);

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }

        return DateTime.TryParse(
            reader.GetString(ordinal),
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var value)
            ? value
            : null;
    }

    private static T GetEnum<T>(SqliteDataReader reader, int ordinal, T fallback)
        where T : struct, Enum
        => Enum.TryParse<T>(GetString(reader, ordinal), ignoreCase: true, out var value) ? value : fallback;

    private sealed record ProjectionFieldBatchRow(
        string ProcessEntityId,
        string FieldName,
        string ObservationId,
        string SourceRunId,
        int ValueQuality,
        string ResolutionReason,
        DateTime UpdatedUtc);

    private sealed record ProcessProjectionBatchRow(
        ProcessRecord Process,
        IReadOnlyList<ProcessProjectionFieldWinner> Winners,
        int ConflictCount);

    private sealed record ProcessObservationGroup(
        string ProcessEntityId,
        List<ProcessObservation> Observations);

    private readonly struct CommandLease : IDisposable
    {
        private readonly bool _ownsCommand;

        internal CommandLease(SqliteCommand command, bool ownsCommand)
        {
            Command = command;
            _ownsCommand = ownsCommand;
        }

        internal SqliteCommand Command { get; }

        public void Dispose()
        {
            if (_ownsCommand)
            {
                Command.Dispose();
            }
        }
    }

    private sealed class ReusableCommandCache : IDisposable
    {
        private readonly ProcessEvidenceWriteService _owner;
        private readonly Dictionary<string, SqliteCommand> _commands = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _aliasResolutions = new(StringComparer.Ordinal);

        internal ReusableCommandCache(ProcessEvidenceWriteService owner)
        {
            _owner = owner;
        }

        internal SqliteCommand GetOrCreate(string sql)
        {
            if (_commands.TryGetValue(sql, out var command))
            {
                return command;
            }

            command = _owner.CreateCommand(sql);
            _commands.Add(sql, command);
            return command;
        }

        internal bool TryGetAliasResolution(string cacheKey, out string processEntityId)
            => _aliasResolutions.TryGetValue(cacheKey, out processEntityId!);

        internal void SetAliasResolution(string cacheKey, string processEntityId)
            => _aliasResolutions[cacheKey] = processEntityId;

        public void Dispose()
        {
            foreach (var command in _commands.Values)
            {
                command.Dispose();
            }

            _commands.Clear();
            _aliasResolutions.Clear();
        }
    }
}
