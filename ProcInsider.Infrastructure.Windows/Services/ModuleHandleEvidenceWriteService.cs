using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal interface IModuleHandleEvidenceWriteService
{
    void UpsertModule(ModuleObservationRecord module);
    void UpsertModules(IEnumerable<ModuleObservationRecord> modules);
    void UpsertModuleSnapshot(
        string processKey,
        IEnumerable<ModuleObservationRecord> modules,
        DateTime observedUtc,
        string source);
    void UpsertModuleSnapshotBatch(
        string processKey,
        IEnumerable<ModuleObservationRecord> modules,
        DateTime observedUtc,
        string source);
    int CloseStaleModulesForSnapshot(
        string processKey,
        IReadOnlySet<string> seenKeys,
        DateTime observedUtc,
        string source,
        int maxRows);
    void UpsertHandle(HandleObservationRecord handle);
    void UpsertHandles(IEnumerable<HandleObservationRecord> handles);
    void UpsertHandleSnapshot(
        string processKey,
        IEnumerable<HandleObservationRecord> handles,
        DateTime observedUtc,
        string source);
    void UpsertHandleSnapshotBatch(
        string processKey,
        IEnumerable<HandleObservationRecord> handles,
        DateTime observedUtc,
        string source);
    int CloseStaleHandlesForSnapshot(
        string processKey,
        IReadOnlySet<string> seenKeys,
        DateTime observedUtc,
        string source,
        int maxRows);
}

/// <summary>
/// Focused runtime module/handle lifecycle writer. The store facade owns database
/// selection, the connection, and transaction lifetime; this component owns only
/// family-specific SQL, lifecycle projection, and atomic search/relation side effects.
/// </summary>
internal sealed class ModuleHandleEvidenceWriteService : IModuleHandleEvidenceWriteService
{
    private readonly SqliteWriteTransactionContext _context;

    internal ModuleHandleEvidenceWriteService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public void UpsertModule(ModuleObservationRecord module)
    {
        ArgumentNullException.ThrowIfNull(module);
        _context.Execute(() =>
        {
            using var command = CreateModuleUpsertCommand();
            WriteModuleCore(command, module);
        });
    }

    public void UpsertModules(IEnumerable<ModuleObservationRecord> modules)
    {
        ArgumentNullException.ThrowIfNull(modules);
        var snapshot = modules.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateModuleUpsertCommand();
            command.Prepare();
            foreach (var module in snapshot)
            {
                ArgumentNullException.ThrowIfNull(module);
                WriteModuleCore(command, module);
            }
        });
    }

    public void UpsertModuleSnapshot(
        string processKey,
        IEnumerable<ModuleObservationRecord> modules,
        DateTime observedUtc,
        string source)
    {
        ArgumentNullException.ThrowIfNull(modules);
        var snapshot = modules.ToList();
        processKey = ResolveProcessKey(processKey, snapshot.Select(module => module?.ProcessKey));
        if (string.IsNullOrWhiteSpace(processKey))
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateModuleUpsertCommand();
            command.Prepare();
            var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var module in snapshot)
            {
                ArgumentNullException.ThrowIfNull(module);
                if (!PrepareCurrentModule(module, processKey, observedUtc, source))
                {
                    continue;
                }

                seenKeys.Add(module.ModuleKey);
                WriteModuleCore(command, module);
            }

            foreach (var stale in ReadModulesForProcess(processKey)
                         .Where(module => module.State != ModuleObservationState.Unloaded &&
                                          !seenKeys.Contains(module.ModuleKey)))
            {
                CloseModule(stale, observedUtc, source);
                WriteModuleCore(command, stale);
            }
        });
    }

    public void UpsertModuleSnapshotBatch(
        string processKey,
        IEnumerable<ModuleObservationRecord> modules,
        DateTime observedUtc,
        string source)
    {
        ArgumentNullException.ThrowIfNull(modules);
        var snapshot = modules.ToList();
        processKey = ResolveProcessKey(processKey, snapshot.Select(module => module?.ProcessKey));
        if (string.IsNullOrWhiteSpace(processKey) || snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateModuleUpsertCommand();
            command.Prepare();
            foreach (var module in snapshot)
            {
                ArgumentNullException.ThrowIfNull(module);
                if (PrepareCurrentModule(module, processKey, observedUtc, source))
                {
                    WriteModuleCore(command, module);
                }
            }
        });
    }

    public int CloseStaleModulesForSnapshot(
        string processKey,
        IReadOnlySet<string> seenKeys,
        DateTime observedUtc,
        string source,
        int maxRows)
    {
        ArgumentNullException.ThrowIfNull(seenKeys);
        if (string.IsNullOrWhiteSpace(processKey))
        {
            return 0;
        }

        var closedCount = 0;
        _context.Execute(() =>
        {
            var staleModules = ReadModulesForProcess(processKey)
                .Where(module => module.State != ModuleObservationState.Unloaded &&
                                 !seenKeys.Contains(module.ModuleKey))
                .Take(Math.Max(1, maxRows))
                .ToList();
            if (staleModules.Count == 0)
            {
                return;
            }

            using var command = CreateModuleUpsertCommand();
            command.Prepare();
            foreach (var stale in staleModules)
            {
                CloseModule(stale, observedUtc, source);
                WriteModuleCore(command, stale);
            }

            closedCount = staleModules.Count;
        });
        return closedCount;
    }

    public void UpsertHandle(HandleObservationRecord handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        _context.Execute(() =>
        {
            using var command = CreateHandleUpsertCommand();
            WriteHandleCore(command, handle);
        });
    }

    public void UpsertHandles(IEnumerable<HandleObservationRecord> handles)
    {
        ArgumentNullException.ThrowIfNull(handles);
        var snapshot = handles.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateHandleUpsertCommand();
            command.Prepare();
            foreach (var handle in snapshot)
            {
                ArgumentNullException.ThrowIfNull(handle);
                WriteHandleCore(command, handle);
            }
        });
    }

    public void UpsertHandleSnapshot(
        string processKey,
        IEnumerable<HandleObservationRecord> handles,
        DateTime observedUtc,
        string source)
    {
        ArgumentNullException.ThrowIfNull(handles);
        var snapshot = handles.ToList();
        processKey = ResolveProcessKey(processKey, snapshot.Select(handle => handle?.ProcessKey));
        if (string.IsNullOrWhiteSpace(processKey))
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateHandleUpsertCommand();
            command.Prepare();
            var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var handle in snapshot)
            {
                ArgumentNullException.ThrowIfNull(handle);
                if (!PrepareCurrentHandle(handle, processKey, observedUtc, source))
                {
                    continue;
                }

                seenKeys.Add(handle.HandleKey);
                WriteHandleCore(command, handle);
            }

            foreach (var stale in ReadHandlesForProcess(processKey)
                         .Where(handle => handle.State != HandleObservationState.Closed &&
                                          !seenKeys.Contains(handle.HandleKey)))
            {
                CloseHandle(stale, observedUtc, source);
                WriteHandleCore(command, stale);
            }
        });
    }

    public void UpsertHandleSnapshotBatch(
        string processKey,
        IEnumerable<HandleObservationRecord> handles,
        DateTime observedUtc,
        string source)
    {
        ArgumentNullException.ThrowIfNull(handles);
        var snapshot = handles.ToList();
        processKey = ResolveProcessKey(processKey, snapshot.Select(handle => handle?.ProcessKey));
        if (string.IsNullOrWhiteSpace(processKey) || snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateHandleUpsertCommand();
            command.Prepare();
            foreach (var handle in snapshot)
            {
                ArgumentNullException.ThrowIfNull(handle);
                if (PrepareCurrentHandle(handle, processKey, observedUtc, source))
                {
                    WriteHandleCore(command, handle);
                }
            }
        });
    }

    public int CloseStaleHandlesForSnapshot(
        string processKey,
        IReadOnlySet<string> seenKeys,
        DateTime observedUtc,
        string source,
        int maxRows)
    {
        ArgumentNullException.ThrowIfNull(seenKeys);
        if (string.IsNullOrWhiteSpace(processKey))
        {
            return 0;
        }

        var closedCount = 0;
        _context.Execute(() =>
        {
            var staleHandles = ReadHandlesForProcess(processKey)
                .Where(handle => handle.State != HandleObservationState.Closed &&
                                 !seenKeys.Contains(handle.HandleKey))
                .Take(Math.Max(1, maxRows))
                .ToList();
            if (staleHandles.Count == 0)
            {
                return;
            }

            using var command = CreateHandleUpsertCommand();
            command.Prepare();
            foreach (var stale in staleHandles)
            {
                CloseHandle(stale, observedUtc, source);
                WriteHandleCore(command, stale);
            }

            closedCount = staleHandles.Count;
        });
        return closedCount;
    }

    private void WriteModuleCore(SqliteCommand command, ModuleObservationRecord module)
    {
        var sourceId = _context.EnsureTelemetrySource(module.LastSource, "Module");
        var identity = _context.ResolveEvidenceIdentity(module, "Module", module.LastSource);
        ApplyEvidenceIdentity(module, identity);
        var attachment = _context.PrepareProcessAttachedEvidence(
            module,
            EvidenceReferenceKind.Module,
            module.ModuleKey,
            module.ProcessId,
            module.ProcessGuid,
            processStartTimeUtc: null,
            module.ModuleName,
            module.LastSeenUtc);

        Set(command, "$SequenceId", module.SequenceId);
        SetEvidenceIdentityParameters(command, identity);
        Set(command, "$SourceId", sourceId);
        Set(command, "$ProcessEntityId", module.ProcessEntityId);
        Set(command, "$SourceRunId", EmptyToNull(module.SourceRunId));
        Set(command, "$IngestionJobId", module.IngestionJobId);
        Set(command, "$ProcessKey", module.ProcessKey);
        Set(command, "$ProcessId", module.ProcessId);
        Set(command, "$ProcessGuid", module.ProcessGuid);
        Set(command, "$ModuleKey", module.ModuleKey);
        Set(command, "$ModuleName", module.ModuleName);
        Set(command, "$FullPath", module.FullPath);
        Set(command, "$BaseAddress", module.BaseAddress);
        Set(command, "$ModuleMemorySize", module.ModuleMemorySize);
        Set(command, "$FileVersion", module.FileVersion);
        Set(command, "$CompanyName", module.CompanyName);
        Set(command, "$Description", module.Description);
        Set(command, "$Sha256Hash", module.Sha256Hash);
        Set(command, "$FirstSeenUtc", module.FirstSeenUtc);
        Set(command, "$LastSeenUtc", module.LastSeenUtc);
        Set(command, "$UnloadedUtc", module.UnloadedUtc);
        Set(command, "$State", module.State.ToString());
        Set(command, "$Sources", module.Sources);
        Set(command, "$LastSource", module.LastSource);
        Set(command, "$DedupKey", module.ModuleKey);
        command.ExecuteNonQuery();

        _context.UpsertSearchIndex(CreateModuleSearchIndexRow(module));
        _context.PersistProcessAttachedRelation(
            module,
            EvidenceReferenceKind.Module,
            module.ModuleKey,
            EvidenceRelationType.Loaded,
            attachment,
            module.LastSeenUtc,
            module.UnloadedUtc,
            module.ModuleKey,
            module.State.ToString(),
            processIsSource: true);
    }

    private void WriteHandleCore(SqliteCommand command, HandleObservationRecord handle)
    {
        var sourceId = _context.EnsureTelemetrySource(handle.LastSource, "Handle");
        var identity = _context.ResolveEvidenceIdentity(handle, "Handle", handle.LastSource);
        ApplyEvidenceIdentity(handle, identity);
        var attachment = _context.PrepareProcessAttachedEvidence(
            handle,
            EvidenceReferenceKind.Handle,
            handle.HandleKey,
            handle.ProcessId,
            processGuid: string.Empty,
            processStartTimeUtc: null,
            processName: string.Empty,
            handle.LastSeenUtc);

        Set(command, "$SequenceId", handle.SequenceId);
        SetEvidenceIdentityParameters(command, identity);
        Set(command, "$SourceId", sourceId);
        Set(command, "$ProcessEntityId", handle.ProcessEntityId);
        Set(command, "$SourceRunId", EmptyToNull(handle.SourceRunId));
        Set(command, "$IngestionJobId", handle.IngestionJobId);
        Set(command, "$ProcessKey", handle.ProcessKey);
        Set(command, "$ProcessId", handle.ProcessId);
        Set(command, "$HandleKey", handle.HandleKey);
        Set(command, "$HandleValue", handle.HandleValue);
        Set(command, "$HandleValueNumeric", unchecked((long)handle.HandleValueNumeric));
        Set(command, "$ObjectType", handle.ObjectType);
        Set(command, "$ObjectName", handle.ObjectName);
        Set(command, "$GrantedAccess", handle.GrantedAccess);
        Set(command, "$GrantedAccessValue", handle.GrantedAccessValue);
        Set(command, "$HandleAttributes", handle.HandleAttributes);
        Set(command, "$HandleAttributesValue", handle.HandleAttributesValue);
        Set(command, "$ObjectAddress", handle.ObjectAddress);
        Set(command, "$FirstSeenUtc", handle.FirstSeenUtc);
        Set(command, "$LastSeenUtc", handle.LastSeenUtc);
        Set(command, "$ClosedUtc", handle.ClosedUtc);
        Set(command, "$State", handle.State.ToString());
        Set(command, "$LastSource", handle.LastSource);
        Set(command, "$DedupKey", handle.HandleKey);
        command.ExecuteNonQuery();

        _context.UpsertSearchIndex(CreateHandleSearchIndexRow(handle));
        _context.PersistProcessAttachedRelation(
            handle,
            EvidenceReferenceKind.Handle,
            handle.HandleKey,
            EvidenceRelationType.Opened,
            attachment,
            handle.LastSeenUtc,
            handle.ClosedUtc,
            handle.HandleKey,
            handle.State.ToString(),
            processIsSource: true);
    }

    private SqliteCommand CreateModuleUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO Modules (
                SequenceId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceId, ProcessEntityId, SourceRunId, IngestionJobId,
                ProcessKey, ProcessId, ProcessGuid, ModuleKey, ModuleName,
                FullPath, BaseAddress, ModuleMemorySize, FileVersion, CompanyName, Description,
                Sha256Hash, FirstSeenUtc, LastSeenUtc, UnloadedUtc, State, Sources, LastSource, DedupKey)
            VALUES (
                $SequenceId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceId, $ProcessEntityId, $SourceRunId, $IngestionJobId,
                $ProcessKey, $ProcessId, $ProcessGuid, $ModuleKey, $ModuleName,
                $FullPath, $BaseAddress, $ModuleMemorySize, $FileVersion, $CompanyName, $Description,
                $Sha256Hash, $FirstSeenUtc, $LastSeenUtc, $UnloadedUtc, $State, $Sources, $LastSource, $DedupKey)
            ON CONFLICT(ModuleKey) DO UPDATE SET
                SequenceId = excluded.SequenceId,
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceId = excluded.SourceId,
                ProcessEntityId = excluded.ProcessEntityId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                ProcessId = excluded.ProcessId,
                ProcessGuid = excluded.ProcessGuid,
                ModuleName = excluded.ModuleName,
                FullPath = excluded.FullPath,
                BaseAddress = excluded.BaseAddress,
                ModuleMemorySize = excluded.ModuleMemorySize,
                FileVersion = excluded.FileVersion,
                CompanyName = excluded.CompanyName,
                Description = excluded.Description,
                Sha256Hash = excluded.Sha256Hash,
                FirstSeenUtc = excluded.FirstSeenUtc,
                LastSeenUtc = excluded.LastSeenUtc,
                UnloadedUtc = excluded.UnloadedUtc,
                State = excluded.State,
                Sources = excluded.Sources,
                LastSource = excluded.LastSource,
                DedupKey = excluded.DedupKey;
            """);
        AddParameters(command,
            "$SequenceId", "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId", "$ExecutionRootId",
            "$SourceId", "$ProcessEntityId", "$SourceRunId", "$IngestionJobId", "$ProcessKey", "$ProcessId", "$ProcessGuid",
            "$ModuleKey", "$ModuleName", "$FullPath", "$BaseAddress", "$ModuleMemorySize", "$FileVersion", "$CompanyName",
            "$Description", "$Sha256Hash", "$FirstSeenUtc", "$LastSeenUtc", "$UnloadedUtc", "$State", "$Sources",
            "$LastSource", "$DedupKey");
        return command;
    }

    private SqliteCommand CreateHandleUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO Handles (
                SequenceId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId,
                SourceId, ProcessEntityId, SourceRunId, IngestionJobId,
                ProcessKey, ProcessId, HandleKey, HandleValue, HandleValueNumeric,
                ObjectType, ObjectName, GrantedAccess, GrantedAccessValue, HandleAttributes,
                HandleAttributesValue, ObjectAddress, FirstSeenUtc, LastSeenUtc, ClosedUtc, State,
                LastSource, DedupKey)
            VALUES (
                $SequenceId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId,
                $SourceId, $ProcessEntityId, $SourceRunId, $IngestionJobId,
                $ProcessKey, $ProcessId, $HandleKey, $HandleValue, $HandleValueNumeric,
                $ObjectType, $ObjectName, $GrantedAccess, $GrantedAccessValue, $HandleAttributes,
                $HandleAttributesValue, $ObjectAddress, $FirstSeenUtc, $LastSeenUtc, $ClosedUtc, $State,
                $LastSource, $DedupKey)
            ON CONFLICT(HandleKey) DO UPDATE SET
                SequenceId = excluded.SequenceId,
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceId = excluded.SourceId,
                ProcessEntityId = excluded.ProcessEntityId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                ProcessId = excluded.ProcessId,
                HandleValue = excluded.HandleValue,
                HandleValueNumeric = excluded.HandleValueNumeric,
                ObjectType = excluded.ObjectType,
                ObjectName = excluded.ObjectName,
                GrantedAccess = excluded.GrantedAccess,
                GrantedAccessValue = excluded.GrantedAccessValue,
                HandleAttributes = excluded.HandleAttributes,
                HandleAttributesValue = excluded.HandleAttributesValue,
                ObjectAddress = excluded.ObjectAddress,
                FirstSeenUtc = excluded.FirstSeenUtc,
                LastSeenUtc = excluded.LastSeenUtc,
                ClosedUtc = excluded.ClosedUtc,
                State = excluded.State,
                LastSource = excluded.LastSource,
                DedupKey = excluded.DedupKey;
            """);
        AddParameters(command,
            "$SequenceId", "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId", "$ExecutionRootId",
            "$SourceId", "$ProcessEntityId", "$SourceRunId", "$IngestionJobId", "$ProcessKey", "$ProcessId", "$HandleKey",
            "$HandleValue", "$HandleValueNumeric", "$ObjectType", "$ObjectName", "$GrantedAccess", "$GrantedAccessValue",
            "$HandleAttributes", "$HandleAttributesValue", "$ObjectAddress", "$FirstSeenUtc", "$LastSeenUtc", "$ClosedUtc",
            "$State", "$LastSource", "$DedupKey");
        return command;
    }

    private IReadOnlyList<ModuleObservationRecord> ReadModulesForProcess(string processKey)
    {
        var rows = new List<ModuleObservationRecord>();
        using var command = _context.CreateCommand("""
            SELECT SequenceId, ProcessEntityId, ProcessKey, ProcessId, ProcessGuid, ModuleKey, ModuleName, FullPath,
                   BaseAddress, ModuleMemorySize, FileVersion, CompanyName, Description, Sha256Hash,
                   FirstSeenUtc, LastSeenUtc, UnloadedUtc, State, Sources, LastSource,
                   CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId
            FROM Modules
            WHERE ProcessKey = $ProcessKey;
            """);
        SqliteWriteTransactionContext.Add(command, "$ProcessKey", processKey);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new ModuleObservationRecord
            {
                SequenceId = GetLong(reader, 0),
                ProcessEntityId = GetString(reader, 1),
                ProcessKey = GetString(reader, 2),
                ProcessId = GetInt(reader, 3),
                ProcessGuid = GetString(reader, 4),
                ModuleKey = GetString(reader, 5),
                ModuleName = GetString(reader, 6),
                FullPath = GetString(reader, 7),
                BaseAddress = GetString(reader, 8),
                ModuleMemorySize = GetLong(reader, 9),
                FileVersion = GetString(reader, 10),
                CompanyName = GetString(reader, 11),
                Description = GetString(reader, 12),
                Sha256Hash = GetString(reader, 13),
                FirstSeenUtc = GetDateTime(reader, 14) ?? DateTime.UtcNow,
                LastSeenUtc = GetDateTime(reader, 15) ?? DateTime.UtcNow,
                UnloadedUtc = GetDateTime(reader, 16),
                State = GetEnum(reader, 17, ModuleObservationState.Loaded),
                Sources = GetString(reader, 18),
                LastSource = GetString(reader, 19),
                CaseId = GetString(reader, 20),
                EvidenceSessionId = GetString(reader, 21),
                CaptureId = GetString(reader, 22),
                SourceIdentityId = GetString(reader, 23),
                HostId = GetString(reader, 24),
                ExecutionRootId = GetString(reader, 25)
            });
        }

        return rows;
    }

    private IReadOnlyList<HandleObservationRecord> ReadHandlesForProcess(string processKey)
    {
        var rows = new List<HandleObservationRecord>();
        using var command = _context.CreateCommand("""
            SELECT SequenceId, ProcessEntityId, ProcessKey, ProcessId, HandleKey, HandleValue, HandleValueNumeric,
                   ObjectType, ObjectName, GrantedAccess, GrantedAccessValue, HandleAttributes,
                   HandleAttributesValue, ObjectAddress, FirstSeenUtc, LastSeenUtc, ClosedUtc, State,
                   LastSource, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId
            FROM Handles
            WHERE ProcessKey = $ProcessKey;
            """);
        SqliteWriteTransactionContext.Add(command, "$ProcessKey", processKey);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new HandleObservationRecord
            {
                SequenceId = GetLong(reader, 0),
                ProcessEntityId = GetString(reader, 1),
                ProcessKey = GetString(reader, 2),
                ProcessId = GetInt(reader, 3),
                HandleKey = GetString(reader, 4),
                HandleValue = GetString(reader, 5),
                HandleValueNumeric = unchecked((ulong)GetLong(reader, 6)),
                ObjectType = GetString(reader, 7),
                ObjectName = GetString(reader, 8),
                GrantedAccess = GetString(reader, 9),
                GrantedAccessValue = GetUInt(reader, 10),
                HandleAttributes = GetString(reader, 11),
                HandleAttributesValue = GetUInt(reader, 12),
                ObjectAddress = GetString(reader, 13),
                FirstSeenUtc = GetDateTime(reader, 14) ?? DateTime.UtcNow,
                LastSeenUtc = GetDateTime(reader, 15) ?? DateTime.UtcNow,
                ClosedUtc = GetDateTime(reader, 16),
                State = GetEnum(reader, 17, HandleObservationState.Open),
                LastSource = GetString(reader, 18),
                CaseId = GetString(reader, 19),
                EvidenceSessionId = GetString(reader, 20),
                CaptureId = GetString(reader, 21),
                SourceIdentityId = GetString(reader, 22),
                HostId = GetString(reader, 23),
                ExecutionRootId = GetString(reader, 24)
            });
        }

        return rows;
    }

    internal static SearchIndexRow CreateModuleSearchIndexRow(ModuleObservationRecord module)
        => new SearchIndexRow
        {
            Kind = "Module",
            RecordKey = module.ModuleKey,
            ProcessKey = module.ProcessKey,
            ProcessId = module.ProcessId.ToString(CultureInfo.InvariantCulture),
            ProcessName = string.Empty,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(module.LastSeenUtc),
            Source = module.LastSource,
            Title = module.ModuleName,
            Subtitle = $"{module.FullPath} | {module.State}",
            ProcessGuidText = module.ProcessGuid,
            ModuleNameText = module.ModuleName,
            PathText = module.FullPath,
            CompanyText = module.CompanyName,
            DescriptionText = module.Description,
            FileVersionText = module.FileVersion,
            Sha256Text = module.Sha256Hash,
            BaseAddressText = module.BaseAddress,
            StatusText = module.State.ToString(),
            SourceText = module.Sources
        }.WithSearchText();

    internal static SearchIndexRow CreateHandleSearchIndexRow(HandleObservationRecord handle)
        => new SearchIndexRow
        {
            Kind = "Handle",
            RecordKey = handle.HandleKey,
            ProcessKey = handle.ProcessKey,
            ProcessId = handle.ProcessId.ToString(CultureInfo.InvariantCulture),
            ProcessName = string.Empty,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(handle.LastSeenUtc),
            Source = handle.LastSource,
            Title = string.IsNullOrWhiteSpace(handle.ObjectName) || handle.ObjectName == "<not available>"
                ? $"{handle.ObjectType} Handle"
                : handle.ObjectName,
            Subtitle = $"Handle {handle.HandleValue} | {handle.ObjectType} | {handle.State}",
            ObjectTypeText = handle.ObjectType,
            ObjectNameText = handle.ObjectName,
            GrantedAccessText = handle.GrantedAccess,
            HandleText = handle.HandleValue,
            StatusText = handle.State.ToString()
        }.WithSearchText();

    private static bool PrepareCurrentModule(
        ModuleObservationRecord module,
        string processKey,
        DateTime observedUtc,
        string source)
    {
        if (string.IsNullOrWhiteSpace(module.ModuleKey))
        {
            return false;
        }

        module.ProcessKey = string.IsNullOrWhiteSpace(module.ProcessKey) ? processKey : module.ProcessKey;
        module.State = ModuleObservationState.Loaded;
        module.UnloadedUtc = null;
        module.LastSeenUtc = observedUtc;
        module.LastSource = string.IsNullOrWhiteSpace(module.LastSource) ? source : module.LastSource;
        module.Sources = AddSourceValue(module.Sources, module.LastSource);
        return true;
    }

    private static bool PrepareCurrentHandle(
        HandleObservationRecord handle,
        string processKey,
        DateTime observedUtc,
        string source)
    {
        if (string.IsNullOrWhiteSpace(handle.HandleKey))
        {
            return false;
        }

        handle.ProcessKey = string.IsNullOrWhiteSpace(handle.ProcessKey) ? processKey : handle.ProcessKey;
        handle.State = HandleObservationState.Open;
        handle.ClosedUtc = null;
        handle.LastSeenUtc = observedUtc;
        handle.LastSource = string.IsNullOrWhiteSpace(handle.LastSource) ? source : handle.LastSource;
        return true;
    }

    private static void CloseModule(ModuleObservationRecord module, DateTime observedUtc, string source)
    {
        module.State = ModuleObservationState.Unloaded;
        module.UnloadedUtc = observedUtc;
        module.LastSeenUtc = observedUtc;
        module.LastSource = string.IsNullOrWhiteSpace(source) ? module.LastSource : source;
        module.Sources = AddSourceValue(module.Sources, module.LastSource);
    }

    private static void CloseHandle(HandleObservationRecord handle, DateTime observedUtc, string source)
    {
        handle.State = HandleObservationState.Closed;
        handle.ClosedUtc = observedUtc;
        handle.LastSeenUtc = observedUtc;
        handle.LastSource = string.IsNullOrWhiteSpace(source) ? handle.LastSource : source;
    }

    private static string ResolveProcessKey(string processKey, IEnumerable<string?> candidates)
        => string.IsNullOrWhiteSpace(processKey)
            ? candidates.FirstOrDefault(candidate => !string.IsNullOrWhiteSpace(candidate)) ?? string.Empty
            : processKey;

    private static string AddSourceValue(string sources, string source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return sources;
        }

        var existing = sources
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        if (!existing.Any(value => string.Equals(value, source, StringComparison.OrdinalIgnoreCase)))
        {
            existing.Add(source);
        }

        return string.Join(';', existing);
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

    private static void SetEvidenceIdentityParameters(SqliteCommand command, EvidenceIdentity identity)
    {
        Set(command, "$CaseId", identity.CaseId);
        Set(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Set(command, "$CaptureId", identity.CaptureId);
        Set(command, "$SourceIdentityId", identity.SourceIdentityId);
        Set(command, "$HostId", identity.HostId);
        Set(command, "$ExecutionRootId", identity.ExecutionRootId);
    }

    private static void AddParameters(SqliteCommand command, params string[] names)
    {
        foreach (var name in names)
        {
            SqliteWriteTransactionContext.Add(command, name, null);
        }
    }

    private static void Set(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = SqliteWriteTransactionContext.FormatDate(dateTime);
        }

        command.Parameters[name].Value = value ?? DBNull.Value;
    }

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture) ?? string.Empty;

    private static int GetInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : Convert.ToInt32(reader.GetValue(ordinal), CultureInfo.InvariantCulture);

    private static long GetLong(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : Convert.ToInt64(reader.GetValue(ordinal), CultureInfo.InvariantCulture);

    private static uint GetUInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : Convert.ToUInt32(reader.GetValue(ordinal), CultureInfo.InvariantCulture);

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal)
            ? null
            : DateTime.TryParse(
                GetString(reader, ordinal),
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var value)
                ? value
                : null;

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum fallback)
        where TEnum : struct, Enum
        => Enum.TryParse<TEnum>(GetString(reader, ordinal), ignoreCase: true, out var value)
            ? value
            : fallback;

    private static object? EmptyToNull(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;
}
