using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Owns rebuildable SQLite analysis-index and FTS maintenance behind the staging-store facade.
/// The supplied context is store-authorized and never opens, selects, migrates, or checkpoints a database.
/// </summary>
internal sealed class SqliteAnalysisIndexMaintenanceService : ISqliteAnalysisIndexMaintenanceService
{
    private readonly SqliteAnalysisIndexMaintenanceContext _context;
    private readonly ISqliteProcessRiskProjectionMaintenanceService _processRiskMaintenance;
    private bool _enabled;
    private bool _rebuildingSearchIndex;
    private string _databaseRole = "SnapshotDb";
    private string _maintenanceMode = "Snapshot";

    internal SqliteAnalysisIndexMaintenanceService(
        SqliteAnalysisIndexMaintenanceContext context,
        ISqliteProcessRiskProjectionMaintenanceService processRiskMaintenance)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _processRiskMaintenance = processRiskMaintenance ??
            throw new ArgumentNullException(nameof(processRiskMaintenance));
    }

    public void Disable()
        => _enabled = false;

    public void Enable(string databaseRole, string maintenanceMode)
    {
        _enabled = true;
        _databaseRole = string.IsNullOrWhiteSpace(databaseRole) ? "SnapshotDb" : databaseRole;
        _maintenanceMode = string.IsNullOrWhiteSpace(maintenanceMode) ? "Snapshot" : maintenanceMode;
    }

    public void EnsureAnalysisIndexes(
        IProgress<SqliteAnalysisIndexBuildProgress>? progress,
        CancellationToken cancellationToken)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var totalAllocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var totalAllocatedBytes = 0L;
        _enabled = true;
        var groups = SqlitePerformanceProfile.AnalysisIndexGroups;
        var totalGroups = groups.Count + 2;
        var completedGroups = 0;
        try
        {
            foreach (var group in groups)
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report(CreateProgress(
                    completedGroups,
                    totalGroups,
                    group.Name,
                    isSearchIndex: false,
                    SqliteAnalysisIndexBuildStageState.Started,
                    stageElapsedMilliseconds: 0,
                    stageAllocatedBytes: 0,
                    stopwatch.Elapsed.TotalMilliseconds,
                    totalAllocatedBytes));

                var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
                var groupStopwatch = System.Diagnostics.Stopwatch.StartNew();
                _context.EnsureAnalysisIndexGroup(group, cancellationToken);
                groupStopwatch.Stop();
                var groupAllocatedBytes = Math.Max(
                    0,
                    GC.GetAllocatedBytesForCurrentThread() - allocatedBefore);
                totalAllocatedBytes = Math.Max(
                    0,
                    GC.GetAllocatedBytesForCurrentThread() - totalAllocatedBefore);
                completedGroups++;
                _context.LogOperation(
                    _databaseRole,
                    $"BuildIndexGroup.{group.Name.Replace(' ', '.')}",
                    groupStopwatch.Elapsed,
                    $"status=completed indexes={group.Statements.Count} allocated_bytes={groupAllocatedBytes}");
                progress?.Report(CreateProgress(
                    completedGroups,
                    totalGroups,
                    group.Name,
                    isSearchIndex: false,
                    SqliteAnalysisIndexBuildStageState.Completed,
                    groupStopwatch.Elapsed.TotalMilliseconds,
                    groupAllocatedBytes,
                    stopwatch.Elapsed.TotalMilliseconds,
                    totalAllocatedBytes));
            }

            cancellationToken.ThrowIfCancellationRequested();
            const string processRiskGroupName = "Process risk projections";
            progress?.Report(CreateProgress(
                completedGroups,
                totalGroups,
                processRiskGroupName,
                isSearchIndex: false,
                SqliteAnalysisIndexBuildStageState.Started,
                stageElapsedMilliseconds: 0,
                stageAllocatedBytes: 0,
                stopwatch.Elapsed.TotalMilliseconds,
                totalAllocatedBytes));
            var riskAllocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            var riskStopwatch = System.Diagnostics.Stopwatch.StartNew();
            var riskResult = _processRiskMaintenance.Rebuild(progress: null, cancellationToken);
            riskStopwatch.Stop();
            var riskAllocatedBytes = Math.Max(
                0,
                GC.GetAllocatedBytesForCurrentThread() - riskAllocatedBefore);
            totalAllocatedBytes = Math.Max(
                0,
                GC.GetAllocatedBytesForCurrentThread() - totalAllocatedBefore);
            completedGroups++;
            _context.LogOperation(
                _databaseRole,
                "BuildIndexGroup.Process.risk.projections",
                riskStopwatch.Elapsed,
                $"status={riskResult.State} evaluated={riskResult.EvaluatedProcesses} ready={riskResult.ReadyProjections} failed={riskResult.FailedProjections} allocated_bytes={riskAllocatedBytes}");
            progress?.Report(CreateProgress(
                completedGroups,
                totalGroups,
                processRiskGroupName,
                isSearchIndex: false,
                SqliteAnalysisIndexBuildStageState.Completed,
                riskStopwatch.Elapsed.TotalMilliseconds,
                riskAllocatedBytes,
                stopwatch.Elapsed.TotalMilliseconds,
                totalAllocatedBytes));

            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new SqliteAnalysisIndexBuildProgress(
                completedGroups,
                totalGroups,
                "Full-text search",
                IsSearchIndex: true,
                SqliteAnalysisIndexBuildStageState.Started,
                TotalElapsedMilliseconds: stopwatch.Elapsed.TotalMilliseconds,
                TotalAllocatedBytes: totalAllocatedBytes));

            var searchAllocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            var searchStopwatch = System.Diagnostics.Stopwatch.StartNew();
            RebuildSearchIndex(cancellationToken);
            searchStopwatch.Stop();
            var searchAllocatedBytes = Math.Max(
                0,
                GC.GetAllocatedBytesForCurrentThread() - searchAllocatedBefore);
            totalAllocatedBytes = Math.Max(
                0,
                GC.GetAllocatedBytesForCurrentThread() - totalAllocatedBefore);
            completedGroups++;

            _context.RecordAnalysisIndexMigration();
            _context.UpsertSchemaInfo("SearchIndexMaintenance", _maintenanceMode);
            _context.UpsertSchemaInfo("SearchIndexLastBuiltUtc", FormatDate(DateTime.UtcNow));
            _context.UpsertSchemaInfo("AnalysisIndexesLastVerifiedUtc", FormatDate(DateTime.UtcNow));
            totalAllocatedBytes = Math.Max(
                0,
                GC.GetAllocatedBytesForCurrentThread() - totalAllocatedBefore);
            stopwatch.Stop();
            _context.LogOperation(
                _databaseRole,
                "BuildIndexGroup.Full-text.search",
                searchStopwatch.Elapsed,
                $"status=completed allocated_bytes={searchAllocatedBytes}");
            _context.LogOperation(
                _databaseRole,
                "EnsureAnalysisIndexes",
                stopwatch.Elapsed,
                $"status=completed groups={completedGroups}/{totalGroups} allocated_bytes={totalAllocatedBytes}");
            progress?.Report(CreateProgress(
                completedGroups,
                totalGroups,
                "Full-text search",
                isSearchIndex: true,
                SqliteAnalysisIndexBuildStageState.Completed,
                searchStopwatch.Elapsed.TotalMilliseconds,
                searchAllocatedBytes,
                stopwatch.Elapsed.TotalMilliseconds,
                totalAllocatedBytes));
        }
        catch (OperationCanceledException)
        {
            totalAllocatedBytes = Math.Max(
                0,
                GC.GetAllocatedBytesForCurrentThread() - totalAllocatedBefore);
            stopwatch.Stop();
            _context.LogOperation(
                _databaseRole,
                "EnsureAnalysisIndexes",
                stopwatch.Elapsed,
                $"status=canceled groups={completedGroups}/{totalGroups} allocated_bytes={totalAllocatedBytes}");
            throw;
        }
        catch (Exception ex)
        {
            totalAllocatedBytes = Math.Max(
                0,
                GC.GetAllocatedBytesForCurrentThread() - totalAllocatedBefore);
            stopwatch.Stop();
            _context.LogOperation(
                _databaseRole,
                "EnsureAnalysisIndexes",
                stopwatch.Elapsed,
                $"status=failed groups={completedGroups}/{totalGroups} allocated_bytes={totalAllocatedBytes} error={ex.GetType().Name}");
            throw;
        }
    }

    private static SqliteAnalysisIndexBuildProgress CreateProgress(
        int completedGroups,
        int totalGroups,
        string groupName,
        bool isSearchIndex,
        SqliteAnalysisIndexBuildStageState stageState,
        double stageElapsedMilliseconds,
        long stageAllocatedBytes,
        double totalElapsedMilliseconds,
        long totalAllocatedBytes)
        => new(
            completedGroups,
            totalGroups,
            groupName,
            isSearchIndex,
            stageState,
            stageElapsedMilliseconds,
            stageAllocatedBytes,
            totalElapsedMilliseconds,
            totalAllocatedBytes);

    public void Upsert(SearchIndexRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (!_enabled)
        {
            return;
        }

        if (!_rebuildingSearchIndex)
        {
            using var delete = _context.CreateCommand("""
                DELETE FROM SearchIndex
                WHERE Kind = $Kind AND RecordKey = $RecordKey;
                """);
            Add(delete, "$Kind", row.Kind);
            Add(delete, "$RecordKey", row.RecordKey);
            delete.ExecuteNonQuery();
        }

        using var insert = _context.CreateCommand("""
            INSERT INTO SearchIndex (
                Kind, RecordKey, ProcessKey, ProcessId, ProcessName, TimestampUtc, Source, Title, Subtitle,
                StatusText, ProcessNameText, PathText, CommandLineText, UserText, CompanyText,
                DescriptionText, Sha256Text, ParentText, TargetText, SummaryText, DetailsText,
                RiskFlagsText, EventCodeText, ActionText, CategoryText, ProcessGuidText, ModuleNameText,
                FileVersionText, BaseAddressText, ObjectTypeText, ObjectNameText, GrantedAccessText,
                HandleText, SearchText)
            VALUES (
                $Kind, $RecordKey, $ProcessKey, $ProcessId, $ProcessName, $TimestampUtc, $Source, $Title, $Subtitle,
                $StatusText, $ProcessNameText, $PathText, $CommandLineText, $UserText, $CompanyText,
                $DescriptionText, $Sha256Text, $ParentText, $TargetText, $SummaryText, $DetailsText,
                $RiskFlagsText, $EventCodeText, $ActionText, $CategoryText, $ProcessGuidText, $ModuleNameText,
                $FileVersionText, $BaseAddressText, $ObjectTypeText, $ObjectNameText, $GrantedAccessText,
                $HandleText, $SearchText);
            """);
        AddSearchIndexParameters(insert, row);
        insert.ExecuteNonQuery();
    }

    public void UpsertProcess(ProcessRecord process)
        => Upsert(CreateProcessSearchIndexRow(process));

    public void UpsertCorrelation(EvidenceCorrelationInput input, EvidenceRelation decision)
        => Upsert(CreateCorrelationSearchIndexRow(input, decision));

    private void RebuildSearchIndex(CancellationToken cancellationToken)
    {
        if (!_enabled)
        {
            return;
        }

        _context.ExecuteTransaction(() =>
        {
            _rebuildingSearchIndex = true;
            try
            {
                using (var delete = _context.CreateCommand("DELETE FROM SearchIndex;"))
                {
                    delete.ExecuteNonQuery();
                }

                foreach (var process in ReadAllProcesses())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    UpsertProcess(process);
                }

                foreach (var processEvent in ReadAllEvents())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(EventEvidenceWriteService.CreateSearchIndexRow(processEvent));
                }

                foreach (var module in ReadAllModules())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(ModuleHandleEvidenceWriteService.CreateModuleSearchIndexRow(module));
                }

                foreach (var handle in ReadAllHandles())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(ModuleHandleEvidenceWriteService.CreateHandleSearchIndexRow(handle));
                }

                foreach (var capture in ReadAllNetworkCaptures())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(NetworkEvidenceWriteService.CreateNetworkCaptureSearchIndexRow(capture));
                }

                foreach (var artifact in ReadAllZeekArtifacts())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(NetworkEvidenceWriteService.CreateZeekSearchIndexRow(artifact));
                }

                foreach (var image in ReadAllMemoryImages())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(SystemMemoryEvidenceWriteService.CreateMemoryImageSearchIndexRow(image));
                }

                foreach (var run in ReadAllVolatilityPluginRuns())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(SystemMemoryEvidenceWriteService.CreateVolatilityRunSearchIndexRow(run));
                }

                foreach (var memoryProcess in ReadAllMemoryProcesses())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(SystemMemoryEvidenceWriteService.CreateMemoryProcessSearchIndexRow(memoryProcess));
                }

                foreach (var artifact in ReadAllFilesystemArtifacts())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Upsert(FilesystemEvidenceWriteService.CreateFilesystemArtifactSearchIndexRow(artifact));
                }

                foreach (var entry in _context.ReadCorrelationEntries(maxCount: 1000))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    UpsertCorrelation(entry.Input, entry.Decision);
                }
            }
            finally
            {
                _rebuildingSearchIndex = false;
            }
        });
    }

    private IReadOnlyList<ProcessRecord> ReadAllProcesses()
    {
        var rows = new List<ProcessRecord>();
        using var command = _context.CreateCommand("""
            SELECT ProcessKey, ProcessId, ProcessGuid, StartTimeUtc, EndTimeUtc, Status,
                   ModuleCaptureStatus, ModuleCount, ModuleLastCapturedUtc, ModuleCaptureError,
                   HandleCaptureStatus, HandleCount, HandleLastCapturedUtc, HandleCaptureError,
                   ParentProcessId, ParentProcessKey, ParentProcessName, ProcessName, ProcessPath,
                   CommandLine, UserName, SessionId, Architecture, CpuUsage, MemoryUsageBytes,
                   CompanyName, FileDescription, Sha256Hash, TreeDepth, FirstObservedUtc,
                   LastObservedUtc, LastSource
            FROM Processes;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new ProcessRecord
            {
                ProcessKey = GetString(reader, 0),
                ProcessId = GetInt(reader, 1),
                ProcessGuid = GetString(reader, 2),
                StartTimeUtc = GetDateTime(reader, 3),
                EndTimeUtc = GetDateTime(reader, 4),
                Status = GetEnum(reader, 5, ProcessStatus.Running),
                ModuleCaptureStatus = GetEnum(reader, 6, ArtifactCaptureStatus.Pending),
                ModuleCount = GetInt(reader, 7),
                ModuleLastCapturedUtc = GetDateTime(reader, 8),
                ModuleCaptureError = GetString(reader, 9),
                HandleCaptureStatus = GetEnum(reader, 10, ArtifactCaptureStatus.Pending),
                HandleCount = GetInt(reader, 11),
                HandleLastCapturedUtc = GetDateTime(reader, 12),
                HandleCaptureError = GetString(reader, 13),
                ParentProcessId = GetInt(reader, 14),
                ParentProcessKey = GetString(reader, 15),
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

    private IReadOnlyList<TelemetryEventRecord> ReadAllEvents()
    {
        var rows = new List<TelemetryEventRecord>();
        using var command = _context.CreateCommand("""
            SELECT SequenceId, TimestampUtc, Source, ProcessKey, ProcessId, ProcessGuid,
                   ProcessStartTimeUtc, ProcessName, ParentProcessId, EventCode, Category, Action,
                   Target, Summary, Details, RiskFlags, IsInteresting, RepeatCount, RawProvider,
                   RawLogName, RawRecordIdText, CorrelationMethod
            FROM ProcessEvents;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new TelemetryEventRecord
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
            });
        }

        return rows;
    }

    private IReadOnlyList<ModuleObservationRecord> ReadAllModules()
    {
        var rows = new List<ModuleObservationRecord>();
        using var command = _context.CreateCommand("""
            SELECT SequenceId, ProcessKey, ProcessId, ProcessGuid, ModuleKey, ModuleName, FullPath,
                   BaseAddress, ModuleMemorySize, FileVersion, CompanyName, Description, Sha256Hash,
                   FirstSeenUtc, LastSeenUtc, UnloadedUtc, State, Sources, LastSource
            FROM Modules;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new ModuleObservationRecord
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
            });
        }

        return rows;
    }

    private IReadOnlyList<HandleObservationRecord> ReadAllHandles()
    {
        var rows = new List<HandleObservationRecord>();
        using var command = _context.CreateCommand("""
            SELECT SequenceId, ProcessKey, ProcessId, HandleKey, HandleValue, HandleValueNumeric,
                   ObjectType, ObjectName, GrantedAccess, GrantedAccessValue, HandleAttributes,
                   HandleAttributesValue, ObjectAddress, FirstSeenUtc, LastSeenUtc, ClosedUtc, State, LastSource
            FROM Handles;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new HandleObservationRecord
            {
                SequenceId = GetLong(reader, 0),
                ProcessKey = GetString(reader, 1),
                ProcessId = GetInt(reader, 2),
                HandleKey = GetString(reader, 3),
                HandleValue = GetString(reader, 4),
                HandleValueNumeric = unchecked((ulong)GetLong(reader, 5)),
                ObjectType = GetString(reader, 6),
                ObjectName = GetString(reader, 7),
                GrantedAccess = GetString(reader, 8),
                GrantedAccessValue = GetUInt(reader, 9),
                HandleAttributes = GetString(reader, 10),
                HandleAttributesValue = GetUInt(reader, 11),
                ObjectAddress = GetString(reader, 12),
                FirstSeenUtc = GetDateTime(reader, 13) ?? DateTime.UtcNow,
                LastSeenUtc = GetDateTime(reader, 14) ?? DateTime.UtcNow,
                ClosedUtc = GetDateTime(reader, 15),
                State = GetEnum(reader, 16, HandleObservationState.Open),
                LastSource = GetString(reader, 17)
            });
        }

        return rows;
    }

    private IReadOnlyList<NetworkCaptureRecord> ReadAllNetworkCaptures()
    {
        var rows = new List<NetworkCaptureRecord>();
        using var command = _context.CreateCommand("""
            SELECT CaptureId, JobId, SegmentIndex, Status, RequestedUtc, StartedUtc, CompletedUtc,
                   OutputDirectory, EtlFilePath, FilePath, FileSizeBytes, Sha256Hash, ToolName,
                   CaptureSource, FilterDescription, ErrorMessage, SourceRunId, IngestionJobId
            FROM NetworkCaptures;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new NetworkCaptureRecord
            {
                CaptureId = GetString(reader, 0),
                JobId = Guid.TryParse(GetString(reader, 1), out var jobId) ? jobId : null,
                SegmentIndex = GetInt(reader, 2),
                Status = GetEnum(reader, 3, NetworkCaptureStatus.Requested),
                RequestedUtc = GetDateTime(reader, 4) ?? DateTime.UtcNow,
                StartedUtc = GetDateTime(reader, 5),
                CompletedUtc = GetDateTime(reader, 6),
                OutputDirectory = GetString(reader, 7),
                EtlFilePath = GetString(reader, 8),
                FilePath = GetString(reader, 9),
                FileSizeBytes = GetLong(reader, 10),
                Sha256Hash = GetString(reader, 11),
                ToolName = GetString(reader, 12),
                CaptureSource = GetString(reader, 13),
                FilterDescription = GetString(reader, 14),
                ErrorMessage = GetString(reader, 15),
                SourceRunId = GetString(reader, 16),
                IngestionJobId = GetString(reader, 17)
            });
        }

        return rows;
    }

    private IReadOnlyList<ZeekNetworkRecord> ReadAllZeekArtifacts()
    {
        var rows = new List<ZeekNetworkRecord>();
        using var command = _context.CreateCommand("""
            SELECT ArtifactId, CaptureId, JobId, Status, TimestampUtc, LogType, ZeekUid,
                   SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol, Service,
                   DnsQuery, HttpMethod, HttpHost, HttpUri, DurationSeconds, OrigBytes, RespBytes,
                   OrigPackets, RespPackets, OrigIpBytes, RespIpBytes, ConnectionState, History,
                   ServerName, ClientProtocol, TlsVersion, TlsCipher, TlsEstablished,
                   WeirdName, WeirdAdditional, Summary,
                   ProcessKey, ProcessId, ProcessName, CorrelationMethod, CorrelationConfidence,
                   RawLogPath, RawLineNumber, RawLineHash, RawText, ErrorMessage, SourceRunId, IngestionJobId
            FROM ZeekNetworkArtifacts;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new ZeekNetworkRecord
            {
                ArtifactId = GetString(reader, 0),
                CaptureId = GetString(reader, 1),
                JobId = Guid.TryParse(GetString(reader, 2), out var jobId) ? jobId : null,
                Status = GetEnum(reader, 3, ZeekArtifactStatus.Imported),
                TimestampUtc = GetDateTime(reader, 4) ?? DateTime.UtcNow,
                LogType = GetString(reader, 5),
                ZeekUid = GetString(reader, 6),
                SourceIp = GetString(reader, 7),
                SourcePort = GetInt(reader, 8),
                DestinationIp = GetString(reader, 9),
                DestinationPort = GetInt(reader, 10),
                Protocol = GetString(reader, 11),
                Service = GetString(reader, 12),
                DnsQuery = GetString(reader, 13),
                HttpMethod = GetString(reader, 14),
                HttpHost = GetString(reader, 15),
                HttpUri = GetString(reader, 16),
                DurationSeconds = GetDouble(reader, 17),
                OrigBytes = GetLong(reader, 18),
                RespBytes = GetLong(reader, 19),
                OrigPackets = GetLong(reader, 20),
                RespPackets = GetLong(reader, 21),
                OrigIpBytes = GetLong(reader, 22),
                RespIpBytes = GetLong(reader, 23),
                ConnectionState = GetString(reader, 24),
                History = GetString(reader, 25),
                ServerName = GetString(reader, 26),
                ClientProtocol = GetString(reader, 27),
                TlsVersion = GetString(reader, 28),
                TlsCipher = GetString(reader, 29),
                TlsEstablished = GetBool(reader, 30),
                WeirdName = GetString(reader, 31),
                WeirdAdditional = GetString(reader, 32),
                Summary = GetString(reader, 33),
                ProcessKey = GetString(reader, 34),
                ProcessId = GetInt(reader, 35),
                ProcessName = GetString(reader, 36),
                CorrelationMethod = GetString(reader, 37),
                CorrelationConfidence = GetDouble(reader, 38),
                RawLogPath = GetString(reader, 39),
                RawLineNumber = GetLong(reader, 40),
                RawLineHash = GetString(reader, 41),
                RawText = GetString(reader, 42),
                ErrorMessage = GetString(reader, 43),
                SourceRunId = GetString(reader, 44),
                IngestionJobId = GetString(reader, 45)
            });
        }

        return rows;
    }

    private IReadOnlyList<MemoryImageRecord> ReadAllMemoryImages()
    {
        var rows = new List<MemoryImageRecord>();
        using var command = _context.CreateCommand("""
            SELECT ImageId, JobId, Status, ImportedUtc, SourcePath, FilePath, DisplayName, ImageFormat,
                   FileSizeBytes, Sha256Hash, HostName, OsBuild, AcquisitionTool, AcquisitionToolVersion,
                   AcquisitionCommandLine, PrivilegeState, ErrorMessage, SourceRunId, IngestionJobId
            FROM MemoryImages;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new MemoryImageRecord
            {
                ImageId = GetString(reader, 0),
                JobId = Guid.TryParse(GetString(reader, 1), out var jobId) ? jobId : null,
                Status = GetEnum(reader, 2, MemoryImageStatus.Imported),
                ImportedUtc = GetDateTime(reader, 3) ?? DateTime.UtcNow,
                SourcePath = GetString(reader, 4),
                FilePath = GetString(reader, 5),
                DisplayName = GetString(reader, 6),
                ImageFormat = GetString(reader, 7),
                FileSizeBytes = GetLong(reader, 8),
                Sha256Hash = GetString(reader, 9),
                HostName = GetString(reader, 10),
                OsBuild = GetString(reader, 11),
                AcquisitionTool = GetString(reader, 12),
                AcquisitionToolVersion = GetString(reader, 13),
                AcquisitionCommandLine = GetString(reader, 14),
                PrivilegeState = GetString(reader, 15),
                ErrorMessage = GetString(reader, 16),
                SourceRunId = GetString(reader, 17),
                IngestionJobId = GetString(reader, 18),
                Source = "AgentMemoryImageImport"
            });
        }

        return rows;
    }

    private IReadOnlyList<VolatilityPluginRunRecord> ReadAllVolatilityPluginRuns()
    {
        var rows = new List<VolatilityPluginRunRecord>();
        using var command = _context.CreateCommand("""
            SELECT RunId, ImageId, JobId, PluginName, Status, RequestedUtc, StartedUtc, CompletedUtc,
                   VolatilityPath, VolatilityVersion, CommandLine, OutputDirectory, StdoutPath, StderrPath,
                   RawOutputHash, SymbolsPath, ProfileOrLayer, NormalizedRowCount, ErrorMessage, SourceRunId, IngestionJobId
            FROM VolatilityPluginRuns;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new VolatilityPluginRunRecord
            {
                RunId = GetString(reader, 0),
                ImageId = GetString(reader, 1),
                JobId = Guid.TryParse(GetString(reader, 2), out var jobId) ? jobId : null,
                PluginName = GetString(reader, 3),
                Status = GetEnum(reader, 4, VolatilityPluginRunStatus.Queued),
                RequestedUtc = GetDateTime(reader, 5) ?? DateTime.UtcNow,
                StartedUtc = GetDateTime(reader, 6),
                CompletedUtc = GetDateTime(reader, 7),
                VolatilityPath = GetString(reader, 8),
                VolatilityVersion = GetString(reader, 9),
                CommandLine = GetString(reader, 10),
                OutputDirectory = GetString(reader, 11),
                StdoutPath = GetString(reader, 12),
                StderrPath = GetString(reader, 13),
                RawOutputHash = GetString(reader, 14),
                SymbolsPath = GetString(reader, 15),
                ProfileOrLayer = GetString(reader, 16),
                NormalizedRowCount = GetInt(reader, 17),
                ErrorMessage = GetString(reader, 18),
                SourceRunId = GetString(reader, 19),
                IngestionJobId = GetString(reader, 20),
                Source = "AgentVolatility"
            });
        }

        return rows;
    }

    private IReadOnlyList<MemoryProcessRecord> ReadAllMemoryProcesses()
    {
        var rows = new List<MemoryProcessRecord>();
        using var command = _context.CreateCommand("""
            SELECT ArtifactId, ImageId, PluginRunId, PluginName, EvidenceKind, RowNumber, ObjectOffset,
                   ProcessId, ParentProcessId, ProcessName, ImagePath, CommandLine, CreateTimeUtc,
                   ExitTimeUtc, SessionId, ThreadCount, HandleCount, Wow64, ProcessKey,
                   CorrelationState, CorrelationMethod, CorrelationConfidence, RawRowHash, RawJson, SourceRunId, IngestionJobId
            FROM MemoryProcesses;
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(new MemoryProcessRecord
            {
                ArtifactId = GetString(reader, 0),
                ImageId = GetString(reader, 1),
                PluginRunId = GetString(reader, 2),
                PluginName = GetString(reader, 3),
                EvidenceKind = GetEnum(reader, 4, MemoryProcessEvidenceKind.Unknown),
                RowNumber = GetInt(reader, 5),
                ObjectOffset = GetString(reader, 6),
                ProcessId = GetInt(reader, 7),
                ParentProcessId = GetInt(reader, 8),
                ProcessName = GetString(reader, 9),
                ImagePath = GetString(reader, 10),
                CommandLine = GetString(reader, 11),
                CreateTimeUtc = GetDateTime(reader, 12),
                ExitTimeUtc = GetDateTime(reader, 13),
                SessionId = GetInt(reader, 14),
                ThreadCount = GetInt(reader, 15),
                HandleCount = GetInt(reader, 16),
                Wow64 = GetString(reader, 17),
                ProcessKey = GetString(reader, 18),
                CorrelationState = GetEnum(reader, 19, MemoryProcessCorrelationState.Unknown),
                CorrelationMethod = GetString(reader, 20),
                CorrelationConfidence = GetDouble(reader, 21),
                RawRowHash = GetString(reader, 22),
                RawJson = GetString(reader, 23),
                SourceRunId = GetString(reader, 24),
                IngestionJobId = GetString(reader, 25),
                Source = "AgentVolatility"
            });
        }

        return rows;
    }

    private IReadOnlyList<FilesystemArtifactRecord> ReadAllFilesystemArtifacts()
    {
        var rows = new List<FilesystemArtifactRecord>();
        using var command = _context.CreateCommand("""
            SELECT a.ArtifactId, a.ArtifactType, a.TimestampUtc, a.Name, a.Path, a.Summary, a.Hash,
                   r.RawRecordId, r.PayloadHash, r.PayloadText, a.SourceRunId, a.IngestionJobId
            FROM Artifacts a
            LEFT JOIN RawRecords r ON r.RawRecordId = a.RawRecordId
            WHERE a.ArtifactType IN ('NtfsMft', 'NtfsUsnJournal', 'NtfsLogFile', 'Prefetch', 'FileMetadata');
            """);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var artifactId = GetString(reader, 0);
            rows.Add(new FilesystemArtifactRecord
            {
                ArtifactId = artifactId,
                Kind = GetEnum(reader, 1, FilesystemArtifactKind.Unknown),
                TimestampUtc = GetDateTime(reader, 2) ?? DateTime.UtcNow,
                Name = GetString(reader, 3),
                SourcePath = GetString(reader, 4),
                Summary = GetString(reader, 5),
                Sha256Hash = GetString(reader, 6),
                RawRecordId = GetLong(reader, 7).ToString(CultureInfo.InvariantCulture),
                RawPayloadHash = GetString(reader, 8),
                RawText = GetString(reader, 9),
                SourceRunId = GetString(reader, 10),
                IngestionJobId = GetString(reader, 11),
                Properties = ReadArtifactProperties(artifactId)
            });
        }

        return rows;
    }

    private IReadOnlyDictionary<string, string> ReadArtifactProperties(string artifactId)
    {
        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var command = _context.CreateCommand("""
            SELECT Name, Value
            FROM ArtifactProperties
            WHERE ArtifactId = $ArtifactId
            ORDER BY Name;
            """);
        Add(command, "$ArtifactId", artifactId);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            properties[GetString(reader, 0)] = GetString(reader, 1);
        }

        return properties;
    }

    internal static SearchIndexRow CreateProcessSearchIndexRow(ProcessRecord process)
        => new SearchIndexRow
        {
            Kind = "Process",
            RecordKey = string.IsNullOrWhiteSpace(process.ProcessEntityId) ? process.ProcessKey : process.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ProcessId = process.ProcessId.ToString(CultureInfo.InvariantCulture),
            ProcessName = process.ProcessName,
            TimestampUtc = FormatDate(process.LastObservedUtc),
            Source = process.LastSource,
            Title = process.ProcessName,
            Subtitle = $"{process.ProcessPath} | PID {process.ProcessId} | {process.Status}",
            StatusText = process.Status.ToString(),
            ProcessNameText = process.ProcessName,
            PathText = process.ProcessPath,
            CommandLineText = process.CommandLine,
            UserText = process.UserName,
            CompanyText = process.CompanyName,
            DescriptionText = process.FileDescription,
            Sha256Text = process.Sha256Hash,
            ParentText = process.ParentProcessName,
            ProcessGuidText = process.ProcessGuid
        }.WithSearchText();

    internal static SearchIndexRow CreateCorrelationSearchIndexRow(
        EvidenceCorrelationInput input,
        EvidenceRelation decision)
        => new SearchIndexRow
        {
            Kind = "CorrelationEvidence",
            RecordKey = input.InputId,
            ProcessId = input.ProcessId > 0 ? input.ProcessId.ToString(CultureInfo.InvariantCulture) : string.Empty,
            ProcessName = input.ProcessName,
            TimestampUtc = FormatDate(input.ObservedUtc),
            Source = input.Source,
            Title = $"{decision.State}: {input.EvidenceKind} {input.EvidenceType}".Trim(),
            Subtitle = decision.CorrelationDiagnostics,
            StatusText = decision.State.ToString(),
            SourceText = input.Source,
            ProcessNameText = input.ProcessName,
            PathText = input.ProcessPath,
            TargetText = string.Join(" ", new[]
            {
                input.SourceEndpoint,
                input.DestinationEndpoint,
                input.SourceNativeId,
                input.RawInputId
            }.Where(value => !string.IsNullOrWhiteSpace(value))),
            DescriptionText = $"confidence={decision.Confidence:0.00}",
            SummaryText = decision.CorrelationMethod,
            DetailsText = decision.CorrelationDiagnostics,
            CategoryText = input.EvidenceKind.ToString(),
            EventCodeText = decision.CandidateCount.ToString(CultureInfo.InvariantCulture),
            ActionText = decision.ResolverVersion,
            ProcessGuidText = input.ProcessGuid
        }.WithSearchText();

    private static void AddSearchIndexParameters(SqliteCommand command, SearchIndexRow row)
    {
        Add(command, "$Kind", row.Kind);
        Add(command, "$RecordKey", row.RecordKey);
        Add(command, "$ProcessKey", row.ProcessKey);
        Add(command, "$ProcessId", row.ProcessId);
        Add(command, "$ProcessName", row.ProcessName);
        Add(command, "$TimestampUtc", row.TimestampUtc);
        Add(command, "$Source", row.Source);
        Add(command, "$Title", row.Title);
        Add(command, "$Subtitle", row.Subtitle);
        Add(command, "$StatusText", row.StatusText);
        Add(command, "$ProcessNameText", row.ProcessNameText);
        Add(command, "$PathText", row.PathText);
        Add(command, "$CommandLineText", row.CommandLineText);
        Add(command, "$UserText", row.UserText);
        Add(command, "$CompanyText", row.CompanyText);
        Add(command, "$DescriptionText", row.DescriptionText);
        Add(command, "$Sha256Text", row.Sha256Text);
        Add(command, "$ParentText", row.ParentText);
        Add(command, "$TargetText", row.TargetText);
        Add(command, "$SummaryText", row.SummaryText);
        Add(command, "$DetailsText", row.DetailsText);
        Add(command, "$RiskFlagsText", row.RiskFlagsText);
        Add(command, "$EventCodeText", row.EventCodeText);
        Add(command, "$ActionText", row.ActionText);
        Add(command, "$CategoryText", row.CategoryText);
        Add(command, "$ProcessGuidText", row.ProcessGuidText);
        Add(command, "$ModuleNameText", row.ModuleNameText);
        Add(command, "$FileVersionText", row.FileVersionText);
        Add(command, "$BaseAddressText", row.BaseAddressText);
        Add(command, "$ObjectTypeText", row.ObjectTypeText);
        Add(command, "$ObjectNameText", row.ObjectNameText);
        Add(command, "$GrantedAccessText", row.GrantedAccessText);
        Add(command, "$HandleText", row.HandleText);
        Add(command, "$SearchText", row.SearchText);
    }

    private static void Add(SqliteCommand command, string name, object? value)
    {
        if (value is DateTime dateTime)
        {
            value = FormatDate(dateTime);
        }

        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    private static string FormatDate(DateTime value)
        => value.Kind == DateTimeKind.Utc
            ? value.ToString("O")
            : value.ToUniversalTime().ToString("O");

    private static string GetString(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);

    private static int GetInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt32(ordinal);

    private static int? GetNullableInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);

    private static long GetLong(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetInt64(ordinal);

    private static uint GetUInt(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : unchecked((uint)reader.GetInt64(ordinal));

    private static double GetDouble(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? 0 : reader.GetDouble(ordinal);

    private static bool GetBool(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return false;
        }

        if (reader.GetFieldType(ordinal) == typeof(string))
        {
            var value = GetString(reader, ordinal);
            return value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("T", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("1", StringComparison.OrdinalIgnoreCase);
        }

        return reader.GetInt64(ordinal) != 0;
    }

    private static DateTime? GetDateTime(SqliteDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) || !DateTimeOffset.TryParse(reader.GetString(ordinal), out var value)
            ? null
            : value.UtcDateTime;

    private static TEnum GetEnum<TEnum>(SqliteDataReader reader, int ordinal, TEnum fallback)
        where TEnum : struct
        => !reader.IsDBNull(ordinal) && Enum.TryParse<TEnum>(reader.GetString(ordinal), out var value)
            ? value
            : fallback;
}

internal sealed class SqliteAnalysisIndexMaintenanceContext
{
    private readonly SqliteStagingStore _owner;

    internal SqliteAnalysisIndexMaintenanceContext(SqliteStagingStore owner)
    {
        _owner = owner ?? throw new ArgumentNullException(nameof(owner));
    }

    internal SqliteCommand CreateCommand(string sql)
        => _owner.CreateAnalysisMaintenanceCommand(sql);

    internal void ExecuteTransaction(Action action)
        => _owner.ExecuteAnalysisMaintenanceTransaction(action);

    internal void EnsureAnalysisIndexGroup(
        SqliteAnalysisIndexGroup group,
        CancellationToken cancellationToken)
        => _owner.EnsureComponentAnalysisIndexGroup(group, cancellationToken);

    internal void RecordAnalysisIndexMigration()
        => _owner.RecordComponentAnalysisIndexMigration();

    internal void UpsertSchemaInfo(string key, string value)
        => _owner.UpsertComponentAnalysisSchemaInfo(key, value);

    internal void LogOperation(
        string databaseRole,
        string operation,
        TimeSpan elapsed,
        string details = "")
        => _owner.LogComponentAnalysisOperation(databaseRole, operation, elapsed, details);

    internal IReadOnlyList<CorrelationSearchIndexEntry> ReadCorrelationEntries(int maxCount)
        => _owner.ReadComponentCorrelationSearchEntries(maxCount);
}
