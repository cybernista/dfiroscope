using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Data.Sqlite;
using ProcInsider.Models;

namespace ProcInsider.Services;

internal interface ISystemMemoryEvidenceWriteService
{
    void UpsertMemoryImage(MemoryImageRecord image);
    void UpsertMemoryImages(IEnumerable<MemoryImageRecord> memoryImages);
    void UpsertVolatilityPluginRun(VolatilityPluginRunRecord run);
    void UpsertVolatilityPluginRuns(IEnumerable<VolatilityPluginRunRecord> pluginRuns);
    void UpsertMemoryProcess(MemoryProcessRecord process);
    void UpsertMemoryProcesses(IEnumerable<MemoryProcessRecord> processes);
}

/// <summary>
/// Focused system-memory image, Volatility run, and memory-process writer.
/// The store facade owns database selection, the connection, and transaction
/// lifetime; this component owns only family SQL, binding, source-run lineage,
/// search projection, and initial memory-process correlation side effects.
/// </summary>
internal sealed class SystemMemoryEvidenceWriteService : ISystemMemoryEvidenceWriteService
{
    private readonly SqliteWriteTransactionContext _context;

    internal SystemMemoryEvidenceWriteService(SqliteWriteTransactionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public void UpsertMemoryImage(MemoryImageRecord image)
    {
        ArgumentNullException.ThrowIfNull(image);
        _context.Execute(() =>
        {
            using var command = CreateMemoryImageUpsertCommand();
            WriteMemoryImageCore(command, image);
        });
    }

    public void UpsertMemoryImages(IEnumerable<MemoryImageRecord> memoryImages)
    {
        ArgumentNullException.ThrowIfNull(memoryImages);
        var snapshot = memoryImages.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateMemoryImageUpsertCommand();
            command.Prepare();
            foreach (var image in snapshot)
            {
                ArgumentNullException.ThrowIfNull(image);
                WriteMemoryImageCore(command, image);
            }
        });
    }

    public void UpsertVolatilityPluginRun(VolatilityPluginRunRecord run)
    {
        ArgumentNullException.ThrowIfNull(run);
        _context.Execute(() =>
        {
            using var command = CreateVolatilityPluginRunUpsertCommand();
            WriteVolatilityPluginRunCore(command, run);
        });
    }

    public void UpsertVolatilityPluginRuns(IEnumerable<VolatilityPluginRunRecord> pluginRuns)
    {
        ArgumentNullException.ThrowIfNull(pluginRuns);
        var snapshot = pluginRuns.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateVolatilityPluginRunUpsertCommand();
            command.Prepare();
            foreach (var run in snapshot)
            {
                ArgumentNullException.ThrowIfNull(run);
                WriteVolatilityPluginRunCore(command, run);
            }
        });
    }

    public void UpsertMemoryProcess(MemoryProcessRecord process)
    {
        ArgumentNullException.ThrowIfNull(process);
        _context.Execute(() =>
        {
            using var command = CreateMemoryProcessUpsertCommand();
            WriteMemoryProcessCore(command, process);
        });
    }

    public void UpsertMemoryProcesses(IEnumerable<MemoryProcessRecord> processes)
    {
        ArgumentNullException.ThrowIfNull(processes);
        var snapshot = processes.ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        _context.Execute(() =>
        {
            using var command = CreateMemoryProcessUpsertCommand();
            command.Prepare();
            foreach (var process in snapshot)
            {
                ArgumentNullException.ThrowIfNull(process);
                WriteMemoryProcessCore(command, process);
            }
        });
    }

    private void WriteMemoryImageCore(SqliteCommand command, MemoryImageRecord image)
    {
        image.ImageId = NormalizeIdentifier(image.ImageId);
        var sourceId = _context.EnsureTelemetrySource(image.Source, "MemoryImage");
        var identity = _context.ResolveEvidenceIdentity(image, "MemoryImage", image.Source);
        ApplyEvidenceIdentity(image, identity);
        _context.ApplySystemMemoryEvidenceProvenance(image);

        Set(command, "$ImageId", image.ImageId);
        AddEvidenceIdentityParameters(command, identity);
        Set(command, "$SourceRunId", EmptyToNull(image.SourceRunId));
        Set(command, "$IngestionJobId", image.IngestionJobId);
        Set(command, "$SourceId", sourceId);
        Set(command, "$JobId", image.JobId?.ToString("D"));
        Set(command, "$Status", image.Status.ToString());
        Set(command, "$ImportedUtc", image.ImportedUtc);
        Set(command, "$SourcePath", image.SourcePath);
        Set(command, "$FilePath", image.FilePath);
        Set(command, "$DisplayName", image.DisplayName);
        Set(command, "$ImageFormat", image.ImageFormat);
        Set(command, "$FileSizeBytes", image.FileSizeBytes);
        Set(command, "$Sha256Hash", image.Sha256Hash);
        Set(command, "$HostName", image.HostName);
        Set(command, "$OsBuild", image.OsBuild);
        Set(command, "$AcquisitionTool", image.AcquisitionTool);
        Set(command, "$AcquisitionToolVersion", image.AcquisitionToolVersion);
        Set(command, "$AcquisitionCommandLine", image.AcquisitionCommandLine);
        Set(command, "$PrivilegeState", image.PrivilegeState);
        Set(command, "$ErrorMessage", image.ErrorMessage);
        command.ExecuteNonQuery();

        _context.PersistSystemMemorySourceRunRelation(
            image,
            EvidenceReferenceKind.MemoryImage,
            image.ImageId,
            image.ImportedUtc,
            image.Sha256Hash);
        _context.UpsertSearchIndex(CreateMemoryImageSearchIndexRow(image));
    }

    private void WriteVolatilityPluginRunCore(SqliteCommand command, VolatilityPluginRunRecord run)
    {
        run.RunId = NormalizeIdentifier(run.RunId);
        var sourceId = _context.EnsureTelemetrySource(run.Source, "Volatility");
        var identity = _context.ResolveEvidenceIdentity(run, "Volatility", run.Source);
        ApplyEvidenceIdentity(run, identity);
        _context.ApplySystemMemoryEvidenceProvenance(run);

        Set(command, "$RunId", run.RunId);
        Set(command, "$ImageId", run.ImageId);
        AddEvidenceIdentityParameters(command, identity);
        Set(command, "$SourceRunId", EmptyToNull(run.SourceRunId));
        Set(command, "$IngestionJobId", run.IngestionJobId);
        Set(command, "$SourceId", sourceId);
        Set(command, "$JobId", run.JobId?.ToString("D"));
        Set(command, "$PluginName", run.PluginName);
        Set(command, "$Status", run.Status.ToString());
        Set(command, "$RequestedUtc", run.RequestedUtc);
        Set(command, "$StartedUtc", run.StartedUtc);
        Set(command, "$CompletedUtc", run.CompletedUtc);
        Set(command, "$VolatilityPath", run.VolatilityPath);
        Set(command, "$VolatilityVersion", run.VolatilityVersion);
        Set(command, "$CommandLine", run.CommandLine);
        Set(command, "$OutputDirectory", run.OutputDirectory);
        Set(command, "$StdoutPath", run.StdoutPath);
        Set(command, "$StderrPath", run.StderrPath);
        Set(command, "$RawOutputHash", run.RawOutputHash);
        Set(command, "$SymbolsPath", run.SymbolsPath);
        Set(command, "$ProfileOrLayer", run.ProfileOrLayer);
        Set(command, "$NormalizedRowCount", run.NormalizedRowCount);
        Set(command, "$ErrorMessage", run.ErrorMessage);
        command.ExecuteNonQuery();

        _context.PersistSystemMemorySourceRunRelation(
            run,
            EvidenceReferenceKind.VolatilityPluginRun,
            run.RunId,
            run.RequestedUtc,
            run.RawOutputHash);
        _context.UpsertSearchIndex(CreateVolatilityRunSearchIndexRow(run));
    }

    private void WriteMemoryProcessCore(SqliteCommand command, MemoryProcessRecord process)
    {
        process.ArtifactId = NormalizeIdentifier(process.ArtifactId);
        var sourceId = _context.EnsureTelemetrySource(process.Source, "MemoryProcess");
        var identity = _context.ResolveEvidenceIdentity(process, "MemoryProcess", process.Source);
        ApplyEvidenceIdentity(process, identity);
        _context.ApplySystemMemoryEvidenceProvenance(process);

        Set(command, "$ArtifactId", process.ArtifactId);
        Set(command, "$ImageId", process.ImageId);
        Set(command, "$PluginRunId", process.PluginRunId);
        AddEvidenceIdentityParameters(command, identity);
        Set(command, "$SourceRunId", EmptyToNull(process.SourceRunId));
        Set(command, "$IngestionJobId", process.IngestionJobId);
        Set(command, "$SourceId", sourceId);
        Set(command, "$PluginName", process.PluginName);
        Set(command, "$EvidenceKind", process.EvidenceKind.ToString());
        Set(command, "$RowNumber", process.RowNumber);
        Set(command, "$ObjectOffset", process.ObjectOffset);
        Set(command, "$ProcessId", process.ProcessId);
        Set(command, "$ParentProcessId", process.ParentProcessId);
        Set(command, "$ProcessName", process.ProcessName);
        Set(command, "$ImagePath", process.ImagePath);
        Set(command, "$CommandLine", process.CommandLine);
        Set(command, "$CreateTimeUtc", process.CreateTimeUtc);
        Set(command, "$ExitTimeUtc", process.ExitTimeUtc);
        Set(command, "$SessionId", process.SessionId);
        Set(command, "$ThreadCount", process.ThreadCount);
        Set(command, "$HandleCount", process.HandleCount);
        Set(command, "$Wow64", process.Wow64);
        Set(command, "$ProcessKey", process.ProcessKey);
        Set(command, "$CorrelationState", process.CorrelationState.ToString());
        Set(command, "$CorrelationMethod", process.CorrelationMethod);
        Set(command, "$CorrelationConfidence", process.CorrelationConfidence);
        Set(command, "$RawRowHash", process.RawRowHash);
        Set(command, "$RawJson", process.RawJson);
        command.ExecuteNonQuery();

        _context.PersistSystemMemorySourceRunRelation(
            process,
            EvidenceReferenceKind.MemoryProcess,
            process.ArtifactId,
            process.CreateTimeUtc ?? DateTime.UtcNow,
            process.RawRowHash);
        _context.UpsertSearchIndex(CreateMemoryProcessSearchIndexRow(process));
        var input = CreateMemoryProcessCorrelationInput(process);
        _context.ApplyPersistedMemoryProcessCorrelationProvenance(input, process.ArtifactId);
        _context.UpsertEvidenceCorrelationInput(input);
        _context.EnsureInitialCorrelationDecision(input);
    }

    private SqliteCommand CreateMemoryImageUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO MemoryImages (
                ImageId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                SourceId, JobId, Status, ImportedUtc, SourcePath, FilePath, DisplayName, ImageFormat,
                FileSizeBytes, Sha256Hash, HostName, OsBuild, AcquisitionTool, AcquisitionToolVersion,
                AcquisitionCommandLine, PrivilegeState, ErrorMessage)
            VALUES (
                $ImageId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId, $SourceRunId, $IngestionJobId,
                $SourceId, $JobId, $Status, $ImportedUtc, $SourcePath, $FilePath, $DisplayName, $ImageFormat,
                $FileSizeBytes, $Sha256Hash, $HostName, $OsBuild, $AcquisitionTool, $AcquisitionToolVersion,
                $AcquisitionCommandLine, $PrivilegeState, $ErrorMessage)
            ON CONFLICT(ImageId) DO UPDATE SET
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                SourceId = excluded.SourceId,
                JobId = excluded.JobId,
                Status = excluded.Status,
                ImportedUtc = excluded.ImportedUtc,
                SourcePath = excluded.SourcePath,
                FilePath = excluded.FilePath,
                DisplayName = excluded.DisplayName,
                ImageFormat = excluded.ImageFormat,
                FileSizeBytes = excluded.FileSizeBytes,
                Sha256Hash = excluded.Sha256Hash,
                HostName = excluded.HostName,
                OsBuild = excluded.OsBuild,
                AcquisitionTool = excluded.AcquisitionTool,
                AcquisitionToolVersion = excluded.AcquisitionToolVersion,
                AcquisitionCommandLine = excluded.AcquisitionCommandLine,
                PrivilegeState = excluded.PrivilegeState,
                ErrorMessage = excluded.ErrorMessage;
            """);
        AddParameters(command, new[]
        {
            "$ImageId", "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId",
            "$ExecutionRootId", "$SourceRunId", "$IngestionJobId", "$SourceId", "$JobId", "$Status",
            "$ImportedUtc", "$SourcePath", "$FilePath", "$DisplayName", "$ImageFormat", "$FileSizeBytes",
            "$Sha256Hash", "$HostName", "$OsBuild", "$AcquisitionTool", "$AcquisitionToolVersion",
            "$AcquisitionCommandLine", "$PrivilegeState", "$ErrorMessage"
        });
        return command;
    }

    private SqliteCommand CreateVolatilityPluginRunUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO VolatilityPluginRuns (
                RunId, ImageId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                SourceId, JobId, PluginName, Status, RequestedUtc, StartedUtc, CompletedUtc,
                VolatilityPath, VolatilityVersion, CommandLine, OutputDirectory, StdoutPath, StderrPath,
                RawOutputHash, SymbolsPath, ProfileOrLayer, NormalizedRowCount, ErrorMessage)
            VALUES (
                $RunId, $ImageId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId, $SourceRunId, $IngestionJobId,
                $SourceId, $JobId, $PluginName, $Status, $RequestedUtc, $StartedUtc, $CompletedUtc,
                $VolatilityPath, $VolatilityVersion, $CommandLine, $OutputDirectory, $StdoutPath, $StderrPath,
                $RawOutputHash, $SymbolsPath, $ProfileOrLayer, $NormalizedRowCount, $ErrorMessage)
            ON CONFLICT(RunId) DO UPDATE SET
                ImageId = excluded.ImageId,
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                SourceId = excluded.SourceId,
                JobId = excluded.JobId,
                PluginName = excluded.PluginName,
                Status = excluded.Status,
                RequestedUtc = excluded.RequestedUtc,
                StartedUtc = excluded.StartedUtc,
                CompletedUtc = excluded.CompletedUtc,
                VolatilityPath = excluded.VolatilityPath,
                VolatilityVersion = excluded.VolatilityVersion,
                CommandLine = excluded.CommandLine,
                OutputDirectory = excluded.OutputDirectory,
                StdoutPath = excluded.StdoutPath,
                StderrPath = excluded.StderrPath,
                RawOutputHash = excluded.RawOutputHash,
                SymbolsPath = excluded.SymbolsPath,
                ProfileOrLayer = excluded.ProfileOrLayer,
                NormalizedRowCount = excluded.NormalizedRowCount,
                ErrorMessage = excluded.ErrorMessage;
            """);
        AddParameters(command, new[]
        {
            "$RunId", "$ImageId", "$CaseId", "$EvidenceSessionId", "$CaptureId", "$SourceIdentityId", "$HostId",
            "$ExecutionRootId", "$SourceRunId", "$IngestionJobId", "$SourceId", "$JobId", "$PluginName", "$Status",
            "$RequestedUtc", "$StartedUtc", "$CompletedUtc", "$VolatilityPath", "$VolatilityVersion", "$CommandLine",
            "$OutputDirectory", "$StdoutPath", "$StderrPath", "$RawOutputHash", "$SymbolsPath", "$ProfileOrLayer",
            "$NormalizedRowCount", "$ErrorMessage"
        });
        return command;
    }

    private SqliteCommand CreateMemoryProcessUpsertCommand()
    {
        var command = _context.CreateCommand("""
            INSERT INTO MemoryProcesses (
                ArtifactId, ImageId, PluginRunId, CaseId, EvidenceSessionId, CaptureId, SourceIdentityId, HostId, ExecutionRootId, SourceRunId, IngestionJobId,
                SourceId, PluginName, EvidenceKind, RowNumber, ObjectOffset, ProcessId, ParentProcessId,
                ProcessName, ImagePath, CommandLine, CreateTimeUtc, ExitTimeUtc, SessionId, ThreadCount,
                HandleCount, Wow64, ProcessKey, CorrelationState, CorrelationMethod, CorrelationConfidence,
                RawRowHash, RawJson)
            VALUES (
                $ArtifactId, $ImageId, $PluginRunId, $CaseId, $EvidenceSessionId, $CaptureId, $SourceIdentityId, $HostId, $ExecutionRootId, $SourceRunId, $IngestionJobId,
                $SourceId, $PluginName, $EvidenceKind, $RowNumber, $ObjectOffset, $ProcessId, $ParentProcessId,
                $ProcessName, $ImagePath, $CommandLine, $CreateTimeUtc, $ExitTimeUtc, $SessionId, $ThreadCount,
                $HandleCount, $Wow64, $ProcessKey, $CorrelationState, $CorrelationMethod, $CorrelationConfidence,
                $RawRowHash, $RawJson)
            ON CONFLICT(ArtifactId) DO UPDATE SET
                ImageId = excluded.ImageId,
                PluginRunId = excluded.PluginRunId,
                CaseId = excluded.CaseId,
                EvidenceSessionId = excluded.EvidenceSessionId,
                CaptureId = excluded.CaptureId,
                SourceIdentityId = excluded.SourceIdentityId,
                HostId = excluded.HostId,
                ExecutionRootId = excluded.ExecutionRootId,
                SourceRunId = excluded.SourceRunId,
                IngestionJobId = excluded.IngestionJobId,
                SourceId = excluded.SourceId,
                PluginName = excluded.PluginName,
                EvidenceKind = excluded.EvidenceKind,
                RowNumber = excluded.RowNumber,
                ObjectOffset = excluded.ObjectOffset,
                ProcessId = excluded.ProcessId,
                ParentProcessId = excluded.ParentProcessId,
                ProcessName = excluded.ProcessName,
                ImagePath = excluded.ImagePath,
                CommandLine = excluded.CommandLine,
                CreateTimeUtc = excluded.CreateTimeUtc,
                ExitTimeUtc = excluded.ExitTimeUtc,
                SessionId = excluded.SessionId,
                ThreadCount = excluded.ThreadCount,
                HandleCount = excluded.HandleCount,
                Wow64 = excluded.Wow64,
                ProcessKey = excluded.ProcessKey,
                CorrelationState = excluded.CorrelationState,
                CorrelationMethod = excluded.CorrelationMethod,
                CorrelationConfidence = excluded.CorrelationConfidence,
                RawRowHash = excluded.RawRowHash,
                RawJson = excluded.RawJson;
            """);
        AddParameters(command, new[]
        {
            "$ArtifactId", "$ImageId", "$PluginRunId", "$CaseId", "$EvidenceSessionId", "$CaptureId",
            "$SourceIdentityId", "$HostId", "$ExecutionRootId", "$SourceRunId", "$IngestionJobId", "$SourceId",
            "$PluginName", "$EvidenceKind", "$RowNumber", "$ObjectOffset", "$ProcessId", "$ParentProcessId",
            "$ProcessName", "$ImagePath", "$CommandLine", "$CreateTimeUtc", "$ExitTimeUtc", "$SessionId",
            "$ThreadCount", "$HandleCount", "$Wow64", "$ProcessKey", "$CorrelationState", "$CorrelationMethod",
            "$CorrelationConfidence", "$RawRowHash", "$RawJson"
        });
        return command;
    }

    internal static SearchIndexRow CreateMemoryImageSearchIndexRow(MemoryImageRecord image)
        => new SearchIndexRow
        {
            Kind = "MemoryImage",
            RecordKey = image.ImageId,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(image.ImportedUtc),
            Source = image.Source,
            Title = string.IsNullOrWhiteSpace(image.DisplayName) ? image.ImageId : image.DisplayName,
            Subtitle = $"{image.FilePath} | {image.Status}",
            StatusText = image.Status.ToString(),
            PathText = image.FilePath,
            Sha256Text = image.Sha256Hash,
            TargetText = image.ImageId,
            SummaryText = $"{image.ImageFormat} memory image | {image.HostName} | {image.OsBuild}",
            DetailsText = string.Join(
                Environment.NewLine,
                new[]
                {
                    image.SourcePath,
                    image.AcquisitionTool,
                    image.AcquisitionToolVersion,
                    image.AcquisitionCommandLine,
                    image.PrivilegeState,
                    image.SourceRunId,
                    image.IngestionJobId,
                    image.ErrorMessage
                }.Where(value => !string.IsNullOrWhiteSpace(value)))
        }.WithSearchText();

    internal static SearchIndexRow CreateVolatilityRunSearchIndexRow(VolatilityPluginRunRecord run)
        => new SearchIndexRow
        {
            Kind = "VolatilityRun",
            RecordKey = run.RunId,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(run.CompletedUtc ?? run.StartedUtc ?? run.RequestedUtc),
            Source = run.Source,
            Title = run.PluginName,
            Subtitle = $"{run.ImageId} | {run.Status}",
            StatusText = run.Status.ToString(),
            PathText = string.Join(' ', new[] { run.OutputDirectory, run.StdoutPath, run.StderrPath }.Where(value => !string.IsNullOrWhiteSpace(value))),
            CommandLineText = run.CommandLine,
            Sha256Text = run.RawOutputHash,
            TargetText = run.ImageId,
            SummaryText = $"{run.NormalizedRowCount} normalized row(s)",
            DetailsText = string.Join(
                Environment.NewLine,
                new[]
                {
                    run.VolatilityPath,
                    run.VolatilityVersion,
                    run.SymbolsPath,
                    run.ProfileOrLayer,
                    run.SourceRunId,
                    run.IngestionJobId,
                    run.ErrorMessage
                }.Where(value => !string.IsNullOrWhiteSpace(value)))
        }.WithSearchText();

    internal static SearchIndexRow CreateMemoryProcessSearchIndexRow(MemoryProcessRecord process)
        => new SearchIndexRow
        {
            Kind = "MemoryProcess",
            RecordKey = process.ArtifactId,
            ProcessKey = process.ProcessKey,
            ProcessId = process.ProcessId.ToString(),
            ProcessName = process.ProcessName,
            TimestampUtc = SqliteWriteTransactionContext.FormatDate(process.CreateTimeUtc ?? DateTime.UtcNow),
            Source = process.Source,
            Title = string.IsNullOrWhiteSpace(process.ProcessName) ? $"PID {process.ProcessId}" : process.ProcessName,
            Subtitle = $"{process.PluginName} | {process.CorrelationState}",
            StatusText = process.CorrelationState.ToString(),
            ProcessNameText = process.ProcessName,
            PathText = process.ImagePath,
            CommandLineText = process.CommandLine,
            ParentText = process.ParentProcessId > 0 ? process.ParentProcessId.ToString() : string.Empty,
            TargetText = process.ObjectOffset,
            SummaryText = $"{process.EvidenceKind} memory process row from image {process.ImageId}",
            DetailsText = string.Join(
                Environment.NewLine,
                new[]
                {
                    process.PluginRunId,
                    process.SourceRunId,
                    process.IngestionJobId,
                    process.CorrelationMethod,
                    process.RawRowHash,
                    process.RawJson
                }.Where(value => !string.IsNullOrWhiteSpace(value)))
        }.WithSearchText();

    private static EvidenceCorrelationInput CreateMemoryProcessCorrelationInput(MemoryProcessRecord process)
        => new()
        {
            InputId = $"memory-process:{process.ArtifactId}",
            EvidenceKind = EvidenceReferenceKind.MemoryProcess,
            EvidenceId = process.ArtifactId,
            EvidenceType = process.EvidenceKind.ToString(),
            Source = process.Source,
            RelationType = EvidenceRelationType.CorrelatesWith,
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            RawInputId = process.RawRowHash,
            ProcessId = process.ProcessId,
            ProcessStartTimeUtc = process.CreateTimeUtc,
            ProcessName = process.ProcessName,
            ProcessPath = process.ImagePath,
            SourceNativeId = process.ProcessKey,
            ObservedUtc = process.CreateTimeUtc ?? DateTime.UtcNow,
            CreatedUtc = DateTime.UtcNow
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

    private static void AddEvidenceIdentityParameters(SqliteCommand command, EvidenceIdentity identity)
    {
        Set(command, "$CaseId", identity.CaseId);
        Set(command, "$EvidenceSessionId", identity.EvidenceSessionId);
        Set(command, "$CaptureId", identity.CaptureId);
        Set(command, "$SourceIdentityId", identity.SourceIdentityId);
        Set(command, "$HostId", identity.HostId);
        Set(command, "$ExecutionRootId", identity.ExecutionRootId);
    }

    private static void AddParameters(SqliteCommand command, IEnumerable<string> names)
    {
        foreach (var name in names)
        {
            SqliteWriteTransactionContext.Add(command, name, null);
        }
    }

    private static string NormalizeIdentifier(string value)
        => string.IsNullOrWhiteSpace(value) ? Guid.NewGuid().ToString("N") : value;

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
}
