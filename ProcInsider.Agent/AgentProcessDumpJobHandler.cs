using ProcInsider.Models;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentProcessDumpJobHandler : IAgentJobHandler
{
    private readonly string _databasePath;
    private readonly AgentStagingWriter _writer;
    private readonly ProcessDumpService _dumpService;

    public AgentProcessDumpJobHandler(
        string databasePath,
        AgentStagingWriter writer,
        ProcessDumpService dumpService)
    {
        _databasePath = databasePath;
        _writer = writer;
        _dumpService = dumpService;
    }

    public async Task ExecuteAsync(AgentJobContext context)
    {
        var parameters = context.Request.ReadParameters<ProcessDumpParameters>();
        if (string.IsNullOrWhiteSpace(parameters.ProcessKey))
        {
            throw new ArgumentException("Process dump jobs require a ProcessKey target.");
        }

        var queryService = new SqliteStagingQueryService(
            _databasePath,
            openContext: CaptureOpenContext.AgentWritableLive);
        var lookup = queryService.GetProcessByKey(parameters.ProcessKey);
        var requestedUtc = DateTime.UtcNow;
        if (lookup.Process is not { } process)
        {
            var notFoundDump = CreateNotFoundDumpRecord(
                context,
                parameters,
                requestedUtc,
                "No staged process matched the requested ProcessKey.");
            await _writer.UpsertMemoryDumpsAsync(new[] { notFoundDump }, context.CancellationToken).ConfigureAwait(false);
            await context.ReportProgressAsync(1, 1, "Process dump target was not found in staging.").ConfigureAwait(false);
            throw new InvalidOperationException(notFoundDump.ErrorMessage);
        }

        if (!TryOpenMatchingLiveProcess(process, out var liveError))
        {
            var notFoundDump = CreateNotFoundDumpRecord(context, parameters, requestedUtc, liveError);
            await _writer.UpsertMemoryDumpsAsync(new[] { notFoundDump }, context.CancellationToken).ConfigureAwait(false);
            await context.ReportProgressAsync(1, 1, liveError).ConfigureAwait(false);
            throw new InvalidOperationException(liveError);
        }

        var dump = CreateDumpRecord(context, parameters, process, requestedUtc, MemoryDumpStatus.Capturing);
        await _writer.UpsertMemoryDumpsAsync(new[] { dump }, context.CancellationToken).ConfigureAwait(false);
        await context.ReportProgressAsync(0, 1, $"Capturing {parameters.DumpKind} dump for {process.ProcessName} (PID {process.ProcessId}).").ConfigureAwait(false);

        try
        {
            var result = await _dumpService.CreateDumpAsync(
                process,
                parameters.DumpKind,
                parameters.OutputDirectory,
                parameters.OverwriteExisting,
                context.CancellationToken).ConfigureAwait(false);
            var completed = CreateCapturedDumpRecord(context, parameters, process, requestedUtc, result);
            await _writer.UpsertMemoryDumpsAsync(new[] { completed }, context.CancellationToken).ConfigureAwait(false);
            await context.ReportProgressAsync(1, 1, $"Captured dump: {result.FilePath}").ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var failed = CreateFailedDumpRecord(context, parameters, process, requestedUtc, ex.Message);
            await _writer.UpsertMemoryDumpsAsync(new[] { failed }, CancellationToken.None).ConfigureAwait(false);
            await context.ReportProgressAsync(1, 1, $"Process dump failed: {ex.Message}").ConfigureAwait(false);
            throw new InvalidOperationException(ex.Message, ex);
        }
    }

    private static MemoryDumpRecord CreateDumpRecord(
        AgentJobContext context,
        ProcessDumpParameters parameters,
        ProcessRecord process,
        DateTime requestedUtc,
        MemoryDumpStatus status)
    {
        return new MemoryDumpRecord
        {
            CaseId = process.CaseId,
            EvidenceSessionId = process.EvidenceSessionId,
            CaptureId = process.CaptureId,
            SourceIdentityId = process.SourceIdentityId,
            HostId = process.HostId,
            ExecutionRootId = process.ExecutionRootId,
            DumpId = BuildDumpId(context.Request.JobId, parameters.ProcessKey),
            JobId = context.Request.JobId,
            ProcessEntityId = process.ProcessEntityId,
            ProcessKey = process.ProcessKey,
            ProcessId = process.ProcessId,
            ProcessGuid = process.ProcessGuid,
            ProcessName = process.ProcessName,
            DumpKind = parameters.DumpKind,
            Status = status,
            RequestedUtc = requestedUtc,
            CompletedUtc = status is MemoryDumpStatus.Capturing or MemoryDumpStatus.Requested ? null : DateTime.UtcNow,
            OutputDirectory = parameters.OutputDirectory,
            FilePath = string.Empty,
            FileSizeBytes = 0,
            Sha256Hash = string.Empty,
            ToolName = "MiniDumpWriteDump",
            ErrorMessage = string.Empty,
            Source = "AgentProcessDump"
        };
    }

    private static MemoryDumpRecord CreateCapturedDumpRecord(
        AgentJobContext context,
        ProcessDumpParameters parameters,
        ProcessRecord process,
        DateTime requestedUtc,
        ProcessDumpResult result)
    {
        var dump = CreateDumpRecord(context, parameters, process, requestedUtc, MemoryDumpStatus.Captured);
        dump.CompletedUtc = DateTime.UtcNow;
        dump.OutputDirectory = result.OutputDirectory;
        dump.FilePath = result.FilePath;
        dump.FileSizeBytes = result.FileSizeBytes;
        dump.Sha256Hash = result.Sha256Hash;
        dump.ToolName = result.ToolName;
        return dump;
    }

    private static MemoryDumpRecord CreateFailedDumpRecord(
        AgentJobContext context,
        ProcessDumpParameters parameters,
        ProcessRecord process,
        DateTime requestedUtc,
        string error)
    {
        var dump = CreateDumpRecord(context, parameters, process, requestedUtc, MemoryDumpStatus.Failed);
        dump.CompletedUtc = DateTime.UtcNow;
        dump.ErrorMessage = error;
        return dump;
    }

    private static MemoryDumpRecord CreateNotFoundDumpRecord(
        AgentJobContext context,
        ProcessDumpParameters parameters,
        DateTime requestedUtc,
        string error)
    {
        return new MemoryDumpRecord
        {
            DumpId = BuildDumpId(context.Request.JobId, parameters.ProcessKey),
            JobId = context.Request.JobId,
            ProcessKey = parameters.ProcessKey,
            DumpKind = parameters.DumpKind,
            Status = MemoryDumpStatus.NotFound,
            RequestedUtc = requestedUtc,
            CompletedUtc = requestedUtc,
            OutputDirectory = parameters.OutputDirectory,
            ErrorMessage = error,
            Source = "AgentProcessDump"
        };
    }

    private static bool TryOpenMatchingLiveProcess(ProcessRecord process, out string error)
    {
        error = string.Empty;
        if (process.Status == ProcessStatus.Exited)
        {
            error = $"Process {process.ProcessName} (PID {process.ProcessId}) is marked exited; memory dump capture requires a live process.";
            return false;
        }

        System.Diagnostics.Process? liveProcess = null;
        try
        {
            liveProcess = System.Diagnostics.Process.GetProcessById(process.ProcessId);
            if (liveProcess.HasExited)
            {
                error = $"Process {process.ProcessName} (PID {process.ProcessId}) has exited.";
                return false;
            }

            if (process.StartTimeUtc.HasValue &&
                Math.Abs((liveProcess.StartTime.ToUniversalTime() - process.StartTimeUtc.Value).TotalSeconds) > 2)
            {
                error = $"PID {process.ProcessId} was reused; the live process does not match the staged ProcessKey.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = $"Process {process.ProcessName} (PID {process.ProcessId}) is unavailable: {ex.Message}";
            return false;
        }
        finally
        {
            liveProcess?.Dispose();
        }
    }

    private static string BuildDumpId(Guid jobId, string processKey)
    {
        return $"{jobId:N}-{processKey}".Replace('|', '_');
    }

    private sealed record ProcessDumpParameters
    {
        public string ProcessKey { get; init; } = string.Empty;

        public MemoryDumpKind DumpKind { get; init; } = MemoryDumpKind.Full;

        public string OutputDirectory { get; init; } = string.Empty;

        public bool OverwriteExisting { get; init; }
    }
}
