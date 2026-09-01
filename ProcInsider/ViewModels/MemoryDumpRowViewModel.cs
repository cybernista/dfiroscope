using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class MemoryDumpRowViewModel : ViewModelBase
{
    private readonly MemoryDumpRecord _record;

    public MemoryDumpRowViewModel(MemoryDumpRecord record)
    {
        _record = record;
    }

    public string DumpId => _record.DumpId;

    public string JobId => _record.JobId?.ToString("D") ?? string.Empty;

    public string ProcessName => _record.ProcessName;

    public int ProcessId => _record.ProcessId;

    public string DumpKind => _record.DumpKind.ToString();

    public string Status => _record.Status.ToString();

    public DateTime RequestedUtc => _record.RequestedUtc;

    public string RequestedDisplay => _record.RequestedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public string CompletedDisplay => _record.CompletedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;

    public string FilePath => _record.FilePath;

    public long FileSizeBytes => _record.FileSizeBytes;

    public string FileSizeDisplay => FormatBytes(_record.FileSizeBytes);

    public string Sha256Hash => _record.Sha256Hash;

    public string ToolName => _record.ToolName;

    public string ErrorMessage => _record.ErrorMessage;

    public bool HasError => !string.IsNullOrWhiteSpace(ErrorMessage);

    public MemoryDumpRecord ToRecord()
    {
        return new MemoryDumpRecord
        {
            CaseId = _record.CaseId,
            EvidenceSessionId = _record.EvidenceSessionId,
            CaptureId = _record.CaptureId,
            SourceIdentityId = _record.SourceIdentityId,
            HostId = _record.HostId,
            ExecutionRootId = _record.ExecutionRootId,
            DumpId = _record.DumpId,
            JobId = _record.JobId,
            ProcessEntityId = _record.ProcessEntityId,
            ProcessKey = _record.ProcessKey,
            ProcessId = _record.ProcessId,
            ProcessGuid = _record.ProcessGuid,
            ProcessName = _record.ProcessName,
            DumpKind = _record.DumpKind,
            Status = _record.Status,
            RequestedUtc = _record.RequestedUtc,
            CompletedUtc = _record.CompletedUtc,
            OutputDirectory = _record.OutputDirectory,
            FilePath = _record.FilePath,
            FileSizeBytes = _record.FileSizeBytes,
            Sha256Hash = _record.Sha256Hash,
            ToolName = _record.ToolName,
            ErrorMessage = _record.ErrorMessage,
            Source = _record.Source,
            SourceRunId = _record.SourceRunId,
            IngestionJobId = _record.IngestionJobId
        };
    }

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.MemoryDump,
            TargetKind = "MemoryDump",
            TargetTable = "MemoryDumps",
            TargetId = DumpId,
            ArtifactId = DumpId,
            CaseId = _record.CaseId,
            EvidenceSessionId = _record.EvidenceSessionId,
            CaptureId = _record.CaptureId,
            SourceIdentityId = _record.SourceIdentityId,
            HostId = _record.HostId,
            ExecutionRootId = _record.ExecutionRootId,
            ProcessKey = _record.ProcessKey,
            ProcessId = ProcessId,
            ProcessName = ProcessName,
            DisplayPath = FilePath,
            Header = $"{DumpKind} dump | {Status}",
            Subtitle = string.IsNullOrWhiteSpace(FilePath)
                ? $"{ProcessName} (PID {ProcessId})"
                : FilePath,
            EmptyStateMessage = "Select a memory dump artifact to inspect it here.",
            RawText = BuildRawText(),
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Dump ID", DumpId),
                new("Identity", "Job ID", string.IsNullOrWhiteSpace(JobId) ? "<none>" : JobId),
                new("Process", "Process Key", _record.ProcessKey),
                new("Process", "Process Entity", _record.ProcessEntityId),
                new("Provenance", "Source Run", _record.SourceRunId),
                new("Provenance", "Ingestion Job", _record.IngestionJobId),
                new("Process", "Process Name", ProcessName),
                new("Process", "PID", ProcessId.ToString()),
                new("Process", "Process Guid", string.IsNullOrWhiteSpace(_record.ProcessGuid) ? "<none>" : _record.ProcessGuid),
                new("Dump", "Kind", DumpKind),
                new("Dump", "Status", Status),
                new("Dump", "Requested", RequestedDisplay),
                new("Dump", "Completed", string.IsNullOrWhiteSpace(CompletedDisplay) ? "<not completed>" : CompletedDisplay),
                new("File", "Output Directory", string.IsNullOrWhiteSpace(_record.OutputDirectory) ? "<default>" : _record.OutputDirectory),
                new("File", "Path", string.IsNullOrWhiteSpace(FilePath) ? "<none>" : FilePath),
                new("File", "Size", FileSizeDisplay),
                new("File", "SHA256", string.IsNullOrWhiteSpace(Sha256Hash) ? "<none>" : Sha256Hash),
                new("Execution", "Tool", string.IsNullOrWhiteSpace(ToolName) ? "<none>" : ToolName),
                new("Execution", "Source", string.IsNullOrWhiteSpace(_record.Source) ? "<none>" : _record.Source),
                new("Execution", "Error", string.IsNullOrWhiteSpace(ErrorMessage) ? "<none>" : ErrorMessage)
            }
        };
    }

    private string BuildRawText()
    {
        var lines = new List<string>
        {
            $"DumpId: {DumpId}",
            $"JobId: {(string.IsNullOrWhiteSpace(JobId) ? "<none>" : JobId)}",
            $"Process: {ProcessName} (PID {ProcessId})",
            $"Kind: {DumpKind}",
            $"Status: {Status}",
            $"Requested: {RequestedDisplay}",
            $"Completed: {(string.IsNullOrWhiteSpace(CompletedDisplay) ? "<not completed>" : CompletedDisplay)}",
            $"Tool: {(string.IsNullOrWhiteSpace(ToolName) ? "<none>" : ToolName)}",
            $"FilePath: {(string.IsNullOrWhiteSpace(FilePath) ? "<none>" : FilePath)}",
            $"FileSize: {FileSizeDisplay}",
            $"SHA256: {(string.IsNullOrWhiteSpace(Sha256Hash) ? "<none>" : Sha256Hash)}"
        };

        if (!string.IsNullOrWhiteSpace(ErrorMessage))
        {
            lines.Add($"Error: {ErrorMessage}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "0 B";
        }

        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0 ? $"{bytes} B" : $"{value:F1} {units[unit]}";
    }
}
