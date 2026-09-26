using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class NetworkCaptureRowViewModel : ViewModelBase
{
    private readonly NetworkCaptureRecord _record;

    public NetworkCaptureRowViewModel(NetworkCaptureRecord record)
    {
        _record = record;
    }

    public string CaptureId => _record.CaptureId;

    public string JobId => _record.JobId?.ToString("D") ?? string.Empty;

    public int SegmentIndex => _record.SegmentIndex;

    public string Status => _record.Status.ToString();

    public NetworkCaptureStatus StatusKind => _record.Status;

    public bool CanRunZeek => _record.Status == NetworkCaptureStatus.Captured && !string.IsNullOrWhiteSpace(_record.FilePath);

    public DateTime RequestedUtc => _record.RequestedUtc;

    public string RequestedDisplay => _record.RequestedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public string StartedDisplay => _record.StartedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;

    public string CompletedDisplay => _record.CompletedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;

    public string FilePath => _record.FilePath;

    public string EtlFilePath => _record.EtlFilePath;

    public long FileSizeBytes => _record.FileSizeBytes;

    public string FileSizeDisplay => FormatBytes(_record.FileSizeBytes);

    public string Sha256Hash => _record.Sha256Hash;

    public string ToolName => _record.ToolName;

    public string ErrorMessage => _record.ErrorMessage;

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.NetworkCapture,
            TargetKind = "NetworkCapture",
            TargetTable = "NetworkCaptures",
            TargetId = CaptureId,
            ArtifactId = CaptureId,
            CaseId = _record.CaseId,
            EvidenceSessionId = _record.EvidenceSessionId,
            CaptureId = _record.CaptureId,
            SourceIdentityId = _record.SourceIdentityId,
            HostId = _record.HostId,
            ExecutionRootId = _record.ExecutionRootId,
            SourceRunId = _record.SourceRunId,
            IngestionJobId = _record.IngestionJobId,
            DisplayPath = FilePath,
            Header = $"Network capture segment {SegmentIndex} | {Status}",
            Subtitle = string.IsNullOrWhiteSpace(FilePath) ? _record.CaptureSource : FilePath,
            EmptyStateMessage = "Select a network capture segment to inspect it here.",
            RawText = BuildRawText(),
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Capture ID", CaptureId),
                new("Identity", "Job ID", string.IsNullOrWhiteSpace(JobId) ? "<none>" : JobId),
                new("Provenance", "Source Run ID", string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId),
                new("Provenance", "Ingestion Job ID", string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId),
                new("Capture", "Status", Status),
                new("Capture", "Segment", SegmentIndex.ToString()),
                new("Capture", "Requested", RequestedDisplay),
                new("Capture", "Started", string.IsNullOrWhiteSpace(StartedDisplay) ? "<not started>" : StartedDisplay),
                new("Capture", "Completed", string.IsNullOrWhiteSpace(CompletedDisplay) ? "<not completed>" : CompletedDisplay),
                new("Capture", "Source", _record.CaptureSource),
                new("Capture", "Filter", _record.FilterDescription),
                new("File", "Output Directory", string.IsNullOrWhiteSpace(_record.OutputDirectory) ? "<default>" : _record.OutputDirectory),
                new("File", "PCAPNG Path", string.IsNullOrWhiteSpace(FilePath) ? "<none>" : FilePath),
                new("File", "ETL Path", string.IsNullOrWhiteSpace(EtlFilePath) ? "<none>" : EtlFilePath),
                new("File", "Size", FileSizeDisplay),
                new("File", "SHA256", string.IsNullOrWhiteSpace(Sha256Hash) ? "<none>" : Sha256Hash),
                new("Execution", "Tool", string.IsNullOrWhiteSpace(ToolName) ? "<none>" : ToolName),
                new("Execution", "Error", string.IsNullOrWhiteSpace(ErrorMessage) ? "<none>" : ErrorMessage)
            }
        };
    }

    private string BuildRawText()
    {
        var lines = new List<string>
        {
            $"CaptureId: {CaptureId}",
            $"JobId: {(string.IsNullOrWhiteSpace(JobId) ? "<none>" : JobId)}",
            $"SourceRunId: {(string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId)}",
            $"IngestionJobId: {(string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId)}",
            $"Segment: {SegmentIndex}",
            $"Status: {Status}",
            $"Requested: {RequestedDisplay}",
            $"Started: {(string.IsNullOrWhiteSpace(StartedDisplay) ? "<not started>" : StartedDisplay)}",
            $"Completed: {(string.IsNullOrWhiteSpace(CompletedDisplay) ? "<not completed>" : CompletedDisplay)}",
            $"Tool: {(string.IsNullOrWhiteSpace(ToolName) ? "<none>" : ToolName)}",
            $"PCAPNG: {(string.IsNullOrWhiteSpace(FilePath) ? "<none>" : FilePath)}",
            $"ETL: {(string.IsNullOrWhiteSpace(EtlFilePath) ? "<none>" : EtlFilePath)}",
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
