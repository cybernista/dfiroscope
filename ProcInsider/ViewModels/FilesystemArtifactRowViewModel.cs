using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class FilesystemArtifactRowViewModel : ViewModelBase
{
    private readonly FilesystemArtifactRecord _record;

    public FilesystemArtifactRowViewModel(FilesystemArtifactRecord record)
    {
        _record = record;
    }

    public string ArtifactId => _record.ArtifactId;
    public string CaseId => _record.CaseId;
    public string EvidenceSessionId => _record.EvidenceSessionId;
    public string CaptureId => _record.CaptureId;
    public string SourceIdentityId => _record.SourceIdentityId;
    public string HostId => _record.HostId;
    public string ExecutionRootId => _record.ExecutionRootId;
    public string Kind => _record.Kind.ToString();
    public string Status => _record.Status.ToString();
    public DateTime TimestampUtc => _record.TimestampUtc;
    public string TimestampDisplay => _record.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string Name => _record.Name;
    public string SourcePath => _record.SourcePath;
    public long FileSizeBytes => _record.FileSizeBytes;
    public string FileSizeDisplay => FormatBytes(_record.FileSizeBytes);
    public string Sha256Hash => _record.Sha256Hash;
    public string Summary => _record.Summary;
    public string ProcessName => _record.ProcessName;
    public int RunCount => _record.RunCount;
    public string LastRunDisplay => _record.LastRunUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;
    public string ErrorMessage => _record.ErrorMessage;

    public InspectorPayload ToInspectorPayload()
    {
        var properties = new List<PropertyItemViewModel>
        {
            new("Identity", "Artifact ID", ArtifactId),
            new("Identity", "Kind", Kind),
            new("Identity", "Status", Status),
            new("Provenance", "Source Run ID", string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId),
            new("Provenance", "Ingestion Job ID", string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId),
            new("Source", "Path", SourcePath),
            new("Source", "Name", Name),
            new("Source", "Size", FileSizeDisplay),
            new("Source", "SHA256", string.IsNullOrWhiteSpace(Sha256Hash) ? "<none>" : Sha256Hash),
            new("Time", "Timestamp", TimestampDisplay),
            new("Prefetch", "Executable", string.IsNullOrWhiteSpace(ProcessName) ? "<none>" : ProcessName),
            new("Prefetch", "Run Count", RunCount.ToString()),
            new("Prefetch", "Last Run", string.IsNullOrWhiteSpace(LastRunDisplay) ? "<none>" : LastRunDisplay),
            new("Raw", "Raw Record ID", string.IsNullOrWhiteSpace(_record.RawRecordId) ? "<none>" : _record.RawRecordId),
            new("Raw", "Payload SHA256", string.IsNullOrWhiteSpace(_record.RawPayloadHash) ? "<none>" : _record.RawPayloadHash),
            new("Execution", "Error", string.IsNullOrWhiteSpace(ErrorMessage) ? "<none>" : ErrorMessage)
        };

        foreach (var property in _record.Properties)
        {
            properties.Add(new PropertyItemViewModel("Properties", property.Key, property.Value));
        }

        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.FilesystemArtifact,
            TargetKind = "FilesystemArtifact",
            TargetTable = "Artifacts",
            TargetId = ArtifactId,
            ArtifactId = ArtifactId,
            CaseId = CaseId,
            EvidenceSessionId = EvidenceSessionId,
            CaptureId = CaptureId,
            SourceIdentityId = SourceIdentityId,
            HostId = HostId,
            ExecutionRootId = ExecutionRootId,
            SourceRunId = _record.SourceRunId,
            IngestionJobId = _record.IngestionJobId,
            ProcessName = ProcessName,
            DisplayPath = SourcePath,
            Header = $"{Kind} | {Status}",
            Subtitle = string.IsNullOrWhiteSpace(Summary) ? SourcePath : Summary,
            EmptyStateMessage = "Select a filesystem artifact to inspect it here.",
            RawText = BuildRawText(),
            Properties = properties
        };
    }

    private string BuildRawText()
    {
        var lines = new List<string>
        {
            $"ArtifactId: {ArtifactId}",
            $"SourceRunId: {(string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId)}",
            $"IngestionJobId: {(string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId)}",
            $"Kind: {Kind}",
            $"Status: {Status}",
            $"Timestamp: {TimestampDisplay}",
            $"Path: {SourcePath}",
            $"Size: {FileSizeDisplay}",
            $"SHA256: {Sha256Hash}",
            $"Summary: {Summary}",
            $"RawRecordId: {_record.RawRecordId}",
            $"RawPayloadHash: {_record.RawPayloadHash}"
        };

        if (!string.IsNullOrWhiteSpace(ErrorMessage))
        {
            lines.Add($"Error: {ErrorMessage}");
        }

        if (!string.IsNullOrWhiteSpace(_record.RawText))
        {
            lines.Add($"RawSampleHex: {_record.RawText}");
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
