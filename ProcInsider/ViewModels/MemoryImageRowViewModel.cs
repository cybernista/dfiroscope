using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class MemoryImageRowViewModel : ViewModelBase
{
    private readonly MemoryImageRecord _record;

    public MemoryImageRowViewModel(MemoryImageRecord record)
    {
        _record = record;
    }

    public string ImageId => _record.ImageId;
    public string JobId => _record.JobId?.ToString("D") ?? string.Empty;
    public string DisplayName => string.IsNullOrWhiteSpace(_record.DisplayName) ? _record.ImageId : _record.DisplayName;
    public string Status => _record.Status.ToString();
    public DateTime ImportedUtc => _record.ImportedUtc;
    public string ImportedDisplay => ImportedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string FilePath => _record.FilePath;
    public string SourcePath => _record.SourcePath;
    public string ImageFormat => _record.ImageFormat;
    public long FileSizeBytes => _record.FileSizeBytes;
    public string FileSizeDisplay => FormatBytes(_record.FileSizeBytes);
    public string Sha256Hash => _record.Sha256Hash;
    public string HostName => _record.HostName;
    public string OsBuild => _record.OsBuild;
    public string AcquisitionTool => _record.AcquisitionTool;
    public string ErrorMessage => _record.ErrorMessage;
    public bool HasError => !string.IsNullOrWhiteSpace(ErrorMessage);

    public MemoryImageRecord ToRecord() => _record;

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.MemoryImage,
            TargetKind = "MemoryImage",
            TargetTable = "MemoryImages",
            TargetId = ImageId,
            ArtifactId = ImageId,
            CaseId = _record.CaseId,
            EvidenceSessionId = _record.EvidenceSessionId,
            CaptureId = _record.CaptureId,
            SourceIdentityId = _record.SourceIdentityId,
            HostId = _record.HostId,
            ExecutionRootId = _record.ExecutionRootId,
            SourceRunId = _record.SourceRunId,
            IngestionJobId = _record.IngestionJobId,
            DisplayPath = FilePath,
            Header = $"{DisplayName} | {Status}",
            Subtitle = FilePath,
            EmptyStateMessage = "Select a memory image to inspect it here.",
            RawText = BuildRawText(),
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Image ID", ImageId),
                new("Identity", "Job ID", string.IsNullOrWhiteSpace(JobId) ? "<none>" : JobId),
                new("Provenance", "Source Run ID", string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId),
                new("Provenance", "Ingestion Job ID", string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId),
                new("Image", "Display Name", DisplayName),
                new("Image", "Status", Status),
                new("Image", "Imported", ImportedDisplay),
                new("Image", "Format", string.IsNullOrWhiteSpace(ImageFormat) ? "<unknown>" : ImageFormat),
                new("File", "Path", string.IsNullOrWhiteSpace(FilePath) ? "<none>" : FilePath),
                new("File", "Source Path", string.IsNullOrWhiteSpace(SourcePath) ? "<none>" : SourcePath),
                new("File", "Size", FileSizeDisplay),
                new("File", "SHA256", string.IsNullOrWhiteSpace(Sha256Hash) ? "<none>" : Sha256Hash),
                new("Acquisition", "Host", string.IsNullOrWhiteSpace(HostName) ? "<none>" : HostName),
                new("Acquisition", "OS Build", string.IsNullOrWhiteSpace(OsBuild) ? "<none>" : OsBuild),
                new("Acquisition", "Tool", string.IsNullOrWhiteSpace(AcquisitionTool) ? "<none>" : AcquisitionTool),
                new("Acquisition", "Tool Version", string.IsNullOrWhiteSpace(_record.AcquisitionToolVersion) ? "<none>" : _record.AcquisitionToolVersion),
                new("Acquisition", "Command Line", string.IsNullOrWhiteSpace(_record.AcquisitionCommandLine) ? "<none>" : _record.AcquisitionCommandLine),
                new("Acquisition", "Privilege State", string.IsNullOrWhiteSpace(_record.PrivilegeState) ? "<none>" : _record.PrivilegeState),
                new("Status", "Error", string.IsNullOrWhiteSpace(ErrorMessage) ? "<none>" : ErrorMessage)
            }
        };
    }

    private string BuildRawText()
    {
        var lines = new List<string>
        {
            $"ImageId: {ImageId}",
            $"JobId: {(string.IsNullOrWhiteSpace(JobId) ? "<none>" : JobId)}",
            $"SourceRunId: {(string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId)}",
            $"IngestionJobId: {(string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId)}",
            $"Status: {Status}",
            $"Imported: {ImportedDisplay}",
            $"FilePath: {FilePath}",
            $"FileSize: {FileSizeDisplay}",
            $"SHA256: {Sha256Hash}",
            $"HostName: {HostName}",
            $"OsBuild: {OsBuild}",
            $"AcquisitionTool: {AcquisitionTool}"
        };
        if (!string.IsNullOrWhiteSpace(ErrorMessage))
        {
            lines.Add($"Error: {ErrorMessage}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    internal static string FormatBytes(long bytes)
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
