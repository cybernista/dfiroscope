using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class MemoryProcessRowViewModel : ViewModelBase
{
    private readonly MemoryProcessRecord _record;

    public MemoryProcessRowViewModel(MemoryProcessRecord record)
    {
        _record = record;
    }

    public string ArtifactId => _record.ArtifactId;
    public string ImageId => _record.ImageId;
    public string PluginRunId => _record.PluginRunId;
    public string PluginName => _record.PluginName;
    public string EvidenceKind => _record.EvidenceKind.ToString();
    public int RowNumber => _record.RowNumber;
    public string ObjectOffset => _record.ObjectOffset;
    public int ProcessId => _record.ProcessId;
    public int ParentProcessId => _record.ParentProcessId;
    public string ProcessName => _record.ProcessName;
    public string ImagePath => _record.ImagePath;
    public string CommandLine => _record.CommandLine;
    public string CreateTimeDisplay => _record.CreateTimeUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;
    public string ExitTimeDisplay => _record.ExitTimeUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;
    public int SessionId => _record.SessionId;
    public int ThreadCount => _record.ThreadCount;
    public int HandleCount => _record.HandleCount;
    public string Wow64 => _record.Wow64;
    public string ProcessKey => _record.ProcessKey;
    public string CorrelationState => _record.CorrelationState.ToString();
    public string CorrelationMethod => _record.CorrelationMethod;
    public double CorrelationConfidence => _record.CorrelationConfidence;
    public string RawRowHash => _record.RawRowHash;

    public MemoryProcessRecord ToRecord() => _record;

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.MemoryProcess,
            TargetKind = "MemoryProcess",
            TargetTable = "MemoryProcesses",
            TargetId = ArtifactId,
            ArtifactId = ArtifactId,
            CaseId = _record.CaseId,
            EvidenceSessionId = _record.EvidenceSessionId,
            CaptureId = _record.CaptureId,
            SourceIdentityId = _record.SourceIdentityId,
            HostId = _record.HostId,
            ExecutionRootId = _record.ExecutionRootId,
            SourceRunId = _record.SourceRunId,
            IngestionJobId = _record.IngestionJobId,
            ProcessKey = ProcessKey,
            ProcessId = ProcessId,
            ProcessName = ProcessName,
            DisplayPath = ImagePath,
            Header = $"{ProcessName} | PID {ProcessId}",
            Subtitle = $"{PluginName} | {CorrelationState}",
            EmptyStateMessage = "Select a memory-derived process row to inspect it here.",
            RawText = _record.RawJson,
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Artifact ID", ArtifactId),
                new("Identity", "Image ID", ImageId),
                new("Identity", "Plugin Run ID", PluginRunId),
                new("Provenance", "Source Run ID", string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId),
                new("Provenance", "Ingestion Job ID", string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId),
                new("Plugin", "Plugin", PluginName),
                new("Plugin", "Evidence Kind", EvidenceKind),
                new("Plugin", "Row Number", RowNumber.ToString()),
                new("Plugin", "Object Offset", string.IsNullOrWhiteSpace(ObjectOffset) ? "<none>" : ObjectOffset),
                new("Process", "PID", ProcessId.ToString()),
                new("Process", "Parent PID", ParentProcessId.ToString()),
                new("Process", "Name", string.IsNullOrWhiteSpace(ProcessName) ? "<unknown>" : ProcessName),
                new("Process", "Image Path", string.IsNullOrWhiteSpace(ImagePath) ? "<none>" : ImagePath),
                new("Process", "Command Line", string.IsNullOrWhiteSpace(CommandLine) ? "<none>" : CommandLine),
                new("Process", "Create Time", string.IsNullOrWhiteSpace(CreateTimeDisplay) ? "<none>" : CreateTimeDisplay),
                new("Process", "Exit Time", string.IsNullOrWhiteSpace(ExitTimeDisplay) ? "<none>" : ExitTimeDisplay),
                new("Process", "Session", SessionId.ToString()),
                new("Process", "Threads", ThreadCount.ToString()),
                new("Process", "Handles", HandleCount.ToString()),
                new("Correlation", "State", CorrelationState),
                new("Correlation", "Process Key", string.IsNullOrWhiteSpace(ProcessKey) ? "<none>" : ProcessKey),
                new("Correlation", "Method", string.IsNullOrWhiteSpace(CorrelationMethod) ? "<none>" : CorrelationMethod),
                new("Correlation", "Confidence", CorrelationConfidence.ToString("0.00")),
                new("Raw", "Row Hash", string.IsNullOrWhiteSpace(RawRowHash) ? "<none>" : RawRowHash)
            }
        };
    }
}
