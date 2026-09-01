using System.Collections.Generic;
using ProcInsider.Models;

namespace ProcInsider.ViewModels;

public sealed class VolatilityPluginRunRowViewModel : ViewModelBase
{
    private readonly VolatilityPluginRunRecord _record;

    public VolatilityPluginRunRowViewModel(VolatilityPluginRunRecord record)
    {
        _record = record;
    }

    public string RunId => _record.RunId;
    public string ImageId => _record.ImageId;
    public string JobId => _record.JobId?.ToString("D") ?? string.Empty;
    public string PluginName => _record.PluginName;
    public string Status => _record.Status.ToString();
    public DateTime RequestedUtc => _record.RequestedUtc;
    public string RequestedDisplay => RequestedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string StartedDisplay => _record.StartedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;
    public string CompletedDisplay => _record.CompletedUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? string.Empty;
    public string VolatilityPath => _record.VolatilityPath;
    public string VolatilityVersion => _record.VolatilityVersion;
    public string CommandLine => _record.CommandLine;
    public string OutputDirectory => _record.OutputDirectory;
    public string StdoutPath => _record.StdoutPath;
    public string StderrPath => _record.StderrPath;
    public string RawOutputHash => _record.RawOutputHash;
    public int NormalizedRowCount => _record.NormalizedRowCount;
    public string ErrorMessage => _record.ErrorMessage;
    public bool HasError => !string.IsNullOrWhiteSpace(ErrorMessage);

    public VolatilityPluginRunRecord ToRecord() => _record;

    public InspectorPayload ToInspectorPayload()
    {
        return new InspectorPayload
        {
            ArtifactKind = InspectorArtifactKind.VolatilityPluginRun,
            TargetKind = "VolatilityPluginRun",
            TargetTable = "VolatilityPluginRuns",
            TargetId = RunId,
            ArtifactId = RunId,
            CaseId = _record.CaseId,
            EvidenceSessionId = _record.EvidenceSessionId,
            CaptureId = _record.CaptureId,
            SourceIdentityId = _record.SourceIdentityId,
            HostId = _record.HostId,
            ExecutionRootId = _record.ExecutionRootId,
            SourceRunId = _record.SourceRunId,
            IngestionJobId = _record.IngestionJobId,
            DisplayPath = StdoutPath,
            Header = $"{PluginName} | {Status}",
            Subtitle = string.IsNullOrWhiteSpace(CommandLine) ? ImageId : CommandLine,
            EmptyStateMessage = "Select a Volatility plugin run to inspect it here.",
            RawText = BuildRawText(),
            Properties = new List<PropertyItemViewModel>
            {
                new("Identity", "Run ID", RunId),
                new("Identity", "Image ID", ImageId),
                new("Identity", "Job ID", string.IsNullOrWhiteSpace(JobId) ? "<none>" : JobId),
                new("Provenance", "Source Run ID", string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId),
                new("Provenance", "Ingestion Job ID", string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId),
                new("Plugin", "Name", PluginName),
                new("Plugin", "Status", Status),
                new("Plugin", "Requested", RequestedDisplay),
                new("Plugin", "Started", string.IsNullOrWhiteSpace(StartedDisplay) ? "<not started>" : StartedDisplay),
                new("Plugin", "Completed", string.IsNullOrWhiteSpace(CompletedDisplay) ? "<not completed>" : CompletedDisplay),
                new("Execution", "Volatility Path", string.IsNullOrWhiteSpace(VolatilityPath) ? "<none>" : VolatilityPath),
                new("Execution", "Volatility Version", string.IsNullOrWhiteSpace(VolatilityVersion) ? "<none>" : VolatilityVersion),
                new("Execution", "Command Line", string.IsNullOrWhiteSpace(CommandLine) ? "<none>" : CommandLine),
                new("Output", "Directory", string.IsNullOrWhiteSpace(OutputDirectory) ? "<none>" : OutputDirectory),
                new("Output", "Stdout", string.IsNullOrWhiteSpace(StdoutPath) ? "<none>" : StdoutPath),
                new("Output", "Stderr", string.IsNullOrWhiteSpace(StderrPath) ? "<none>" : StderrPath),
                new("Output", "Raw Output Hash", string.IsNullOrWhiteSpace(RawOutputHash) ? "<none>" : RawOutputHash),
                new("Output", "Normalized Rows", NormalizedRowCount.ToString()),
                new("Symbols", "Path", string.IsNullOrWhiteSpace(_record.SymbolsPath) ? "<none>" : _record.SymbolsPath),
                new("Symbols", "Profile / Layer", string.IsNullOrWhiteSpace(_record.ProfileOrLayer) ? "<none>" : _record.ProfileOrLayer),
                new("Status", "Error", string.IsNullOrWhiteSpace(ErrorMessage) ? "<none>" : ErrorMessage)
            }
        };
    }

    private string BuildRawText()
    {
        var lines = new List<string>
        {
            $"RunId: {RunId}",
            $"ImageId: {ImageId}",
            $"JobId: {(string.IsNullOrWhiteSpace(JobId) ? "<none>" : JobId)}",
            $"SourceRunId: {(string.IsNullOrWhiteSpace(_record.SourceRunId) ? "<legacy / unavailable>" : _record.SourceRunId)}",
            $"IngestionJobId: {(string.IsNullOrWhiteSpace(_record.IngestionJobId) ? "<legacy / unavailable>" : _record.IngestionJobId)}",
            $"Plugin: {PluginName}",
            $"Status: {Status}",
            $"CommandLine: {CommandLine}",
            $"StdoutPath: {StdoutPath}",
            $"StderrPath: {StderrPath}",
            $"NormalizedRows: {NormalizedRowCount}"
        };
        if (!string.IsNullOrWhiteSpace(ErrorMessage))
        {
            lines.Add($"Error: {ErrorMessage}");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
