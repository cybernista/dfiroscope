using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Agent;

internal sealed record AgentJobRequest
{
    public Guid JobId { get; init; } = Guid.NewGuid();

    public string SourceRunId { get; init; } = $"srun_{Guid.NewGuid():N}";

    public Guid? OriginatingCommandId { get; init; }

    public JobKind JobKind { get; init; }

    public string SourceType { get; init; } = "Agent";

    public string SourceDisplayName { get; init; } = "Agent job";

    public string SourcePath { get; init; } = string.Empty;

    public string SourceProvider { get; init; } = string.Empty;

    public string SourceChannel { get; init; } = string.Empty;

    public string ToolVersion { get; init; } = string.Empty;

    public string ParserVersion { get; init; } = string.Empty;

    public string EvidenceSourceAdapterId { get; init; } = string.Empty;

    public string EvidenceSourceAdapterVersion { get; init; } = string.Empty;

    public EvidenceIdentity EvidenceIdentity { get; init; } = new();

    public string SourceMetadataJson { get; init; } = "{}";

    public string ParentSourceRunId { get; init; } = string.Empty;

    public string InputArtifactId { get; init; } = string.Empty;

    public string InputPath { get; init; } = string.Empty;

    public string InputHash { get; init; } = string.Empty;

    public string CaptureId { get; init; } = string.Empty;

    public bool IsCaptureScoped { get; init; }

    public bool IsLiveSource { get; init; }

    public AgentJobOwnership Ownership { get; init; }

    public AgentRequestedWorkloads RequestedWorkloads { get; init; } = new();

    public DateTime AcceptedAtUtc { get; init; } = DateTime.UtcNow;

    public object? Parameters { get; init; }

    public string ToParametersJson()
    {
        if (Parameters is null)
        {
            return "{}";
        }

        return JsonSerializer.Serialize(Parameters, AgentJson.JsonOptions);
    }

    public string ReadParameterString(params string[] names)
    {
        if (Parameters is null || names.Length == 0)
        {
            return string.Empty;
        }

        using var document = JsonDocument.Parse(ToParametersJson());
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.String &&
                names.Any(name => string.Equals(name, property.Name, StringComparison.OrdinalIgnoreCase)))
            {
                return property.Value.GetString() ?? string.Empty;
            }
        }

        return string.Empty;
    }
}
