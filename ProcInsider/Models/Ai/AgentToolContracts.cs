using System.Text.Json;

namespace ProcInsider.Models.Ai;

public enum AgentPermission
{
    EvidenceRead,
    QueryLocal,
    InvestigationModify,
    FindingCreate,
    HypothesisCreate,
    TaskCreate
}

public static class AgentPermissionNames
{
    public static string ToPolicyName(this AgentPermission permission) => permission switch
    {
        AgentPermission.EvidenceRead => "Evidence.Read",
        AgentPermission.QueryLocal => "Query.Local",
        AgentPermission.InvestigationModify => "Investigation.Modify",
        AgentPermission.FindingCreate => "Finding.Create",
        AgentPermission.HypothesisCreate => "Hypothesis.Create",
        AgentPermission.TaskCreate => "Task.Create",
        _ => throw new ArgumentOutOfRangeException(nameof(permission))
    };
}

public sealed record AgentLimits(int MaximumIterations, int MaximumToolCalls, TimeSpan MaximumRuntime)
{
    public static AgentLimits Stage1Default { get; } = new(8, 36, TimeSpan.FromMinutes(5));

    public bool IsValid => MaximumIterations is >= 1 and <= 32 &&
        MaximumToolCalls is >= 1 and <= 64 &&
        MaximumRuntime >= TimeSpan.FromSeconds(5) && MaximumRuntime <= TimeSpan.FromMinutes(15);
}

public sealed class AgentDefinition
{
    public const string InteractiveInvestigatorId = "InteractiveInvestigator";
    public const string ReviewRecordSkillId = "ReviewRecord";
    public const string ExplainObjectSkillId = "ExplainObject";
    public const string QueryEvidenceSkillId = "QueryEvidence";
    public const string InvestigateProcessSkillId = "InvestigateProcess";

    public static AgentDefinition InteractiveInvestigator { get; } = new(
        InteractiveInvestigatorId, "Human", "Interactive",
        [ExplainObjectSkillId, QueryEvidenceSkillId, InvestigateProcessSkillId, ReviewRecordSkillId],
        [AgentPermission.EvidenceRead, AgentPermission.QueryLocal,
            AgentPermission.InvestigationModify, AgentPermission.FindingCreate,
            AgentPermission.HypothesisCreate, AgentPermission.TaskCreate],
        AgentLimits.Stage1Default);

    public AgentDefinition(string id, string initiator, string mode,
        IEnumerable<string> allowedSkillIds, IEnumerable<AgentPermission> allowedPermissions,
        AgentLimits limits)
    {
        if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(initiator) ||
            string.IsNullOrWhiteSpace(mode) || limits is null || !limits.IsValid)
            throw new ArgumentException("Agent definition is invalid.");
        Id = id;
        Initiator = initiator;
        Mode = mode;
        AllowedSkillIds = Array.AsReadOnly(allowedSkillIds.Distinct(StringComparer.Ordinal).ToArray());
        AllowedPermissions = Array.AsReadOnly(allowedPermissions.Distinct().ToArray());
        Limits = limits;
    }

    public string Id { get; }
    public string Initiator { get; }
    public string Mode { get; }
    public IReadOnlyList<string> AllowedSkillIds { get; }
    public IReadOnlyList<AgentPermission> AllowedPermissions { get; }
    public AgentLimits Limits { get; }
}

public sealed class AgentToolDescriptor
{
    public AgentToolDescriptor(string id, string name, string description,
        IEnumerable<AgentPermission> requiredPermissions, IEnumerable<string> allowedSkillIds,
        JsonElement inputSchema, JsonElement outputSchema)
    {
        Id = id;
        Name = name;
        Description = description;
        RequiredPermissions = Array.AsReadOnly(requiredPermissions.Distinct().ToArray());
        AllowedSkillIds = Array.AsReadOnly(allowedSkillIds.Distinct(StringComparer.Ordinal).ToArray());
        InputSchema = inputSchema.Clone();
        OutputSchema = outputSchema.Clone();
    }

    public string Id { get; }
    public string Name { get; }
    public string Description { get; }
    public IReadOnlyList<AgentPermission> RequiredPermissions { get; }
    public IReadOnlyList<string> AllowedSkillIds { get; }
    public JsonElement InputSchema { get; }
    public JsonElement OutputSchema { get; }
}

public enum AgentToolStatus
{
    Available,
    Unavailable,
    NotFound,
    Ambiguous,
    InvalidRequest,
    Denied,
    UnknownTool,
    InvalidOutput
}

public sealed record AgentToolResult(
    string ToolId,
    AgentToolStatus Status,
    JsonElement Output,
    IReadOnlyList<AiEvidenceReference> Evidence,
    int ObservedCount,
    bool CountIsExact,
    bool IsTruncated,
    IReadOnlyList<string> Omissions,
    string DiagnosticCode)
{
    public static AgentToolResult Rejected(string toolId, AgentToolStatus status, string code) =>
        new(toolId, status, JsonSerializer.SerializeToElement(new { }), [], 0, false, false, [], code);

    public static AgentToolResult Rejected(string toolId, AgentToolStatus status, string code,
        string diagnostic) => new(toolId, status,
            JsonSerializer.SerializeToElement(new { diagnostic }), [], 0, false, false, [], code);
}
