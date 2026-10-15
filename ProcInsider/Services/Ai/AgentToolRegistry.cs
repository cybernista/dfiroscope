using System.Text;
using System.Text.Json;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public interface IAgentTool
{
    AgentToolDescriptor Descriptor { get; }
    Task<AgentToolResult> ExecuteAsync(AgentToolSession session, JsonElement arguments,
        CancellationToken cancellationToken);
}

internal interface IAgentToolAvailability
{
    bool IsAvailableFor(AgentToolSession session);
}

public sealed class AgentToolRegistry
{
    private const int MaximumSchemaBytes = 32_000;
    private const int MaximumInputBytes = 16_000;
    private const int MaximumOutputBytes = 64_000;
    private readonly AgentPolicy _policy;
    private readonly TelemetryProjectionService _projection;
    private readonly IReadOnlyDictionary<string, IAgentTool> _tools;

    public AgentToolRegistry(AgentPolicy policy, TelemetryProjectionService projection,
        IEnumerable<IAgentTool>? tools = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _projection = projection ?? throw new ArgumentNullException(nameof(projection));
        var registered = tools?.ToArray() ?? ProcessEvidenceAgentTools.Create(projection)
            .Concat(EvidenceObjectAgentTools.Create(projection, policy.Access))
            .Concat(SnapshotEvidenceAgentTools.Create(projection, policy.Access))
            .Concat(ArtifactEvidenceAgentTools.Create(projection, policy.Access))
            .Append(new ReviewRecordAgentTool(projection, policy.Access)).ToArray();
        var byId = new Dictionary<string, IAgentTool>(StringComparer.Ordinal);
        foreach (var tool in registered)
        {
            if (tool is null || !ValidDescriptor(tool.Descriptor) ||
                !byId.TryAdd(tool.Descriptor.Id, tool))
                throw new ArgumentException("Agent tool registration is invalid or duplicates an ID.");
        }
        _tools = byId;
        Descriptors = Array.AsReadOnly(byId.Values.Select(tool => tool.Descriptor).ToArray());
    }

    public IReadOnlyList<AgentToolDescriptor> Descriptors { get; }

    public IReadOnlyList<ModelToolDefinition> GetModelToolDefinitions(AgentToolSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        return Array.AsReadOnly(_tools.Values.Where(tool =>
                _policy.CheckTool(session, tool.Descriptor).Allowed &&
                (tool is not IAgentToolAvailability availability || availability.IsAvailableFor(session)))
            .Select(tool => new ModelToolDefinition(tool.Descriptor.Id, tool.Descriptor.Description,
                tool.Descriptor.InputSchema.Clone())).ToArray());
    }

    internal async Task<AiObjectContext?> RevalidateSavedReferenceAsync(AgentToolSession session,
        AiEvidenceReference reference, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (session is null || reference is null || !ValidEvidenceReference(reference) ||
            !session.ReadBoundaryAdmits(reference.Identity) || session.ReadBindingToken is null ||
            !_projection.IsCurrentReadBinding(session.ReadBindingToken) ||
            !_policy.CheckIteration(session)) return null;
        try
        {
            using var scope = _projection.BeginReadScope(session.ReadBindingToken);
            var original = await AiEvidenceReferenceResolver.ResolveObjectAsync(_projection,
                _policy.Access, reference, session.Scope.Identity.EvidenceSessionId, cancellationToken);
            return _projection.IsCurrentReadBinding(session.ReadBindingToken) &&
                original?.Reference.ReferenceId == reference.ReferenceId &&
                original.Reference.CanonicalObjectKey == reference.CanonicalObjectKey &&
                original.Reference.Identity == reference.Identity ? original : null;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { return null; }
    }

    public async Task<AgentToolResult> DispatchAsync(AgentToolSession session,
        ModelToolRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (session is null) return AgentToolResult.Rejected(string.Empty, AgentToolStatus.Denied, "tool.no-session");
        if (!session.TryCountAttempt())
            return AgentToolResult.Rejected(request is not null && SafeId(request.Name) &&
                _tools.TryGetValue(request.Name, out var known) ? known.Descriptor.Id : string.Empty,
                AgentToolStatus.Denied, "tool.call-limit");
        if (request is null || !SafeId(request.Name) ||
            !_tools.TryGetValue(request.Name, out var tool))
            return AgentToolResult.Rejected(string.Empty, AgentToolStatus.UnknownTool, "tool.unknown-id");
        var decision = _policy.CheckTool(session, tool.Descriptor);
        if (!decision.Allowed)
            return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.Denied, decision.Code);
        if (tool is IAgentToolAvailability availability && !availability.IsAvailableFor(session))
            return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.Denied, "tool.feature-unpublished");
        if (string.IsNullOrWhiteSpace(request.CallId) || request.CallId.Length > 160 ||
            !ValidJson(request.Arguments, MaximumInputBytes) ||
            request.Arguments.ValueKind != JsonValueKind.Object)
            return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.InvalidRequest,
                "tool.invalid-input", "Tool call ID or argument object is missing, malformed or exceeds its bound. Supply one bounded JSON object with the original query constraints.");
        if (!ModelJsonSchemaValidator.IsValid(request.Arguments, tool.Descriptor.InputSchema))
            return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.InvalidRequest,
                "tool.invalid-input", ModelJsonSchemaValidator.DescribeFailure(request.Arguments,
                    tool.Descriptor.InputSchema));
        if (session.ReadBindingToken is null || !_projection.IsCurrentReadBinding(session.ReadBindingToken))
            return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.Unavailable, "tool.stale-read-binding");
        cancellationToken.ThrowIfCancellationRequested();
        var remaining = session.RemainingRuntime;
        if (remaining <= TimeSpan.Zero)
            return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.Denied, "tool.runtime-limit");
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(remaining);
        try
        {
            using var readScope = _projection.BeginReadScope(session.ReadBindingToken);
            var result = await tool.ExecuteAsync(session, request.Arguments.Clone(), linked.Token)
                .WaitAsync(linked.Token);
            cancellationToken.ThrowIfCancellationRequested();
            if (!_policy.CheckTool(session, tool.Descriptor).Allowed ||
                !_projection.IsCurrentReadBinding(session.ReadBindingToken))
                return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.Unavailable, "tool.stale-or-expired");
            if (result is null || result.ToolId != tool.Descriptor.Id ||
                !ValidJson(result.Output, MaximumOutputBytes,
                    tool.Descriptor.Id == "GetSnapshotEvidenceContent" &&
                    SnapshotEvidenceAgentTools.IsCheckedRelatedTool(tool, _projection) ? 32_000 : 8_192) ||
                !ModelJsonSchemaValidator.IsValid(result.Output, tool.Descriptor.OutputSchema) ||
                result.Evidence is null || result.Evidence.Count > 50 ||
                result.Evidence.Any(reference => reference is null ||
                    !(AgentPolicy.ScopeAdmits(session.Scope, reference.Identity) ||
                      (ProcessEvidenceAgentTools.IsCheckedRelatedTool(tool, _projection) ||
                       EvidenceObjectAgentTools.IsCheckedRelatedTool(tool, _projection) ||
                       SnapshotEvidenceAgentTools.IsCheckedRelatedTool(tool, _projection) ||
                       ArtifactEvidenceAgentTools.IsCheckedRelatedTool(tool, _projection)) &&
                      AgentPolicy.RelatedBoundaryAdmits(session.Scope, reference.Identity))) ||
                result.ObservedCount < 0 || result.Omissions is null || result.Omissions.Count > 16 ||
                result.Omissions.Any(omission => string.IsNullOrWhiteSpace(omission) || omission.Length > 100) ||
                result.DiagnosticCode is null || result.DiagnosticCode.Length > 120 ||
                !Enum.IsDefined(result.Status) ||
                result.Evidence.Any(reference => !ValidEvidenceReference(reference)) ||
                !EvidenceFits(result.Output, result.Evidence))
                return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.InvalidOutput, "tool.invalid-output");
            var frozen = result with { Evidence = Array.AsReadOnly(result.Evidence.ToArray()),
                Omissions = Array.AsReadOnly(result.Omissions.ToArray()), Output = result.Output.Clone() };
            if (frozen.Status == AgentToolStatus.Available && session.AllowsConversationReads &&
                (ProcessEvidenceAgentTools.IsCheckedRelatedTool(tool, _projection) ||
                 EvidenceObjectAgentTools.IsCheckedRelatedTool(tool, _projection) ||
                 SnapshotEvidenceAgentTools.IsCheckedRelatedTool(tool, _projection) ||
                 ArtifactEvidenceAgentTools.IsCheckedRelatedTool(tool, _projection)) &&
                !session.TryRecordCheckedRelatedEvidence(frozen.Evidence))
                return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.InvalidOutput, "tool.reference-ledger-invalid");
            return frozen;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return AgentToolResult.Rejected(tool.Descriptor.Id,
                session.RemainingRuntime <= TimeSpan.Zero ? AgentToolStatus.Denied : AgentToolStatus.Unavailable,
                session.RemainingRuntime <= TimeSpan.Zero ? "tool.runtime-limit" : "tool.stale-read-binding");
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return AgentToolResult.Rejected(tool.Descriptor.Id, AgentToolStatus.Unavailable, "tool.read-failed");
        }
    }

    private static bool ValidDescriptor(AgentToolDescriptor descriptor)
    {
        if (descriptor is null || !SafeId(descriptor.Id) || descriptor.Name != descriptor.Id ||
            string.IsNullOrWhiteSpace(descriptor.Description) || descriptor.Description.Length > 500 ||
            descriptor.RequiredPermissions.Count == 0 ||
            descriptor.RequiredPermissions.Any(permission => !Enum.IsDefined(permission)) ||
            descriptor.AllowedSkillIds.Count == 0 ||
            descriptor.AllowedSkillIds.Any(skill => !AgentDefinition.InteractiveInvestigator.AllowedSkillIds.Contains(skill)) ||
            !SchemaSupported(descriptor.InputSchema) || !SchemaSupported(descriptor.OutputSchema))
            return false;
        return descriptor.InputSchema.GetProperty("type").GetString() == "object" &&
            descriptor.OutputSchema.GetProperty("type").GetString() == "object";
    }

    private static bool SafeId(string id) => !string.IsNullOrWhiteSpace(id) && id.Length <= 64 &&
        id.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');

    private static bool SchemaSupported(JsonElement schema) =>
        ValidJson(schema, MaximumSchemaBytes) && ModelJsonSchemaValidator.IsSupportedSchema(schema) &&
        SchemaKeywordsMatchTypes(schema);

    private static bool SchemaKeywordsMatchTypes(JsonElement schema)
    {
        var type = schema.GetProperty("type").GetString();
        if (schema.TryGetProperty("properties", out var properties) && type != "object" ||
            schema.TryGetProperty("required", out _) && type != "object" ||
            schema.TryGetProperty("additionalProperties", out _) && type != "object" ||
            schema.TryGetProperty("items", out _) && type != "array" ||
            schema.TryGetProperty("minItems", out _) && type != "array" ||
            schema.TryGetProperty("maxItems", out _) && type != "array" ||
            schema.TryGetProperty("minLength", out _) && type != "string" ||
            schema.TryGetProperty("maxLength", out _) && type != "string" ||
            schema.TryGetProperty("minimum", out _) && type is not ("number" or "integer") ||
            schema.TryGetProperty("maximum", out _) && type is not ("number" or "integer"))
            return false;
        if (properties.ValueKind == JsonValueKind.Object &&
            properties.EnumerateObject().Any(property => !SchemaKeywordsMatchTypes(property.Value))) return false;
        return !schema.TryGetProperty("items", out var items) || SchemaKeywordsMatchTypes(items);
    }

    private static bool ValidJson(JsonElement value, int maximumBytes, int maximumNodes = 1_024)
    {
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return false;
        if (Encoding.UTF8.GetByteCount(value.GetRawText()) > maximumBytes) return false;
        var nodes = 0;
        return NoDuplicateProperties(value, 0, maximumNodes, ref nodes);
    }

    private static bool NoDuplicateProperties(JsonElement value, int depth, int maximumNodes, ref int nodes)
    {
        if (depth > 12 || ++nodes > maximumNodes) return false;
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
                if (!names.Add(property.Name) || !NoDuplicateProperties(property.Value, depth + 1, maximumNodes, ref nodes))
                    return false;
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray())
                if (!NoDuplicateProperties(item, depth + 1, maximumNodes, ref nodes)) return false;
        return true;
    }

    private static bool ValidEvidenceReference(AiEvidenceReference reference)
    {
        if (reference.Identity is null || string.IsNullOrWhiteSpace(reference.ReferenceId) ||
            reference.ReferenceId.Length > 160 || string.IsNullOrWhiteSpace(reference.Identity.EvidenceSessionId) ||
            string.IsNullOrWhiteSpace(reference.Identity.CaptureId) ||
            string.IsNullOrWhiteSpace(reference.Identity.SourceIdentityId) ||
            string.IsNullOrWhiteSpace(reference.Identity.HostId) ||
            string.IsNullOrWhiteSpace(reference.DataSource) || reference.DataSource.Length > 120 ||
            reference.DisplayName is null || reference.DisplayName.Length > 500 ||
            reference.CompactSnapshot is null || reference.CompactSnapshot.Length > 4096 ||
            !Enum.IsDefined(reference.Evidence.Kind) ||
            reference.TimestampUtc is { Kind: not DateTimeKind.Utc } ||
            reference.CompactSnapshot.Length > 0 && string.IsNullOrWhiteSpace(reference.SnapshotProvenance) ||
            !BoundedEvidenceStrings(reference))
            return false;
        if (reference.Evidence.Kind == ProcInsider.Models.EvidenceReferenceKind.ProcessEntity)
            return !string.IsNullOrWhiteSpace(reference.Evidence.Id) ||
                !string.IsNullOrWhiteSpace(reference.Process?.ProcessKey);
        return !string.IsNullOrWhiteSpace(reference.Evidence.Id) &&
            (!string.IsNullOrWhiteSpace(reference.SourceRunId) ||
             !string.IsNullOrWhiteSpace(reference.SourceRevision));
    }

    private static bool BoundedEvidenceStrings(AiEvidenceReference reference)
    {
        static bool Bounded(string? value) => value is not null && Encoding.UTF8.GetByteCount(value) <= 4_096;
        var identity = reference.Identity;
        var process = reference.Process;
        return Bounded(reference.ReferenceId) && Bounded(reference.Evidence.Id) &&
            Bounded(reference.DataSource) && Bounded(reference.SourceRunId) &&
            Bounded(reference.SourceRevision) && Bounded(reference.DisplayName) &&
            Bounded(reference.CompactSnapshot) && Bounded(reference.SnapshotProvenance) &&
            Bounded(identity.CaseId) && Bounded(identity.EvidenceSessionId) &&
            Bounded(identity.CaptureId) && Bounded(identity.SourceIdentityId) &&
            Bounded(identity.HostId) && Bounded(identity.ExecutionRootId) &&
            (process is null || Bounded(process.ProcessEntityId) && Bounded(process.ProcessKey) &&
                Bounded(process.CaseId) && Bounded(process.EvidenceSessionId) &&
                Bounded(process.CaptureId) && Bounded(process.SourceIdentityId) &&
                Bounded(process.HostId) && Bounded(process.ExecutionRootId));
    }

    private static bool EvidenceFits(JsonElement output, IReadOnlyList<AiEvidenceReference> evidence)
    {
        try
        {
            return Encoding.UTF8.GetByteCount(output.GetRawText()) +
                JsonSerializer.SerializeToUtf8Bytes(evidence).Length <= MaximumOutputBytes;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
