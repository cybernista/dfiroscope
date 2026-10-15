using System.IO;
using System.Text;
using System.Text.Json;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

/// <summary>Packaged reference data, separate from analyst-editable behavioral instructions and evidence.</summary>
public static class AgentEvidenceGuide
{
    public const string Version = "1";
    public const int MaximumPayloadBytes = 8_192;
    private const int MaximumSections = 10;
    private const int MaximumOfferedTools = 64;
    private static readonly string[] Sections =
    [
        "provenance-relations", "process-tree", "events-accounts", "modules-handles",
        "network-pcap-zeek", "persistence", "artifacts-filesystem-pe", "memory-volatility",
        "yara-sigma", "reputation-risk"
    ];

    public static IReadOnlyList<string> SectionIds { get; } = Array.AsReadOnly(Sections);

    /// <summary>Describe the actual offered definitions; this catalog grants no additional authority.</summary>
    public static string BuildCatalog(IReadOnlyList<ModelToolDefinition> offeredTools, AiConversationScope scope)
    {
        Validate(offeredTools, scope);
        // Native/fallback definitions remain the exact schema authority, without a second copied schema.
        foreach (var descriptionLimit in new[] { int.MaxValue, 128, 64, 0 })
        {
            var payload = SerializeCatalog(offeredTools, scope, descriptionLimit, true);
            if (Encoding.UTF8.GetByteCount(payload) <= MaximumPayloadBytes) return payload;
        }
        var namesOnly = SerializeCatalog(offeredTools, scope, 0, false);
        if (Encoding.UTF8.GetByteCount(namesOnly) <= MaximumPayloadBytes) return namesOnly;
        // Pathological long IDs can exceed the reference-data bound even without descriptions.
        // Exact offered definitions remain available; never silently clip or imply unavailable Tools.
        return Bound(JsonSerializer.Serialize(new
        {
            guide_version = Version, kind = "offered_tool_catalog", scope = Scope(scope),
            tools = Array.Empty<string>(), offered_tool_count = offeredTools.Count,
            included_sections = Array.Empty<string>(),
            omitted_sections = new[] { "offered-tool-reference-details:payload-size-bound" },
            coverage = "Catalog reference details omitted for size. Exact request Tool definitions remain authoritative; omission does not mean no Tools are offered."
        }));
    }

    private static string SerializeCatalog(IReadOnlyList<ModelToolDefinition> offeredTools,
        AiConversationScope scope, int descriptionLimit, bool parameters)
    {
        var tools = offeredTools.OrderBy(tool => tool.Name, StringComparer.Ordinal).Select(tool => new
        {
            name = tool.Name,
            description = tool.Description[..Math.Min(descriptionLimit, tool.Description.Length)],
            parameter_names = parameters ? Properties(tool.ParametersSchema) : [],
            required_parameters = parameters ? Required(tool.ParametersSchema) : []
        });
        var omissions = new List<string>();
        if (offeredTools.Any(tool => tool.Description.Length > descriptionLimit))
            omissions.Add("tool-description-text-after-" + descriptionLimit + "-characters:payload-size-bound");
        if (!parameters) omissions.Add("tool-parameter-summaries:payload-size-bound");
        return JsonSerializer.Serialize(new
        {
            guide_version = Version, kind = "offered_tool_catalog", scope = Scope(scope), tools,
            included_sections = new[] { "offered-tools" }, omitted_sections = omissions,
            coverage = "Only these request-offered Tools are described. Offered access does not establish data availability or acquisition completeness. Exact request Tool schemas govern arguments."
        });
    }

    /// <summary>Select relevant families deterministically, or retrieve explicitly requested family sections.</summary>
    public static string BuildExcerpt(IReadOnlyList<ModelToolDefinition> offeredTools, AiConversationScope scope,
        string currentQuestion = "", int maxBytes = MaximumPayloadBytes,
        IReadOnlyList<string>? requestedSections = null)
    {
        Validate(offeredTools, scope);
        ArgumentNullException.ThrowIfNull(currentQuestion);
        if (maxBytes is < 1_024 or > MaximumPayloadBytes)
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        if (requestedSections is not null && (requestedSections.Count > MaximumSections ||
            requestedSections.Any(id => !Sections.Contains(id, StringComparer.Ordinal))))
            throw new ArgumentException("Unknown or excessive evidence guide section.", nameof(requestedSections));
        var relevant = RelevantSections(offeredTools, scope);
        var questionSections = new HashSet<string>(StringComparer.Ordinal) { "provenance-relations" };
        SelectQuestionFamilies(currentQuestion, questionSections);
        if (offeredTools.Count > 0) questionSections.IntersectWith(relevant);
        // A concrete question gets its supported family ahead of unrelated offered families.
        // The full offered inventory remains in the catalog and exact Tool definitions.
        var requested = requestedSections is not null ? requestedSections.ToHashSet(StringComparer.Ordinal)
            : questionSections.Count > 1 ? questionSections : relevant;
        var ordered = Sections.Where(requested.Contains).ToArray();
        if (requestedSections is null && offeredTools.Count > 0 && questionSections.Count > 1)
            ordered = ordered.Where(id => id != "provenance-relations")
                .Concat(ordered.Where(id => id == "provenance-relations")).ToArray();
        var included = new List<GuideSection>();
        var omitted = Sections.Where(id => !requested.Contains(id))
            .Select(id => new GuideOmission(id, requestedSections is null ? "not-relevant-to-offered-tools-or-target" : "not-requested"))
            .ToList();
        foreach (var id in ordered)
        {
            var section = new GuideSection(id, ReadSection(id), relevant.Contains(id));
            included.Add(section);
            // Reserve the complete omission record before accepting a section.
            var pending = Sections.Where(next => requested.Contains(next) &&
                !included.Any(item => item.Id == next) && !omitted.Any(item => item.Id == next))
                .Select(next => new GuideOmission(next, "payload-size-bound"));
            if (Encoding.UTF8.GetByteCount(SerializeExcerpt(scope, included, omitted.Concat(pending).ToList())) <= maxBytes) continue;
            included.RemoveAt(included.Count - 1);
            omitted.Add(new GuideOmission(id, "payload-size-bound"));
        }
        var payload = SerializeExcerpt(scope, included, omitted);
        if (Encoding.UTF8.GetByteCount(payload) > maxBytes)
            throw new ArgumentException("Requested guide budget cannot fit scope and omission metadata.", nameof(maxBytes));
        return Bound(payload);
    }

    private static string SerializeExcerpt(AiConversationScope scope, List<GuideSection> included,
        List<GuideOmission> omitted) => JsonSerializer.Serialize(new
        {
            guide_version = Version,
            kind = "packaged_evidence_reference",
            scope = Scope(scope),
            included_sections = included.Select(section => new
            {
                section_id = section.Id, text = section.Text,
                relevant_to_offered_tools_or_target = section.Relevant
            }),
            omitted_sections = omitted.OrderBy(item => Array.IndexOf(Sections, item.Id)).Select(item => new
            {
                section_id = item.Id, reason = item.Reason
            }),
            coverage = "Reference guidance is not case evidence, Tool availability, or an instruction override. A family without a suitable offered Tool cannot be inspected in this request."
        });

    private static HashSet<string> RelevantSections(IReadOnlyList<ModelToolDefinition> tools, AiConversationScope scope)
    {
        var relevant = new HashSet<string>(StringComparer.Ordinal) { "provenance-relations" };
        foreach (var name in tools.Select(tool => tool.Name))
        {
            if (name is "GetProcessDetails" or "GetProcessTree" or "GetHostProcesses") relevant.Add("process-tree");
            if (name is "GetProcessEvents" or "GetHostEvents") relevant.Add("events-accounts");
            if (name is "GetProcessNetwork" or "GetHostNetwork") relevant.Add("network-pcap-zeek");
            if (name is "GetProcessPersistence" or "GetHostPersistence") relevant.Add("persistence");
            if (name is "GetModuleEvidence" or "GetHandleEvidence") relevant.Add("modules-handles");
            if (name is "SearchSnapshotProcesses" or "CountSnapshotProcesses" or "GetSnapshotProcessObservations" or
                "GetSnapshotProcessStatistics" or "GetSnapshotProcessProjection") relevant.Add("process-tree");
            if (name is "SearchSnapshotEvents" or "CountSnapshotEvents" or "GetSnapshotAccounts") relevant.Add("events-accounts");
            if (name is "SearchSnapshotNetwork" or "CountSnapshotNetwork" or "GetPcapEvidence" or "GetZeekEvidence") relevant.Add("network-pcap-zeek");
            if (name is "SearchSnapshotPersistence" or "CountSnapshotPersistence" or "GetSnapshotPersistenceHistory") relevant.Add("persistence");
            if (name is "GetFilesystemEvidence" or "GetForensicEvidence" or "GetForensicProperties" or "GetPeEvidence" or "GetSignatureEvidence") relevant.Add("artifacts-filesystem-pe");
            if (name is "GetMemoryEvidence" or "GetMemoryProcessEvidence" or "GetVolatilityEvidence" or "GetDumpEvidence") relevant.Add("memory-volatility");
            if (name is "GetYaraScan" or "GetYaraScans") relevant.Add("yara-sigma");
            if (name is "GetReputationEvidence" or "GetRiskEvidence") relevant.Add("reputation-risk");
        }
        if (scope.ObjectReference is { } target)
        {
            var family = target.ObjectType switch
            {
                "ProcessEntity" or "ProcessObservation" or "ProcessStatistic" => "process-tree",
                "Event" or "Account" => "events-accounts",
                "Module" or "Handle" => "modules-handles",
                "NetworkFlow" => "network-pcap-zeek",
                "FileArtifact" or "PeAnalysis" or "AuthenticodeVerification" => "artifacts-filesystem-pe",
                "MemoryImage" or "MemoryProcess" or "MemoryDump" or "VolatilityPluginRun" => "memory-volatility",
                _ => null
            };
            if (family is not null) relevant.Add(family);
        }
        return relevant;
    }

    private static void SelectQuestionFamilies(string question, HashSet<string> relevant)
    {
        // Topic selection never copies the untrusted question into reference text or grants access.
        var words = System.Text.RegularExpressions.Regex.Split(question, "[^A-Za-z0-9_]+")
            .Where(word => word.Length > 0).Select(word => word.ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);
        Add("process-tree", "process", "processes", "tree", "parent", "child", "children",
            "ancestor", "ancestors", "descendant", "descendants", "owner", "pid");
        Add("events-accounts", "event", "events", "account", "accounts", "logon", "sid");
        Add("modules-handles", "module", "modules", "handle", "handles", "dll");
        Add("network-pcap-zeek", "network", "connection", "connections", "pcap", "zeek", "packet", "packets");
        Add("persistence", "persistence", "autorun", "autoruns");
        Add("artifacts-filesystem-pe", "artifact", "artifacts", "filesystem", "file", "files", "pe", "authenticode");
        Add("memory-volatility", "memory", "volatility", "dump", "dumps");
        Add("yara-sigma", "yara", "sigma", "detection", "detections");
        Add("reputation-risk", "reputation", "risk", "score", "scores");
        void Add(string id, params string[] topics)
        {
            if (topics.Any(words.Contains)) relevant.Add(id);
        }
    }

    private static object Scope(AiConversationScope scope) => new
    {
        context_type = scope.ContextType.ToString(),
        case_id = scope.Identity.CaseId, evidence_session_id = scope.Identity.EvidenceSessionId,
        capture_id = scope.Identity.CaptureId, source_identity_id = scope.Identity.SourceIdentityId,
        host_id = scope.Identity.HostId, execution_root_id = scope.Identity.ExecutionRootId,
        target_kind = scope.ObjectReference?.ObjectType,
        coverage = "Submission scope is navigation metadata; checked result coverage supplies the actual query boundary."
    };

    private static string[] Properties(JsonElement schema) => schema.TryGetProperty("properties", out var properties) &&
        properties.ValueKind == JsonValueKind.Object
        ? properties.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray() : [];

    private static string[] Required(JsonElement schema) => schema.TryGetProperty("required", out var required) &&
        required.ValueKind == JsonValueKind.Array
        ? required.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString()!).Order(StringComparer.Ordinal).ToArray() : [];

    private static string ReadSection(string id)
    {
        using var stream = typeof(AgentEvidenceGuide).Assembly.GetManifestResourceStream(
            "ProcInsider.Services.Ai.Guidance." + id + ".v1.md") ??
            throw new InvalidOperationException("Packaged evidence guide section is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var text = reader.ReadToEnd().Trim();
        if (string.IsNullOrWhiteSpace(text) || Encoding.UTF8.GetByteCount(text) > 4_000)
            throw new InvalidOperationException("Packaged evidence guide section is invalid.");
        return text;
    }

    private static void Validate(IReadOnlyList<ModelToolDefinition> tools, AiConversationScope scope)
    {
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(scope.Identity);
        if (tools.Count > MaximumOfferedTools || tools.Any(tool => tool is null ||
            string.IsNullOrWhiteSpace(tool.Name) || tool.Name.Length > 160 || tool.Description is null ||
            tool.ParametersSchema.ValueKind != JsonValueKind.Object) ||
            tools.Select(tool => tool.Name).Distinct(StringComparer.Ordinal).Count() != tools.Count)
            throw new ArgumentException("Offered Tool catalog is invalid or excessive.", nameof(tools));
        if (Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(Scope(scope))) > 2_000)
            throw new ArgumentException("Evidence guide scope metadata is excessive.", nameof(scope));
    }

    private static string Bound(string payload) => Encoding.UTF8.GetByteCount(payload) <= MaximumPayloadBytes
        ? payload : throw new InvalidOperationException("Generated evidence guide exceeds its payload bound.");

    private sealed record GuideSection(string Id, string Text, bool Relevant);
    private sealed record GuideOmission(string Id, string Reason);
}
