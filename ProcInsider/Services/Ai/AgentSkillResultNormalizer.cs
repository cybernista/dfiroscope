using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ProcInsider.Models.Ai;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Services.Ai;

internal static class AgentSkillResultNormalizer
{
    private const int MaximumOutputBytes = 32_000;
    private static readonly Regex Citation = new(@"\[\[ref:([^\]\r\n]*)\]\]",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    internal static AgentSkillResult NormalizeConversation(AgentSkillPlan plan, string content,
        IReadOnlyDictionary<string, AiEvidenceReference> admitted,
        IReadOnlyList<AgentSkillToolCoverage> coverage, string? validationFailure = null)
    {
        if (string.IsNullOrWhiteSpace(content) || Encoding.UTF8.GetByteCount(content) > MaximumOutputBytes)
            throw new ArgumentException("Conversational output is empty or exceeds 32,000 UTF-8 bytes.");
        var references = new List<AiEvidenceReference>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var unsupported = new List<string>();
        var markers = Citation.Matches(content);
        foreach (Match citation in markers)
        {
            var id = citation.Groups[1].Value;
            if (id.Length is < 1 or > 160 || !admitted.TryGetValue(id, out var reference) || !plan.Session.AdmitReference(reference))
            {
                unsupported.Add(id.Length == 0 ? "<empty reference ID>" : id[..Math.Min(id.Length, 160)]);
                continue;
            }
            if (seen.Add(reference.CanonicalObjectKey)) references.Add(reference);
            if (references.Count > 50) throw new ArgumentException("Conversation cites more than 50 checked references.");
        }
        if (content.Split("[[ref:", StringSplitOptions.None).Length - 1 != markers.Count)
            unsupported.Add("<malformed citation marker>");
        // Structured-record rejection never publishes records or references. Prose references
        // are checked independently, retaining supported links and rejecting unsupported ones.
        if (!string.IsNullOrEmpty(validationFailure)) references.Clear();
        var status = !string.IsNullOrEmpty(validationFailure)
            ? "**Validation: structured investigation records were rejected; no finding or citation was published.** " + validationFailure
            : unsupported.Count > 0
                ? $"**Validation: unsupported citation marker(s) rejected; {references.Count} reference(s) independently checked.** " +
                  string.Join(", ", unsupported.Distinct(StringComparer.Ordinal).Take(8))
                : references.Count == 0
                    ? "**Validation: no checked evidence citation was supplied. Capture-specific claims remain unverified.**"
                    : string.Empty;
        var summary = string.IsNullOrEmpty(status) ? content : status + "\n\n" + content;
        return new AgentSkillResult(summary, [], [], [], [],
            Array.AsReadOnly(references.ToArray()), [], Array.AsReadOnly(coverage.ToArray()),
            plan.NotCheckedSourcesFor(coverage), false)
        {
            ValidationDiagnostic = !string.IsNullOrEmpty(validationFailure) ? validationFailure :
                unsupported.Count == 0 ? string.Empty :
                "Unsupported evidence citation marker(s): " + string.Join(", ", unsupported.Distinct(StringComparer.Ordinal).Take(8)) +
                ". Cite only exact checked reference IDs; unsupported markers were not accepted."
        };
    }

    internal static AgentSkillResult Normalize(AgentSkillPlan plan, JsonElement output,
        IReadOnlyDictionary<string, AiEvidenceReference> admitted,
        IReadOnlyList<AgentSkillToolCoverage> coverage)
    {
        if (output.ValueKind != JsonValueKind.Object ||
            Encoding.UTF8.GetByteCount(output.GetRawText()) > MaximumOutputBytes ||
            !UniqueJsonProperties(output, 0, new Counter()) ||
            !ModelJsonSchemaValidator.IsValid(output, plan.OutputStructure.Schema))
            throw new ArgumentException("Skill output is malformed or outside its bounded schema.");
        var summary = RequiredText(output.GetProperty("summary"));
        var used = new Dictionary<string, AiEvidenceReference>(StringComparer.Ordinal);
        IReadOnlyList<AiEvidenceReference> References(JsonElement values)
        {
            var result = new List<AiEvidenceReference>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var seenObjects = new HashSet<string>(StringComparer.Ordinal);
            foreach (var value in values.EnumerateArray())
            {
                var id = RequiredText(value);
                if (!admitted.TryGetValue(id, out var reference) ||
                    !plan.Session.AdmitReference(reference))
                    throw new ArgumentException("Skill output cites a duplicate or unavailable evidence reference.");
                if (!seen.Add(id)) continue;
                if (!seenObjects.Add(reference.CanonicalObjectKey))
                    throw new ArgumentException("Skill output cites a duplicate or unavailable evidence reference.");
                result.Add(reference);
                used.TryAdd(id, reference);
                if (used.Count > 50)
                    throw new ArgumentException("Skill output cites more than 50 distinct references.");
            }
            return Array.AsReadOnly(result.ToArray());
        }

        var observations = new List<AgentSkillObservation>();
        foreach (var item in output.GetProperty("observations").EnumerateArray())
        {
            var kind = Enum.Parse<AgentSkillAssertionKind>(item.GetProperty("kind").GetString()!, false);
            var text = RequiredText(item.GetProperty("text"));
            var references = References(item.GetProperty("evidence_reference_ids"));
            if (references.Count == 0)
                throw new ArgumentException("An observation or inference requires supplied evidence context.");
            observations.Add(new(kind, text, references));
        }

        var findings = new List<AgentSkillFinding>();
        foreach (var item in OptionalArray(output, "findings"))
        {
            var supporting = References(item.GetProperty("supporting_reference_ids"));
            var contradicting = References(item.GetProperty("contradicting_reference_ids"));
            Disjoint(supporting, contradicting);
            var assessment = Enum.Parse<FindingVerificationState>(item.GetProperty("assessment").GetString()!, false);
            var uncertainty = item.GetProperty("uncertainty").GetString()!;
            if (assessment == FindingVerificationState.AnalystVerified ||
                supporting.Count + contradicting.Count == 0 ||
                (assessment is FindingVerificationState.Supported or FindingVerificationState.WeaklySupported) &&
                    supporting.Count == 0 ||
                assessment == FindingVerificationState.Contradicted && contradicting.Count == 0 ||
                assessment == FindingVerificationState.NeedsMoreEvidence && string.IsNullOrWhiteSpace(uncertainty))
                throw new ArgumentException("A finding lacks evidence or has an unsupported assessment.");
            findings.Add(new(RequiredText(item.GetProperty("title")),
                RequiredText(item.GetProperty("claim")), RequiredText(item.GetProperty("description")),
                Enum.Parse<AnalysisFindingSeverity>(item.GetProperty("severity").GetString()!, false),
                Confidence(item), assessment, uncertainty, supporting, contradicting));
        }

        var hypotheses = new List<AgentSkillHypothesis>();
        foreach (var item in OptionalArray(output, "hypotheses"))
        {
            var supporting = References(item.GetProperty("supporting_reference_ids"));
            var contradicting = References(item.GetProperty("contradicting_reference_ids"));
            Disjoint(supporting, contradicting);
            var uncertainty = item.GetProperty("uncertainty").GetString()!;
            if (supporting.Count + contradicting.Count == 0 && string.IsNullOrWhiteSpace(uncertainty))
                throw new ArgumentException("An unsupported hypothesis must state uncertainty.");
            hypotheses.Add(new(RequiredText(item.GetProperty("statement")), Confidence(item),
                uncertainty, supporting, contradicting));
        }

        var tasks = OptionalArray(output, "tasks")
            .Select(item => new AgentSkillTask(RequiredText(item.GetProperty("objective")))).ToArray();
        References(output.GetProperty("evidence_reference_ids"));
        var questions = output.GetProperty("open_questions").EnumerateArray()
            .Select(RequiredText).ToArray();
        if (plan.SkillId != AgentDefinition.InvestigateProcessSkillId &&
            (findings.Count > 0 || hypotheses.Count > 0 || tasks.Length > 0))
            throw new ArgumentException("Only InvestigateProcess may propose formal investigation records.");
        var result = new AgentSkillResult(summary,
            Array.AsReadOnly(observations.ToArray()), Array.AsReadOnly(findings.ToArray()),
            Array.AsReadOnly(hypotheses.ToArray()), Array.AsReadOnly(tasks),
            Array.AsReadOnly(used.Values.ToArray()), Array.AsReadOnly(questions),
            Array.AsReadOnly(coverage.ToArray()), plan.NotCheckedSourcesFor(coverage),
            false);
        if (JsonSerializer.SerializeToUtf8Bytes(result).Length > 128_000)
            throw new ArgumentException("Skill result exceeds the bounded evidence sidecar limit.");
        return result;
    }

    private static string RequiredText(JsonElement value)
    {
        var text = value.GetString();
        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException("Skill output contains an empty required statement.");
        return text;
    }

    private static IEnumerable<JsonElement> OptionalArray(JsonElement output, string name)
    {
        if (!output.TryGetProperty(name, out var array)) yield break;
        foreach (var item in array.EnumerateArray()) yield return item;
    }

    private static double? Confidence(JsonElement item) =>
        item.TryGetProperty("confidence", out var value) ? value.GetDouble() : null;

    private static void Disjoint(IReadOnlyList<AiEvidenceReference> first,
        IReadOnlyList<AiEvidenceReference> second)
    {
        var firstObjects = first.Select(reference => reference.CanonicalObjectKey).ToHashSet(StringComparer.Ordinal);
        if (second.Any(reference => firstObjects.Contains(reference.CanonicalObjectKey)))
            throw new ArgumentException("One claim cannot cite the same reference as both support and contradiction.");
    }

    private sealed class Counter { public int Value; }

    private static bool UniqueJsonProperties(JsonElement value, int depth, Counter counter)
    {
        if (depth > 12 || ++counter.Value > 4_096) return false;
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
                if (!names.Add(property.Name) || !UniqueJsonProperties(property.Value, depth + 1, counter))
                    return false;
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var child in value.EnumerateArray())
                if (!UniqueJsonProperties(child, depth + 1, counter)) return false;
        return true;
    }
}
