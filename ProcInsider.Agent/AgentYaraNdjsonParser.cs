using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcInsider.Models.Analysis;

namespace ProcInsider.Agent;

internal sealed record YaraNdjsonParseResult
{
    public bool Accepted { get; init; }

    public string Diagnostic { get; init; } = string.Empty;

    public YaraScanResult? Result { get; init; }
}

internal static class AgentYaraNdjsonParser
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static YaraNdjsonParseResult Parse(
        byte[] output,
        string expectedTargetPath,
        YaraAgentExecutionRequest request,
        DateTime completedUtc)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(request);

        string text;
        try
        {
            text = StrictUtf8.GetString(output);
        }
        catch (DecoderFallbackException)
        {
            return Reject("The YARA scanner output was not valid UTF-8.");
        }

        var lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != 1 || lines[0].Length == 0)
        {
            return Reject("The YARA scanner did not return exactly one NDJSON file result.");
        }

        try
        {
            using var document = JsonDocument.Parse(lines[0], new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16
            });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !TryReadExactObject(root, ["path", "rules"], out var rootProperties))
            {
                return Reject("The YARA NDJSON file result has an unsupported shape.");
            }

            var path = rootProperties["path"];
            var rules = rootProperties["rules"];
            if (path.ValueKind != JsonValueKind.String || rules.ValueKind != JsonValueKind.Array ||
                !PathsEqual(path.GetString(), expectedTargetPath))
            {
                return Reject("The YARA NDJSON file identity did not match the staged target.");
            }

            var parsedMatches = new List<YaraRuleMatch>();
            var matchIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var rule in rules.EnumerateArray())
            {
                if (rule.ValueKind != JsonValueKind.Object ||
                    !TryReadExactObject(rule, ["identifier", "namespace", "meta", "tags"], out var fields))
                {
                    return Reject("A YARA rule result has an unsupported or path-bearing shape.");
                }

                if (fields["identifier"].ValueKind != JsonValueKind.String ||
                    fields["namespace"].ValueKind != JsonValueKind.String ||
                    fields["meta"].ValueKind != JsonValueKind.Array ||
                    fields["tags"].ValueKind != JsonValueKind.Array)
                {
                    return Reject("A YARA rule result has invalid identifier, namespace, metadata, or tags.");
                }

                var ruleId = fields["identifier"].GetString() ?? string.Empty;
                var ruleNamespace = fields["namespace"].GetString() ?? string.Empty;
                var matchId = CreateMatchId(ruleNamespace, ruleId);
                if (!matchIds.Add(matchId))
                {
                    return Reject("The YARA NDJSON result contains a duplicate rule match.");
                }

                var tags = new List<string>();
                var tagIds = new HashSet<string>(StringComparer.Ordinal);
                foreach (var tag in fields["tags"].EnumerateArray())
                {
                    if (tag.ValueKind != JsonValueKind.String ||
                        !tagIds.Add(tag.GetString() ?? string.Empty))
                    {
                        return Reject("The YARA NDJSON result contains an invalid or duplicate tag.");
                    }

                    tags.Add(tag.GetString() ?? string.Empty);
                }

                if (tags.Count > request.Limits.MaximumTagsPerMatch)
                {
                    return Reject("The YARA NDJSON result exceeds the authorized tag limit.");
                }

                var metadata = new List<YaraMatchMetadata>();
                var metadataKeys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var item in fields["meta"].EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Array)
                    {
                        return Reject("The YARA NDJSON result contains invalid or duplicate metadata.");
                    }

                    var tuple = item.EnumerateArray().ToArray();
                    if (tuple.Length != 2 || tuple[0].ValueKind != JsonValueKind.String)
                    {
                        return Reject("The YARA NDJSON result contains invalid or duplicate metadata.");
                    }

                    var key = tuple[0].GetString() ?? string.Empty;
                    if (!metadataKeys.Add(key) ||
                        !TryFormatMetadata(tuple[1], out var value))
                    {
                        return Reject("The YARA NDJSON result contains invalid or duplicate metadata.");
                    }

                    metadata.Add(new YaraMatchMetadata(key, value));
                }

                if (metadata.Count > request.Limits.MaximumMetadataPerMatch)
                {
                    return Reject("The YARA NDJSON result exceeds the authorized metadata limit.");
                }

                parsedMatches.Add(new YaraRuleMatch
                {
                    MatchId = matchId,
                    RuleNamespace = ruleNamespace,
                    RuleId = ruleId,
                    Tags = tags,
                    Metadata = metadata,
                    StringMatches = Array.Empty<YaraStringMatch>()
                });
            }

            var canonical = parsedMatches
                .OrderBy(match => match.RuleNamespace, StringComparer.Ordinal)
                .ThenBy(match => match.RuleId, StringComparer.Ordinal)
                .ThenBy(match => match.MatchId, StringComparer.Ordinal)
                .ToArray();
            var truncated = canonical.Length > request.Limits.MaximumMatches;
            var candidate = new YaraScanResult
            {
                ScanId = request.ScanId,
                Availability = AnalysisSourceAvailability.Available,
                Target = request.Target,
                Ruleset = request.RulesetIdentity,
                RequestedUtc = request.RequestedUtc,
                CompletedUtc = completedUtc,
                IsTruncated = truncated,
                Diagnostic = truncated
                    ? "The YARA result was truncated at the authorized match limit."
                    : string.Empty,
                Matches = canonical.Take(request.Limits.MaximumMatches).ToArray()
            };
            var validation = YaraAnalysisContractPolicy.Validate(candidate);
            return validation.Accepted && validation.Result != null
                ? new YaraNdjsonParseResult { Accepted = true, Result = validation.Result }
                : Reject("The YARA scanner output violated the normalized result contract.");
        }
        catch (JsonException)
        {
            return Reject("The YARA scanner output was malformed JSON.");
        }
    }

    private static bool TryReadExactObject(
        JsonElement element,
        IReadOnlyCollection<string> expectedNames,
        out Dictionary<string, JsonElement> properties)
    {
        properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!expectedNames.Contains(property.Name, StringComparer.Ordinal) ||
                !properties.TryAdd(property.Name, property.Value))
            {
                return false;
            }
        }

        return properties.Count == expectedNames.Count &&
               expectedNames.All(properties.ContainsKey);
    }

    private static bool TryFormatMetadata(JsonElement value, out string formatted)
    {
        formatted = string.Empty;
        if (value.ValueKind == JsonValueKind.String)
        {
            formatted = value.GetString() ?? string.Empty;
            return true;
        }

        if (value.ValueKind is JsonValueKind.Number or JsonValueKind.True or
            JsonValueKind.False or JsonValueKind.Null)
        {
            formatted = value.GetRawText();
            return true;
        }

        if (value.ValueKind != JsonValueKind.Array ||
            value.EnumerateArray().Any(item => item.ValueKind is JsonValueKind.Array or JsonValueKind.Object))
        {
            return false;
        }

        formatted = value.GetRawText();
        return true;
    }

    private static string CreateMatchId(string ruleNamespace, string ruleId)
    {
        var bytes = Encoding.UTF8.GetBytes(
            $"{ruleNamespace.Length}:{ruleNamespace}{ruleId.Length}:{ruleId}");
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static bool PathsEqual(string? actual, string expected)
    {
        if (string.IsNullOrWhiteSpace(actual) || string.IsNullOrWhiteSpace(expected))
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(actual),
                Path.GetFullPath(expected),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static YaraNdjsonParseResult Reject(string diagnostic) => new()
    {
        Accepted = false,
        Diagnostic = diagnostic
    };
}
