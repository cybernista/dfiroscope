using System.Text.Json;

namespace ProcInsider.Models.Ai;

public sealed record ModelCapabilities(
    string ProviderId,
    string ModelId,
    int? ContextTokenLimit,
    int? OutputTokenLimit,
    bool? SupportsTools,
    bool? SupportsStructuredOutput,
    bool? SupportsStreaming,
    bool? SupportsVision);

public enum ModelMessageRole { System, User, Assistant, Tool }

public sealed record ModelMessage(
    ModelMessageRole Role,
    string Content,
    string? ToolCallId = null,
    IReadOnlyList<ModelToolRequest>? ToolRequests = null)
{
    // Transient, provider-owned Responses output for stateless reasoning/tool continuation.
    [System.Text.Json.Serialization.JsonIgnore]
    public JsonElement? ProviderOutputItems { get; init; }
}

public sealed record ModelToolDefinition(string Name, string Description, JsonElement ParametersSchema);

public sealed record ModelOutputStructure(string Name, JsonElement Schema);

public sealed record ModelProviderOptions(double? Temperature = null);

public sealed record ModelRequest(
    string SystemInstructions,
    IReadOnlyList<ModelMessage> Messages,
    JsonElement? StructuredContext = null,
    IReadOnlyList<ModelToolDefinition>? Tools = null,
    ModelOutputStructure? OutputStructure = null,
    int? MaxOutputTokens = null,
    int? MaxContextTokens = null,
    ModelProviderOptions? Options = null,
    [property: System.Text.Json.Serialization.JsonIgnore] Func<ModelSubmittedRequest, CancellationToken, Task>? BeforeSubmit = null);

// The validated body at the POST boundary; excludes transport headers and credentials.
public sealed record ModelSubmittedRequest(string ProviderId, string ModelId, DateTime SubmittedUtc, string RequestBody);

public sealed record ModelToolRequest(string CallId, string Name, JsonElement Arguments);

public sealed record ModelTokenUsage(int? InputTokens, int? OutputTokens, int? TotalTokens);

public enum ModelErrorCategory
{
    Configuration, Authentication, Authorization, ModelUnavailable, RateLimited,
    Timeout, Network, ProviderUnavailable, InvalidResponse, InvalidRequest
}

public sealed record ModelError(ModelErrorCategory Category, string Message)
{
    // Adapter-owned classification; endpoint prose cannot grant a correction attempt.
    public bool IsRecoverableFormatError { get; init; }
    // Diagnostics are untrusted display data, never model instructions or evidence.
    public string SafeDiagnostic => ModelDiagnosticRedactor.Sanitize(Message);
}

public static class ModelDiagnosticRedactor
{
    public const int MaximumDiagnosticCharacters = 2_100_000;
    private static readonly System.Text.RegularExpressions.Regex CredentialField = new(
        """(?im)(["']?\b(?:authorization|proxy-authorization|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n,;}]+)""",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.NonBacktracking);

    public static string Sanitize(string? diagnostic, params string?[] secrets)
    {
        var result = diagnostic ?? string.Empty;
        foreach (var secret in secrets)
        {
            if (string.IsNullOrEmpty(secret)) continue;
            result = result.Replace(secret, "[REDACTED]", StringComparison.Ordinal);
            var jsonEscaped = JsonSerializer.Serialize(secret)[1..^1];
            if (jsonEscaped != secret) result = result.Replace(jsonEscaped, "[REDACTED]", StringComparison.Ordinal);
        }
        result = CredentialField.Replace(result, match => match.Groups[1].Value + "[REDACTED]");
        if (result.Length <= MaximumDiagnosticCharacters) return result;
        var notice = $"\n[Diagnostic exceeded the {MaximumDiagnosticCharacters}-character storage limit after credential redaction: {result.Length} characters. Remaining text omitted.]";
        return result[..(MaximumDiagnosticCharacters - notice.Length)] + notice;
    }
}

public sealed record ModelResponse(
    string ProviderId,
    string ModelId,
    string Content,
    IReadOnlyList<ModelToolRequest> ToolRequests,
    JsonElement? StructuredResult,
    ModelTokenUsage? Usage,
    ModelError? Error)
{
    public bool Success => Error is null;
    // Never persisted as an analyst answer; Runtime may replay it within this execution.
    [System.Text.Json.Serialization.JsonIgnore]
    public JsonElement? ProviderOutputItems { get; init; }
}
