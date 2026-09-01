using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ProcInsider.Models;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class OpenAiCompatibleAiProvider : IAiProvider
{
    public async Task<AiProviderResponse> CompleteAsync(
        AiProviderSettings settings,
        string apiKey,
        string systemPrompt,
        string userPrompt,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(settings.BaseUrl))
        {
            return Fail(settings, "Base URL is required for the selected AI provider.");
        }

        if (string.IsNullOrWhiteSpace(settings.ModelName))
        {
            return Fail(settings, "Model name is required for the selected AI provider.");
        }

        if (settings.RequiresApiKey && string.IsNullOrWhiteSpace(apiKey))
        {
            return Fail(settings, "API key/token is required for cloud or commercial AI providers.");
        }

        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(Math.Clamp(settings.TimeoutSeconds, 5, 900))
        };

        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        }

        var payload = new
        {
            model = settings.ModelName,
            messages = new object[]
            {
                new { role = "system", content = systemPrompt },
                new { role = "user", content = userPrompt }
            },
            temperature = 0.2,
            max_tokens = EstimateMaxTokens(settings.MaxResponseCharacters)
        };

        try
        {
            var uri = ResolveChatCompletionsUri(settings.BaseUrl);
            using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            using var response = await client.PostAsync(uri, content, cancellationToken);
            var responseText = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return Fail(settings, $"Provider returned {(int)response.StatusCode} {response.ReasonPhrase}: {Trim(responseText, 1200)}");
            }

            return ParseResponse(settings, responseText);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Fail(settings, $"Provider request timed out after {settings.TimeoutSeconds} seconds.");
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidOperationException or UriFormatException)
        {
            return Fail(settings, $"Provider request failed: {ex.Message}");
        }
    }

    private static AiProviderResponse ParseResponse(AiProviderSettings settings, string responseText)
    {
        using var document = JsonDocument.Parse(responseText);
        var root = document.RootElement;
        var content = string.Empty;

        if (root.TryGetProperty("choices", out var choices) &&
            choices.ValueKind == JsonValueKind.Array &&
            choices.GetArrayLength() > 0)
        {
            var first = choices[0];
            if (first.TryGetProperty("message", out var message) &&
                message.TryGetProperty("content", out var messageContent))
            {
                content = messageContent.GetString() ?? string.Empty;
            }
            else if (first.TryGetProperty("text", out var text))
            {
                content = text.GetString() ?? string.Empty;
            }
        }

        if (string.IsNullOrWhiteSpace(content))
        {
            return Fail(settings, "Provider response did not include a chat completion message.");
        }

        int? promptTokens = null;
        int? completionTokens = null;
        int? totalTokens = null;
        if (root.TryGetProperty("usage", out var usage))
        {
            promptTokens = ReadInt(usage, "prompt_tokens");
            completionTokens = ReadInt(usage, "completion_tokens");
            totalTokens = ReadInt(usage, "total_tokens");
        }

        return new AiProviderResponse
        {
            Success = true,
            Content = Trim(content, settings.MaxResponseCharacters),
            ProviderName = settings.ProviderDisplayName,
            ModelName = settings.ModelName,
            PromptTokens = promptTokens,
            CompletionTokens = completionTokens,
            TotalTokens = totalTokens
        };
    }

    private static AiProviderResponse Fail(AiProviderSettings settings, string message)
    {
        return new AiProviderResponse
        {
            Success = false,
            ProviderName = settings.ProviderDisplayName,
            ModelName = settings.ModelName,
            ErrorMessage = message
        };
    }

    private static Uri ResolveChatCompletionsUri(string baseUrl)
    {
        var trimmed = baseUrl.Trim().TrimEnd('/');
        if (trimmed.EndsWith("/chat/completions", StringComparison.OrdinalIgnoreCase))
        {
            return new Uri(trimmed);
        }

        if (trimmed.EndsWith("/v1", StringComparison.OrdinalIgnoreCase))
        {
            return new Uri($"{trimmed}/chat/completions");
        }

        return new Uri($"{trimmed}/v1/chat/completions");
    }

    private static int EstimateMaxTokens(int maxResponseCharacters)
    {
        return Math.Clamp(maxResponseCharacters / 4, 128, 16000);
    }

    private static int? ReadInt(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value) && value.TryGetInt32(out var parsed)
            ? parsed
            : null;
    }

    private static string Trim(string value, int maxCharacters)
    {
        if (maxCharacters <= 0 || value.Length <= maxCharacters)
        {
            return value;
        }

        return value[..maxCharacters] + $"\n\n[Response truncated by {ProductIdentity.DisplayName} max response size setting.]";
    }
}
