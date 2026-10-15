using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed record AiModelCatalogResult(
    IReadOnlyList<string> ModelIds, bool IsComplete, string StatusMessage, ModelErrorCategory? ErrorCategory);

// Enumeration never sends prompts/evidence or invokes a model. Callers own feature activation,
// credential scope and cancellation when the editor destination or keystore state changes.
public sealed class AiModelCatalogService
{
    public const int MaximumResponseBytes = 2_000_000;
    public const int MaximumTotalBytes = 8_000_000;
    public const int MaximumPages = 20;
    public const int MaximumModels = 2000;
    private static readonly HttpClient SharedClient = new(new HttpClientHandler
        { AllowAutoRedirect = false, UseCookies = false }) { Timeout = Timeout.InfiniteTimeSpan };
    private readonly HttpClient _client;

    public AiModelCatalogService(HttpClient? client = null) => _client = client ?? SharedClient;

    public async Task<AiModelCatalogResult> DiscoverAsync(
        AiProviderSettings settings, string? apiKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = settings.Clone();
        var models = new HashSet<string>(StringComparer.Ordinal);
        AiModelCatalogResult Fail(ModelErrorCategory category, string reason) => new(
            Array.AsReadOnly(models.OrderBy(x => x, StringComparer.Ordinal).ToArray()), false,
            models.Count == 0 ? reason : $"Partial model catalog ({models.Count} models). {reason}", category);
        if (snapshot.ProviderKind is not (AiProviderKind.LocalOpenAiCompatible or
            AiProviderKind.CommercialOpenAiCompatible or AiProviderKind.Anthropic))
            return Fail(ModelErrorCategory.Configuration, "Select a supported provider before retrieving models.");
        if (!snapshot.TryValidateTransport(apiKey, out var transportError))
            return Fail(ModelErrorCategory.Configuration, transportError);
        snapshot.TryGetEndpoint(out var endpoint);
        var anthropic = snapshot.ProviderKind == AiProviderKind.Anthropic;
        if (anthropic && endpoint.Scheme != Uri.UriSchemeHttps)
            return Fail(ModelErrorCategory.Configuration, "Claude provider endpoint requires HTTPS.");
        if (snapshot.RequiresApiKey && string.IsNullOrWhiteSpace(apiKey))
            return Fail(ModelErrorCategory.Configuration, "API key is required for this provider and endpoint.");
        if (apiKey?.Any(char.IsControl) == true)
            return Fail(ModelErrorCategory.Configuration, "API key contains invalid header characters.");

        var path = endpoint.AbsolutePath.TrimEnd('/');
        var suffix = anthropic ? "/messages" : "/chat/completions";
        var baseUrl = endpoint.AbsoluteUri.TrimEnd('/');
        if (path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) baseUrl = baseUrl[..^suffix.Length];
        else if (!path.EndsWith("/v1", StringComparison.OrdinalIgnoreCase)) baseUrl += "/v1";
        var catalogUri = new Uri(baseUrl + "/models");
        var cursors = new HashSet<string>(StringComparer.Ordinal);
        string? cursor = null;
        long totalBytes = 0;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(snapshot.TimeoutSeconds, 5, 900)));
        try
        {
            for (var page = 0; page < MaximumPages; page++)
            {
                var uri = anthropic ? new Uri(catalogUri.AbsoluteUri + "?limit=100" +
                    (cursor is null ? "" : "&after_id=" + Uri.EscapeDataString(cursor))) : catalogUri;
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                if (anthropic)
                {
                    request.Headers.Add("x-api-key", apiKey);
                    request.Headers.Add("anthropic-version", "2023-06-01");
                }
                else if (!string.IsNullOrWhiteSpace(apiKey))
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
                using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                if (!response.IsSuccessStatusCode)
                    return Fail(MapStatus(response.StatusCode), $"Model catalog returned HTTP {(int)response.StatusCode}.");
                if (response.Content.Headers.ContentLength > MaximumResponseBytes)
                    return Fail(ModelErrorCategory.InvalidResponse, "Model catalog response exceeded the size limit.");
                await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
                using var buffer = new MemoryStream();
                var bytes = new byte[8192];
                int count;
                while ((count = await stream.ReadAsync(bytes, timeout.Token)) != 0)
                {
                    totalBytes += count;
                    if (buffer.Length + count > MaximumResponseBytes || totalBytes > MaximumTotalBytes)
                        return Fail(ModelErrorCategory.InvalidResponse, "Model catalog response exceeded the size limit.");
                    buffer.Write(bytes, 0, count);
                }
                using var document = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object || HasDuplicateKeys(root) ||
                    !root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                    return Fail(ModelErrorCategory.InvalidResponse, "Model catalog has invalid model-list fields.");
                var pageModels = new List<string>();
                var newIds = new HashSet<string>(StringComparer.Ordinal);
                foreach (var item in data.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty("id", out var id) ||
                        id.ValueKind != JsonValueKind.String || !ValidId(id.GetString()) ||
                        (!string.IsNullOrEmpty(apiKey) && id.GetString()!.Contains(apiKey, StringComparison.Ordinal)))
                        return Fail(ModelErrorCategory.InvalidResponse, "Model catalog contains an invalid model ID.");
                    pageModels.Add(id.GetString()!);
                    if (!models.Contains(id.GetString()!)) newIds.Add(id.GetString()!);
                    if (pageModels.Count > MaximumModels || models.Count + newIds.Count > MaximumModels)
                        return Fail(ModelErrorCategory.InvalidResponse, "Model catalog exceeded the model count limit.");
                }
                var hasMore = false;
                string? nextCursor = null;
                if (anthropic)
                {
                    if (!root.TryGetProperty("has_more", out var more) ||
                        more.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                        return Fail(ModelErrorCategory.InvalidResponse, "Model catalog has invalid pagination fields.");
                    hasMore = more.GetBoolean();
                    if (hasMore)
                    {
                        if (pageModels.Count == 0 || !root.TryGetProperty("last_id", out var last) ||
                            last.ValueKind != JsonValueKind.String || !ValidId(nextCursor = last.GetString()) ||
                            nextCursor != pageModels[^1] || !cursors.Add(nextCursor!))
                            return Fail(ModelErrorCategory.InvalidResponse, "Model catalog has invalid or repeated pagination cursor.");
                    }
                }
                models.UnionWith(pageModels);
                if (!hasMore) return new(Array.AsReadOnly(models.OrderBy(x => x, StringComparer.Ordinal).ToArray()),
                    true, models.Count == 0 ? "Provider returned no visible models." :
                    $"Retrieved {models.Count} visible models. Availability does not guarantee chat or tool support.", null);
                cursor = nextCursor;
            }
            return Fail(ModelErrorCategory.InvalidResponse, "Model catalog exceeded the pagination limit.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return Fail(ModelErrorCategory.Timeout, "Model catalog request timed out."); }
        catch (HttpRequestException) { return Fail(ModelErrorCategory.Network, "Model catalog connection failed."); }
        catch (IOException) { return Fail(ModelErrorCategory.Network, "Model catalog response could not be read."); }
        catch (JsonException) { return Fail(ModelErrorCategory.InvalidResponse, "Model catalog returned invalid JSON."); }
        catch (InvalidOperationException) { return Fail(ModelErrorCategory.InvalidResponse, "Model catalog has invalid fields."); }
        catch (FormatException) { return Fail(ModelErrorCategory.Configuration, "API key contains invalid header characters."); }
    }

    private static bool ValidId(string? id) => !string.IsNullOrWhiteSpace(id) && id.Length <= 512 &&
        !id.Any(c => char.IsControl(c) || char.IsWhiteSpace(c));

    private static bool HasDuplicateKeys(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name) || HasDuplicateKeys(property.Value)) return true;
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) if (HasDuplicateKeys(item)) return true;
        return false;
    }

    private static ModelErrorCategory MapStatus(HttpStatusCode status) => (int)status switch
    {
        401 => ModelErrorCategory.Authentication, 403 => ModelErrorCategory.Authorization,
        404 => ModelErrorCategory.ModelUnavailable, 429 => ModelErrorCategory.RateLimited,
        >= 500 => ModelErrorCategory.ProviderUnavailable, _ => ModelErrorCategory.InvalidResponse
    };
}
