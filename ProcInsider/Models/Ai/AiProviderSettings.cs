using System.Net;
using System.Net.Sockets;
using System.Text.Json.Serialization;

namespace ProcInsider.Models.Ai;

public sealed class AiProviderSettings
{
    public const int DefaultTimeoutSeconds = 180;

    public int SchemaVersion { get; set; } = 1;

    /// <summary>Stable catalog identity; keys remain bound to provider and endpoint.</summary>
    public string ProfileId { get; set; } = string.Empty;

    public AiProviderKind ProviderKind { get; set; } = AiProviderKind.Disabled;

    public string ProfileName { get; set; } = "Disabled";

    public string BaseUrl { get; set; } = string.Empty;

    public string ModelName { get; set; } = string.Empty;

    public bool AllowPrivateNetworkHttp { get; set; }

    public int TimeoutSeconds { get; set; } = DefaultTimeoutSeconds;

    public int MaxContextCharacters { get; set; } = 12000;

    public int MaxResponseCharacters { get; set; } = 4000;

    public int? ContextWindowTokens { get; set; }

    public int? MaximumOutputTokens { get; set; }

    public bool? SupportsTools { get; set; }

    public bool? SupportsStructuredOutput { get; set; }

    [JsonIgnore]
    public bool IsEnabled => ProviderKind != AiProviderKind.Disabled;

    [JsonIgnore]
    public bool IsCloudProvider => IsEnabled && (!TryGetEndpoint(out var endpoint) || !endpoint.IsLoopback);

    [JsonIgnore]
    public bool RequiresApiKey => ProviderKind is AiProviderKind.CommercialOpenAiCompatible or AiProviderKind.Anthropic;

    [JsonIgnore]
    public string ProviderDisplayName => ProviderKind switch
    {
        AiProviderKind.LocalOpenAiCompatible => "OpenAI compatible",
        AiProviderKind.CommercialOpenAiCompatible => "OpenAI",
        AiProviderKind.Anthropic => "Claude",
        _ => "Disabled"
    };

    [JsonIgnore]
    public string DestinationDisplay => !IsEnabled ? "Disabled"
        : $"{(IsCloudProvider ? "Cloud/external" : "Local")} • {ProviderDisplayName} • {ModelName}";

    [JsonIgnore]
    public string EndpointDisplay => TryGetEndpoint(out var endpoint)
        ? endpoint.GetLeftPart(UriPartial.Path)
        : "Invalid endpoint";

    public bool TryGetEndpoint(out Uri endpoint)
    {
        endpoint = null!;
        if (!Uri.TryCreate(BaseUrl?.Trim(), UriKind.Absolute, out var candidate) ||
            (candidate.Scheme != Uri.UriSchemeHttp && candidate.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(candidate.UserInfo) ||
            !string.IsNullOrEmpty(candidate.Query) ||
            !string.IsNullOrEmpty(candidate.Fragment))
        {
            return false;
        }

        endpoint = candidate;
        return true;
    }

    [JsonIgnore]
    public bool IsPrivateNetworkHttp => TryGetEndpoint(out var endpoint) &&
        endpoint.Scheme == Uri.UriSchemeHttp && !endpoint.IsLoopback && IsPrivateNetworkAddress(endpoint);

    public bool TryValidateTransport(string? apiKey, out string error)
    {
        error = "Provider endpoint is invalid.";
        if (!TryGetEndpoint(out var endpoint)) return false;
        if (endpoint.IsLoopback || endpoint.Scheme == Uri.UriSchemeHttps)
        {
            error = string.Empty;
            return true;
        }
        if (ProviderKind != AiProviderKind.LocalOpenAiCompatible || !AllowPrivateNetworkHttp ||
            !IsPrivateNetworkAddress(endpoint))
        {
            error = "External provider endpoint requires HTTPS. Private network HTTP requires explicit permission for a local provider and a private IP address.";
            return false;
        }
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            error = "API keys cannot be sent over private network HTTP. Clear the key or use HTTPS.";
            return false;
        }
        error = string.Empty;
        return true;
    }

    private bool IsPrivateNetworkAddress(Uri endpoint)
    {
        // Inspect the literal authority, not DNS resolution or Uri's normalization of IPv4 aliases.
        var raw = BaseUrl.Trim();
        var authority = raw[(raw.IndexOf("://", StringComparison.Ordinal) + 3)..].Split('/')[0];
        var host = authority.StartsWith('[')
            ? authority[1..authority.IndexOf(']')]
            : authority.Split(':')[0];
        if (host.Contains('%') || !IPAddress.TryParse(host, out var address)) return false;
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return endpoint.HostNameType == UriHostNameType.IPv6 && (bytes[0] & 0xfe) == 0xfc;
        if (address.AddressFamily != AddressFamily.InterNetwork || endpoint.HostNameType != UriHostNameType.IPv4 ||
            host != address.ToString()) return false;
        return bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
            bytes[0] == 192 && bytes[1] == 168;
    }

    [JsonIgnore]
    public string SecretScope => TryGetEndpoint(out var endpoint)
        ? $"{ProviderKind}|{endpoint.GetLeftPart(UriPartial.Authority).ToLowerInvariant()}{endpoint.AbsolutePath.TrimEnd('/')}"
        : string.Empty;

    public bool OutputTokenLimitExceeded(int? requested) =>
        MaximumOutputTokens is { } known && requested is { } actual && actual > known;

    public static AiProviderSettings CreateDefault() => new();

    public AiProviderSettings Clone()
    {
        return new AiProviderSettings
        {
            SchemaVersion = SchemaVersion,
            ProfileId = ProfileId,
            ProviderKind = ProviderKind,
            ProfileName = ProfileName,
            BaseUrl = BaseUrl,
            ModelName = ModelName,
            AllowPrivateNetworkHttp = AllowPrivateNetworkHttp,
            TimeoutSeconds = TimeoutSeconds,
            MaxContextCharacters = MaxContextCharacters,
            MaxResponseCharacters = MaxResponseCharacters,
            ContextWindowTokens = ContextWindowTokens,
            MaximumOutputTokens = MaximumOutputTokens,
            SupportsTools = SupportsTools,
            SupportsStructuredOutput = SupportsStructuredOutput
        };
    }
}

public sealed class AiProviderCatalog
{
    public int SchemaVersion { get; set; } = 1;

    public List<AiProviderSettings> Profiles { get; set; } = new();

    public string? DefaultProfileId { get; set; }
}
