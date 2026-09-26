using System.Text.Json.Serialization;

namespace ProcInsider.Models.Ai;

public sealed class AiProviderSettings
{
    public const int DefaultTimeoutSeconds = 180;

    public int SchemaVersion { get; set; } = 1;

    public AiProviderKind ProviderKind { get; set; } = AiProviderKind.Disabled;

    public string ProfileName { get; set; } = "Disabled";

    public string BaseUrl { get; set; } = string.Empty;

    public string ModelName { get; set; } = string.Empty;

    public int TimeoutSeconds { get; set; } = DefaultTimeoutSeconds;

    public int MaxContextCharacters { get; set; } = 12000;

    public int MaxResponseCharacters { get; set; } = 4000;

    [JsonIgnore]
    public bool IsEnabled => ProviderKind != AiProviderKind.Disabled;

    [JsonIgnore]
    public bool IsCloudProvider => ProviderKind == AiProviderKind.CommercialOpenAiCompatible;

    [JsonIgnore]
    public bool RequiresApiKey => ProviderKind == AiProviderKind.CommercialOpenAiCompatible;

    [JsonIgnore]
    public string ProviderDisplayName => ProviderKind switch
    {
        AiProviderKind.LocalOpenAiCompatible => "Local OpenAI-compatible",
        AiProviderKind.CommercialOpenAiCompatible => "Commercial/cloud OpenAI-compatible",
        _ => "Disabled"
    };

    public static AiProviderSettings CreateDefault() => new();

    public AiProviderSettings Clone()
    {
        return new AiProviderSettings
        {
            SchemaVersion = SchemaVersion,
            ProviderKind = ProviderKind,
            ProfileName = ProfileName,
            BaseUrl = BaseUrl,
            ModelName = ModelName,
            TimeoutSeconds = TimeoutSeconds,
            MaxContextCharacters = MaxContextCharacters,
            MaxResponseCharacters = MaxResponseCharacters
        };
    }
}
