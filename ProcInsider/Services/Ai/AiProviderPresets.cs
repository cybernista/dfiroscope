using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

// Nonsecret starting choices for a fresh application catalog. Once saved, the
// analyst's catalog is authoritative, including an intentionally empty one.
internal static class AiProviderPresets
{
    private const string LunaId = "14d4d02e-e62b-a648-7e6b-931ba623f443";

    internal static AiProviderCatalog CreateInitialCatalog() => new()
    {
        DefaultProfileId = LunaId,
        Profiles =
        [
            Create(LunaId, AiProviderKind.CommercialOpenAiCompatible,
                "OpenAI", "https://api.openai.com/v1", "gpt-6-luna",
                120, 50_000, 32_768, true, null),
            Create("6baf5863-4ffc-45fc-85fe-d7ec0344daef", AiProviderKind.Anthropic,
                "Claude", "https://api.anthropic.com/v1",
                "claude-haiku-4-5-20251001", 120, 50_000, 65_536, true, true),
            Create("c25ca12b-d8d7-4a16-94a7-e5d4ffb0933f", AiProviderKind.LocalOpenAiCompatible,
                "OpenAI compatible", "http://localhost:1234/v1",
                "qwen2.5-7b-instruct", 180, 4_000, 32_768, null, null)
        ]
    };

    internal static AiProviderSettings CreateConnection(AiProviderKind kind)
    {
        var settings = CreateInitialCatalog().Profiles.Single(profile => profile.ProviderKind == kind).Clone();
        settings.ProfileId = string.Empty;
        return settings;
    }

    // Visibility from discovery does not establish capabilities. Unknown models
    // start without overrides instead of inheriting the previous model's claims.
    internal static void ApplyModelCapabilities(AiProviderSettings settings, string model)
    {
        settings.ModelName = model.Trim();
        settings.ContextWindowTokens = null;
        settings.MaximumOutputTokens = null;
        settings.SupportsTools = null;
        settings.SupportsStructuredOutput = null;
        var known = settings.ProviderKind switch
        {
            AiProviderKind.CommercialOpenAiCompatible when settings.ModelName is "gpt-6-luna" or "gpt-5.6-terra" or "gpt-6-sol" or "gpt-6.1-sol" => true,
            AiProviderKind.Anthropic when settings.ModelName is "claude-haiku-4-5-20251001" or "claude-sonnet-4-6" or "claude-opus-4-6" => true,
            AiProviderKind.LocalOpenAiCompatible when settings.ModelName == "qwen2.5-7b-instruct" => true,
            _ => false
        };
        if (!known) return;
        settings.ContextWindowTokens = settings.ProviderKind == AiProviderKind.Anthropic ? 65_536 : 32_768;
        settings.MaximumOutputTokens = 6_144;
        settings.SupportsTools = settings.ProviderKind == AiProviderKind.LocalOpenAiCompatible ? null : true;
        settings.SupportsStructuredOutput = settings.ModelName == "claude-haiku-4-5-20251001" ? true
            : settings.ModelName == "gpt-6-luna" || settings.ProviderKind == AiProviderKind.LocalOpenAiCompatible ? null : false;
    }
    private static AiProviderSettings Create(string id, AiProviderKind kind, string name,
        string endpoint, string model, int timeoutSeconds, int maxResponseCharacters,
        int contextWindowTokens, bool? supportsTools, bool? supportsStructuredOutput) => new()
    {
        ProfileId = id,
        ProviderKind = kind,
        ProfileName = name,
        BaseUrl = endpoint,
        ModelName = model,
        AllowPrivateNetworkHttp = false,
        TimeoutSeconds = timeoutSeconds,
        MaxContextCharacters = 12_000,
        MaxResponseCharacters = maxResponseCharacters,
        ContextWindowTokens = contextWindowTokens,
        MaximumOutputTokens = 6_144,
        SupportsTools = supportsTools,
        SupportsStructuredOutput = supportsStructuredOutput
    };
}
