using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class AiProviderFactory
{
    public IModelProvider Create(AiProviderSettings settings, string apiKey = "")
    {
        return settings.ProviderKind switch
        {
            AiProviderKind.LocalOpenAiCompatible => new OpenAiCompatibleAiProvider(settings, apiKey),
            AiProviderKind.CommercialOpenAiCompatible => new OpenAiCompatibleAiProvider(settings, apiKey),
            AiProviderKind.Anthropic => new AnthropicModelProvider(settings, apiKey),
            _ => new DisabledModelProvider()
        };
    }
}
