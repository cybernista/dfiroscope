using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class AiProviderFactory
{
    public IAiProvider Create(AiProviderSettings settings)
    {
        return settings.ProviderKind switch
        {
            AiProviderKind.LocalOpenAiCompatible => new OpenAiCompatibleAiProvider(),
            AiProviderKind.CommercialOpenAiCompatible => new OpenAiCompatibleAiProvider(),
            _ => new DisabledAiProvider()
        };
    }
}
