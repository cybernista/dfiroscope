using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class DisabledAiProvider : IAiProvider
{
    public Task<AiProviderResponse> CompleteAsync(
        AiProviderSettings settings,
        string apiKey,
        string systemPrompt,
        string userPrompt,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(new AiProviderResponse
        {
            Success = false,
            ProviderName = settings.ProviderDisplayName,
            ErrorMessage = "AI provider is disabled. Configure a local or commercial provider before running AI analysis."
        });
    }
}
