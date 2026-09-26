using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public interface IAiProvider
{
    Task<AiProviderResponse> CompleteAsync(
        AiProviderSettings settings,
        string apiKey,
        string systemPrompt,
        string userPrompt,
        CancellationToken cancellationToken);
}
