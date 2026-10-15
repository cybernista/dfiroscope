using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public sealed class DisabledModelProvider : IModelProvider
{
    public string ProviderId => "disabled";

    public Task<ModelCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new ModelCapabilities(ProviderId, string.Empty, null, null, false, false, false, false));
    }

    public Task<ModelResponse> InvokeAsync(ModelRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new ModelResponse(ProviderId, string.Empty, string.Empty, Array.Empty<ModelToolRequest>(),
            null, null, new ModelError(ModelErrorCategory.Configuration, "AI provider is disabled.")));
    }
}
