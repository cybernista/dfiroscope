using ProcInsider.Models.Ai;

namespace ProcInsider.Services.Ai;

public interface IModelProvider
{
    string ProviderId { get; }

    Task<ModelCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken);

    Task<ModelResponse> InvokeAsync(ModelRequest request, CancellationToken cancellationToken);
}
