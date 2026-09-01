using System.Text.Json;

namespace ProcInsider.Agent;

internal sealed class StubAgentJobHandler : IAgentJobHandler
{
    public async Task ExecuteAsync(AgentJobContext context)
    {
        const int totalSteps = 3;
        for (var step = 1; step <= totalSteps; step++)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(TimeSpan.FromMilliseconds(25), context.CancellationToken).ConfigureAwait(false);
            await context.ReportProgressAsync(step, totalSteps, $"Stub {context.Request.JobKind} step {step} of {totalSteps}.").ConfigureAwait(false);
        }

        if (ShouldForceFailure(context.Request.Parameters))
        {
            throw new InvalidOperationException("Stub job requested a forced failure.");
        }
    }

    private static bool ShouldForceFailure(object? parameters)
    {
        if (parameters is null)
        {
            return false;
        }

        if (parameters is JsonElement element &&
            element.TryGetProperty("forceFailure", out var forceFailure) &&
            forceFailure.ValueKind == JsonValueKind.True)
        {
            return true;
        }

        var json = JsonSerializer.Serialize(parameters, AgentJson.JsonOptions);
        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty("forceFailure", out var property) &&
               property.ValueKind == JsonValueKind.True;
    }
}
