using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public static class AgentIpcJson
{
    public static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Converters =
        {
            new AgentCommandOperationalAvailabilityJsonConverter(),
            new JsonStringEnumConverter()
        }
    };
}
