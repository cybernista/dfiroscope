using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProcInsider.Agent;

internal static class AgentJson
{
    public static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Converters =
        {
            new JsonStringEnumConverter()
        }
    };
}
