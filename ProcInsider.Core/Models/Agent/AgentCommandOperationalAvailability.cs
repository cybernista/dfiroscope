using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProcInsider.Models.Agent;

/// <summary>
/// Whether a published command discriminator is executable by the current
/// agent. Unknown is deliberately conservative for older or newer health JSON.
/// </summary>
[JsonConverter(typeof(AgentCommandOperationalAvailabilityJsonConverter))]
public enum AgentCommandOperationalAvailability
{
    Unknown = 0,
    Supported = 1,
    Unavailable = 2,
    Reserved = 3
}

/// <summary>
/// Tolerant wire converter for the additive operational-availability field.
/// Future values remain Unknown instead of rejecting the complete health payload.
/// </summary>
public sealed class AgentCommandOperationalAvailabilityJsonConverter
    : JsonConverter<AgentCommandOperationalAvailability>
{
    public override AgentCommandOperationalAvailability Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            var text = reader.GetString();
            return Enum.TryParse<AgentCommandOperationalAvailability>(text, ignoreCase: true, out var parsed) &&
                   Enum.IsDefined(parsed)
                ? parsed
                : AgentCommandOperationalAvailability.Unknown;
        }

        if (reader.TokenType == JsonTokenType.Number &&
            reader.TryGetInt32(out var numeric) &&
            Enum.IsDefined(typeof(AgentCommandOperationalAvailability), numeric))
        {
            return (AgentCommandOperationalAvailability)numeric;
        }

        if (reader.TokenType is JsonTokenType.StartArray or JsonTokenType.StartObject)
        {
            using var ignored = JsonDocument.ParseValue(ref reader);
        }

        return AgentCommandOperationalAvailability.Unknown;
    }

    public override void Write(
        Utf8JsonWriter writer,
        AgentCommandOperationalAvailability value,
        JsonSerializerOptions options)
    {
        writer.WriteStringValue(Enum.IsDefined(value)
            ? value.ToString()
            : AgentCommandOperationalAvailability.Unknown.ToString());
    }
}
