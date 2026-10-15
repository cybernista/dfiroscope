using System.Text.Json;

namespace ProcInsider.Services.Ai;

internal static class ModelJsonSchemaValidator
{
    public static string DescribeFailure(JsonElement value, JsonElement schema)
    {
        return Describe(value, schema, "$", 0) ?? "Arguments do not match the offered Tool schema. Correct the named fields and retry; do not broaden the query by dropping a filter.";
    }

    private static string? Describe(JsonElement value, JsonElement schema, string path, int depth)
    {
        if (depth > 12 || schema.ValueKind != JsonValueKind.Object)
            return $"{path}: unsupported or overdeep schema.";
        if (schema.TryGetProperty("type", out var type))
        {
            var expected = type.GetString();
            var matches = expected switch
            {
                "object" => value.ValueKind == JsonValueKind.Object,
                "array" => value.ValueKind == JsonValueKind.Array,
                "string" => value.ValueKind == JsonValueKind.String,
                "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _),
                "number" => value.ValueKind == JsonValueKind.Number,
                "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
                "null" => value.ValueKind == JsonValueKind.Null,
                _ => false
            };
            if (!matches) return $"{path}: expected {expected}; received {value.ValueKind}. Supply the declared type.";
        }
        if (schema.TryGetProperty("enum", out var choices) &&
            !choices.EnumerateArray().Any(choice => choice.GetRawText() == value.GetRawText()))
            return $"{path}: value is outside the permitted choices. Use one of {string.Join(", ", choices.EnumerateArray().Select(choice => choice.GetRawText()))}.";
        if (value.ValueKind == JsonValueKind.Object)
        {
            var properties = schema.TryGetProperty("properties", out var p) ? p : default;
            if (schema.TryGetProperty("required", out var required))
                foreach (var name in required.EnumerateArray().Select(item => item.GetString()!))
                    if (!value.TryGetProperty(name, out _))
                        return $"{path}.{name}: required argument is missing. Supply it with the declared shape.";
            foreach (var property in value.EnumerateObject())
            {
                var childPath = path + "." + property.Name;
                if (properties.ValueKind == JsonValueKind.Object &&
                    properties.TryGetProperty(property.Name, out var child))
                {
                    var failure = Describe(property.Value, child, childPath, depth + 1);
                    if (failure is not null) return failure;
                }
                else if (schema.TryGetProperty("additionalProperties", out var additional) &&
                         additional.ValueKind == JsonValueKind.False)
                    return $"{childPath}: argument is not offered by this Tool. Remove this unsupported argument; retain all meaningful supported filters.";
            }
        }
        if (value.ValueKind == JsonValueKind.String)
        {
            var length = value.GetString()!.Length;
            var minimum = schema.TryGetProperty("minLength", out var min) ? min.GetInt32() : 0;
            var maximum = schema.TryGetProperty("maxLength", out var max) ? max.GetInt32() : int.MaxValue;
            if (length < minimum || length > maximum)
                return $"{path}: expected string length {minimum}–{maximum}; received {length}. Supply a value within that range. Do not omit a meaningful filter to broaden the query without analyst direction.";
        }
        if (value.ValueKind == JsonValueKind.Array)
        {
            var count = value.GetArrayLength();
            var minimum = schema.TryGetProperty("minItems", out var min) ? min.GetInt32() : 0;
            var maximum = schema.TryGetProperty("maxItems", out var max) ? max.GetInt32() : int.MaxValue;
            if (count < minimum || count > maximum)
                return $"{path}: expected {minimum}–{maximum} items; received {count}. Supply a bounded array.";
            if (schema.TryGetProperty("items", out var items))
            {
                var index = 0;
                foreach (var item in value.EnumerateArray())
                {
                    var failure = Describe(item, items, $"{path}[{index++}]", depth + 1);
                    if (failure is not null) return failure;
                }
            }
        }
        if (value.ValueKind == JsonValueKind.Number)
        {
            if (schema.TryGetProperty("minimum", out var minimum) && value.GetDouble() < minimum.GetDouble())
                return $"{path}: expected at least {minimum.GetRawText()}; received {value.GetRawText()}. Supply a value within the offered range.";
            if (schema.TryGetProperty("maximum", out var maximum) && value.GetDouble() > maximum.GetDouble())
                return $"{path}: expected at most {maximum.GetRawText()}; received {value.GetRawText()}. Supply a value within the offered range.";
        }
        return null;
    }
    // Deliberately small accepted JSON Schema subset. Unknown assertions fail closed.
    private static readonly HashSet<string> Accepted = new(StringComparer.Ordinal)
    {
        "type", "properties", "required", "additionalProperties", "items", "enum",
        "minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum",
        "description", "title", "$schema"
    };

    public static bool IsSupportedSchema(JsonElement schema, int depth = 0)
    {
        if (depth > 12 || schema.ValueKind != JsonValueKind.Object ||
            !schema.TryGetProperty("type", out _)) return false;
        foreach (var property in schema.EnumerateObject())
        {
            if (!Accepted.Contains(property.Name)) return false;
            if (property.Name == "type" && (property.Value.ValueKind != JsonValueKind.String ||
                property.Value.GetString() is not ("object" or "array" or "string" or "number" or "integer" or "boolean" or "null"))) return false;
            if (property.Name == "properties" && (property.Value.ValueKind != JsonValueKind.Object ||
                property.Value.EnumerateObject().Any(child => !IsSupportedSchema(child.Value, depth + 1)))) return false;
            if (property.Name == "items" && !IsSupportedSchema(property.Value, depth + 1)) return false;
            if (property.Name == "required" && (property.Value.ValueKind != JsonValueKind.Array ||
                property.Value.EnumerateArray().Any(item => item.ValueKind != JsonValueKind.String))) return false;
            if (property.Name == "enum" && property.Value.ValueKind != JsonValueKind.Array) return false;
            if (property.Name == "additionalProperties" && property.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
            if ((property.Name is "minItems" or "maxItems" or "minLength" or "maxLength") &&
                (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetInt32(out var positive) || positive < 0)) return false;
            if ((property.Name is "minimum" or "maximum") && property.Value.ValueKind != JsonValueKind.Number) return false;
        }
        return true;
    }

    public static bool IsValid(JsonElement value, JsonElement schema, int depth = 0)
    {
        if (depth > 12 || schema.ValueKind != JsonValueKind.Object) return false;
        if (!IsSupportedSchema(schema, depth)) return false;
        if (schema.TryGetProperty("type", out var type))
        {
            if (type.ValueKind != JsonValueKind.String) return false;
            var matches = type.GetString() switch
            {
                "object" => value.ValueKind == JsonValueKind.Object,
                "array" => value.ValueKind == JsonValueKind.Array,
                "string" => value.ValueKind == JsonValueKind.String,
                "number" => value.ValueKind == JsonValueKind.Number,
                "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _),
                "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
                "null" => value.ValueKind == JsonValueKind.Null,
                _ => false
            };
            if (!matches) return false;
        }
        if (schema.TryGetProperty("enum", out var choices))
        {
            if (choices.ValueKind != JsonValueKind.Array || !choices.EnumerateArray().Any(item =>
                item.GetRawText() == value.GetRawText())) return false;
        }
        if (value.ValueKind == JsonValueKind.Object)
        {
            var properties = schema.TryGetProperty("properties", out var p) ? p : default;
            if (properties.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Object)) return false;
            if (schema.TryGetProperty("required", out var required))
            {
                if (required.ValueKind != JsonValueKind.Array || required.EnumerateArray().Any(r =>
                    r.ValueKind != JsonValueKind.String || !value.TryGetProperty(r.GetString()!, out _))) return false;
            }
            var allowAdditional = !schema.TryGetProperty("additionalProperties", out var additional) || additional.ValueKind == JsonValueKind.True;
            if (schema.TryGetProperty("additionalProperties", out additional) && additional.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
            foreach (var item in value.EnumerateObject())
            {
                if (properties.ValueKind == JsonValueKind.Object && properties.TryGetProperty(item.Name, out var child))
                {
                    if (!IsValid(item.Value, child, depth + 1)) return false;
                }
                else if (!allowAdditional) return false;
            }
        }
        if (value.ValueKind == JsonValueKind.Array)
        {
            if (schema.TryGetProperty("minItems", out var minItems) && (minItems.ValueKind != JsonValueKind.Number || value.GetArrayLength() < minItems.GetInt32())) return false;
            if (schema.TryGetProperty("maxItems", out var maxItems) && (maxItems.ValueKind != JsonValueKind.Number || value.GetArrayLength() > maxItems.GetInt32())) return false;
            if (schema.TryGetProperty("items", out var items) && value.EnumerateArray().Any(item => !IsValid(item, items, depth + 1))) return false;
        }
        if (value.ValueKind == JsonValueKind.String)
        {
            var length = value.GetString()!.Length;
            if (schema.TryGetProperty("minLength", out var minLength) && (minLength.ValueKind != JsonValueKind.Number || length < minLength.GetInt32())) return false;
            if (schema.TryGetProperty("maxLength", out var maxLength) && (maxLength.ValueKind != JsonValueKind.Number || length > maxLength.GetInt32())) return false;
        }
        if (value.ValueKind == JsonValueKind.Number)
        {
            if (schema.TryGetProperty("minimum", out var minimum) && (minimum.ValueKind != JsonValueKind.Number || value.GetDouble() < minimum.GetDouble())) return false;
            if (schema.TryGetProperty("maximum", out var maximum) && (maximum.ValueKind != JsonValueKind.Number || value.GetDouble() > maximum.GetDouble())) return false;
        }
        return true;
    }
}
