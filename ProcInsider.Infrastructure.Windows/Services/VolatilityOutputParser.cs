using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcInsider.Models;

namespace ProcInsider.Services;

public sealed class VolatilityOutputParser
{
    public IReadOnlyList<MemoryProcessRecord> ParseProcessPlugin(
        string imageId,
        string pluginRunId,
        string pluginName,
        string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput) || !IsProcessPlugin(pluginName))
        {
            return Array.Empty<MemoryProcessRecord>();
        }

        try
        {
            var jsonRows = ParseJsonRows(rawOutput);
            if (jsonRows.Count > 0)
            {
                return jsonRows
                    .Select((row, index) => CreateProcessRecord(imageId, pluginRunId, pluginName, index + 1, row))
                    .ToList();
            }
        }
        catch (JsonException)
        {
            // Fall through to tabular parsing. Volatility output renderer can vary by version.
        }

        return ParseTextRows(imageId, pluginRunId, pluginName, rawOutput);
    }

    private static IReadOnlyList<IReadOnlyDictionary<string, string>> ParseJsonRows(string rawOutput)
    {
        using var document = JsonDocument.Parse(rawOutput);
        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            return document.RootElement.EnumerateArray()
                .Select(ReadObjectRow)
                .Where(row => row.Count > 0)
                .ToList();
        }

        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            return Array.Empty<IReadOnlyDictionary<string, string>>();
        }

        if (document.RootElement.TryGetProperty("rows", out var rows) && rows.ValueKind == JsonValueKind.Array)
        {
            var columns = ReadColumns(document.RootElement);
            return rows.EnumerateArray()
                .Select(row => ReadRow(row, columns))
                .Where(row => row.Count > 0)
                .ToList();
        }

        if (document.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
        {
            return data.EnumerateArray()
                .Select(ReadObjectRow)
                .Where(row => row.Count > 0)
                .ToList();
        }

        return Array.Empty<IReadOnlyDictionary<string, string>>();
    }

    private static IReadOnlyList<string> ReadColumns(JsonElement root)
    {
        if (!root.TryGetProperty("columns", out var columns) || columns.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        var names = new List<string>();
        foreach (var column in columns.EnumerateArray())
        {
            if (column.ValueKind == JsonValueKind.String)
            {
                names.Add(column.GetString() ?? string.Empty);
            }
            else if (column.ValueKind == JsonValueKind.Object && column.TryGetProperty("name", out var name))
            {
                names.Add(name.GetString() ?? string.Empty);
            }
        }

        return names;
    }

    private static IReadOnlyDictionary<string, string> ReadRow(JsonElement row, IReadOnlyList<string> columns)
    {
        if (row.ValueKind == JsonValueKind.Object)
        {
            return ReadObjectRow(row);
        }

        if (row.ValueKind != JsonValueKind.Array || columns.Count == 0)
        {
            return new Dictionary<string, string>();
        }

        var values = row.EnumerateArray().ToArray();
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < Math.Min(columns.Count, values.Length); index++)
        {
            if (!string.IsNullOrWhiteSpace(columns[index]))
            {
                result[columns[index]] = ToString(values[index]);
            }
        }

        return result;
    }

    private static IReadOnlyDictionary<string, string> ReadObjectRow(JsonElement row)
    {
        if (row.ValueKind != JsonValueKind.Object)
        {
            return new Dictionary<string, string>();
        }

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in row.EnumerateObject())
        {
            result[property.Name] = ToString(property.Value);
        }

        return result;
    }

    private static IReadOnlyList<MemoryProcessRecord> ParseTextRows(
        string imageId,
        string pluginRunId,
        string pluginName,
        string rawOutput)
    {
        var records = new List<MemoryProcessRecord>();
        var lines = rawOutput
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => !line.StartsWith("Volatility", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (lines.Count < 2)
        {
            return records;
        }

        var headerIndex = lines.FindIndex(line => line.Contains("PID", StringComparison.OrdinalIgnoreCase) ||
                                                  line.Contains("ImageFileName", StringComparison.OrdinalIgnoreCase));
        if (headerIndex < 0 || headerIndex + 1 >= lines.Count)
        {
            return records;
        }

        var headers = SplitColumns(lines[headerIndex]);
        for (var index = headerIndex + 1; index < lines.Count; index++)
        {
            var values = SplitColumns(lines[index]);
            if (values.Count == 0)
            {
                continue;
            }

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var column = 0; column < Math.Min(headers.Count, values.Count); column++)
            {
                map[headers[column]] = values[column];
            }

            records.Add(CreateProcessRecord(imageId, pluginRunId, pluginName, records.Count + 1, map));
        }

        return records;
    }

    private static IReadOnlyList<string> SplitColumns(string line)
    {
        if (line.Contains('\t'))
        {
            return line.Split('\t', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        return line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static MemoryProcessRecord CreateProcessRecord(
        string imageId,
        string pluginRunId,
        string pluginName,
        int rowNumber,
        IReadOnlyDictionary<string, string> row)
    {
        var processId = GetInt(row, "PID", "Pid", "ProcessId", "Process ID");
        var parentProcessId = GetInt(row, "PPID", "InheritedFromUniqueProcessId", "ParentProcessId", "Parent PID");
        var processName = Get(row, "ImageFileName", "Image", "Name", "ProcessName", "Process");
        var commandLine = Get(row, "CommandLine", "CmdLine", "Arguments");
        var path = Get(row, "Path", "ImagePath", "FilePath");
        var objectOffset = Get(row, "Offset(V)", "Offset(P)", "Offset", "VirtualOffset");
        var rawJson = JsonSerializer.Serialize(row);
        var artifactId = Sha256($"{imageId}|{pluginRunId}|{pluginName}|{rowNumber}|{objectOffset}|{processId}|{processName}|{commandLine}")[..32];

        return new MemoryProcessRecord
        {
            ArtifactId = artifactId,
            ImageId = imageId,
            PluginRunId = pluginRunId,
            PluginName = pluginName,
            EvidenceKind = GetEvidenceKind(pluginName),
            RowNumber = rowNumber,
            ObjectOffset = objectOffset,
            ProcessId = processId,
            ParentProcessId = parentProcessId,
            ProcessName = processName,
            ImagePath = path,
            CommandLine = commandLine,
            CreateTimeUtc = GetDate(row, "CreateTime", "Create Time", "CreateTimeUtc"),
            ExitTimeUtc = GetDate(row, "ExitTime", "Exit Time", "ExitTimeUtc"),
            SessionId = GetInt(row, "SessionId", "Session"),
            ThreadCount = GetInt(row, "Threads", "ThreadCount"),
            HandleCount = GetInt(row, "Handles", "HandleCount"),
            Wow64 = Get(row, "Wow64"),
            RawRowHash = Sha256(rawJson),
            RawJson = rawJson,
            Source = "AgentVolatility"
        };
    }

    private static MemoryProcessEvidenceKind GetEvidenceKind(string pluginName)
    {
        var normalized = pluginName.ToLowerInvariant();
        if (normalized.Contains("pslist", StringComparison.Ordinal))
        {
            return MemoryProcessEvidenceKind.PsList;
        }

        if (normalized.Contains("psscan", StringComparison.Ordinal))
        {
            return MemoryProcessEvidenceKind.PsScan;
        }

        if (normalized.Contains("pstree", StringComparison.Ordinal))
        {
            return MemoryProcessEvidenceKind.PsTree;
        }

        if (normalized.Contains("cmdline", StringComparison.Ordinal))
        {
            return MemoryProcessEvidenceKind.CmdLine;
        }

        return MemoryProcessEvidenceKind.Unknown;
    }

    private static bool IsProcessPlugin(string pluginName)
    {
        var normalized = pluginName.ToLowerInvariant();
        return normalized.Contains("pslist", StringComparison.Ordinal) ||
               normalized.Contains("psscan", StringComparison.Ordinal) ||
               normalized.Contains("pstree", StringComparison.Ordinal) ||
               normalized.Contains("cmdline", StringComparison.Ordinal);
    }

    private static string Get(IReadOnlyDictionary<string, string> row, params string[] names)
    {
        foreach (var name in names)
        {
            if (row.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static int GetInt(IReadOnlyDictionary<string, string> row, params string[] names)
    {
        var value = Get(row, names);
        return int.TryParse(value, out var parsed) ? parsed : 0;
    }

    private static DateTime? GetDate(IReadOnlyDictionary<string, string> row, params string[] names)
    {
        var value = Get(row, names);
        return DateTime.TryParse(value, out var parsed) ? parsed.ToUniversalTime() : null;
    }

    private static string ToString(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? string.Empty,
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => string.Empty,
            _ => element.GetRawText()
        };
    }

    private static string Sha256(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
