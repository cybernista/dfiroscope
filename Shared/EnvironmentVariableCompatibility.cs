namespace ProcInsider.Compatibility;

public static class DfiroscopeEnvironmentVariables
{
    public const string MemoryAcquisitionTool = "DFIROSCOPE_MEMORY_ACQUISITION_TOOL";
    public const string LegacyMemoryAcquisitionTool = "PROCINSIDER_MEMORY_ACQUISITION_TOOL";

    public const string MemoryAcquisitionArguments = "DFIROSCOPE_MEMORY_ACQUISITION_ARGS";
    public const string LegacyMemoryAcquisitionArguments = "PROCINSIDER_MEMORY_ACQUISITION_ARGS";

    public const string ProcessMonitorPath = "DFIROSCOPE_PROCMON_PATH";
    public const string LegacyProcessMonitorPath = "PROCINSIDER_PROCMON_PATH";

    public const string TelemetryLabRoot = "DFIROSCOPE_TELEMETRY_LAB_ROOT";
    public const string LegacyTelemetryLabRoot = "PROCINSIDER_TELEMETRY_LAB_ROOT";
}

public sealed record EnvironmentVariableResolution
{
    public string PrimaryName { get; init; } = string.Empty;

    public string LegacyName { get; init; } = string.Empty;

    public string Value { get; init; } = string.Empty;

    public string SourceName { get; init; } = string.Empty;

    public bool PrimaryIsSet { get; init; }

    public bool LegacyIsSet { get; init; }

    public bool HasValue => !string.IsNullOrWhiteSpace(Value);

    public bool UsedLegacyAlias => HasValue && !PrimaryIsSet && LegacyIsSet;

    public bool HasConflict { get; init; }

    public string Diagnostic => HasConflict
        ? $"Both {PrimaryName} and legacy alias {LegacyName} are set with different values; {PrimaryName} takes precedence."
        : PrimaryIsSet
            ? $"Using {PrimaryName}."
            : LegacyIsSet
                ? $"Using legacy alias {LegacyName} because {PrimaryName} is not set."
                : $"Neither {PrimaryName} nor legacy alias {LegacyName} is set.";
}

public static class EnvironmentVariableCompatibility
{
    public static EnvironmentVariableResolution Resolve(
        string primaryName,
        string legacyName,
        Func<string, string?>? readValue = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(primaryName);
        ArgumentException.ThrowIfNullOrWhiteSpace(legacyName);

        readValue ??= Environment.GetEnvironmentVariable;
        var primaryValue = readValue(primaryName);
        var legacyValue = readValue(legacyName);
        var primaryIsSet = !string.IsNullOrWhiteSpace(primaryValue);
        var legacyIsSet = !string.IsNullOrWhiteSpace(legacyValue);

        return new EnvironmentVariableResolution
        {
            PrimaryName = primaryName,
            LegacyName = legacyName,
            Value = primaryIsSet ? primaryValue! : legacyIsSet ? legacyValue! : string.Empty,
            SourceName = primaryIsSet ? primaryName : legacyIsSet ? legacyName : string.Empty,
            PrimaryIsSet = primaryIsSet,
            LegacyIsSet = legacyIsSet,
            HasConflict = primaryIsSet && legacyIsSet &&
                          !string.Equals(primaryValue, legacyValue, StringComparison.Ordinal)
        };
    }
}
