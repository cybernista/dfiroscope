using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models;

namespace ProcInsider.Cli;

internal enum CliExitCode
{
    Success = 0,
    Failure = 1,
    Usage = 2,
    Unavailable = 3,
    Rejected = 4,
    AgentRejected = 5,
    Timeout = 124,
    Canceled = 130
}

internal enum CliOutputMode
{
    Text = 0,
    Json = 1
}

internal enum CliCommandKind
{
    Unknown = 0,
    Help = 1,
    Version = 2,
    AgentDiscover = 3,
    AgentStatus = 4,
    AgentCapabilities = 5,
    CaptureConfigurationShow = 6,
    Shell = 7,
    AgentReconnect = 8,
    AgentStart = 9,
    AgentStop = 10,
    AgentPairingStatus = 11,
    AgentPairingRotate = 12,
    AgentPairingRevoke = 13,
    CaptureConfigurationCheck = 14,
    CaptureConfigurationSave = 15,
    CaptureStart = 16,
    CaptureStop = 17,
    CaptureSourceStart = 18,
    CaptureSourceStop = 19,
    AgentJobList = 20,
    AgentJobStatus = 21,
    AgentJobWait = 22,
    AgentJobCancel = 23,
    AgentEvidenceEnrich = 24,
    AgentProcessDump = 25,
    AgentFilesystemImport = 26,
    AgentNetworkStart = 27,
    AgentNetworkStop = 28,
    AgentZeekRun = 29,
    AgentProcessMonitorStart = 30,
    AgentProcessMonitorStop = 31,
    AgentProcessMonitorImport = 32,
    AgentSqliteBenchmarkStart = 33,
    AgentMemoryAcquire = 34,
    AgentMemoryImport = 35,
    AgentVolatilityRun = 36,
    HostMonitoringConfigurationShow = 37,
    HostMonitoringConfigurationCheck = 38,
    HostMonitoringConfigurationSave = 39,
    HostMonitoringDeploy = 40,
    HostMonitoringReverse = 41
}

internal sealed record CliInvocation(
    CliCommandKind Kind,
    string CommandName,
    CliOutputMode OutputMode,
    string? SessionTarget,
    bool NoPrompt = false,
    bool Confirmed = false,
    int? LiveBufferMemoryMegabytes = null,
    int? TimeoutSeconds = null,
    string? FilePath = null,
    string? Source = null,
    Guid? JobId = null,
    bool Wait = false,
    bool AllProcesses = false,
    IReadOnlyList<string>? ProcessEntityIds = null,
    IReadOnlyList<string>? ProcessKeys = null,
    bool CaptureModules = false,
    bool CaptureHandles = false,
    bool CapturePe = false,
    PeStringExtractionMode PeStringExtractionMode = PeStringExtractionMode.Deferred,
    MemoryDumpKind? DumpKind = null,
    string? SourcePath = null,
    bool Recurse = false,
    bool IncludeNtfs = false,
    bool IncludePrefetch = false,
    int? MaxFiles = null,
    string? CaptureId = null,
    string? PcapPath = null,
    string? ZeekPath = null,
    string? WslDistributionName = null,
    string? WslZeekCommand = null,
    string? ProcmonPath = null,
    bool AcceptEula = false,
    string? InputPath = null,
    int? MaxRows = null,
    int? PhaseDurationSeconds = null,
    int? MaxPhaseCount = null,
    int? InitialProcessBatchSize = null,
    int? InitialEventsPerProcess = null,
    int? MaxInFlightBatches = null,
    int? MaxPendingWriterWorkItems = null,
    string? OutputFileName = null,
    int? AcquisitionTimeoutSeconds = null,
    string? ImagePath = null,
    string? DisplayName = null,
    string? HostName = null,
    string? OsBuild = null,
    string? AcquisitionTool = null,
    string? AcquisitionToolVersion = null,
    string? AcquisitionCommandLine = null,
    string? PrivilegeState = null,
    string? ImageId = null,
    IReadOnlyList<string>? PluginNames = null,
    int? PluginTimeoutSeconds = null);

internal sealed record CliParseResult(
    CliInvocation? Invocation,
    CliOutputMode OutputMode,
    string ErrorCode,
    string ErrorMessage)
{
    public bool Success => Invocation != null;
}

internal sealed record CliErrorDto(
    string Code,
    string Message,
    bool Retryable);

internal sealed record CliEnvelopeDto(
    int SchemaVersion,
    string Command,
    bool Success,
    int ExitCode,
    string TimestampUtc,
    object? Data,
    CliErrorDto? Error);

internal sealed record CliCommandResult(
    CliExitCode ExitCode,
    string Text,
    object? Data,
    CliErrorDto? Error)
{
    public bool Success => ExitCode == CliExitCode.Success && Error == null;

    public static CliCommandResult Succeeded(string text, object? data = null) =>
        new(CliExitCode.Success, text, data, null);

    public static CliCommandResult Failed(
        CliExitCode exitCode,
        string errorCode,
        string message,
        bool retryable = false,
        string? text = null,
        object? data = null) =>
        new(
            exitCode,
            text ?? message,
            data,
            new CliErrorDto(
                CliValueSanitizer.Code(errorCode),
                CliValueSanitizer.OneLine(message),
                retryable));
}

internal interface ICliConsole
{
    TextReader In { get; }

    TextWriter Out { get; }

    TextWriter Error { get; }

    bool IsInputRedirected { get; }

    bool IsOutputRedirected { get; }

    bool IsErrorRedirected { get; }

    bool TryClear() => false;
}

internal sealed class SystemCliConsole : ICliConsole
{
    public TextReader In => Console.In;

    public TextWriter Out => Console.Out;

    public TextWriter Error => Console.Error;

    public bool IsInputRedirected => Console.IsInputRedirected;

    public bool IsOutputRedirected => Console.IsOutputRedirected;

    public bool IsErrorRedirected => Console.IsErrorRedirected;

    public bool TryClear()
    {
        try
        {
            Console.Clear();
            return true;
        }
        catch
        {
            return false;
        }
    }
}

internal interface ICliClock
{
    DateTime UtcNow { get; }
}

internal sealed class SystemCliClock : ICliClock
{
    public DateTime UtcNow => DateTime.UtcNow;
}

internal static class CliJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        WriteIndented = false
    };
}

internal static class CliValueSanitizer
{
    public const int MaxMessageLength = 1024;
    public const int MaxCodeLength = 128;
    public const int MaxValueLength = 512;

    public static string Code(string? value) =>
        Bound(value, MaxCodeLength, "UnknownError");

    public static string OneLine(string? value, int maxLength = MaxMessageLength) =>
        Bound(value, maxLength, string.Empty);

    public static string Value(string? value) =>
        Bound(value, MaxValueLength, string.Empty);

    public static string Timestamp(DateTime value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static string Bound(string? value, int maxLength, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        var filtered = new string(value
            .Trim()
            .Select(character => char.IsControl(character) ? ' ' : character)
            .ToArray());
        while (filtered.Contains("  ", StringComparison.Ordinal))
        {
            filtered = filtered.Replace("  ", " ", StringComparison.Ordinal);
        }

        return filtered.Length <= maxLength
            ? filtered
            : filtered[..maxLength];
    }
}
