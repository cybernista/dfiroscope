using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using ProcInsider.Models;
using ProcInsider.Services.Features;

namespace ProcInsider.Services;

public enum CrashDiagnosticEntryPoint
{
    Dispatcher,
    AppDomain,
    TaskScheduler
}

/// <summary>
/// Small, immutable viewer-side snapshot. It deliberately contains no view-model,
/// evidence, annotation, command-line, or agent-service object graph.
/// </summary>
public sealed record CrashDiagnosticContext
{
    public CaptureWorkspaceMode WorkspaceMode { get; init; }

    public string SessionId { get; init; } = string.Empty;

    public string ViewerLifecycleState { get; init; } = "Unknown";

    public bool? AgentConnectedSnapshot { get; init; }

    public bool? CaptureActiveSnapshot { get; init; }

    [JsonIgnore]
    public InvestigationSessionPaths? ActiveSessionPaths { get; init; }
}

public sealed record CrashExceptionDetails
{
    public string Type { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string StackTrace { get; init; } = string.Empty;

    public int HResult { get; init; }

    public CrashExceptionDetails? InnerException { get; init; }

    public IReadOnlyList<CrashExceptionDetails> AggregateChildren { get; init; } =
        Array.Empty<CrashExceptionDetails>();
}

public sealed record ViewerCrashIncident
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string IncidentId { get; init; } = string.Empty;

    public DateTimeOffset TimestampUtc { get; init; }

    public CrashDiagnosticEntryPoint EntryPoint { get; init; }

    public string ProductDisplayName { get; init; } = string.Empty;

    public string FormerCompatibilityName { get; init; } = string.Empty;

    public string InformationalVersion { get; init; } = string.Empty;

    public string FileVersion { get; init; } = string.Empty;

    public string EducationalReleaseId { get; init; } = string.Empty;

    public int ProcessId { get; init; }

    public string ProcessArchitecture { get; init; } = string.Empty;

    public bool? IsElevated { get; init; }

    public string OperatingSystem { get; init; } = string.Empty;

    public string RuntimeVersion { get; init; } = string.Empty;

    public string WorkspaceMode { get; init; } = string.Empty;

    public string SessionId { get; init; } = string.Empty;

    public string ViewerLifecycleState { get; init; } = string.Empty;

    public bool? AgentConnectedSnapshot { get; init; }

    public bool? CaptureActiveSnapshot { get; init; }

    public string OperationalStateAuthority { get; init; } =
        "Viewer-side snapshot only; confirm agent and capture state after restart.";

    public bool WasTruncated { get; init; }

    public CrashExceptionDetails Exception { get; init; } = new();
}

public sealed record CrashDiagnosticWriteResult
{
    public string IncidentId { get; init; } = string.Empty;

    public DateTimeOffset TimestampUtc { get; init; }

    public string? DiagnosticPath { get; init; }

    public string? WriteFailure { get; init; }

    public bool IsDuplicate { get; init; }

    public ViewerCrashIncident? Incident { get; init; }
}

public sealed record CrashDiagnosticServiceOptions
{
    public const int DefaultMaximumRecordBytes = 256 * 1024;
    public const int DefaultMaximumTextCharacters = 16 * 1024;
    public const int DefaultMaximumExceptionDepth = 8;
    public const int DefaultMaximumAggregateChildren = 16;
    public const int DefaultRetentionFileCount = 25;

    public int MaximumRecordBytes { get; init; } = DefaultMaximumRecordBytes;

    public int MaximumTextCharacters { get; init; } = DefaultMaximumTextCharacters;

    public int MaximumExceptionDepth { get; init; } = DefaultMaximumExceptionDepth;

    public int MaximumAggregateChildren { get; init; } = DefaultMaximumAggregateChildren;

    public int RetentionFileCount { get; init; } = DefaultRetentionFileCount;

    public TimeSpan RetentionAge { get; init; } = TimeSpan.FromDays(30);

    public Func<DateTimeOffset>? UtcNowProvider { get; init; }

    public Func<string>? IncidentIdProvider { get; init; }

    public Func<CrashDiagnosticContext, IReadOnlyList<string>>? DestinationResolver { get; init; }
}

/// <summary>
/// Dependency-light, synchronous writer used only at global viewer exception
/// boundaries. It never transmits reports and never opens an evidence database.
/// </summary>
public sealed class CrashDiagnosticService
{
    public const string IncidentFilePrefix = "viewer-crash-";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private readonly object _recordGate = new();
    private readonly ConditionalWeakTable<Exception, CrashDiagnosticWriteResult> _recordedExceptions = new();
    private readonly CrashDiagnosticServiceOptions _options;

    public CrashDiagnosticService(CrashDiagnosticServiceOptions? options = null)
    {
        var supplied = options ?? new CrashDiagnosticServiceOptions();
        _options = supplied with
        {
            MaximumRecordBytes = Math.Clamp(supplied.MaximumRecordBytes, 4 * 1024, 1024 * 1024),
            MaximumTextCharacters = Math.Clamp(supplied.MaximumTextCharacters, 256, 64 * 1024),
            MaximumExceptionDepth = Math.Clamp(supplied.MaximumExceptionDepth, 1, 16),
            MaximumAggregateChildren = Math.Clamp(supplied.MaximumAggregateChildren, 1, 64),
            RetentionFileCount = Math.Clamp(supplied.RetentionFileCount, 1, 500),
            RetentionAge = supplied.RetentionAge <= TimeSpan.Zero
                ? TimeSpan.FromDays(30)
                : supplied.RetentionAge
        };
    }

    /// <summary>
    /// Best-effort and non-throwing. Recording the same exception object through
    /// multiple global handlers returns the original incident and does not write
    /// another file.
    /// </summary>
    public CrashDiagnosticWriteResult Record(
        Exception exception,
        CrashDiagnosticEntryPoint entryPoint,
        CrashDiagnosticContext? context = null)
    {
        ArgumentNullException.ThrowIfNull(exception);
        context ??= new CrashDiagnosticContext();

        lock (_recordGate)
        {
            if (_recordedExceptions.TryGetValue(exception, out var existing))
            {
                return existing with { IsDuplicate = true };
            }

            CrashDiagnosticWriteResult result;
            try
            {
                result = RecordCore(exception, entryPoint, context);
            }
            catch (Exception writerFailure)
            {
                var timestamp = GetUtcNow();
                result = new CrashDiagnosticWriteResult
                {
                    IncidentId = CreateIncidentId(timestamp),
                    TimestampUtc = timestamp,
                    WriteFailure = CrashDiagnosticSanitizer.Sanitize(
                        writerFailure.Message,
                        Math.Min(_options.MaximumTextCharacters, 1024))
                };
            }

            try
            {
                _recordedExceptions.Add(exception, result);
            }
            catch
            {
                // Duplicate suppression is best-effort if the runtime refuses a
                // weak-table insertion during a terminal failure.
            }

            return result;
        }
    }

    private CrashDiagnosticWriteResult RecordCore(
        Exception exception,
        CrashDiagnosticEntryPoint entryPoint,
        CrashDiagnosticContext context)
    {
        var timestamp = GetUtcNow();
        var incidentId = CreateIncidentId(timestamp);
        var incident = BuildIncident(exception, entryPoint, context, timestamp, incidentId);
        var payload = SerializeBounded(incident, out incident);
        var failures = new List<string>();

        foreach (var directory in ResolveDestinations(context))
        {
            try
            {
                var diagnosticPath = WriteAtomically(directory, incidentId, timestamp, payload);
                EnforceRetention(directory, diagnosticPath, timestamp);
                return new CrashDiagnosticWriteResult
                {
                    IncidentId = incidentId,
                    TimestampUtc = timestamp,
                    DiagnosticPath = diagnosticPath,
                    Incident = incident
                };
            }
            catch (Exception ex) when (IsExpectedFileFailure(ex))
            {
                failures.Add(CrashDiagnosticSanitizer.Sanitize(ex.Message, 512));
            }
        }

        return new CrashDiagnosticWriteResult
        {
            IncidentId = incidentId,
            TimestampUtc = timestamp,
            Incident = incident,
            WriteFailure = failures.Count == 0
                ? "No crash diagnostic destination was available."
                : string.Join(" | ", failures.Select(value => CrashDiagnosticSanitizer.Truncate(value, 512)))
        };
    }

    private ViewerCrashIncident BuildIncident(
        Exception exception,
        CrashDiagnosticEntryPoint entryPoint,
        CrashDiagnosticContext context,
        DateTimeOffset timestamp,
        string incidentId)
    {
        var assembly = Assembly.GetEntryAssembly() ?? typeof(CrashDiagnosticService).Assembly;
        return new ViewerCrashIncident
        {
            IncidentId = incidentId,
            TimestampUtc = timestamp,
            EntryPoint = entryPoint,
            ProductDisplayName = ProductIdentity.DisplayName,
            FormerCompatibilityName = ProductIdentity.FormerName,
            InformationalVersion = GetInformationalVersion(assembly),
            FileVersion = GetFileVersion(assembly),
            EducationalReleaseId = CurrentEducationalReleaseProfile.RuntimeCatalog.ReleaseId,
            ProcessId = Environment.ProcessId,
            ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
            IsElevated = TryGetElevationState(),
            OperatingSystem = CrashDiagnosticSanitizer.Sanitize(
                RuntimeInformation.OSDescription,
                _options.MaximumTextCharacters),
            RuntimeVersion = CrashDiagnosticSanitizer.Sanitize(
                RuntimeInformation.FrameworkDescription,
                _options.MaximumTextCharacters),
            WorkspaceMode = context.WorkspaceMode.ToString(),
            SessionId = CrashDiagnosticSanitizer.Sanitize(context.SessionId, 512),
            ViewerLifecycleState = CrashDiagnosticSanitizer.Sanitize(context.ViewerLifecycleState, 256),
            AgentConnectedSnapshot = context.AgentConnectedSnapshot,
            CaptureActiveSnapshot = context.CaptureActiveSnapshot,
            Exception = BuildExceptionDetails(
                exception,
                depth: 0,
                new HashSet<Exception>(ReferenceEqualityComparer.Instance),
                new ExceptionNodeBudget(_options.MaximumExceptionDepth * (_options.MaximumAggregateChildren + 1)))
        };
    }

    private CrashExceptionDetails BuildExceptionDetails(
        Exception exception,
        int depth,
        HashSet<Exception> visited,
        ExceptionNodeBudget budget)
    {
        if (depth >= _options.MaximumExceptionDepth || budget.Remaining <= 0 || !visited.Add(exception))
        {
            return new CrashExceptionDetails
            {
                Type = exception.GetType().FullName ?? exception.GetType().Name,
                Message = "[exception detail truncated]",
                HResult = exception.HResult
            };
        }

        budget.Remaining--;
        var aggregateChildren = exception is AggregateException aggregate
            ? aggregate.InnerExceptions
                .Take(_options.MaximumAggregateChildren)
                .Select(child => BuildExceptionDetails(child, depth + 1, visited, budget))
                .ToArray()
            : Array.Empty<CrashExceptionDetails>();

        return new CrashExceptionDetails
        {
            Type = exception.GetType().FullName ?? exception.GetType().Name,
            Message = CrashDiagnosticSanitizer.Sanitize(exception.Message, _options.MaximumTextCharacters),
            StackTrace = CrashDiagnosticSanitizer.Sanitize(exception.StackTrace, _options.MaximumTextCharacters),
            HResult = exception.HResult,
            InnerException = exception.InnerException == null
                ? null
                : BuildExceptionDetails(exception.InnerException, depth + 1, visited, budget),
            AggregateChildren = aggregateChildren
        };
    }

    private byte[] SerializeBounded(
        ViewerCrashIncident original,
        out ViewerCrashIncident writtenIncident)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(original, JsonOptions);
        if (payload.Length <= _options.MaximumRecordBytes)
        {
            writtenIncident = original;
            return payload;
        }

        var compact = original with
        {
            WasTruncated = true,
            OperatingSystem = CrashDiagnosticSanitizer.Truncate(original.OperatingSystem, 512),
            RuntimeVersion = CrashDiagnosticSanitizer.Truncate(original.RuntimeVersion, 512),
            Exception = CompactException(original.Exception, depth: 0, maximumDepth: 3, maximumChildren: 4, 1024)
        };
        payload = JsonSerializer.SerializeToUtf8Bytes(compact, JsonOptions);
        if (payload.Length <= _options.MaximumRecordBytes)
        {
            writtenIncident = compact;
            return payload;
        }

        var minimal = compact with
        {
            OperatingSystem = CrashDiagnosticSanitizer.Truncate(compact.OperatingSystem, 128),
            RuntimeVersion = CrashDiagnosticSanitizer.Truncate(compact.RuntimeVersion, 128),
            Exception = new CrashExceptionDetails
            {
                Type = CrashDiagnosticSanitizer.Truncate(compact.Exception.Type, 256),
                Message = CrashDiagnosticSanitizer.Truncate(compact.Exception.Message, 512),
                StackTrace = CrashDiagnosticSanitizer.Truncate(compact.Exception.StackTrace, 512),
                HResult = compact.Exception.HResult
            }
        };
        payload = JsonSerializer.SerializeToUtf8Bytes(minimal, JsonOptions);
        writtenIncident = minimal;
        return payload;
    }

    private static CrashExceptionDetails CompactException(
        CrashExceptionDetails source,
        int depth,
        int maximumDepth,
        int maximumChildren,
        int maximumTextCharacters)
    {
        if (depth >= maximumDepth)
        {
            return new CrashExceptionDetails
            {
                Type = CrashDiagnosticSanitizer.Truncate(source.Type, 256),
                Message = "[exception detail truncated]",
                HResult = source.HResult
            };
        }

        return new CrashExceptionDetails
        {
            Type = CrashDiagnosticSanitizer.Truncate(source.Type, 256),
            Message = CrashDiagnosticSanitizer.Truncate(source.Message, maximumTextCharacters),
            StackTrace = CrashDiagnosticSanitizer.Truncate(source.StackTrace, maximumTextCharacters),
            HResult = source.HResult,
            InnerException = source.InnerException == null
                ? null
                : CompactException(
                    source.InnerException,
                    depth + 1,
                    maximumDepth,
                    maximumChildren,
                    maximumTextCharacters),
            AggregateChildren = source.AggregateChildren
                .Take(maximumChildren)
                .Select(child => CompactException(
                    child,
                    depth + 1,
                    maximumDepth,
                    maximumChildren,
                    maximumTextCharacters))
                .ToArray()
        };
    }

    private IReadOnlyList<string> ResolveDestinations(CrashDiagnosticContext context)
    {
        try
        {
            var resolved = _options.DestinationResolver?.Invoke(context) ??
                SessionPathService.GetViewerCrashDiagnosticDirectories(
                    context.ActiveSessionPaths,
                    context.WorkspaceMode);
            return resolved
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(path => Path.GetFullPath(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string WriteAtomically(
        string directory,
        string incidentId,
        DateTimeOffset timestamp,
        byte[] payload)
    {
        Directory.CreateDirectory(directory);
        var finalPath = Path.Combine(directory, $"{IncidentFilePrefix}{incidentId}.json");
        var temporaryPath = Path.Combine(directory, $".{IncidentFilePrefix}{incidentId}-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 16 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(payload);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, finalPath, overwrite: false);
            try
            {
                File.SetLastWriteTimeUtc(finalPath, timestamp.UtcDateTime);
            }
            catch
            {
                // Retention still has creation/last-write metadata from the OS.
            }

            return finalPath;
        }
        catch
        {
            TryDelete(temporaryPath);
            throw;
        }
    }

    private void EnforceRetention(
        string directory,
        string currentPath,
        DateTimeOffset now)
    {
        try
        {
            var cutoff = now.UtcDateTime - _options.RetentionAge;
            var files = new DirectoryInfo(directory)
                .EnumerateFiles($"{IncidentFilePrefix}*.json", SearchOption.TopDirectoryOnly)
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .ThenByDescending(file => file.Name, StringComparer.Ordinal)
                .ToArray();

            foreach (var file in files)
            {
                if (string.Equals(file.FullName, currentPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (file.LastWriteTimeUtc < cutoff ||
                    Array.IndexOf(files, file) >= _options.RetentionFileCount)
                {
                    TryDelete(file.FullName);
                }
            }
        }
        catch
        {
            // Retention must never turn a successfully written incident into a
            // second failure in the global exception path.
        }
    }

    private DateTimeOffset GetUtcNow()
    {
        try
        {
            return (_options.UtcNowProvider?.Invoke() ?? DateTimeOffset.UtcNow).ToUniversalTime();
        }
        catch
        {
            return DateTimeOffset.UtcNow;
        }
    }

    private string CreateIncidentId(DateTimeOffset timestamp)
    {
        try
        {
            var supplied = _options.IncidentIdProvider?.Invoke();
            if (!string.IsNullOrWhiteSpace(supplied))
            {
                return SanitizeIncidentId(supplied);
            }
        }
        catch
        {
            // Fall back to the local stable identifier below.
        }

        return $"{timestamp:yyyyMMddTHHmmssfffZ}-{Guid.NewGuid():N}";
    }

    private static string SanitizeIncidentId(string value)
    {
        var builder = new StringBuilder(Math.Min(value.Length, 96));
        foreach (var character in value.Take(96))
        {
            builder.Append(char.IsLetterOrDigit(character) || character is '-' or '_'
                ? character
                : '_');
        }

        return builder.Length == 0 ? Guid.NewGuid().ToString("N") : builder.ToString();
    }

    private static string GetInformationalVersion(Assembly assembly)
        => CrashDiagnosticSanitizer.Sanitize(
            assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ??
            assembly.GetName().Version?.ToString() ??
            "unknown",
            512);

    private static string GetFileVersion(Assembly assembly)
    {
        try
        {
            return CrashDiagnosticSanitizer.Sanitize(
                FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion ?? "unknown",
                512);
        }
        catch
        {
            return "unknown";
        }
    }

    private static bool? TryGetElevationState()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsExpectedFileFailure(Exception exception)
        => exception is IOException or UnauthorizedAccessException or NotSupportedException or
            System.Security.SecurityException or ArgumentException;

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup only.
        }
    }

    private sealed class ExceptionNodeBudget(int remaining)
    {
        public int Remaining { get; set; } = Math.Max(remaining, 1);
    }
}

internal static partial class CrashDiagnosticSanitizer
{
    private const string Redacted = "[REDACTED]";

    [GeneratedRegex(
        "(?i)\\b(?:authorization)\\s*[:=]\\s*(?:bearer\\s+)?[^\\r\\n;]*",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 100)]
    private static partial Regex AuthorizationRegex();

    [GeneratedRegex(
        "(?i)\\bbearer\\s+[A-Za-z0-9._~+/=-]+",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 100)]
    private static partial Regex BearerRegex();

    [GeneratedRegex(
        "(?i)\\b(?:api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|token|password|passwd|pwd|client[-_ ]?secret|secret|dpapi[-_ ]?(?:secret|payload))\\s*[:=]\\s*[^\\r\\n;]*",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 100)]
    private static partial Regex SecretRegex();

    [GeneratedRegex(
        "(?i)\\b(?:command[-_ ]?line|cmdline|analyst[-_ ]?(?:note|annotation)|annotation[-_ ]?text|raw[-_ ]?(?:event[-_ ]?)?payload|event[-_ ]?payload|memory[-_ ]?(?:content|contents|bytes)|packet[-_ ]?(?:content|contents|bytes)|ai[-_ ]?(?:prompt|response)|prompt|response|sqlite[-_ ]?(?:row|rows|dump)|capture[-_ ]?(?:database[-_ ]?)?contents?|imported[-_ ]?artifact[-_ ]?contents?)\\s*[:=]\\s*[^\\r\\n;]*",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 100)]
    private static partial Regex SensitiveContentRegex();

    public static string Sanitize(string? value, int maximumCharacters)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        try
        {
            var bounded = Truncate(value, Math.Max(maximumCharacters, 1));
            bounded = AuthorizationRegex().Replace(bounded, $"Authorization={Redacted}");
            bounded = BearerRegex().Replace(bounded, $"Bearer {Redacted}");
            bounded = SecretRegex().Replace(bounded, match =>
            {
                var separator = match.Value.IndexOfAny([':', '=']);
                var key = separator < 0 ? "secret" : match.Value[..separator].Trim();
                return $"{key}={Redacted}";
            });
            bounded = SensitiveContentRegex().Replace(bounded, match =>
            {
                var separator = match.Value.IndexOfAny([':', '=']);
                var key = separator < 0 ? "sensitive-content" : match.Value[..separator].Trim();
                return $"{key}={Redacted}";
            });
            return new string(bounded
                .Select(character => char.IsControl(character) && character is not '\r' and not '\n' and not '\t'
                    ? ' '
                    : character)
                .ToArray());
        }
        catch
        {
            return "[REDACTED: sanitization failed]";
        }
    }

    public static string Truncate(string? value, int maximumCharacters)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (value.Length <= maximumCharacters)
        {
            return value;
        }

        const string suffix = "...[truncated]";
        var prefixLength = Math.Max(0, maximumCharacters - suffix.Length);
        return value[..prefixLength] + suffix;
    }
}
