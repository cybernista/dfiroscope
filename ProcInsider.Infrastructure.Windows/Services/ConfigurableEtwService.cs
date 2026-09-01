using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>
/// Collects real-time ETW events from bundled Config ETW provider profiles.
/// </summary>
public sealed class ConfigurableEtwService : IDisposable
{
    private const string ConfigDirectoryName = "Config";
    private const string EtwProfileDirectoryName = "Etw";
    private const string ProfileManifestFileName = "profiles.json";
    private const string ConfigRelativePath = @"Config\Etw\balanced-default.json";
    private const string LegacyConfigRelativePath = @"Config\etw-providers.json";
    private static readonly TimeSpan ConfigReloadDelay = TimeSpan.FromMilliseconds(750);

    private readonly IProcessEventContext _processTracker;
    private readonly ProcessEventStore _eventStore;
    private readonly object _sync = new();
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private TraceEventSession? _session;
    private Thread? _processingThread;
    private FileSystemWatcher? _configWatcher;
    private Timer? _reloadTimer;
    private EtwProviderConfiguration _configuration = new();
    private string? _profileId;
    private string? _profilePath;
    private string? _profileDisplayName;
    private bool _isRunning;
    private bool _disposed;

    public ConfigurableEtwService(
        IProcessEventContext processTracker,
        ProcessEventStore eventStore,
        string? profilePath = null,
        string? profileId = null,
        string? profileDisplayName = null)
    {
        _processTracker = processTracker;
        _eventStore = eventStore;
        _profilePath = string.IsNullOrWhiteSpace(profilePath) ? null : profilePath;
        _profileId = string.IsNullOrWhiteSpace(profileId) ? null : profileId;
        _profileDisplayName = string.IsNullOrWhiteSpace(profileDisplayName) ? null : profileDisplayName;
    }

    public string ConfigPath
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(_profilePath))
            {
                return _profilePath;
            }

            var profilePath = ResolveDefaultProfilePath();
            if (!string.IsNullOrWhiteSpace(profilePath))
            {
                return profilePath;
            }

            var configPath = Path.Combine(AppContext.BaseDirectory, ConfigRelativePath);
            return File.Exists(configPath)
                ? configPath
                : Path.Combine(AppContext.BaseDirectory, LegacyConfigRelativePath);
        }
    }

    public string StatusMessage { get; private set; } = "ETW collection is stopped.";

    public void ConfigureProfile(string? profileId, string? profilePath, string? profileDisplayName)
    {
        lock (_sync)
        {
            _profileId = string.IsNullOrWhiteSpace(profileId) ? null : profileId;
            _profilePath = string.IsNullOrWhiteSpace(profilePath) ? null : profilePath;
            _profileDisplayName = string.IsNullOrWhiteSpace(profileDisplayName) ? null : profileDisplayName;

            if (_isRunning)
            {
                StopConfigWatcher();
                StartConfigWatcher();
                RestartSession();
            }
            else
            {
                StatusMessage = $"ETW collection is stopped. Active profile: {GetProfileDisplayName()}.";
            }
        }
    }

    public void Start()
    {
        lock (_sync)
        {
            if (_isRunning || _disposed)
            {
                return;
            }

            _isRunning = true;
            StartConfigWatcher();
            RestartSession();
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _isRunning = false;
            StopConfigWatcher();
            StopSession();
            StatusMessage = "ETW collection is stopped.";
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Stop();
        _reloadTimer?.Dispose();
        _disposed = true;
    }

    private void StartConfigWatcher()
    {
        var directory = Path.GetDirectoryName(ConfigPath);
        var fileName = Path.GetFileName(ConfigPath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return;
        }

        _configWatcher = new FileSystemWatcher(directory, fileName)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime | NotifyFilters.FileName
        };

        _configWatcher.Changed += OnConfigChanged;
        _configWatcher.Created += OnConfigChanged;
        _configWatcher.Renamed += OnConfigChanged;
        _configWatcher.EnableRaisingEvents = true;
    }

    private void StopConfigWatcher()
    {
        if (_configWatcher == null)
        {
            return;
        }

        _configWatcher.Changed -= OnConfigChanged;
        _configWatcher.Created -= OnConfigChanged;
        _configWatcher.Renamed -= OnConfigChanged;
        _configWatcher.Dispose();
        _configWatcher = null;
    }

    private void OnConfigChanged(object sender, FileSystemEventArgs e)
    {
        lock (_sync)
        {
            _reloadTimer ??= new Timer(_ => ReloadFromTimer(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _reloadTimer.Change(ConfigReloadDelay, Timeout.InfiniteTimeSpan);
        }
    }

    private void ReloadFromTimer()
    {
        lock (_sync)
        {
            if (_isRunning)
            {
                RestartSession();
            }
        }
    }

    private void RestartSession()
    {
        var loaded = TryLoadConfiguration(out var configuration, out var errorMessage);
        if (!loaded)
        {
            StatusMessage = _session == null
                ? $"ETW profile error; ETW collection was not started: {errorMessage}"
                : $"ETW profile error; keeping previous ETW session: {errorMessage}";
            return;
        }

        _configuration = configuration;
        StopSession();
        StartSession(configuration);
    }

    private bool TryLoadConfiguration(out EtwProviderConfiguration configuration, out string errorMessage)
    {
        configuration = new EtwProviderConfiguration();
        errorMessage = string.Empty;

        try
        {
            if (!File.Exists(ConfigPath))
            {
                errorMessage = $"Config file not found: {ConfigPath}";
                return false;
            }

            var json = File.ReadAllText(ConfigPath);
            configuration = JsonSerializer.Deserialize<EtwProviderConfiguration>(json, _jsonOptions) ?? new EtwProviderConfiguration();
            configuration.Profile ??= new EtwProfileMetadata();
            configuration.Session ??= new EtwSessionConfiguration();
            configuration.Providers ??= new List<EtwProviderDefinition>();
            foreach (var provider in configuration.Providers)
            {
                provider.Events ??= new List<EtwEventDefinition>();
            }

            return ValidateConfiguration(configuration, out errorMessage);
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            return false;
        }
    }

    private void StartSession(EtwProviderConfiguration configuration)
    {
        try
        {
            var sessionName = EtwSessionIdentity.ResolveSessionName(configuration.Session.Name);

            foreach (var compatibleSessionName in EtwSessionIdentity.GetSessionsToStopBeforeStart(configuration.Session.Name))
            {
                TraceEventSession.GetActiveSession(compatibleSessionName)?.Dispose();
            }
            _session = new TraceEventSession(sessionName)
            {
                StopOnDispose = true,
                BufferSizeMB = Math.Max(1, configuration.Session.BufferSizeKb / 1024)
            };

            var enabledCount = 0;
            var failedProviders = new List<string>();
            foreach (var provider in configuration.Providers.Where(provider => provider.Enabled))
            {
                if (!TryGetProviderIdentity(provider, out var providerIdentity))
                {
                    failedProviders.Add(string.IsNullOrWhiteSpace(provider.Name) ? "<unnamed provider>" : provider.Name);
                    continue;
                }

                try
                {
                    var level = ParseLevel(provider.Level);
                    var keywords = ParseKeywords(provider.KeywordsHex);
                    _session.EnableProvider(providerIdentity, level, keywords);
                    enabledCount++;
                }
                catch (Exception ex)
                {
                    failedProviders.Add($"{GetProviderDisplayName(provider)} ({ex.Message})");
                }
            }

            _session.Source.Dynamic.All += OnEtwEvent;
            _processingThread = new Thread(() =>
            {
                try
                {
                    _session.Source.Process();
                }
                catch
                {
                    // Real-time ETW processing can stop during session disposal or privilege changes.
                }
            })
            {
                IsBackground = true,
                Name = $"{ProductIdentity.DisplayName} ETW"
            };
            _processingThread.Start();

            var profileName = GetProfileDisplayName(configuration);
            StatusMessage = failedProviders.Count == 0
                ? $"ETW collection started with profile '{profileName}' ({enabledCount} providers)."
                : $"ETW collection started with profile '{profileName}' ({enabledCount} providers; failed: {string.Join("; ", failedProviders)}).";
        }
        catch (Exception ex)
        {
            StopSession();
            StatusMessage = $"ETW collection failed to start: {ex.Message}";
        }
    }

    private void StopSession()
    {
        try
        {
            if (_session != null)
            {
                _session.Source.Dynamic.All -= OnEtwEvent;
                _session.Dispose();
                _session = null;
            }

            if (_processingThread != null && _processingThread.IsAlive)
            {
                _processingThread.Join(TimeSpan.FromSeconds(2));
            }
        }
        catch
        {
            // Best-effort shutdown.
        }
        finally
        {
            _processingThread = null;
        }
    }

    private void OnEtwEvent(TraceEvent traceEvent)
    {
        try
        {
            var eventDefinition = FindEventDefinition(traceEvent);
            var timestampUtc = traceEvent.TimeStamp.ToUniversalTime();
            var process = ResolveProcess(traceEvent, eventDefinition, timestampUtc);
            if (process == null)
            {
                return;
            }

            var target = ResolveTarget(traceEvent, eventDefinition, process);
            var action = ResolveAction(traceEvent, eventDefinition);
            var category = ResolveCategory(traceEvent, eventDefinition, action);
            if (action == ProcessEventAction.ImageLoad)
            {
                AddObservedModule(process, target, traceEvent);
            }

            var processEvent = new ProcessEventInfo
            {
                TimestampUtc = timestampUtc,
                ProcessKey = process.GetUniqueKey(),
                ProcessId = process.ProcessId,
                ProcessStartTimeUtc = process.StartTime?.ToUniversalTime(),
                ProcessName = process.ProcessName,
                ParentProcessId = process.ParentProcessId,
                EventCode = (int)traceEvent.ID,
                Category = category,
                Action = action,
                Target = target,
                Summary = $"ETW {traceEvent.ProviderName}/{traceEvent.EventName}: {target}",
                Details = BuildDetails(traceEvent, process),
                RiskFlags = "etw",
                IsInteresting = true
            };

            _eventStore.AddEvent(processEvent);
        }
        catch
        {
            // Ignore malformed provider payloads.
        }
    }

    private ProcessInfo? ResolveProcess(TraceEvent traceEvent, EtwEventDefinition? eventDefinition, DateTime timestampUtc)
    {
        var processId = ResolveProcessId(traceEvent, eventDefinition);
        var processName = ExtractProcessName(traceEvent, eventDefinition);
        var imagePath = ExtractImagePath(traceEvent, eventDefinition);

        if (processId > 0)
        {
            return _processTracker.GetBestProcessMatch(processId, processName ?? imagePath, timestampUtc);
        }

        if (string.IsNullOrWhiteSpace(processName) && string.IsNullOrWhiteSpace(imagePath))
        {
            return null;
        }

        return _processTracker.GetAllProcesses()
            .Where(process => IsProcessNameOrPathMatch(process, processName, imagePath))
            .Where(process => IsProcessAliveAround(process, timestampUtc, TimeSpan.FromSeconds(10)))
            .OrderByDescending(process => process.Status == ProcessStatus.Running ? 1 : 0)
            .ThenByDescending(process => process.StartTime ?? process.EndTime ?? DateTime.MinValue)
            .FirstOrDefault();
    }

    private int ResolveProcessId(TraceEvent traceEvent, EtwEventDefinition? eventDefinition)
    {
        if (eventDefinition != null)
        {
            foreach (var fieldName in eventDefinition.ProcessIdFields)
            {
                var parsed = ParseProcessId(GetPayloadValue(traceEvent, fieldName));
                if (parsed > 0)
                {
                    return parsed;
                }
            }
        }

        foreach (var fieldName in new[]
                 {
                     "ProcessID",
                     "ProcessId",
                     "PID",
                     "Pid",
                     "ClientProcessId",
                     "ClientProcessID",
                     "ClientPID",
                     "SourceProcessId",
                     "SourceProcessID",
                     "TargetProcessId",
                     "TargetProcessID",
                     "CallerProcessId",
                     "CallerProcessID",
                     "SubjectProcessId",
                     "SubjectProcessID"
                 })
        {
            var parsed = ParseProcessId(GetPayloadValue(traceEvent, fieldName));
            if (parsed > 0)
            {
                return parsed;
            }
        }

        return traceEvent.ProcessID;
    }

    private string ResolveTarget(TraceEvent traceEvent, EtwEventDefinition? eventDefinition, ProcessInfo process)
    {
        if (eventDefinition != null)
        {
            foreach (var fieldName in eventDefinition.TargetFields)
            {
                var value = GetPayloadValue(traceEvent, fieldName);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }
        }

        foreach (var fieldName in new[]
                 {
                     "ImageLoaded",
                     "ImageName",
                     "ImagePath",
                     "ProcessName",
                     "QueryName",
                     "Query",
                     "FileName",
                     "FilePath",
                     "FileObject",
                     "Path",
                     "KeyName",
                     "KeyPath",
                     "ObjectName",
                     "Operation",
                     "daddr",
                     "saddr",
                     "CommandLine"
                 })
        {
            var value = GetPayloadValue(traceEvent, fieldName);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return !string.IsNullOrWhiteSpace(process.ProcessPath) ? process.ProcessPath : process.ProcessName;
    }

    private static void AddObservedModule(ProcessInfo process, string modulePath, TraceEvent traceEvent)
    {
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return;
        }

        lock (process.CachedModules)
        {
            if (process.CachedModules.Any(module =>
                    string.Equals(module.FullPath, modulePath, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            var imageBase = GetPayloadValue(traceEvent, "ImageBase") ?? GetPayloadValue(traceEvent, "BaseAddress");
            var imageSize = ParseLong(GetPayloadValue(traceEvent, "ImageSize") ?? GetPayloadValue(traceEvent, "Size"));

            process.CachedModules.Add(new ModuleInfo
            {
                ModuleName = Path.GetFileName(modulePath),
                FullPath = modulePath,
                BaseAddress = string.IsNullOrWhiteSpace(imageBase) ? "<observed by ETW>" : imageBase,
                ModuleMemorySize = imageSize,
                FileVersion = "<observed by ETW>",
                CompanyName = "<not available>",
                Description = $"ETW image load: {traceEvent.ProviderName}/{traceEvent.EventName}",
                Sha256Hash = "<not available>"
            });
        }
    }

    private string BuildDetails(TraceEvent traceEvent, ProcessInfo process)
    {
        var lines = new List<string>
        {
            $"Provider: {traceEvent.ProviderName}",
            $"Event: {traceEvent.EventName}",
            $"Event ID: {(int)traceEvent.ID}",
            $"Opcode: {traceEvent.OpcodeName}",
            $"Level: {traceEvent.Level}",
            $"Process: {process.ProcessName} (PID: {process.ProcessId})",
            $"Thread ID: {traceEvent.ThreadID}",
            string.Empty,
            "Payload:"
        };

        foreach (var payloadName in traceEvent.PayloadNames)
        {
            lines.Add($"{payloadName}: {GetPayloadValue(traceEvent, payloadName)}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private EtwEventDefinition? FindEventDefinition(TraceEvent traceEvent)
    {
        var provider = _configuration.Providers.FirstOrDefault(provider =>
            string.Equals(provider.Name, traceEvent.ProviderName, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(provider.Guid, traceEvent.ProviderGuid.ToString(), StringComparison.OrdinalIgnoreCase));

        return provider?.Events.FirstOrDefault(evt => evt.Id == (int)traceEvent.ID);
    }

    private static bool TryGetProviderIdentity(EtwProviderDefinition provider, out string providerIdentity)
    {
        providerIdentity = string.Empty;
        if (!string.IsNullOrWhiteSpace(provider.Guid) && Guid.TryParse(provider.Guid, out var providerGuid))
        {
            providerIdentity = providerGuid.ToString();
            return true;
        }

        if (!string.IsNullOrWhiteSpace(provider.Name))
        {
            providerIdentity = provider.Name;
            return true;
        }

        return false;
    }

    private static string GetProviderDisplayName(EtwProviderDefinition provider)
    {
        if (!string.IsNullOrWhiteSpace(provider.Name))
        {
            return provider.Name;
        }

        return string.IsNullOrWhiteSpace(provider.Guid) ? "<unnamed provider>" : provider.Guid;
    }

    private string GetProfileDisplayName(EtwProviderConfiguration? configuration = null)
    {
        if (!string.IsNullOrWhiteSpace(_profileDisplayName))
        {
            return _profileDisplayName;
        }

        if (configuration != null && !string.IsNullOrWhiteSpace(configuration.Profile.DisplayName))
        {
            return configuration.Profile.DisplayName;
        }

        if (configuration != null && !string.IsNullOrWhiteSpace(configuration.Profile.Id))
        {
            return configuration.Profile.Id;
        }

        if (!string.IsNullOrWhiteSpace(_profileId))
        {
            return _profileId;
        }

        return Path.GetFileNameWithoutExtension(ConfigPath);
    }

    private static bool ValidateConfiguration(EtwProviderConfiguration configuration, out string errorMessage)
    {
        var errors = new List<string>();

        if (configuration.Session == null)
        {
            errors.Add("session settings are missing");
        }

        if (configuration.Providers.Count == 0)
        {
            errors.Add("no providers are declared");
        }

        var enabledProviders = configuration.Providers.Where(provider => provider.Enabled).ToList();
        if (enabledProviders.Count == 0)
        {
            errors.Add("no providers are enabled");
        }

        foreach (var provider in enabledProviders)
        {
            if (string.IsNullOrWhiteSpace(provider.Name) && string.IsNullOrWhiteSpace(provider.Guid))
            {
                errors.Add("an enabled provider is missing both Name and Guid");
            }

            if (!string.IsNullOrWhiteSpace(provider.Guid) && !Guid.TryParse(provider.Guid, out _))
            {
                errors.Add($"provider '{GetProviderDisplayName(provider)}' has an invalid Guid '{provider.Guid}'");
            }

            if (!Enum.TryParse<TraceEventLevel>(provider.Level, ignoreCase: true, out _))
            {
                errors.Add($"provider '{GetProviderDisplayName(provider)}' has an invalid level '{provider.Level}'");
            }

            if (!TryParseKeywords(provider.KeywordsHex, out _))
            {
                errors.Add($"provider '{GetProviderDisplayName(provider)}' has invalid KeywordsHex '{provider.KeywordsHex}'");
            }

            foreach (var eventDefinition in provider.Events)
            {
                if (!string.IsNullOrWhiteSpace(eventDefinition.Category) &&
                    !Enum.TryParse<ProcessEventCategory>(eventDefinition.Category, ignoreCase: true, out _))
                {
                    errors.Add($"provider '{GetProviderDisplayName(provider)}' event '{eventDefinition.Name}' has invalid category '{eventDefinition.Category}'");
                }

                if (!string.IsNullOrWhiteSpace(eventDefinition.Action) &&
                    !Enum.TryParse<ProcessEventAction>(eventDefinition.Action, ignoreCase: true, out _))
                {
                    errors.Add($"provider '{GetProviderDisplayName(provider)}' event '{eventDefinition.Name}' has invalid action '{eventDefinition.Action}'");
                }
            }
        }

        errorMessage = string.Join("; ", errors);
        return errors.Count == 0;
    }

    private static TraceEventLevel ParseLevel(string? level)
    {
        return Enum.TryParse<TraceEventLevel>(level, ignoreCase: true, out var parsed)
            ? parsed
            : TraceEventLevel.Verbose;
    }

    private static ulong ParseKeywords(string? keywordsHex)
    {
        return TryParseKeywords(keywordsHex, out var parsed) ? parsed : ulong.MaxValue;
    }

    private static bool TryParseKeywords(string? keywordsHex, out ulong keywords)
    {
        if (string.IsNullOrWhiteSpace(keywordsHex))
        {
            keywords = ulong.MaxValue;
            return true;
        }

        var normalized = keywordsHex.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        return ulong.TryParse(normalized, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out keywords);
    }

    private string? ResolveDefaultProfilePath()
    {
        try
        {
            var manifestPath = Path.Combine(
                AppContext.BaseDirectory,
                ConfigDirectoryName,
                EtwProfileDirectoryName,
                ProfileManifestFileName);

            if (!File.Exists(manifestPath))
            {
                return null;
            }

            var json = File.ReadAllText(manifestPath);
            var manifest = JsonSerializer.Deserialize<ConfigProfileManifest>(json, _jsonOptions);
            var profile = manifest?.Profiles?
                .Where(candidate => candidate.Kind == ConfigProfileKind.Etw)
                .OrderByDescending(candidate => candidate.IsDefault)
                .FirstOrDefault();

            if (profile == null || string.IsNullOrWhiteSpace(profile.FilePath))
            {
                return null;
            }

            var manifestDirectory = Path.GetDirectoryName(manifestPath);
            if (string.IsNullOrWhiteSpace(manifestDirectory))
            {
                return null;
            }

            var normalized = profile.FilePath.Replace('/', Path.DirectorySeparatorChar);
            return Path.GetFullPath(Path.Combine(manifestDirectory, normalized));
        }
        catch
        {
            return null;
        }
    }

    private static int ParseProcessId(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return 0;
        }

        var value = rawValue.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsedHex)
                ? parsedHex
                : 0;
        }

        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;
    }

    private static string? GetPayloadValue(TraceEvent traceEvent, string fieldName)
    {
        try
        {
            if (!traceEvent.PayloadNames.Contains(fieldName, StringComparer.OrdinalIgnoreCase))
            {
                return null;
            }

            var actualName = traceEvent.PayloadNames.First(name => string.Equals(name, fieldName, StringComparison.OrdinalIgnoreCase));
            return traceEvent.PayloadByName(actualName)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static ProcessEventCategory ParseCategory(string? category)
    {
        return Enum.TryParse<ProcessEventCategory>(category, ignoreCase: true, out var parsed)
            ? parsed
            : ProcessEventCategory.Etw;
    }

    private static ProcessEventAction ParseAction(string? action)
    {
        return Enum.TryParse<ProcessEventAction>(action, ignoreCase: true, out var parsed)
            ? parsed
            : ProcessEventAction.EtwEvent;
    }

    private static string? ExtractProcessName(TraceEvent traceEvent, EtwEventDefinition? eventDefinition)
    {
        if (eventDefinition != null)
        {
            foreach (var fieldName in eventDefinition.ProcessNameFields)
            {
                var value = GetPayloadValue(traceEvent, fieldName);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }
        }

        return GetPayloadValue(traceEvent, "ProcessName")
            ?? GetPayloadValue(traceEvent, "ImageName")
            ?? GetPayloadValue(traceEvent, "ImagePath")
            ?? GetPayloadValue(traceEvent, "ExePath")
            ?? GetPayloadValue(traceEvent, "Application");
    }

    private static string? ExtractImagePath(TraceEvent traceEvent, EtwEventDefinition? eventDefinition)
    {
        if (eventDefinition != null)
        {
            foreach (var fieldName in eventDefinition.ImagePathFields)
            {
                var value = GetPayloadValue(traceEvent, fieldName);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }
        }

        return GetPayloadValue(traceEvent, "ImageName")
            ?? GetPayloadValue(traceEvent, "ImagePath")
            ?? GetPayloadValue(traceEvent, "ProcessName")
            ?? GetPayloadValue(traceEvent, "FileName")
            ?? GetPayloadValue(traceEvent, "Path");
    }

    private static bool IsProcessNameOrPathMatch(ProcessInfo process, string? processName, string? imagePath)
    {
        if (!string.IsNullOrWhiteSpace(imagePath))
        {
            if (string.Equals(process.ProcessPath, imagePath, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(process.ProcessName, Path.GetFileNameWithoutExtension(imagePath), StringComparison.OrdinalIgnoreCase) ||
                string.Equals(process.ProcessName, Path.GetFileName(imagePath), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (string.IsNullOrWhiteSpace(processName))
        {
            return false;
        }

        return string.Equals(process.ProcessName, processName, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(process.ProcessName, Path.GetFileNameWithoutExtension(processName), StringComparison.OrdinalIgnoreCase) ||
               string.Equals(process.ProcessPath, processName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsProcessAliveAround(ProcessInfo process, DateTime timestampUtc, TimeSpan tolerance)
    {
        var timestampLocal = timestampUtc.ToLocalTime();
        var startsBefore = !process.StartTime.HasValue || process.StartTime.Value <= timestampLocal.Add(tolerance);
        var endsAfter = !process.EndTime.HasValue || process.EndTime.Value >= timestampLocal.Subtract(tolerance);
        return startsBefore && endsAfter;
    }

    private static ProcessEventAction ResolveAction(TraceEvent traceEvent, EtwEventDefinition? eventDefinition)
    {
        var configured = ParseAction(eventDefinition?.Action);
        if (configured != ProcessEventAction.EtwEvent)
        {
            return configured;
        }

        var provider = traceEvent.ProviderName ?? string.Empty;
        var eventName = traceEvent.EventName ?? string.Empty;
        if (provider.Contains("Image", StringComparison.OrdinalIgnoreCase) ||
            eventName.Contains("ImageLoad", StringComparison.OrdinalIgnoreCase) ||
            (eventName.Contains("Load", StringComparison.OrdinalIgnoreCase) &&
             HasAnyPayload(traceEvent, "ImageLoaded", "ImageName", "ImageBase")))
        {
            return ProcessEventAction.ImageLoad;
        }

        if (provider.Contains("DNS", StringComparison.OrdinalIgnoreCase) ||
            HasAnyPayload(traceEvent, "QueryName", "Query"))
        {
            return ProcessEventAction.DnsQuery;
        }

        if (provider.Contains("WMI", StringComparison.OrdinalIgnoreCase))
        {
            return ProcessEventAction.WmiEvent;
        }

        return ProcessEventAction.EtwEvent;
    }

    private static ProcessEventCategory ResolveCategory(TraceEvent traceEvent, EtwEventDefinition? eventDefinition, ProcessEventAction action)
    {
        var configured = ParseCategory(eventDefinition?.Category);
        if (configured != ProcessEventCategory.Etw)
        {
            return configured;
        }

        return action switch
        {
            ProcessEventAction.ImageLoad => ProcessEventCategory.Process,
            ProcessEventAction.DnsQuery => ProcessEventCategory.Dns,
            ProcessEventAction.WmiEvent => ProcessEventCategory.Wmi,
            ProcessEventAction.RegistryCreateKey or
            ProcessEventAction.RegistrySetValue or
            ProcessEventAction.RegistryDeleteKey or
            ProcessEventAction.RegistryDeleteValue or
            ProcessEventAction.RegistryRenameKey or
            ProcessEventAction.RegistryRenameValue => ProcessEventCategory.Registry,
            ProcessEventAction.FileCreate or
            ProcessEventAction.FileWrite or
            ProcessEventAction.FileRename or
            ProcessEventAction.FileDelete => ProcessEventCategory.File,
            _ => ProcessEventCategory.Etw
        };
    }

    private static bool HasAnyPayload(TraceEvent traceEvent, params string[] fieldNames)
    {
        return fieldNames.Any(fieldName => traceEvent.PayloadNames.Contains(fieldName, StringComparer.OrdinalIgnoreCase));
    }

    private static long ParseLong(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return 0;
        }

        var value = rawValue.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return long.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsedHex)
                ? parsedHex
                : 0;
        }

        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;
    }
}
