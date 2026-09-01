using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProcInsider.Models.Agent;
using ProcInsider.Services;

namespace ProcInsider.Agent;

internal sealed class AgentCaptureConfigurationService
{
    private const string ConfigurationFileName = "agent-capture-configuration.json";
    private const string LifecycleLogFileName = "AgentCaptureLifecycle.jsonl";

    private readonly InvestigationSessionPaths _sessionPaths;
    private readonly AgentConfigurationCheckService _configurationChecks;
    private readonly TextWriter _log;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public AgentCaptureConfigurationService(
        InvestigationSessionPaths sessionPaths,
        AgentConfigurationCheckService configurationChecks,
        TextWriter log)
    {
        _sessionPaths = sessionPaths;
        _configurationChecks = configurationChecks;
        _log = log;
    }

    private string ConfigurationPath => Path.Combine(_sessionPaths.SessionRoot, ConfigurationFileName);

    private string LifecycleLogPath => Path.Combine(_sessionPaths.LogsDirectory, LifecycleLogFileName);

    public AgentCaptureConfiguration GetCaptureConfiguration(GetCaptureConfigurationCommand command)
    {
        var saved = TryReadConfiguration();
        return saved ?? StampConfiguration(_configurationChecks.CreateDefaultCaptureConfiguration(command), command, AgentConfigurationStatus.Draft);
    }

    /// <summary>
    /// Returns only a durable saved configuration so the named-pipe server can
    /// re-evaluate its selected feature families before starting any source.
    /// </summary>
    public AgentCaptureConfiguration? GetSavedCaptureConfigurationForReleasePolicy() =>
        TryReadConfiguration();

    public AgentCaptureConfiguration SaveCaptureConfiguration(SaveCaptureConfigurationCommand command)
    {
        var stamped = StampConfiguration(command.Configuration, command, AgentConfigurationStatus.Saved);
        Directory.CreateDirectory(_sessionPaths.SessionRoot);
        File.WriteAllText(ConfigurationPath, JsonSerializer.Serialize(stamped, _jsonOptions));
        AppendLog(new
        {
            action = "save",
            timestampUtc = DateTime.UtcNow,
            stamped.AgentId,
            stamped.HostId,
            stamped.ConfigurationVersion,
            stamped.ConfigurationHash,
            sourceSummary = BuildSourceSummary(stamped)
        });
        return stamped;
    }

    public AgentArtifactCapturePolicy GetBackgroundArtifactCapturePolicy()
    {
        return TryReadConfiguration()?.ArtifactCapture ?? new AgentArtifactCapturePolicy
        {
            CaptureModules = true,
            CaptureHandles = true,
            CapturePeMetadata = true,
            ScopePolicy = "Default automatic enrichment"
        };
    }

    public AgentConfiguredCaptureStartPlan CreateStartPlan(StartConfiguredCaptureCommand command)
    {
        var startedAtUtc = DateTime.UtcNow;
        var configuration = TryReadConfiguration();
        if (configuration == null)
        {
            return AgentConfiguredCaptureStartPlan.Failure(CreateLifecycleResult(
                command,
                string.Empty,
                AgentCaptureLifecycleAction.Start,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                "No saved capture configuration was found. Configure capture before starting it through the agent."));
        }

        if (command.RequireMatchingHash &&
            !string.IsNullOrWhiteSpace(command.ConfigurationHash) &&
            !string.Equals(command.ConfigurationHash, configuration.ConfigurationHash, StringComparison.OrdinalIgnoreCase))
        {
            return AgentConfiguredCaptureStartPlan.Failure(CreateLifecycleResult(
                command,
                string.Empty,
                AgentCaptureLifecycleAction.Start,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                "Saved capture configuration hash does not match the start command."));
        }

        var check = _configurationChecks.CheckCaptureConfiguration(new CheckCaptureConfigurationCommand
        {
            AgentId = FirstNonEmpty(command.AgentId, configuration.AgentId),
            HostId = FirstNonEmpty(command.HostId, configuration.HostId),
            ConfigurationVersion = configuration.ConfigurationVersion,
            ConfigurationHash = configuration.ConfigurationHash,
            DraftConfiguration = configuration
        });
        if (check.OverallState == AgentConfigurationCheckState.Blocked)
        {
            return AgentConfiguredCaptureStartPlan.Failure(CreateLifecycleResult(
                command,
                string.Empty,
                AgentCaptureLifecycleAction.Start,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                FirstNonEmpty(check.LastError, "Capture configuration check is blocked.")));
        }

        var captureId = FirstNonEmpty(command.CaptureId, BuildCaptureId());
        var liveCommand = CreateLiveCaptureCommand(command, configuration, captureId);
        var startLiveCapture = HasAnyLiveCaptureSource(configuration);
        var startNetworkCapture = configuration.NetworkCapture.Enabled;
        var queueArtifactEnrichment = AgentEnrichmentPlanning.ShouldQueue(configuration.ArtifactCapture);

        if (!startLiveCapture && !startNetworkCapture && !queueArtifactEnrichment)
        {
            return AgentConfiguredCaptureStartPlan.Failure(CreateLifecycleResult(
                command,
                captureId,
                AgentCaptureLifecycleAction.Start,
                startedAtUtc,
                AgentConfigurationOperationStatus.Failed,
                "Capture configuration has no enabled evidence source."));
        }

        var sourceSummary = BuildSourceSummary(configuration);
        var lifecycle = CreateLifecycleResult(
            command,
            captureId,
            AgentCaptureLifecycleAction.Start,
            startedAtUtc,
            AgentConfigurationOperationStatus.Success,
            $"Started configured capture. Sources: {sourceSummary}.");
        AppendLog(lifecycle);

        return AgentConfiguredCaptureStartPlan.Success(
            lifecycle,
            startLiveCapture ? liveCommand : null,
            startNetworkCapture,
            FirstNonEmpty(configuration.NetworkCapture.OutputDirectory, _sessionPaths.NetworkCapturesDirectory),
            queueArtifactEnrichment,
            configuration.ArtifactCapture.CaptureModules,
            configuration.ArtifactCapture.CaptureHandles,
            configuration.ArtifactCapture.CapturePeMetadata);
    }

    public AgentCaptureLifecycleResult CreateStopResult(
        StopConfiguredCaptureCommand command,
        AgentConfigurationOperationStatus status,
        string message)
    {
        var now = DateTime.UtcNow;
        var configuration = TryReadConfiguration();
        var captureId = FirstNonEmpty(command.CaptureId, string.Empty);
        var result = new AgentCaptureLifecycleResult
        {
            AgentId = FirstNonEmpty(command.AgentId, configuration?.AgentId, "local"),
            HostId = FirstNonEmpty(command.HostId, configuration?.HostId, Environment.MachineName),
            CaptureId = captureId,
            ConfigurationVersion = FirstNonEmpty(command.ConfigurationVersion, configuration?.ConfigurationVersion),
            ConfigurationHash = FirstNonEmpty(command.ConfigurationHash, configuration?.ConfigurationHash),
            Action = AgentCaptureLifecycleAction.Stop,
            StartedAtUtc = now,
            CompletedAtUtc = null,
            Status = status,
            Message = message,
            LastError = status == AgentConfigurationOperationStatus.Failed ? message : string.Empty
        };
        AppendLog(result);
        return result;
    }

    private AgentCaptureConfiguration? TryReadConfiguration()
    {
        try
        {
            if (!File.Exists(ConfigurationPath))
            {
                return null;
            }

            return JsonSerializer.Deserialize<AgentCaptureConfiguration>(
                File.ReadAllText(ConfigurationPath),
                _jsonOptions);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to read capture configuration: {ex.Message}");
            return null;
        }
    }

    private AgentCaptureConfiguration StampConfiguration(
        AgentCaptureConfiguration configuration,
        AgentConfigurationCommand command,
        AgentConfigurationStatus status)
    {
        var updatedUtc = DateTime.UtcNow;
        var stamped = configuration with
        {
            AgentId = FirstNonEmpty(command.AgentId, configuration.AgentId, "local"),
            HostId = FirstNonEmpty(command.HostId, configuration.HostId, Environment.MachineName),
            ConfigurationVersion = FirstNonEmpty(command.ConfigurationVersion, configuration.ConfigurationVersion, "capture-v1"),
            ConfigurationHash = string.Empty,
            UpdatedAtUtc = updatedUtc,
            Status = status,
            LastError = string.Empty
        };

        return stamped with
        {
            ConfigurationHash = ComputeHash(stamped)
        };
    }

    private StartLiveCaptureCommand CreateLiveCaptureCommand(
        StartConfiguredCaptureCommand command,
        AgentCaptureConfiguration configuration,
        string captureId)
    {
        return new StartLiveCaptureCommand
        {
            CommandId = command.CommandId,
            IssuedAtUtc = command.IssuedAtUtc,
            CaptureId = captureId,
            ProcessRefreshIntervalSeconds = Math.Clamp(configuration.RuntimeProcessSnapshots.RefreshIntervalSeconds, 1, 3600),
            EtwProfileId = configuration.Etw.ProfileId,
            EtwProfileDisplayName = configuration.Etw.ProfileDisplayName,
            EtwProfilePath = configuration.Etw.ProfilePath,
            CollectRuntimeEvents = configuration.SourceToggles.Runtime && configuration.RuntimeProcessSnapshots.Enabled,
            CollectEtwEvents = configuration.SourceToggles.Etw,
            CollectSecurityEvents = configuration.SourceToggles.Security,
            CollectPowerShellEvents = configuration.SourceToggles.PowerShell,
            CollectOtherWindowsEvents = configuration.SourceToggles.WindowsOther,
            CollectSysmonEvents = configuration.SourceToggles.Sysmon
        };
    }

    private AgentCaptureLifecycleResult CreateLifecycleResult(
        AgentConfigurationCommand command,
        string captureId,
        AgentCaptureLifecycleAction action,
        DateTime startedAtUtc,
        AgentConfigurationOperationStatus status,
        string message)
    {
        return new AgentCaptureLifecycleResult
        {
            AgentId = FirstNonEmpty(command.AgentId, "local"),
            HostId = FirstNonEmpty(command.HostId, Environment.MachineName),
            CaptureId = captureId,
            ConfigurationVersion = command.ConfigurationVersion,
            ConfigurationHash = command.ConfigurationHash,
            Action = action,
            StartedAtUtc = startedAtUtc,
            CompletedAtUtc = status == AgentConfigurationOperationStatus.Failed ? DateTime.UtcNow : null,
            Status = status,
            Message = message,
            LastError = status == AgentConfigurationOperationStatus.Failed ? message : string.Empty
        };
    }

    private static bool HasAnyLiveCaptureSource(AgentCaptureConfiguration configuration)
    {
        return (configuration.SourceToggles.Runtime && configuration.RuntimeProcessSnapshots.Enabled) ||
               configuration.SourceToggles.Etw ||
               configuration.SourceToggles.Security ||
               configuration.SourceToggles.PowerShell ||
               configuration.SourceToggles.WindowsOther ||
               configuration.SourceToggles.Sysmon;
    }

    private static bool HasAnyArtifactCapture(AgentArtifactCapturePolicy policy)
    {
        return policy.CaptureModules || policy.CaptureHandles || policy.CapturePeMetadata || policy.CaptureDumpMetadata;
    }

    private static string BuildSourceSummary(AgentCaptureConfiguration configuration)
    {
        var sources = new List<string>();
        if (configuration.SourceToggles.Runtime && configuration.RuntimeProcessSnapshots.Enabled)
        {
            sources.Add($"Runtime/{Math.Clamp(configuration.RuntimeProcessSnapshots.RefreshIntervalSeconds, 1, 3600)}s");
        }

        if (configuration.SourceToggles.Etw)
        {
            sources.Add(FirstNonEmpty(configuration.Etw.ProfileDisplayName, configuration.Etw.ProfileId, "ETW"));
        }

        AddIf(sources, configuration.SourceToggles.Security, "Security");
        AddIf(sources, configuration.SourceToggles.PowerShell, "PowerShell");
        AddIf(sources, configuration.SourceToggles.WindowsOther, "WindowsOther");
        AddIf(sources, configuration.SourceToggles.Sysmon, "Sysmon");
        AddIf(sources, configuration.NetworkCapture.Enabled, "Network metadata");
        AddIf(sources, configuration.Zeek.Enabled || configuration.Zeek.RunAfterNetworkCapture, "Zeek");
        AddIf(sources, HasAnyArtifactCapture(configuration.ArtifactCapture), "Artifact enrichment");
        return sources.Count == 0 ? "none" : string.Join(", ", sources);
    }

    private static void AddIf(List<string> values, bool condition, string value)
    {
        if (condition)
        {
            values.Add(value);
        }
    }

    private void AppendLog(object entry)
    {
        try
        {
            Directory.CreateDirectory(_sessionPaths.LogsDirectory);
            File.AppendAllText(LifecycleLogPath, JsonSerializer.Serialize(entry, _jsonOptions) + Environment.NewLine);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.WriteLine($"[{DateTimeOffset.Now:O}] Failed to append capture lifecycle log: {ex.Message}");
        }
    }

    private static string BuildCaptureId()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        return $"capture-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{suffix}";
    }

    private static string ComputeHash(AgentCaptureConfiguration configuration)
    {
        var json = JsonSerializer.Serialize(configuration, AgentJson.JsonOptions);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}

internal sealed record AgentConfiguredCaptureStartPlan(
    bool CanStart,
    AgentCaptureLifecycleResult Lifecycle,
    StartLiveCaptureCommand? LiveCaptureCommand,
    bool StartNetworkCapture,
    string NetworkOutputDirectory,
    bool QueueArtifactEnrichment,
    bool CaptureModules,
    bool CaptureHandles,
    bool CapturePe)
{
    public static AgentConfiguredCaptureStartPlan Success(
        AgentCaptureLifecycleResult lifecycle,
        StartLiveCaptureCommand? liveCaptureCommand,
        bool startNetworkCapture,
        string networkOutputDirectory,
        bool queueArtifactEnrichment,
        bool captureModules,
        bool captureHandles,
        bool capturePe)
    {
        return new AgentConfiguredCaptureStartPlan(
            true,
            lifecycle,
            liveCaptureCommand,
            startNetworkCapture,
            networkOutputDirectory,
            queueArtifactEnrichment,
            captureModules,
            captureHandles,
            capturePe);
    }

    public static AgentConfiguredCaptureStartPlan Failure(AgentCaptureLifecycleResult lifecycle)
    {
        return new AgentConfiguredCaptureStartPlan(
            false,
            lifecycle,
            null,
            false,
            string.Empty,
            false,
            false,
            false,
            false);
    }
}
