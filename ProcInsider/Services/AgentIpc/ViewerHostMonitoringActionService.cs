using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using ProcInsider.Models;
using ProcInsider.Models.Agent;

namespace ProcInsider.Services.AgentIpc;

public enum ViewerHostMonitoringActionKind
{
    Unknown = 0,
    GetConfiguration = 1,
    CheckConfiguration = 2,
    SaveConfiguration = 3,
    DeployConfiguration = 4,
    ReverseDeployment = 5
}

public enum ViewerHostMonitoringActionOutcome
{
    Unknown = 0,
    Succeeded = 1,
    Rejected = 2,
    Unavailable = 3,
    AgentRejected = 4,
    TimedOut = 5,
    Canceled = 6,
    Superseded = 7,
    InternalFailure = 8
}

public sealed record ViewerHostMonitoringActionTarget(
    string AgentId,
    string HostId,
    string SessionId,
    string SessionRoot,
    long WorkspaceGeneration,
    bool RequireViewerConnection = false);

public sealed record ViewerHostMonitoringActionResult
{
    public ViewerHostMonitoringActionKind Action { get; init; }

    public ViewerHostMonitoringActionOutcome Outcome { get; init; }

    public bool Succeeded => Outcome == ViewerHostMonitoringActionOutcome.Succeeded;

    public string ErrorCode { get; init; } = string.Empty;

    public string Diagnostic { get; init; } = string.Empty;

    public bool IsRetryable { get; init; }

    public AgentIpcResponse? Response { get; init; }
}

public interface IViewerHostMonitoringActionRuntime
{
    bool IsCurrent(ViewerHostMonitoringActionTarget target);

    Task<AgentIpcResponse?> ExecuteCommandAsync(
        AgentCommand command,
        string action,
        bool requireViewerConnection,
        CancellationToken cancellationToken);
}

public sealed class DelegateViewerHostMonitoringActionRuntime(
    Func<ViewerHostMonitoringActionTarget, bool> isCurrent,
    Func<AgentCommand, string, bool, CancellationToken, Task<AgentIpcResponse?>> executeCommandAsync)
    : IViewerHostMonitoringActionRuntime
{
    private readonly Func<ViewerHostMonitoringActionTarget, bool> _isCurrent =
        isCurrent ?? throw new ArgumentNullException(nameof(isCurrent));
    private readonly Func<AgentCommand, string, bool, CancellationToken, Task<AgentIpcResponse?>> _executeCommandAsync =
        executeCommandAsync ?? throw new ArgumentNullException(nameof(executeCommandAsync));

    public bool IsCurrent(ViewerHostMonitoringActionTarget target) => _isCurrent(target);

    public Task<AgentIpcResponse?> ExecuteCommandAsync(
        AgentCommand command,
        string action,
        bool requireViewerConnection,
        CancellationToken cancellationToken) =>
        _executeCommandAsync(command, action, requireViewerConnection, cancellationToken);
}

/// <summary>
/// Shared headless application owner for agent-backed host-monitoring configuration.
/// It validates one exact live target and typed draft, while the elevated agent remains
/// the only owner of check, persistence, deployment, reversal, and baseline behavior.
/// </summary>
public sealed class ViewerHostMonitoringActionService
{
    public const long MaximumConfigurationFileBytes = 256 * 1024;
    public const int MaximumCollectionItems = 128;

    private const int MaximumIdentifierLength = 128;
    private const int MaximumDisplayNameLength = 256;
    private const int MaximumPathLength = 1024;
    private const int MaximumScheduleLength = 512;
    private const int MaximumScheduleItems = 32;
    private const int MaximumScheduleSeconds = 86400;

    private static readonly string[] SupportedConfigurationVersions =
    [
        "viewer-current-monitoring",
        "monitoring-default-v1",
        "monitoring-v1"
    ];

    private static readonly string[] SupportedEventLogs =
    [
        "Security",
        "System",
        "Application",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational"
    ];

    private static readonly Regex ScheduleTokenPattern = new(
        "^[1-9][0-9]{0,5}[smh]$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private readonly IViewerHostMonitoringActionRuntime _runtime;
    private readonly ConfigProfileService _profiles;

    public ViewerHostMonitoringActionService(
        IViewerHostMonitoringActionRuntime runtime,
        ConfigProfileService? profiles = null)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _profiles = profiles ?? new ConfigProfileService();
    }

    public async Task<ViewerHostMonitoringActionResult> GetConfigurationAsync(
        ViewerHostMonitoringActionTarget target,
        CancellationToken cancellationToken = default)
    {
        var result = await ExecuteCommandAsync(
                ViewerHostMonitoringActionKind.GetConfiguration,
                target,
                new GetHostMonitoringConfigurationCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = "viewer-current-monitoring"
                },
                "get host monitoring configuration",
                cancellationToken)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }

        var configuration = result.Response?.HostMonitoringConfiguration;
        return configuration == null
            ? MissingPayload(
                ViewerHostMonitoringActionKind.GetConfiguration,
                "HostMonitoringConfigurationMissing",
                "The agent accepted the read but returned no host-monitoring configuration.",
                result.Response)
            : ValidateReturnedConfiguration(target, configuration, result);
    }

    public async Task<ViewerHostMonitoringActionResult> CheckSavedConfigurationAsync(
        ViewerHostMonitoringActionTarget target,
        CancellationToken cancellationToken = default)
    {
        var saved = await GetConfigurationAsync(target, cancellationToken).ConfigureAwait(false);
        if (!saved.Succeeded || saved.Response?.HostMonitoringConfiguration == null)
        {
            return saved with { Action = ViewerHostMonitoringActionKind.CheckConfiguration };
        }

        return await CheckConfigurationCoreAsync(
                target,
                saved.Response.HostMonitoringConfiguration,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<ViewerHostMonitoringActionResult> CheckConfigurationAsync(
        ViewerHostMonitoringActionTarget target,
        AgentHostMonitoringConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        var failure = ValidateConfiguration(
            ViewerHostMonitoringActionKind.CheckConfiguration,
            target,
            configuration);
        return failure != null
            ? Task.FromResult(failure)
            : CheckConfigurationCoreAsync(target, configuration, cancellationToken);
    }

    public async Task<ViewerHostMonitoringActionResult> CheckConfigurationFileAsync(
        ViewerHostMonitoringActionTarget target,
        string configurationPath,
        CancellationToken cancellationToken = default)
    {
        var loaded = await LoadConfigurationFileAsync(
                ViewerHostMonitoringActionKind.CheckConfiguration,
                target,
                configurationPath,
                cancellationToken)
            .ConfigureAwait(false);
        return loaded.Result ?? await CheckConfigurationCoreAsync(
                target,
                loaded.Configuration!,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<ViewerHostMonitoringActionResult> SaveConfigurationAsync(
        ViewerHostMonitoringActionTarget target,
        AgentHostMonitoringConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        var failure = ValidateConfiguration(
            ViewerHostMonitoringActionKind.SaveConfiguration,
            target,
            configuration);
        return failure != null
            ? Task.FromResult(failure)
            : SaveConfigurationCoreAsync(target, configuration, cancellationToken);
    }

    public async Task<ViewerHostMonitoringActionResult> SaveConfigurationFileAsync(
        ViewerHostMonitoringActionTarget target,
        string configurationPath,
        CancellationToken cancellationToken = default)
    {
        var loaded = await LoadConfigurationFileAsync(
                ViewerHostMonitoringActionKind.SaveConfiguration,
                target,
                configurationPath,
                cancellationToken)
            .ConfigureAwait(false);
        return loaded.Result ?? await SaveConfigurationCoreAsync(
                target,
                loaded.Configuration!,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ViewerHostMonitoringActionResult> DeploySavedConfigurationAsync(
        ViewerHostMonitoringActionTarget target,
        CancellationToken cancellationToken = default)
    {
        var saved = await GetConfigurationAsync(target, cancellationToken).ConfigureAwait(false);
        if (!saved.Succeeded || saved.Response?.HostMonitoringConfiguration == null)
        {
            return saved with { Action = ViewerHostMonitoringActionKind.DeployConfiguration };
        }

        var configuration = saved.Response.HostMonitoringConfiguration;
        if (!HasExactSavedIdentity(configuration))
        {
            return Rejected(
                ViewerHostMonitoringActionKind.DeployConfiguration,
                "HostMonitoringConfigurationIdentityMissing",
                "The saved host-monitoring configuration has no exact version and hash.");
        }

        var result = await ExecuteCommandAsync(
                ViewerHostMonitoringActionKind.DeployConfiguration,
                target,
                new DeployHostMonitoringConfigurationCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = configuration.ConfigurationVersion,
                    ConfigurationHash = configuration.ConfigurationHash,
                    RequireMatchingHash = true
                },
                "deploy host monitoring configuration",
                cancellationToken)
            .ConfigureAwait(false);
        return ValidateDeploymentResult(
            target,
            configuration,
            AgentMonitoringDeploymentAction.Deploy,
            result);
    }

    public async Task<ViewerHostMonitoringActionResult> ReverseSavedDeploymentAsync(
        ViewerHostMonitoringActionTarget target,
        CancellationToken cancellationToken = default)
    {
        var saved = await GetConfigurationAsync(target, cancellationToken).ConfigureAwait(false);
        if (!saved.Succeeded || saved.Response?.HostMonitoringConfiguration == null)
        {
            return saved with { Action = ViewerHostMonitoringActionKind.ReverseDeployment };
        }

        var configuration = saved.Response.HostMonitoringConfiguration;
        if (!HasExactSavedIdentity(configuration))
        {
            return Rejected(
                ViewerHostMonitoringActionKind.ReverseDeployment,
                "HostMonitoringConfigurationIdentityMissing",
                "The saved host-monitoring configuration has no exact version and hash.");
        }

        var baseline = configuration.OriginalState;
        if (!baseline.BaselineExists ||
            !string.Equals(baseline.AgentId, target.AgentId, StringComparison.Ordinal) ||
            !string.Equals(baseline.HostId, target.HostId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                baseline.ConfigurationHash,
                configuration.ConfigurationHash,
                StringComparison.OrdinalIgnoreCase))
        {
            return Rejected(
                ViewerHostMonitoringActionKind.ReverseDeployment,
                "HostMonitoringBaselineUnavailable",
                "Reverse requires the recorded original-state baseline for the exact agent, host, and saved configuration.");
        }

        var result = await ExecuteCommandAsync(
                ViewerHostMonitoringActionKind.ReverseDeployment,
                target,
                new ReverseHostMonitoringDeploymentCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = configuration.ConfigurationVersion,
                    ConfigurationHash = configuration.ConfigurationHash
                },
                "reverse host monitoring deployment",
                cancellationToken)
            .ConfigureAwait(false);
        return ValidateDeploymentResult(
            target,
            configuration,
            AgentMonitoringDeploymentAction.Reverse,
            result);
    }

    private async Task<ViewerHostMonitoringActionResult> CheckConfigurationCoreAsync(
        ViewerHostMonitoringActionTarget target,
        AgentHostMonitoringConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var configurationHash = IsSha256(configuration.ConfigurationHash)
            ? configuration.ConfigurationHash
            : ComputeCheckHash(configuration);
        var result = await ExecuteCommandAsync(
                ViewerHostMonitoringActionKind.CheckConfiguration,
                target,
                new CheckHostMonitoringConfigurationCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = configuration.ConfigurationVersion,
                    ConfigurationHash = configurationHash,
                    DraftConfiguration = configuration
                },
                "check host monitoring configuration",
                cancellationToken)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }

        var check = result.Response?.ConfigurationCheck;
        if (check == null)
        {
            return MissingPayload(
                ViewerHostMonitoringActionKind.CheckConfiguration,
                "HostMonitoringConfigurationCheckMissing",
                "The agent accepted the check but returned no typed host-monitoring result.",
                result.Response);
        }

        if (check.TargetKind != AgentConfigurationTargetKind.HostMonitoring ||
            !string.Equals(check.AgentId, target.AgentId, StringComparison.Ordinal) ||
            !string.Equals(check.HostId, target.HostId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                check.ConfigurationVersion,
                configuration.ConfigurationVersion,
                StringComparison.Ordinal) ||
            !string.Equals(
                check.ConfigurationHash,
                configurationHash,
                StringComparison.OrdinalIgnoreCase))
        {
            return Rejected(
                ViewerHostMonitoringActionKind.CheckConfiguration,
                "HostMonitoringConfigurationCheckTargetMismatch",
                "The agent returned a host-monitoring check for a different target or configuration.");
        }

        var findings = check.Findings ?? Array.Empty<AgentConfigurationFinding>();
        if (!Enum.IsDefined(check.OverallState) ||
            check.OverallState == AgentConfigurationCheckState.Unknown ||
            findings.Length > MaximumCollectionItems ||
            findings.Any(finding =>
                finding == null ||
                !Enum.IsDefined(finding.Area) ||
                !Enum.IsDefined(finding.Severity)))
        {
            return Rejected(
                ViewerHostMonitoringActionKind.CheckConfiguration,
                "HostMonitoringConfigurationCheckInvalid",
                "The agent returned malformed or unsupported host-monitoring findings.");
        }

        return check.OverallState == AgentConfigurationCheckState.Blocked
            ? result with
            {
                Outcome = ViewerHostMonitoringActionOutcome.Rejected,
                ErrorCode = "HostMonitoringConfigurationCheckBlocked",
                Diagnostic = "The agent reported blocking host-monitoring prerequisites."
            }
            : result;
    }

    private async Task<ViewerHostMonitoringActionResult> SaveConfigurationCoreAsync(
        ViewerHostMonitoringActionTarget target,
        AgentHostMonitoringConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var result = await ExecuteCommandAsync(
                ViewerHostMonitoringActionKind.SaveConfiguration,
                target,
                new SaveHostMonitoringConfigurationCommand
                {
                    AgentId = target.AgentId,
                    HostId = target.HostId,
                    ConfigurationVersion = configuration.ConfigurationVersion,
                    ConfigurationHash = configuration.ConfigurationHash,
                    Configuration = configuration
                },
                "save host monitoring configuration",
                cancellationToken)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }

        var saved = result.Response?.HostMonitoringConfiguration;
        return saved == null
            ? MissingPayload(
                ViewerHostMonitoringActionKind.SaveConfiguration,
                "HostMonitoringConfigurationMissing",
                "The agent accepted the save but returned no host-monitoring configuration.",
                result.Response)
            : ValidateReturnedConfiguration(target, saved, result);
    }

    private async Task<ViewerHostMonitoringActionResult> ExecuteCommandAsync(
        ViewerHostMonitoringActionKind action,
        ViewerHostMonitoringActionTarget target,
        AgentCommand command,
        string description,
        CancellationToken cancellationToken)
    {
        var targetFailure = ValidateTarget(action, target);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        try
        {
            var response = await _runtime.ExecuteCommandAsync(
                    command,
                    description,
                    target.RequireViewerConnection,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!_runtime.IsCurrent(target))
            {
                return Superseded(action);
            }

            if (response == null)
            {
                return Unavailable(
                    action,
                    "AgentUnavailable",
                    "The authenticated local agent did not return a response.");
            }

            if (!response.Success)
            {
                return AgentRejected(action, response);
            }

            return new ViewerHostMonitoringActionResult
            {
                Action = action,
                Outcome = ViewerHostMonitoringActionOutcome.Succeeded,
                Response = response
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Canceled(action);
        }
        catch
        {
            return new ViewerHostMonitoringActionResult
            {
                Action = action,
                Outcome = ViewerHostMonitoringActionOutcome.InternalFailure,
                ErrorCode = "InternalFailure",
                Diagnostic = "The host-monitoring action failed internally."
            };
        }
    }

    private ViewerHostMonitoringActionResult? ValidateTarget(
        ViewerHostMonitoringActionKind action,
        ViewerHostMonitoringActionTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!IsBoundedIdentifier(target.AgentId) ||
            !IsBoundedIdentifier(target.HostId) ||
            !IsBoundedIdentifier(target.SessionId) ||
            string.IsNullOrWhiteSpace(target.SessionRoot) ||
            target.SessionRoot.Length > MaximumPathLength ||
            !Path.IsPathFullyQualified(target.SessionRoot) ||
            target.WorkspaceGeneration <= 0)
        {
            return Rejected(
                action,
                "InvalidHostMonitoringTarget",
                "An exact bounded agent, host, live-session root, session ID, and positive workspace generation are required.");
        }

        return _runtime.IsCurrent(target) ? null : Superseded(action);
    }

    private ViewerHostMonitoringActionResult? ValidateConfiguration(
        ViewerHostMonitoringActionKind action,
        ViewerHostMonitoringActionTarget target,
        AgentHostMonitoringConfiguration? configuration)
    {
        var targetFailure = ValidateTarget(action, target);
        if (targetFailure != null)
        {
            return targetFailure;
        }

        if (configuration == null)
        {
            return Rejected(
                action,
                "HostMonitoringConfigurationMissing",
                "A complete typed host-monitoring configuration is required.");
        }

        if (configuration.Sysmon == null ||
            configuration.SecurityAuditPolicy == null ||
            configuration.EventLogs == null ||
            configuration.PowerShellAuditing == null ||
            configuration.Etw == null ||
            configuration.ScheduledDumps == null ||
            configuration.Deployment == null ||
            configuration.ReverseDeployment == null ||
            configuration.OriginalState == null)
        {
            return Rejected(
                action,
                "HostMonitoringConfigurationFieldInvalid",
                "The host-monitoring configuration must include every typed settings section.");
        }

        if (!string.Equals(configuration.AgentId, target.AgentId, StringComparison.Ordinal) ||
            !string.Equals(configuration.HostId, target.HostId, StringComparison.OrdinalIgnoreCase))
        {
            return Rejected(
                action,
                "HostMonitoringConfigurationTargetMismatch",
                "The configuration agent and host must match the exact authenticated target.");
        }

        if (!SupportedConfigurationVersions.Contains(
                configuration.ConfigurationVersion,
                StringComparer.Ordinal))
        {
            return Rejected(
                action,
                "HostMonitoringConfigurationVersionUnsupported",
                "The host-monitoring configuration version is missing, malformed, or newer than this viewer supports.");
        }

        if (!string.IsNullOrWhiteSpace(configuration.ConfigurationHash) &&
            !IsSha256(configuration.ConfigurationHash))
        {
            return Rejected(
                action,
                "HostMonitoringConfigurationHashInvalid",
                "The host-monitoring configuration hash must be empty or a lowercase/uppercase SHA-256 value.");
        }

        if (!ValidateEnums(configuration))
        {
            return Rejected(
                action,
                "HostMonitoringConfigurationEnumUnsupported",
                "The host-monitoring configuration contains an unknown or future enum value.");
        }

        var fieldFailure = ValidateFields(configuration);
        if (fieldFailure != null)
        {
            return Rejected(action, fieldFailure.Value.Code, fieldFailure.Value.Message);
        }

        var profileFailure = ValidateProfilesAndPaths(target, configuration);
        return profileFailure == null
            ? null
            : Rejected(action, profileFailure.Value.Code, profileFailure.Value.Message);
    }

    private (string Code, string Message)? ValidateFields(
        AgentHostMonitoringConfiguration configuration)
    {
        var boundedValues = new[]
        {
            configuration.Sysmon.ProfileId,
            configuration.SecurityAuditPolicy.PolicyProfileId,
            configuration.EventLogs.ProfileId,
            configuration.PowerShellAuditing.ProfileId,
            configuration.Etw.ProfileId,
            configuration.Etw.SessionName,
            configuration.ScheduledDumps.TargetPolicy
        };
        if (boundedValues.Any(value => !IsOptionalBoundedValue(value, MaximumIdentifierLength)) ||
            !IsOptionalBoundedValue(configuration.Sysmon.ProfileDisplayName, MaximumDisplayNameLength) ||
            !IsOptionalBoundedValue(configuration.SecurityAuditPolicy.PolicyProfileDisplayName, MaximumDisplayNameLength) ||
            !IsOptionalBoundedValue(configuration.EventLogs.ProfileDisplayName, MaximumDisplayNameLength) ||
            !IsOptionalBoundedValue(configuration.Etw.ProfileDisplayName, MaximumDisplayNameLength))
        {
            return (
                "HostMonitoringConfigurationFieldInvalid",
                "A host-monitoring identifier or display field is malformed or exceeds its bound.");
        }

        var channels = configuration.EventLogs.ChannelNames ?? Array.Empty<string>();
        if (channels.Length > SupportedEventLogs.Length ||
            channels.Any(channel =>
                !SupportedEventLogs.Contains(channel, StringComparer.OrdinalIgnoreCase)) ||
            channels.Distinct(StringComparer.OrdinalIgnoreCase).Count() != channels.Length)
        {
            return (
                "HostMonitoringEventLogUnsupported",
                "Event-log configuration contains an unknown or duplicate channel.");
        }

        if ((configuration.Etw.ProviderNames ?? Array.Empty<string>()).Length != 0)
        {
            return (
                "HostMonitoringEtwProviderUnsupported",
                "Direct ETW provider names are not accepted; select a bundled typed profile.");
        }

        if ((configuration.ReverseDeployment.Warnings ?? Array.Empty<string>()).Length > MaximumCollectionItems ||
            (configuration.OriginalState.Areas ?? Array.Empty<AgentMonitoringOriginalStateArea>()).Length > MaximumCollectionItems)
        {
            return (
                "HostMonitoringConfigurationCollectionInvalid",
                "Host-monitoring warning or baseline collections exceed their supported bound.");
        }

        var schedule = configuration.ScheduledDumps;
        if (schedule.IntervalSeconds is < 0 or > MaximumScheduleSeconds ||
            schedule.MaxDumpsPerCapture is < 0 or > MaximumCollectionItems ||
            !TryValidateSchedule(schedule.OffsetsFromCaptureStart))
        {
            return (
                "HostMonitoringScheduleInvalid",
                "Scheduled-dump intervals, offsets, or per-capture bounds are invalid.");
        }

        if (schedule.Enabled &&
            schedule.IntervalSeconds == 0 &&
            string.IsNullOrWhiteSpace(schedule.OffsetsFromCaptureStart))
        {
            return (
                "HostMonitoringScheduleMissing",
                "An enabled scheduled-dump policy requires a bounded interval or offset list.");
        }

        return null;
    }

    private (string Code, string Message)? ValidateProfilesAndPaths(
        ViewerHostMonitoringActionTarget target,
        AgentHostMonitoringConfiguration configuration)
    {
        if (!ValidateProfile(
                ConfigProfileKind.Sysmon,
                configuration.Sysmon.ProfileId,
                configuration.Sysmon.ConfigurationPath,
                configuration.Sysmon.InstallOrUpdate || configuration.Sysmon.VerifyService) ||
            !ValidateProfile(
                ConfigProfileKind.SecurityMonitoring,
                configuration.SecurityAuditPolicy.PolicyProfileId,
                configuration.SecurityAuditPolicy.AuditPolicyPath,
                configuration.SecurityAuditPolicy.ConfigureAuditPolicy) ||
            !ValidateProfile(
                ConfigProfileKind.EventLogs,
                configuration.EventLogs.ProfileId,
                path: string.Empty,
                configuration.EventLogs.ConfigureChannels || configuration.EventLogs.ConfigureRetention) ||
            !ValidateProfile(
                ConfigProfileKind.PowerShellAuditing,
                configuration.PowerShellAuditing.ProfileId,
                path: string.Empty,
                configuration.PowerShellAuditing.EnableScriptBlockLogging ||
                configuration.PowerShellAuditing.EnableModuleLogging ||
                configuration.PowerShellAuditing.EnableTranscription) ||
            !ValidateProfile(
                ConfigProfileKind.Etw,
                configuration.Etw.ProfileId,
                configuration.Etw.ProfilePath,
                configuration.Etw.ConfigureSession))
        {
            return (
                "HostMonitoringProfileUnsupported",
                "A requested monitoring area references an unknown profile or a path outside its bundled profile directory.");
        }

        if (!ValidateOptionalAbsolutePath(configuration.PowerShellAuditing.TranscriptDirectory) ||
            !ValidateSessionOutputPath(target.SessionRoot, configuration.ScheduledDumps.OutputDirectory))
        {
            return (
                "HostMonitoringConfigurationPathInvalid",
                "Transcript and scheduled-dump paths must be bounded absolute paths, and dump output must remain beneath the explicit session root.");
        }

        return null;
    }

    private bool ValidateProfile(
        ConfigProfileKind kind,
        string profileId,
        string path,
        bool required)
    {
        var profiles = _profiles.GetProfiles(kind);
        var profile = string.IsNullOrWhiteSpace(profileId)
            ? null
            : profiles.FirstOrDefault(candidate =>
                string.Equals(candidate.Id, profileId, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(profileId) && profile == null)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!Path.IsPathFullyQualified(path) || path.Length > MaximumPathLength || !File.Exists(path))
            {
                return false;
            }

            var resolvedPaths = profiles
                .Select(_profiles.ResolveProfileFilePath)
                .Where(candidate => !string.IsNullOrWhiteSpace(candidate))
                .Select(candidate => Path.GetFullPath(candidate!))
                .ToArray();
            if (!resolvedPaths.Contains(Path.GetFullPath(path), StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return !required || profile != null || !string.IsNullOrWhiteSpace(path);
    }

    private static bool ValidateOptionalAbsolutePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        try
        {
            return path.Length <= MaximumPathLength && Path.IsPathFullyQualified(path);
        }
        catch (Exception ex) when (ex is
            ArgumentException or
            NotSupportedException or
            PathTooLongException)
        {
            return false;
        }
    }

    private static bool ValidateSessionOutputPath(string sessionRoot, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        try
        {
            if (path.Length > MaximumPathLength || !Path.IsPathFullyQualified(path))
            {
                return false;
            }

            var root = Path.GetFullPath(sessionRoot)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                Path.DirectorySeparatorChar;
            var candidate = Path.GetFullPath(path)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                Path.DirectorySeparatorChar;
            return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is
            ArgumentException or
            NotSupportedException or
            PathTooLongException or
            IOException or
            UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool TryValidateSchedule(string? offsets)
    {
        if (string.IsNullOrWhiteSpace(offsets))
        {
            return true;
        }

        if (offsets.Length > MaximumScheduleLength)
        {
            return false;
        }

        var tokens = offsets.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length is 0 or > MaximumScheduleItems ||
            tokens.Distinct(StringComparer.OrdinalIgnoreCase).Count() != tokens.Length)
        {
            return false;
        }

        return tokens.All(token =>
        {
            if (!ScheduleTokenPattern.IsMatch(token) ||
                !int.TryParse(token[..^1], out var value))
            {
                return false;
            }

            var seconds = char.ToLowerInvariant(token[^1]) switch
            {
                's' => value,
                'm' => value * 60L,
                'h' => value * 3600L,
                _ => long.MaxValue
            };
            return seconds is >= 1 and <= MaximumScheduleSeconds;
        });
    }

    private async Task<ConfigurationFileLoadResult> LoadConfigurationFileAsync(
        ViewerHostMonitoringActionKind action,
        ViewerHostMonitoringActionTarget target,
        string configurationPath,
        CancellationToken cancellationToken)
    {
        var targetFailure = ValidateTarget(action, target);
        if (targetFailure != null)
        {
            return new ConfigurationFileLoadResult(null, targetFailure);
        }

        if (string.IsNullOrWhiteSpace(configurationPath) ||
            !Path.IsPathFullyQualified(configurationPath) ||
            !File.Exists(configurationPath))
        {
            return new ConfigurationFileLoadResult(
                null,
                Rejected(
                    action,
                    "HostMonitoringConfigurationFileUnavailable",
                    "--file must identify an existing absolute JSON file."));
        }

        try
        {
            var info = new FileInfo(configurationPath);
            if (info.Length <= 0 || info.Length > MaximumConfigurationFileBytes)
            {
                return new ConfigurationFileLoadResult(
                    null,
                    Rejected(
                        action,
                        "HostMonitoringConfigurationFileSizeInvalid",
                        $"Host-monitoring JSON must be from 1 through {MaximumConfigurationFileBytes} bytes."));
            }

            var bytes = await File.ReadAllBytesAsync(configurationPath, cancellationToken)
                .ConfigureAwait(false);
            var json = new UTF8Encoding(false, true).GetString(bytes);
            var options = new JsonSerializerOptions(AgentIpcJson.JsonOptions)
            {
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
            };
            options.Converters.Insert(0, new JsonStringEnumConverter(allowIntegerValues: false));
            var configuration = JsonSerializer.Deserialize<AgentHostMonitoringConfiguration>(json, options);
            var failure = ValidateConfiguration(action, target, configuration);
            return failure == null
                ? new ConfigurationFileLoadResult(configuration, null)
                : new ConfigurationFileLoadResult(configuration, failure);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new ConfigurationFileLoadResult(null, Canceled(action));
        }
        catch (Exception ex) when (ex is
            IOException or
            UnauthorizedAccessException or
            DecoderFallbackException or
            JsonException or
            NotSupportedException)
        {
            return new ConfigurationFileLoadResult(
                null,
                Rejected(
                    action,
                    "HostMonitoringConfigurationFileInvalid",
                    "The host-monitoring file is not a current complete bounded UTF-8 JSON document."));
        }
    }

    private ViewerHostMonitoringActionResult ValidateReturnedConfiguration(
        ViewerHostMonitoringActionTarget target,
        AgentHostMonitoringConfiguration configuration,
        ViewerHostMonitoringActionResult result)
    {
        var failure = ValidateConfiguration(result.Action, target, configuration);
        return failure ?? result;
    }

    private static ViewerHostMonitoringActionResult ValidateDeploymentResult(
        ViewerHostMonitoringActionTarget target,
        AgentHostMonitoringConfiguration configuration,
        AgentMonitoringDeploymentAction expectedAction,
        ViewerHostMonitoringActionResult result)
    {
        if (!result.Succeeded)
        {
            return result;
        }

        var deployment = result.Response?.MonitoringDeployment;
        if (deployment == null)
        {
            return MissingPayload(
                result.Action,
                "HostMonitoringDeploymentMissing",
                "The agent accepted the operation but returned no typed per-area deployment result.",
                result.Response);
        }

        var areas = deployment.AreaResults ?? Array.Empty<AgentMonitoringDeploymentAreaResult>();
        var warnings = deployment.Warnings ?? Array.Empty<string>();
        var baseline = deployment.OriginalState;
        if (deployment.Action != expectedAction ||
            !string.Equals(deployment.AgentId, target.AgentId, StringComparison.Ordinal) ||
            !string.Equals(deployment.HostId, target.HostId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                deployment.ConfigurationVersion,
                configuration.ConfigurationVersion,
                StringComparison.Ordinal) ||
            !string.Equals(
                deployment.ConfigurationHash,
                configuration.ConfigurationHash,
                StringComparison.OrdinalIgnoreCase))
        {
            return Rejected(
                result.Action,
                "HostMonitoringDeploymentTargetMismatch",
                "The agent returned deployment results for a different action or saved target.");
        }

        if (!Enum.IsDefined(deployment.Status) ||
            areas.Length > MaximumCollectionItems ||
            warnings.Length > MaximumCollectionItems ||
            areas.Any(area =>
                area == null ||
                !Enum.IsDefined(area.Area) ||
                !Enum.IsDefined(area.Status)) ||
            warnings.Any(warning => warning == null) ||
            baseline == null ||
            !Enum.IsDefined(baseline.LastRevertStatus) ||
            (baseline.Areas ?? Array.Empty<AgentMonitoringOriginalStateArea>()).Length > MaximumCollectionItems ||
            (baseline.Areas ?? Array.Empty<AgentMonitoringOriginalStateArea>()).Any(area =>
                area == null ||
                !Enum.IsDefined(area.Area) ||
                !Enum.IsDefined(area.Status)))
        {
            return Rejected(
                result.Action,
                "HostMonitoringDeploymentResultInvalid",
                "The agent returned malformed or unsupported per-area deployment results.");
        }

        if (areas.Any(area => area.Status == AgentConfigurationOperationStatus.Failed) !=
            (deployment.Status == AgentConfigurationOperationStatus.Failed))
        {
            return Rejected(
                result.Action,
                "HostMonitoringDeploymentResultInvalid",
                "The agent returned an inconsistent overall and per-area deployment status.");
        }

        if (deployment.Status is not
                (AgentConfigurationOperationStatus.Success or
                 AgentConfigurationOperationStatus.Warning))
        {
            return result with
            {
                Outcome = ViewerHostMonitoringActionOutcome.AgentRejected,
                ErrorCode = "HostMonitoringDeploymentFailed",
                Diagnostic = "The agent reported that the host-monitoring operation did not complete successfully."
            };
        }

        return !baseline.BaselineExists ||
               !string.Equals(baseline.AgentId, target.AgentId, StringComparison.Ordinal) ||
               !string.Equals(baseline.HostId, target.HostId, StringComparison.OrdinalIgnoreCase) ||
               !string.Equals(
                   baseline.ConfigurationHash,
                   configuration.ConfigurationHash,
                   StringComparison.OrdinalIgnoreCase)
            ? Rejected(
                result.Action,
                "HostMonitoringDeploymentBaselineMismatch",
                "The agent did not return the exact recorded original-state baseline for the operation.")
            : result;
    }

    private static bool ValidateEnums(AgentHostMonitoringConfiguration configuration) =>
        Enum.IsDefined(configuration.Status) &&
        Enum.IsDefined(configuration.Sysmon.Status) &&
        Enum.IsDefined(configuration.SecurityAuditPolicy.Status) &&
        Enum.IsDefined(configuration.EventLogs.Status) &&
        Enum.IsDefined(configuration.PowerShellAuditing.Status) &&
        Enum.IsDefined(configuration.Etw.Status) &&
        Enum.IsDefined(configuration.ScheduledDumps.Status) &&
        Enum.IsDefined(configuration.Deployment.Status) &&
        Enum.IsDefined(configuration.ReverseDeployment.Status) &&
        Enum.IsDefined(configuration.OriginalState.LastRevertStatus) &&
        (configuration.OriginalState.Areas ?? Array.Empty<AgentMonitoringOriginalStateArea>()).All(area =>
            area != null && Enum.IsDefined(area.Area) && Enum.IsDefined(area.Status));

    private static bool HasExactSavedIdentity(AgentHostMonitoringConfiguration configuration) =>
        SupportedConfigurationVersions.Contains(
            configuration.ConfigurationVersion,
            StringComparer.Ordinal) &&
        IsSha256(configuration.ConfigurationHash);

    private static bool IsBoundedIdentifier(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= MaximumIdentifierLength &&
        value.All(character => !char.IsControl(character));

    private static bool IsOptionalBoundedValue(string? value, int maximumLength) =>
        string.IsNullOrEmpty(value) ||
        value.Length <= maximumLength && value.All(character => !char.IsControl(character));

    private static bool IsSha256(string? value) =>
        value?.Length == 64 && value.All(Uri.IsHexDigit);

    private static string ComputeCheckHash(AgentHostMonitoringConfiguration configuration)
    {
        var json = JsonSerializer.Serialize(configuration, AgentIpcJson.JsonOptions);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)))
            .ToLowerInvariant();
    }

    private static ViewerHostMonitoringActionResult Rejected(
        ViewerHostMonitoringActionKind action,
        string code,
        string diagnostic) =>
        new()
        {
            Action = action,
            Outcome = ViewerHostMonitoringActionOutcome.Rejected,
            ErrorCode = code,
            Diagnostic = diagnostic
        };

    private static ViewerHostMonitoringActionResult Unavailable(
        ViewerHostMonitoringActionKind action,
        string code,
        string diagnostic) =>
        new()
        {
            Action = action,
            Outcome = ViewerHostMonitoringActionOutcome.Unavailable,
            ErrorCode = code,
            Diagnostic = diagnostic,
            IsRetryable = true
        };

    private static ViewerHostMonitoringActionResult AgentRejected(
        ViewerHostMonitoringActionKind action,
        AgentIpcResponse response) =>
        new()
        {
            Action = action,
            Outcome = string.Equals(response.ErrorCode, "AgentTimeout", StringComparison.Ordinal)
                ? ViewerHostMonitoringActionOutcome.TimedOut
                : ViewerHostMonitoringActionOutcome.AgentRejected,
            ErrorCode = FirstNonEmpty(response.ErrorCode, "AgentRejected"),
            Diagnostic = FirstNonEmpty(response.ErrorMessage, "The agent rejected the host-monitoring request."),
            IsRetryable = response.IsRetryable,
            Response = response
        };

    private static ViewerHostMonitoringActionResult MissingPayload(
        ViewerHostMonitoringActionKind action,
        string code,
        string diagnostic,
        AgentIpcResponse? response) =>
        new()
        {
            Action = action,
            Outcome = ViewerHostMonitoringActionOutcome.AgentRejected,
            ErrorCode = code,
            Diagnostic = diagnostic,
            Response = response
        };

    private static ViewerHostMonitoringActionResult Canceled(ViewerHostMonitoringActionKind action) =>
        new()
        {
            Action = action,
            Outcome = ViewerHostMonitoringActionOutcome.Canceled,
            ErrorCode = "Canceled",
            Diagnostic = "The host-monitoring action was canceled."
        };

    private static ViewerHostMonitoringActionResult Superseded(ViewerHostMonitoringActionKind action) =>
        new()
        {
            Action = action,
            Outcome = ViewerHostMonitoringActionOutcome.Superseded,
            ErrorCode = "SessionSuperseded",
            Diagnostic = "The capture workspace changed before the host-monitoring action completed."
        };

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private sealed record ConfigurationFileLoadResult(
        AgentHostMonitoringConfiguration? Configuration,
        ViewerHostMonitoringActionResult? Result);
}
