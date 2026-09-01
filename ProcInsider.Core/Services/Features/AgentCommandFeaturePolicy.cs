using System.Collections.ObjectModel;
using System.Text.Json;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;
using ProcInsider.Services.AgentIpc;

namespace ProcInsider.Services.Features;

/// <summary>
/// Stable error identities for the release-publication boundary. They are
/// intentionally distinct from runtime prerequisite, archived-write, and
/// target-session failures.
/// </summary>
public static class AgentFeaturePolicyErrorCodes
{
    public const string FeatureNotPublished = "FeatureNotPublished";
    public const string ReleaseProfileMismatch = "ReleaseProfileMismatch";
    public const string UnknownCommandFeatureMapping = "UnknownCommandFeatureMapping";
    public const string UnknownJobFeatureMapping = "UnknownJobFeatureMapping";
    public const string InvalidFeatureSelection = "InvalidFeatureSelection";
    public const string InvalidFeaturePolicyPayload = "InvalidFeaturePolicyPayload";
}

public sealed record AgentFeaturePolicyDecision
{
    private AgentFeaturePolicyDecision(
        bool allowed,
        string errorCode,
        string errorMessage,
        IReadOnlyList<FeatureId> requiredFeatures)
    {
        Allowed = allowed;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
        RequiredFeatures = requiredFeatures;
    }

    public bool Allowed { get; }

    public string ErrorCode { get; }

    public string ErrorMessage { get; }

    /// <summary>Release-policy failures are deterministic and never retryable.</summary>
    public bool IsRetryable => false;

    public IReadOnlyList<FeatureId> RequiredFeatures { get; }

    internal static AgentFeaturePolicyDecision Allow(IReadOnlyList<FeatureId> requiredFeatures) =>
        new(true, string.Empty, string.Empty, requiredFeatures);

    internal static AgentFeaturePolicyDecision Reject(
        string errorCode,
        string errorMessage,
        IReadOnlyList<FeatureId>? requiredFeatures = null) =>
        new(false, errorCode, errorMessage, requiredFeatures ?? Array.Empty<FeatureId>());
}

/// <summary>
/// Core-owned authoritative release-feature classification for viewer-to-agent
/// commands and agent job execution. Both processes consume this compiled
/// table; new enum members are unavailable until explicitly classified.
/// </summary>
public static class AgentCommandFeaturePolicy
{
    public const string BackfillUnavailableReason = "Historical event-log backfill is not implemented.";

    private enum ResolverKind
    {
        Static = 0,
        CoreControl = 1,
        StartLiveCapture = 2,
        LiveCaptureSource = 3,
        Enrichment = 4,
        CaptureConfiguration = 5
    }

    private sealed record FeatureRule(
        ResolverKind Resolver,
        IReadOnlyList<FeatureId> BaseFeatures,
        IReadOnlyList<FeatureId> PotentialFeatures,
        bool RequiresSelectedFeature = false,
        AgentCommandOperationalAvailability OperationalAvailability =
            AgentCommandOperationalAvailability.Supported,
        string AvailabilityReason = "");

    private sealed record FeatureResolution(
        bool Success,
        IReadOnlyList<FeatureId> Features,
        string ErrorCode = "",
        string ErrorMessage = "");

    private static readonly IReadOnlyDictionary<AgentCommandKind, FeatureRule> CommandRules =
        BuildCommandRules();

    private static readonly IReadOnlyDictionary<JobKind, FeatureRule> JobRules =
        BuildJobRules();

    public static IReadOnlyList<AgentCommandKind> ClassifiedCommandKinds { get; } =
        Array.AsReadOnly(CommandRules.Keys.OrderBy(kind => (int)kind).ToArray());

    public static IReadOnlyList<JobKind> ClassifiedJobKinds { get; } =
        Array.AsReadOnly(JobRules.Keys.OrderBy(kind => (int)kind).ToArray());

    public static IReadOnlyList<FeatureId> ClassifiedFeatureIds { get; } =
        Array.AsReadOnly(CommandRules.Values
            .Concat(JobRules.Values)
            .SelectMany(rule => rule.BaseFeatures.Concat(rule.PotentialFeatures))
            .Distinct()
            .OrderBy(featureId => featureId.Value, StringComparer.Ordinal)
            .ToArray());

    public static AgentFeaturePolicyDecision EvaluateCommand(
        IFeatureCatalog catalog,
        AgentCommand command)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(command);

        var payload = JsonSerializer.SerializeToElement(
            command,
            command.GetType(),
            AgentIpcJson.JsonOptions);
        var resolution = ResolveCommand(command.Kind, payload);
        return EvaluateResolution(catalog, $"Command '{command.Kind}'", resolution);
    }

    public static AgentFeaturePolicyDecision EvaluateRequest(
        IFeatureCatalog agentCatalog,
        AgentIpcRequest request)
    {
        ArgumentNullException.ThrowIfNull(agentCatalog);
        ArgumentNullException.ThrowIfNull(request);

        if (request.Kind != AgentIpcRequestKind.SubmitCommand)
        {
            return AgentFeaturePolicyDecision.Reject(
                AgentFeaturePolicyErrorCodes.UnknownCommandFeatureMapping,
                $"IPC request '{request.Kind}' is not a feature-specific command request.");
        }

        var resolution = ResolveCommand(request.CommandKind, request.Payload);
        if (!resolution.Success)
        {
            return AgentFeaturePolicyDecision.Reject(
                resolution.ErrorCode,
                resolution.ErrorMessage,
                resolution.Features);
        }

        var isCoreControl = CommandRules.TryGetValue(request.CommandKind, out var rule) &&
                            rule.Resolver == ResolverKind.CoreControl;
        if (!isCoreControl &&
            !string.Equals(
                request.ViewerReleaseId,
                agentCatalog.ReleaseId,
                StringComparison.Ordinal))
        {
            var viewerRelease = string.IsNullOrWhiteSpace(request.ViewerReleaseId)
                ? "<not supplied>"
                : request.ViewerReleaseId;
            return AgentFeaturePolicyDecision.Reject(
                AgentFeaturePolicyErrorCodes.ReleaseProfileMismatch,
                $"Viewer release profile '{viewerRelease}' does not match agent release profile '{agentCatalog.ReleaseId}'.",
                resolution.Features);
        }

        return EvaluateFeatures(
            agentCatalog,
            $"Command '{request.CommandKind}'",
            resolution.Features);
    }

    public static AgentFeaturePolicyDecision EvaluateJob(
        IFeatureCatalog catalog,
        JobKind jobKind,
        JsonElement? parameters)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        var resolution = ResolveJob(jobKind, parameters);
        return EvaluateResolution(catalog, $"Job '{jobKind}'", resolution);
    }

    public static AgentFeaturePolicyDecision EvaluateCaptureConfiguration(
        IFeatureCatalog catalog,
        AgentCaptureConfiguration configuration,
        string subject = "Configured capture")
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(configuration);
        try
        {
            return EvaluateFeatures(catalog, subject, ResolveCaptureConfigurationFeatures(configuration));
        }
        catch (InvalidOperationException ex)
        {
            return AgentFeaturePolicyDecision.Reject(
                AgentFeaturePolicyErrorCodes.InvalidFeaturePolicyPayload,
                ex.Message);
        }
    }

    public static AgentReleaseProfileSnapshot CreateReleaseProfileSnapshot(
        IFeatureCatalog catalog,
        string? viewerReleaseId)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        var normalizedViewerReleaseId = viewerReleaseId ?? string.Empty;
        var match = string.IsNullOrWhiteSpace(normalizedViewerReleaseId)
            ? AgentReleaseProfileMatch.Unknown
            : string.Equals(normalizedViewerReleaseId, catalog.ReleaseId, StringComparison.Ordinal)
                ? AgentReleaseProfileMatch.Match
                : AgentReleaseProfileMatch.Mismatch;
        var status = match switch
        {
            AgentReleaseProfileMatch.Match =>
                $"Viewer and agent use educational release '{catalog.ReleaseId}'.",
            AgentReleaseProfileMatch.Mismatch =>
                $"Viewer release '{normalizedViewerReleaseId}' does not match agent release '{catalog.ReleaseId}'.",
            _ => $"Viewer release identity was not supplied; agent release is '{catalog.ReleaseId}'."
        };

        return new AgentReleaseProfileSnapshot
        {
            ReleaseId = catalog.ReleaseId,
            ViewerReleaseId = normalizedViewerReleaseId,
            Match = match,
            Status = status,
            PublishedCommandCapabilities = GetPublishedCommandCapabilities(catalog)
        };
    }

    public static IReadOnlyList<AgentCommandCapability> GetPublishedCommandCapabilities(
        IFeatureCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        var capabilities = new List<AgentCommandCapability>();
        foreach (var (commandKind, rule) in CommandRules.OrderBy(pair => (int)pair.Key))
        {
            if (rule.Resolver != ResolverKind.CoreControl &&
                rule.BaseFeatures.Any(featureId => !catalog.IsPublished(featureId)))
            {
                continue;
            }

            var publishedPotentialFeatures = rule.PotentialFeatures
                .Where(catalog.IsPublished)
                .ToArray();
            if (rule.RequiresSelectedFeature && publishedPotentialFeatures.Length == 0)
            {
                continue;
            }

            var publishedFeatures = rule.BaseFeatures
                .Concat(publishedPotentialFeatures)
                .Where(catalog.IsPublished)
                .Distinct()
                .Select(featureId => featureId.Value)
                .ToArray();
            capabilities.Add(new AgentCommandCapability
            {
                CommandKind = commandKind,
                IsCoreControl = rule.Resolver == ResolverKind.CoreControl,
                HasPayloadSpecificRequirements = rule.Resolver is
                    ResolverKind.StartLiveCapture or
                    ResolverKind.LiveCaptureSource or
                    ResolverKind.Enrichment or
                    ResolverKind.CaptureConfiguration,
                PublishedFeatureIds = Array.AsReadOnly(publishedFeatures),
                OperationalAvailability = rule.OperationalAvailability,
                AvailabilityReason = rule.AvailabilityReason
            });
        }

        return new ReadOnlyCollection<AgentCommandCapability>(capabilities);
    }

    private static AgentFeaturePolicyDecision EvaluateResolution(
        IFeatureCatalog catalog,
        string subject,
        FeatureResolution resolution)
    {
        return resolution.Success
            ? EvaluateFeatures(catalog, subject, resolution.Features)
            : AgentFeaturePolicyDecision.Reject(
                resolution.ErrorCode,
                resolution.ErrorMessage,
                resolution.Features);
    }

    private static AgentFeaturePolicyDecision EvaluateFeatures(
        IFeatureCatalog catalog,
        string subject,
        IReadOnlyList<FeatureId> features)
    {
        var unknown = features.Where(featureId => !catalog.IsKnown(featureId)).Distinct().ToArray();
        if (unknown.Length > 0)
        {
            return AgentFeaturePolicyDecision.Reject(
                AgentFeaturePolicyErrorCodes.UnknownCommandFeatureMapping,
                $"{subject} resolves to feature IDs absent from release '{catalog.ReleaseId}': {string.Join(", ", unknown)}.",
                features);
        }

        var unpublished = features.Where(featureId => !catalog.IsPublished(featureId)).Distinct().ToArray();
        if (unpublished.Length > 0)
        {
            return AgentFeaturePolicyDecision.Reject(
                AgentFeaturePolicyErrorCodes.FeatureNotPublished,
                $"{subject} requires unpublished feature(s) in educational release '{catalog.ReleaseId}': {string.Join(", ", unpublished)}.",
                features);
        }

        return AgentFeaturePolicyDecision.Allow(features);
    }

    private static FeatureResolution ResolveCommand(AgentCommandKind commandKind, JsonElement? payload)
    {
        if (!CommandRules.TryGetValue(commandKind, out var rule))
        {
            return Failure(
                AgentFeaturePolicyErrorCodes.UnknownCommandFeatureMapping,
                $"Agent command '{commandKind}' has no explicit release-feature classification.");
        }

        var features = rule.BaseFeatures.ToList();
        try
        {
            switch (rule.Resolver)
            {
                case ResolverKind.Static:
                case ResolverKind.CoreControl:
                    break;
                case ResolverKind.StartLiveCapture:
                {
                    var command = Deserialize<StartLiveCaptureCommand>(payload, commandKind);
                    if (command.CollectEtwEvents ||
                        command.CollectSecurityEvents ||
                        command.CollectPowerShellEvents ||
                        command.CollectOtherWindowsEvents ||
                        command.CollectSysmonEvents)
                    {
                        features.Add(FeatureIds.EventTelemetry);
                    }

                    break;
                }
                case ResolverKind.LiveCaptureSource:
                {
                    var source = commandKind == AgentCommandKind.StartLiveCaptureSource
                        ? Deserialize<StartLiveCaptureSourceCommand>(payload, commandKind).Source
                        : Deserialize<StopLiveCaptureSourceCommand>(payload, commandKind).Source;
                    if (IsEventTelemetrySource(source))
                    {
                        features.Add(FeatureIds.EventTelemetry);
                    }
                    else if (!string.Equals(source, "Runtime", StringComparison.OrdinalIgnoreCase))
                    {
                        return Failure(
                            AgentFeaturePolicyErrorCodes.UnknownCommandFeatureMapping,
                            $"Agent command '{commandKind}' names unknown live-capture source '{source}'.",
                            features);
                    }

                    break;
                }
                case ResolverKind.Enrichment:
                {
                    var command = Deserialize<QueueEnrichmentCommand>(payload, commandKind);
                    if (command.CaptureModules || command.CaptureHandles)
                    {
                        features.Add(FeatureIds.ModulesAndHandles);
                    }

                    if (command.CapturePe)
                    {
                        features.Add(FeatureIds.DumpsAndPeAnalysis);
                    }

                    if (!command.CaptureModules && !command.CaptureHandles && !command.CapturePe)
                    {
                        return Failure(
                            AgentFeaturePolicyErrorCodes.InvalidFeatureSelection,
                            "Enrichment commands must select modules, handles, or PE analysis.",
                            features);
                    }

                    break;
                }
                case ResolverKind.CaptureConfiguration:
                {
                    AgentCaptureConfiguration? configuration = commandKind switch
                    {
                        AgentCommandKind.SaveCaptureConfiguration =>
                            Deserialize<SaveCaptureConfigurationCommand>(payload, commandKind).Configuration,
                        AgentCommandKind.CheckCaptureConfiguration =>
                            Deserialize<CheckCaptureConfigurationCommand>(payload, commandKind).DraftConfiguration,
                        _ => null
                    };
                    if (commandKind == AgentCommandKind.SaveCaptureConfiguration && configuration == null)
                    {
                        return Failure(
                            AgentFeaturePolicyErrorCodes.InvalidFeaturePolicyPayload,
                            "Save capture configuration commands require a configuration payload.",
                            features);
                    }

                    if (configuration != null)
                    {
                        features.AddRange(ResolveCaptureConfigurationFeatures(configuration));
                    }

                    break;
                }
                default:
                    return Failure(
                        AgentFeaturePolicyErrorCodes.UnknownCommandFeatureMapping,
                        $"Agent command '{commandKind}' uses unsupported resolver '{rule.Resolver}'.",
                        features);
            }
        }
        catch (JsonException ex)
        {
            return Failure(
                AgentFeaturePolicyErrorCodes.InvalidFeaturePolicyPayload,
                $"Agent command '{commandKind}' payload could not be classified: {ex.Message}",
                features);
        }
        catch (InvalidOperationException ex)
        {
            return Failure(
                AgentFeaturePolicyErrorCodes.InvalidFeaturePolicyPayload,
                ex.Message,
                features);
        }

        return Success(features);
    }

    private static FeatureResolution ResolveJob(JobKind jobKind, JsonElement? parameters)
    {
        if (!JobRules.TryGetValue(jobKind, out var rule))
        {
            return Failure(
                AgentFeaturePolicyErrorCodes.UnknownJobFeatureMapping,
                $"Agent job '{jobKind}' has no explicit release-feature classification.");
        }

        var features = rule.BaseFeatures.ToList();
        try
        {
            if (rule.Resolver == ResolverKind.StartLiveCapture)
            {
                var command = Deserialize<StartLiveCaptureCommand>(parameters, jobKind);
                if (command.CollectEtwEvents ||
                    command.CollectSecurityEvents ||
                    command.CollectPowerShellEvents ||
                    command.CollectOtherWindowsEvents ||
                    command.CollectSysmonEvents)
                {
                    features.Add(FeatureIds.EventTelemetry);
                }
            }
            else if (rule.Resolver == ResolverKind.Enrichment)
            {
                var command = Deserialize<QueueEnrichmentCommand>(parameters, jobKind);
                var expectedJobKind = AgentEnrichmentPlanning.GetJobKind(
                    command.CaptureModules,
                    command.CaptureHandles,
                    command.CapturePe);
                if (expectedJobKind == JobKind.Unknown || expectedJobKind != jobKind)
                {
                    return Failure(
                        AgentFeaturePolicyErrorCodes.InvalidFeatureSelection,
                        $"Agent job '{jobKind}' enrichment flags resolve to '{expectedJobKind}'.",
                        features);
                }

                if (command.CaptureModules || command.CaptureHandles)
                {
                    features.Add(FeatureIds.ModulesAndHandles);
                }

                if (command.CapturePe)
                {
                    features.Add(FeatureIds.DumpsAndPeAnalysis);
                }
            }
        }
        catch (JsonException ex)
        {
            return Failure(
                AgentFeaturePolicyErrorCodes.InvalidFeaturePolicyPayload,
                $"Agent job '{jobKind}' parameters could not be classified: {ex.Message}",
                features);
        }
        catch (InvalidOperationException ex)
        {
            return Failure(
                AgentFeaturePolicyErrorCodes.InvalidFeaturePolicyPayload,
                ex.Message,
                features);
        }

        return Success(features);
    }

    private static IReadOnlyList<FeatureId> ResolveCaptureConfigurationFeatures(
        AgentCaptureConfiguration configuration)
    {
        if (configuration.SourceToggles == null ||
            configuration.NetworkCapture == null ||
            configuration.Zeek == null ||
            configuration.ArtifactCapture == null)
        {
            throw new InvalidOperationException(
                "Capture configuration feature selection is incomplete or malformed.");
        }

        var features = new List<FeatureId> { FeatureIds.AgentsAndCapture };
        if (configuration.SourceToggles.Etw ||
            configuration.SourceToggles.Security ||
            configuration.SourceToggles.PowerShell ||
            configuration.SourceToggles.WindowsOther ||
            configuration.SourceToggles.Sysmon)
        {
            features.Add(FeatureIds.EventTelemetry);
        }

        if (configuration.NetworkCapture.Enabled ||
            configuration.Zeek.Enabled ||
            configuration.Zeek.RunAfterNetworkCapture)
        {
            features.Add(FeatureIds.NetworkAndZeek);
        }

        if (configuration.ArtifactCapture.CaptureModules ||
            configuration.ArtifactCapture.CaptureHandles)
        {
            features.Add(FeatureIds.ModulesAndHandles);
        }

        if (configuration.ArtifactCapture.CapturePeMetadata ||
            configuration.ArtifactCapture.CaptureDumpMetadata)
        {
            features.Add(FeatureIds.DumpsAndPeAnalysis);
        }

        return Distinct(features);
    }

    private static T Deserialize<T>(JsonElement? payload, object discriminator)
    {
        if (payload is null || payload.Value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            throw new InvalidOperationException(
                $"Feature classification for '{discriminator}' requires a command payload.");
        }

        return payload.Value.Deserialize<T>(AgentIpcJson.JsonOptions)
            ?? throw new InvalidOperationException(
                $"Feature classification for '{discriminator}' received an empty payload.");
    }

    private static bool IsEventTelemetrySource(string? source) =>
        string.Equals(source, "ETW", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(source, "Security", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(source, "PowerShell", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(source, "WindowsOther", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(source, "Sysmon", StringComparison.OrdinalIgnoreCase);

    private static FeatureResolution Success(IEnumerable<FeatureId> features) =>
        new(true, Distinct(features));

    private static FeatureResolution Failure(
        string errorCode,
        string errorMessage,
        IEnumerable<FeatureId>? features = null) =>
        new(false, Distinct(features ?? Array.Empty<FeatureId>()), errorCode, errorMessage);

    private static IReadOnlyList<FeatureId> Distinct(IEnumerable<FeatureId> features) =>
        Array.AsReadOnly(features.Distinct().ToArray());

    private static IReadOnlyDictionary<AgentCommandKind, FeatureRule> BuildCommandRules()
    {
        var agents = FeatureIds.AgentsAndCapture;
        var rules = new Dictionary<AgentCommandKind, FeatureRule>
        {
            [AgentCommandKind.StartLiveCapture] = Dynamic(ResolverKind.StartLiveCapture, [agents], [FeatureIds.EventTelemetry]),
            [AgentCommandKind.StopLiveCapture] = Static(agents),
            [AgentCommandKind.QueueBackfill] = Static(agents, FeatureIds.EventTelemetry) with
            {
                OperationalAvailability = AgentCommandOperationalAvailability.Unavailable,
                AvailabilityReason = BackfillUnavailableReason
            },
            [AgentCommandKind.QueueImport] = Static(agents),
            [AgentCommandKind.QueueEnrichment] = Dynamic(
                ResolverKind.Enrichment,
                [agents],
                [FeatureIds.ModulesAndHandles, FeatureIds.DumpsAndPeAnalysis],
                requiresSelectedFeature: true),
            [AgentCommandKind.CancelJob] = CoreControl(),
            [AgentCommandKind.PauseJob] = Static(agents),
            [AgentCommandKind.ResumeJob] = Static(agents),
            [AgentCommandKind.QueueProcessDump] = Static(agents, FeatureIds.DumpsAndPeAnalysis),
            [AgentCommandKind.StartNetworkCapture] = Static(agents, FeatureIds.NetworkAndZeek),
            [AgentCommandKind.StopNetworkCapture] = Static(agents, FeatureIds.NetworkAndZeek),
            [AgentCommandKind.QueueZeekAnalysis] = Static(agents, FeatureIds.NetworkAndZeek),
            [AgentCommandKind.QueueArtifactImport] = Static(agents, FeatureIds.FilesystemArtifacts),
            [AgentCommandKind.ShutdownAgent] = CoreControl(),
            [AgentCommandKind.QueueMemoryImageImport] = Static(agents, FeatureIds.SystemMemoryAndVolatility),
            [AgentCommandKind.QueueMemoryAcquisition] = Static(agents, FeatureIds.SystemMemoryAndVolatility),
            [AgentCommandKind.QueueVolatilityAnalysis] = Static(agents, FeatureIds.SystemMemoryAndVolatility),
            [AgentCommandKind.GetHostMonitoringConfiguration] = Static(agents, FeatureIds.SecurityMonitoringConfiguration),
            [AgentCommandKind.SaveHostMonitoringConfiguration] = Static(agents, FeatureIds.SecurityMonitoringConfiguration),
            [AgentCommandKind.CheckHostMonitoringConfiguration] = Static(agents, FeatureIds.SecurityMonitoringConfiguration),
            [AgentCommandKind.DeployHostMonitoringConfiguration] = Static(agents, FeatureIds.SecurityMonitoringConfiguration),
            [AgentCommandKind.ReverseHostMonitoringDeployment] = Static(agents, FeatureIds.SecurityMonitoringConfiguration),
            [AgentCommandKind.GetCaptureConfiguration] = Static(agents),
            [AgentCommandKind.SaveCaptureConfiguration] = Dynamic(
                ResolverKind.CaptureConfiguration,
                [agents],
                [FeatureIds.EventTelemetry, FeatureIds.ModulesAndHandles, FeatureIds.DumpsAndPeAnalysis, FeatureIds.NetworkAndZeek]),
            [AgentCommandKind.CheckCaptureConfiguration] = Dynamic(
                ResolverKind.CaptureConfiguration,
                [agents],
                [FeatureIds.EventTelemetry, FeatureIds.ModulesAndHandles, FeatureIds.DumpsAndPeAnalysis, FeatureIds.NetworkAndZeek]),
            [AgentCommandKind.StartConfiguredCapture] = Static(agents),
            [AgentCommandKind.StopConfiguredCapture] = Static(agents),
            [AgentCommandKind.StartProcessMonitorCapture] = Static(agents, FeatureIds.EventTelemetry),
            [AgentCommandKind.StopProcessMonitorCapture] = Static(agents, FeatureIds.EventTelemetry),
            [AgentCommandKind.QueueProcessMonitorImport] = Static(agents, FeatureIds.EventTelemetry),
            [AgentCommandKind.QueueSqliteBenchmark] = Static(agents, FeatureIds.EventTelemetry),
            [AgentCommandKind.StopEtwCapture] = Static(agents, FeatureIds.EventTelemetry),
            [AgentCommandKind.StopLiveCaptureSource] = Dynamic(
                ResolverKind.LiveCaptureSource,
                [agents],
                [FeatureIds.EventTelemetry]),
            [AgentCommandKind.StartLiveCaptureSource] = Dynamic(
                ResolverKind.LiveCaptureSource,
                [agents],
                [FeatureIds.EventTelemetry])
        };

        EnsureCoverage(
            Enum.GetValues<AgentCommandKind>().Where(kind => kind != AgentCommandKind.Unknown),
            rules.Keys,
            "agent command");
        ValidateOperationalAvailability(rules);
        return new ReadOnlyDictionary<AgentCommandKind, FeatureRule>(rules);
    }

    private static IReadOnlyDictionary<JobKind, FeatureRule> BuildJobRules()
    {
        var agents = FeatureIds.AgentsAndCapture;
        var rules = new Dictionary<JobKind, FeatureRule>
        {
            [JobKind.LiveCapture] = Dynamic(ResolverKind.StartLiveCapture, [agents], [FeatureIds.EventTelemetry]),
            [JobKind.Backfill] = Static(agents, FeatureIds.EventTelemetry),
            [JobKind.Import] = Static(agents),
            [JobKind.ModuleEnrichment] = Dynamic(
                ResolverKind.Enrichment,
                [agents],
                [FeatureIds.ModulesAndHandles, FeatureIds.DumpsAndPeAnalysis],
                requiresSelectedFeature: true),
            [JobKind.HandleEnrichment] = Dynamic(
                ResolverKind.Enrichment,
                [agents],
                [FeatureIds.ModulesAndHandles, FeatureIds.DumpsAndPeAnalysis],
                requiresSelectedFeature: true),
            [JobKind.ProcessDump] = Static(agents, FeatureIds.DumpsAndPeAnalysis),
            [JobKind.NetworkCapture] = Static(agents, FeatureIds.NetworkAndZeek),
            [JobKind.ZeekAnalysis] = Static(agents, FeatureIds.NetworkAndZeek),
            [JobKind.ArtifactImport] = Static(agents, FeatureIds.FilesystemArtifacts),
            [JobKind.MemoryImageImport] = Static(agents, FeatureIds.SystemMemoryAndVolatility),
            [JobKind.MemoryAcquisition] = Static(agents, FeatureIds.SystemMemoryAndVolatility),
            [JobKind.VolatilityAnalysis] = Static(agents, FeatureIds.SystemMemoryAndVolatility),
            [JobKind.ProcessMonitorCapture] = Static(agents, FeatureIds.EventTelemetry),
            [JobKind.ProcessMonitorImport] = Static(agents, FeatureIds.EventTelemetry),
            [JobKind.SqliteBenchmark] = Static(agents, FeatureIds.EventTelemetry),
            [JobKind.PeAnalysis] = Dynamic(
                ResolverKind.Enrichment,
                [agents],
                [FeatureIds.ModulesAndHandles, FeatureIds.DumpsAndPeAnalysis],
                requiresSelectedFeature: true)
        };

        EnsureCoverage(
            Enum.GetValues<JobKind>().Where(kind => kind != JobKind.Unknown),
            rules.Keys,
            "agent job");
        return new ReadOnlyDictionary<JobKind, FeatureRule>(rules);
    }

    private static FeatureRule Static(params FeatureId[] features) =>
        new(ResolverKind.Static, Array.AsReadOnly(features), Array.Empty<FeatureId>());

    private static FeatureRule CoreControl() =>
        new(ResolverKind.CoreControl, Array.Empty<FeatureId>(), Array.Empty<FeatureId>());

    private static FeatureRule Dynamic(
        ResolverKind resolver,
        FeatureId[] baseFeatures,
        FeatureId[] potentialFeatures,
        bool requiresSelectedFeature = false) =>
        new(
            resolver,
            Array.AsReadOnly(baseFeatures),
            Array.AsReadOnly(potentialFeatures),
            requiresSelectedFeature);

    private static void EnsureCoverage<T>(
        IEnumerable<T> expected,
        IEnumerable<T> actual,
        string policyName)
        where T : struct, Enum
    {
        var missing = expected.Except(actual).ToArray();
        var unexpected = actual.Except(expected).ToArray();
        if (missing.Length != 0 || unexpected.Length != 0)
        {
            throw new InvalidOperationException(
                $"Release feature policy {policyName} coverage mismatch. " +
                $"Missing: {string.Join(", ", missing)}; unexpected: {string.Join(", ", unexpected)}.");
        }
    }

    private static void ValidateOperationalAvailability(
        IReadOnlyDictionary<AgentCommandKind, FeatureRule> rules)
    {
        foreach (var (commandKind, rule) in rules)
        {
            if (rule.OperationalAvailability == AgentCommandOperationalAvailability.Unknown)
            {
                throw new InvalidOperationException(
                    $"Agent command '{commandKind}' has no explicit operational-availability classification.");
            }

            if (rule.AvailabilityReason.Length > AgentCommandCapability.MaxAvailabilityReasonLength)
            {
                throw new InvalidOperationException(
                    $"Agent command '{commandKind}' availability reason exceeds " +
                    $"{AgentCommandCapability.MaxAvailabilityReasonLength} characters.");
            }

            if ((rule.OperationalAvailability is
                    AgentCommandOperationalAvailability.Unavailable or
                    AgentCommandOperationalAvailability.Reserved) &&
                string.IsNullOrWhiteSpace(rule.AvailabilityReason))
            {
                throw new InvalidOperationException(
                    $"Agent command '{commandKind}' requires a bounded unavailability reason.");
            }
        }
    }
}
