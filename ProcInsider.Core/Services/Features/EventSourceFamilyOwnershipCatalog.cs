using System.Collections.ObjectModel;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// Release-independent identities for the six Windows event source families. These values are
/// publication metadata only; they do not replace persisted evidence or IPC source discriminators.
/// </summary>
public enum EventSourceFamilyKind
{
    Unknown = 0,
    Runtime = 1,
    Etw = 2,
    WindowsSecurity = 3,
    PowerShell = 4,
    WindowsOther = 5,
    Sysmon = 6,
}

/// <summary>
/// Source-family-scoped configuration areas. The broad host-monitoring command envelope may carry
/// several of these areas, but authorization and reversal can be evaluated one area at a time.
/// </summary>
public enum EventSourceFamilyConfigurationAreaKind
{
    Unknown = 0,
    RuntimeCapture = 1,
    EtwProviderSelection = 2,
    WindowsSecurityAuditPolicy = 3,
    WindowsSecurityCommandLineAuditing = 4,
    WindowsSecurityChannel = 5,
    PowerShellLogging = 6,
    WindowsOtherChannels = 7,
    SysmonServiceAndProfile = 8,
}

/// <summary>
/// Typed operational resources whose release payload ownership must remain exhaustive.
/// </summary>
public enum EventSourceFamilyResourceKind
{
    Unknown = 0,
    RuntimeCaptureSettings = 1,
    EtwCaptureProfile = 2,
    WindowsSecurityAuditPolicyProfile = 3,
    WindowsSecurityEventLogProfile = 4,
    PowerShellAuditProfile = 5,
    PowerShellTranscriptSettings = 6,
    WindowsOtherEventLogProfile = 7,
    SysmonProfile = 8,
    SysmonNotice = 9,
}

public sealed record EventSourceFamilyConfigurationAreaDefinition(
    EventSourceFamilyConfigurationAreaKind Kind,
    bool SupportsCheck,
    bool SupportsApply,
    bool SupportsReverse);

/// <summary>
/// Complete ownership record for one logical event source family. The stable source-family feature
/// identity may be reserved while current presentation, capture, and configuration publication
/// remain assigned to retained owners.
/// Command kinds may appear in more than one record when the command is a shared envelope whose
/// payload selects sources; every source-specific selection still resolves to exactly one family.
/// </summary>
public sealed record EventSourceFamilyOwnershipDefinition
{
    public EventSourceFamilyOwnershipDefinition(
        EventSourceFamilyKind family,
        FeatureId featureId,
        FeatureId presentationFeatureId,
        FeatureId captureFeatureId,
        FeatureId configurationFeatureId,
        string projectionSource,
        string navigationKey,
        string captureOptionId,
        string captureSource,
        string healthSource,
        string listingSource,
        string cliSource,
        IEnumerable<AgentCommandKind> agentCommandKinds,
        IEnumerable<EventSourceFamilyConfigurationAreaDefinition> configurationAreas,
        IEnumerable<EventSourceFamilyResourceKind> resourceKinds,
        IEnumerable<string> releaseAssetRoots)
    {
        Family = family;
        FeatureId = featureId;
        PresentationFeatureId = presentationFeatureId;
        CaptureFeatureId = captureFeatureId;
        ConfigurationFeatureId = configurationFeatureId;
        ProjectionSource = projectionSource;
        NavigationKey = navigationKey;
        CaptureOptionId = captureOptionId;
        CaptureSource = captureSource;
        HealthSource = healthSource;
        ListingSource = listingSource;
        CliSource = cliSource;
        AgentCommandKinds = Freeze(agentCommandKinds);
        ConfigurationAreas = Freeze(configurationAreas);
        ResourceKinds = Freeze(resourceKinds);
        ReleaseAssetRoots = Freeze(releaseAssetRoots);
    }

    public EventSourceFamilyKind Family { get; }
    /// <summary>Stable logical identity for the source family; it is not necessarily publishable.</summary>
    public FeatureId FeatureId { get; }
    /// <summary>Feature that currently authorizes projection, navigation, and Listing presentation.</summary>
    public FeatureId PresentationFeatureId { get; }
    /// <summary>
    /// Source-specific publication owner for the capture option, health, and CLI selection.
    /// Live capture operations can additionally require the AgentsAndCapture foundation.
    /// </summary>
    public FeatureId CaptureFeatureId { get; }
    /// <summary>Feature that currently authorizes this family's configuration area.</summary>
    public FeatureId ConfigurationFeatureId { get; }
    public bool IsIndependentlyPublishable =>
        FeatureId == PresentationFeatureId &&
        FeatureId == CaptureFeatureId &&
        FeatureId == ConfigurationFeatureId;
    public string ProjectionSource { get; }
    public string NavigationKey { get; }
    public string CaptureOptionId { get; }
    public string CaptureSource { get; }
    public string HealthSource { get; }
    public string ListingSource { get; }
    public string CliSource { get; }
    public IReadOnlyList<AgentCommandKind> AgentCommandKinds { get; }
    public IReadOnlyList<EventSourceFamilyConfigurationAreaDefinition> ConfigurationAreas { get; }
    public IReadOnlyList<EventSourceFamilyResourceKind> ResourceKinds { get; }
    public IReadOnlyList<string> ReleaseAssetRoots { get; }

    private static IReadOnlyList<T> Freeze<T>(IEnumerable<T> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        return new ReadOnlyCollection<T>(values.ToArray());
    }
}

/// <summary>
/// Core-owned authoritative ownership inventory for event-family presentation, capture,
/// configuration, health, CLI and release assets.
/// </summary>
public static class EventSourceFamilyOwnershipCatalog
{
    private static readonly AgentCommandKind[] CaptureCommands =
    [
        AgentCommandKind.StartLiveCapture,
        AgentCommandKind.StopLiveCapture,
        AgentCommandKind.GetCaptureConfiguration,
        AgentCommandKind.SaveCaptureConfiguration,
        AgentCommandKind.CheckCaptureConfiguration,
        AgentCommandKind.StartConfiguredCapture,
        AgentCommandKind.StopConfiguredCapture,
        AgentCommandKind.StartLiveCaptureSource,
        AgentCommandKind.StopLiveCaptureSource,
    ];

    private static readonly AgentCommandKind[] HostConfigurationCommands =
    [
        AgentCommandKind.GetHostMonitoringConfiguration,
        AgentCommandKind.SaveHostMonitoringConfiguration,
        AgentCommandKind.CheckHostMonitoringConfiguration,
        AgentCommandKind.DeployHostMonitoringConfiguration,
        AgentCommandKind.ReverseHostMonitoringDeployment,
    ];

    private static readonly IReadOnlyList<string> LegacySharedReleaseAssetRootsValue =
        Array.AsReadOnly(new[]
        {
            "Config/EventLogs",
            "Config/SecurityMonitoring",
        });

    private static readonly IReadOnlyList<EventSourceFamilyOwnershipDefinition> DefinitionsValue =
        Array.AsReadOnly(new[]
        {
            Define(
                EventSourceFamilyKind.Runtime,
                FeatureIds.RuntimeEvents,
                FeatureIds.EventTelemetry,
                FeatureIds.AgentsAndCapture,
                FeatureIds.AgentsAndCapture,
                "Runtime",
                "runtime-events",
                "process-live-events",
                CaptureCommands,
                [Area(EventSourceFamilyConfigurationAreaKind.RuntimeCapture, reverse: false)],
                [EventSourceFamilyResourceKind.RuntimeCaptureSettings],
                []),
            Define(
                EventSourceFamilyKind.Etw,
                FeatureIds.EtwEvents,
                FeatureIds.EventTelemetry,
                FeatureIds.EventTelemetry,
                FeatureIds.SecurityMonitoringConfiguration,
                "ETW",
                "etw-events",
                "etw-events",
                CaptureCommands.Concat(HostConfigurationCommands).Append(AgentCommandKind.StopEtwCapture),
                [Area(EventSourceFamilyConfigurationAreaKind.EtwProviderSelection)],
                [EventSourceFamilyResourceKind.EtwCaptureProfile],
                ["Config/Etw", "Config/etw-providers.json"]),
            Define(
                EventSourceFamilyKind.WindowsSecurity,
                FeatureIds.WindowsSecurityEvents,
                FeatureIds.WindowsSecurityEvents,
                FeatureIds.WindowsSecurityEvents,
                FeatureIds.WindowsSecurityEvents,
                "Security",
                "security-events",
                "security-events",
                CaptureCommands.Concat(HostConfigurationCommands),
                [
                    Area(EventSourceFamilyConfigurationAreaKind.WindowsSecurityAuditPolicy),
                    Area(EventSourceFamilyConfigurationAreaKind.WindowsSecurityCommandLineAuditing),
                    Area(EventSourceFamilyConfigurationAreaKind.WindowsSecurityChannel),
                ],
                [
                    EventSourceFamilyResourceKind.WindowsSecurityAuditPolicyProfile,
                    EventSourceFamilyResourceKind.WindowsSecurityEventLogProfile,
                ],
                ["Config/WindowsSecurity"]),
            Define(
                EventSourceFamilyKind.PowerShell,
                FeatureIds.PowerShellEvents,
                FeatureIds.EventTelemetry,
                FeatureIds.EventTelemetry,
                FeatureIds.SecurityMonitoringConfiguration,
                "PowerShell",
                "powershell-events",
                "powershell-events",
                CaptureCommands.Concat(HostConfigurationCommands),
                [Area(EventSourceFamilyConfigurationAreaKind.PowerShellLogging)],
                [
                    EventSourceFamilyResourceKind.PowerShellAuditProfile,
                    EventSourceFamilyResourceKind.PowerShellTranscriptSettings,
                ],
                ["Config/PowerShellAuditing"]),
            Define(
                EventSourceFamilyKind.WindowsOther,
                FeatureIds.WindowsOtherEvents,
                FeatureIds.EventTelemetry,
                FeatureIds.EventTelemetry,
                FeatureIds.SecurityMonitoringConfiguration,
                "WindowsOther",
                "windows-other-events",
                "windows-other-events",
                CaptureCommands.Concat(HostConfigurationCommands),
                [Area(EventSourceFamilyConfigurationAreaKind.WindowsOtherChannels)],
                [EventSourceFamilyResourceKind.WindowsOtherEventLogProfile],
                []),
            Define(
                EventSourceFamilyKind.Sysmon,
                FeatureIds.SysmonEvents,
                FeatureIds.EventTelemetry,
                FeatureIds.EventTelemetry,
                FeatureIds.SecurityMonitoringConfiguration,
                "Sysmon",
                "sysmon-events",
                "sysmon-events",
                CaptureCommands.Concat(HostConfigurationCommands),
                [Area(EventSourceFamilyConfigurationAreaKind.SysmonServiceAndProfile, reverse: false)],
                [EventSourceFamilyResourceKind.SysmonProfile, EventSourceFamilyResourceKind.SysmonNotice],
                ["Config/Sysmon", "Sysmon"]),
        });

    private static readonly IReadOnlyDictionary<EventSourceFamilyKind, EventSourceFamilyOwnershipDefinition>
        DefinitionsByFamily;
    private static readonly IReadOnlyDictionary<string, EventSourceFamilyOwnershipDefinition>
        DefinitionsByCaptureSource;

    static EventSourceFamilyOwnershipCatalog()
    {
        Validate(DefinitionsValue);
        DefinitionsByFamily = new ReadOnlyDictionary<EventSourceFamilyKind, EventSourceFamilyOwnershipDefinition>(
            DefinitionsValue.ToDictionary(definition => definition.Family));
        DefinitionsByCaptureSource = new ReadOnlyDictionary<string, EventSourceFamilyOwnershipDefinition>(
            DefinitionsValue.ToDictionary(definition => definition.CaptureSource, StringComparer.OrdinalIgnoreCase));
    }

    public static IReadOnlyList<EventSourceFamilyOwnershipDefinition> Definitions => DefinitionsValue;

    /// <summary>
    /// Compatibility assets that currently configure more than one source family. They remain
    /// explicit residual ownership until a later source-family issue safely splits their format.
    /// </summary>
    public static IReadOnlyList<string> LegacySharedReleaseAssetRoots => LegacySharedReleaseAssetRootsValue;

    public static IReadOnlyList<FeatureId> SourceFamilyFeatureIds { get; } =
        Array.AsReadOnly(DefinitionsValue.Select(definition => definition.FeatureId).ToArray());

    public static IReadOnlyList<FeatureId> PresentationFeatureIds { get; } =
        Array.AsReadOnly(DefinitionsValue
            .Select(definition => definition.PresentationFeatureId)
            .Distinct()
            .ToArray());

    public static IReadOnlyList<FeatureId> CaptureFeatureIds { get; } =
        Array.AsReadOnly(DefinitionsValue
            .Select(definition => definition.CaptureFeatureId)
            .Distinct()
            .ToArray());

    public static IReadOnlyList<FeatureId> ConfigurationFeatureIds { get; } =
        Array.AsReadOnly(DefinitionsValue
            .Select(definition => definition.ConfigurationFeatureId)
            .Distinct()
            .ToArray());

    public static bool TryGet(
        EventSourceFamilyKind family,
        out EventSourceFamilyOwnershipDefinition? definition) =>
        DefinitionsByFamily.TryGetValue(family, out definition);

    public static bool TryGetByCaptureSource(
        string? captureSource,
        out EventSourceFamilyOwnershipDefinition? definition)
    {
        definition = null;
        return !string.IsNullOrWhiteSpace(captureSource) &&
               DefinitionsByCaptureSource.TryGetValue(captureSource, out definition);
    }

    public static void ValidateAgainstCatalog(IFeatureCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        Validate(DefinitionsValue);
        var errors = new List<string>();
        foreach (var definition in DefinitionsValue)
        {
            if (!catalog.TryGetDefinition(definition.FeatureId, out var feature))
            {
                errors.Add($"family '{definition.Family}' references unknown feature '{definition.FeatureId}'");
                continue;
            }

            if (!feature.Dependencies.SequenceEqual([Models.Features.FeatureIds.ProcessListing]))
            {
                errors.Add(
                    $"family '{definition.Family}' feature '{definition.FeatureId}' must depend only on '{Models.Features.FeatureIds.ProcessListing}'");
            }

            if (definition.Family != EventSourceFamilyKind.WindowsSecurity &&
                feature.State != FeatureReleaseState.InDevelopment)
            {
                errors.Add(
                    $"family '{definition.Family}' feature '{definition.FeatureId}' is reserved and must remain InDevelopment");
            }

            if (definition.Family == EventSourceFamilyKind.WindowsSecurity &&
                feature.State == FeatureReleaseState.InDevelopment)
            {
                errors.Add(
                    $"family '{definition.Family}' feature '{definition.FeatureId}' must remain eligible for independent publication");
            }
        }

        ValidateOwnerAgainstCatalog(
            catalog,
            Models.Features.FeatureIds.EventTelemetry,
            [Models.Features.FeatureIds.ProcessListing],
            "retained event presentation/capture owner",
            errors);
        ValidateOwnerAgainstCatalog(
            catalog,
            Models.Features.FeatureIds.WindowsSecurityEvents,
            [Models.Features.FeatureIds.ProcessListing],
            "Windows Security owner",
            errors);
        ValidateOwnerAgainstCatalog(
            catalog,
            Models.Features.FeatureIds.SecurityMonitoringConfiguration,
            [Models.Features.FeatureIds.AgentsAndCapture],
            "retained host-configuration owner",
            errors);
        ValidateOwnerAgainstCatalog(
            catalog,
            Models.Features.FeatureIds.AgentsAndCapture,
            [],
            "Runtime capture/configuration foundation owner",
            errors);

        ThrowIfInvalid(errors);
    }

    public static void Validate(
        IEnumerable<EventSourceFamilyOwnershipDefinition> definitions,
        IEnumerable<string>? governedReleaseAssetRoots = null)
    {
        ArgumentNullException.ThrowIfNull(definitions);
        var values = definitions.ToArray();
        var errors = new List<string>();
        if (values.Any(definition => definition is null))
        {
            errors.Add("ownership inventory contains a null definition");
        }

        var valid = values.Where(definition => definition is not null).ToArray();
        ValidateExactEnumCoverage(valid.Select(definition => definition.Family), "family", errors);
        ValidateExactSet(
            valid.Select(definition => definition.FeatureId),
            [
                Models.Features.FeatureIds.RuntimeEvents,
                Models.Features.FeatureIds.EtwEvents,
                Models.Features.FeatureIds.WindowsSecurityEvents,
                Models.Features.FeatureIds.PowerShellEvents,
                Models.Features.FeatureIds.WindowsOtherEvents,
                Models.Features.FeatureIds.SysmonEvents,
            ],
            "feature ID",
            errors);
        foreach (var definition in valid)
        {
            ValidateOperationalOwner(
                definition,
                definition.PresentationFeatureId,
                ExpectedPresentationFeatureId(definition.Family),
                "presentation owner",
                errors);
            ValidateOperationalOwner(
                definition,
                definition.CaptureFeatureId,
                ExpectedCaptureFeatureId(definition.Family),
                "capture owner",
                errors);
            ValidateOperationalOwner(
                definition,
                definition.ConfigurationFeatureId,
                ExpectedConfigurationFeatureId(definition.Family),
                "configuration owner",
                errors);
        }
        ValidateUniqueRequired(valid, definition => definition.ProjectionSource, "projection source", errors);
        ValidateUniqueRequired(valid, definition => definition.NavigationKey, "navigation key", errors);
        ValidateUniqueRequired(valid, definition => definition.CaptureOptionId, "capture option", errors);
        ValidateUniqueRequired(valid, definition => definition.CaptureSource, "capture source", errors);
        ValidateUniqueRequired(valid, definition => definition.HealthSource, "health source", errors);
        ValidateUniqueRequired(valid, definition => definition.ListingSource, "listing source", errors);
        ValidateUniqueRequired(valid, definition => definition.CliSource, "CLI source", errors);

        var configurationAreas = valid.SelectMany(definition => definition.ConfigurationAreas).ToArray();
        ValidateExactEnumCoverage(configurationAreas.Select(area => area.Kind), "configuration area", errors);
        if (configurationAreas.Any(area => !area.SupportsCheck || !area.SupportsApply))
        {
            errors.Add("every configuration area must explicitly support check and apply");
        }

        ValidateExactEnumCoverage(valid.SelectMany(definition => definition.ResourceKinds), "resource kind", errors);
        foreach (var definition in valid)
        {
            var invalidCommands = definition.AgentCommandKinds
                .Where(kind => kind == AgentCommandKind.Unknown || !Enum.IsDefined(kind))
                .ToArray();
            if (invalidCommands.Length != 0)
            {
                errors.Add($"family '{definition.Family}' contains unknown agent command kinds");
            }

            if (definition.AgentCommandKinds.Count != definition.AgentCommandKinds.Distinct().Count())
            {
                errors.Add($"family '{definition.Family}' contains duplicate agent command kinds");
            }
        }

        var assetRoots = valid
            .SelectMany(definition => definition.ReleaseAssetRoots)
            .Concat(LegacySharedReleaseAssetRootsValue)
            .ToArray();
        ValidateNormalizedAssetRoots(assetRoots, "owned release asset root", errors);
        AddDuplicates(assetRoots, "release asset root", errors, StringComparer.OrdinalIgnoreCase);
        if (governedReleaseAssetRoots is not null)
        {
            var governedAssets = governedReleaseAssetRoots.ToArray();
            ValidateNormalizedAssetRoots(governedAssets, "governed release asset root", errors);
            AddDuplicates(governedAssets, "governed release asset root", errors, StringComparer.OrdinalIgnoreCase);
            var unowned = governedAssets.Except(assetRoots, StringComparer.OrdinalIgnoreCase).ToArray();
            var nonexistent = assetRoots.Except(governedAssets, StringComparer.OrdinalIgnoreCase).ToArray();
            if (unowned.Length != 0 || nonexistent.Length != 0)
            {
                errors.Add(
                    $"release asset ownership is incomplete; unowned: {Join(unowned)}; nonexistent: {Join(nonexistent)}");
            }
        }

        ThrowIfInvalid(errors);
    }

    private static void ValidateNormalizedAssetRoots(
        IEnumerable<string> assetRoots,
        string subject,
        ICollection<string> errors)
    {
        var invalidAssetRoots = assetRoots.Where(path =>
            string.IsNullOrWhiteSpace(path) ||
            Path.IsPathRooted(path) ||
            path.Contains('\\') ||
            path.Split('/').Any(segment => segment is "" or "." or ".."))
            .ToArray();
        if (invalidAssetRoots.Length != 0)
        {
            errors.Add($"{subject}s must be normalized repository-relative paths: {string.Join(", ", invalidAssetRoots)}");
        }
    }

    private static EventSourceFamilyOwnershipDefinition Define(
        EventSourceFamilyKind family,
        FeatureId featureId,
        FeatureId presentationFeatureId,
        FeatureId captureFeatureId,
        FeatureId configurationFeatureId,
        string source,
        string navigationKey,
        string captureOptionId,
        IEnumerable<AgentCommandKind> agentCommandKinds,
        IEnumerable<EventSourceFamilyConfigurationAreaDefinition> configurationAreas,
        IEnumerable<EventSourceFamilyResourceKind> resourceKinds,
        IEnumerable<string> releaseAssetRoots) =>
        new(
            family,
            featureId,
            presentationFeatureId,
            captureFeatureId,
            configurationFeatureId,
            source,
            navigationKey,
            captureOptionId,
            source,
            source,
            source,
            source,
            agentCommandKinds,
            configurationAreas,
            resourceKinds,
            releaseAssetRoots);

    private static FeatureId ExpectedPresentationFeatureId(EventSourceFamilyKind family) =>
        family == EventSourceFamilyKind.WindowsSecurity
            ? Models.Features.FeatureIds.WindowsSecurityEvents
            : Models.Features.FeatureIds.EventTelemetry;

    private static FeatureId ExpectedCaptureFeatureId(EventSourceFamilyKind family) => family switch
    {
        EventSourceFamilyKind.WindowsSecurity => Models.Features.FeatureIds.WindowsSecurityEvents,
        EventSourceFamilyKind.Runtime => Models.Features.FeatureIds.AgentsAndCapture,
        _ => Models.Features.FeatureIds.EventTelemetry,
    };

    private static FeatureId ExpectedConfigurationFeatureId(EventSourceFamilyKind family) => family switch
    {
        EventSourceFamilyKind.WindowsSecurity => Models.Features.FeatureIds.WindowsSecurityEvents,
        EventSourceFamilyKind.Runtime => Models.Features.FeatureIds.AgentsAndCapture,
        _ => Models.Features.FeatureIds.SecurityMonitoringConfiguration,
    };

    private static void ValidateOperationalOwner(
        EventSourceFamilyOwnershipDefinition definition,
        FeatureId actual,
        FeatureId expected,
        string subject,
        ICollection<string> errors)
    {
        if (!Models.Features.FeatureIds.All.Contains(actual))
        {
            errors.Add($"family '{definition.Family}' references unknown {subject} '{actual}'");
            return;
        }

        if (actual != expected)
        {
            errors.Add(
                $"family '{definition.Family}' {subject} must be '{expected}', not '{actual}'");
        }
    }

    private static void ValidateOwnerAgainstCatalog(
        IFeatureCatalog catalog,
        FeatureId featureId,
        IReadOnlyList<FeatureId> expectedDependencies,
        string subject,
        ICollection<string> errors)
    {
        if (!catalog.TryGetDefinition(featureId, out var definition))
        {
            errors.Add($"{subject} references unknown feature '{featureId}'");
            return;
        }

        if (!definition.Dependencies.SequenceEqual(expectedDependencies))
        {
            errors.Add(
                $"{subject} '{featureId}' has an invalid dependency set");
        }
    }

    private static EventSourceFamilyConfigurationAreaDefinition Area(
        EventSourceFamilyConfigurationAreaKind kind,
        bool reverse = true) =>
        new(kind, SupportsCheck: true, SupportsApply: true, SupportsReverse: reverse);

    private static void ValidateExactEnumCoverage<T>(
        IEnumerable<T> values,
        string subject,
        ICollection<string> errors)
        where T : struct, Enum
    {
        var actual = values.ToArray();
        var expected = Enum.GetValues<T>()
            .Where(value => Convert.ToInt32(value) != 0)
            .ToArray();
        var unknown = actual.Where(value => Convert.ToInt32(value) == 0 || !Enum.IsDefined(value)).ToArray();
        if (unknown.Length != 0)
        {
            errors.Add($"{subject} inventory contains unknown values");
        }

        AddDuplicates(actual, subject, errors, EqualityComparer<T>.Default);
        var missing = expected.Except(actual).ToArray();
        var unexpected = actual.Except(expected).ToArray();
        if (missing.Length != 0 || unexpected.Length != 0)
        {
            errors.Add(
                $"{subject} inventory is incomplete; missing: {Join(missing)}; unexpected: {Join(unexpected)}");
        }
    }

    private static void ValidateExactSet<T>(
        IEnumerable<T> values,
        IEnumerable<T> expectedValues,
        string subject,
        ICollection<string> errors)
        where T : notnull
    {
        var actual = values.ToArray();
        var expected = expectedValues.ToArray();
        AddDuplicates(actual, subject, errors, EqualityComparer<T>.Default);
        var missing = expected.Except(actual).ToArray();
        var unexpected = actual.Except(expected).ToArray();
        if (missing.Length != 0 || unexpected.Length != 0)
        {
            errors.Add(
                $"{subject} inventory is incomplete; missing: {Join(missing)}; unexpected: {Join(unexpected)}");
        }
    }

    private static void ValidateUniqueRequired(
        IEnumerable<EventSourceFamilyOwnershipDefinition> definitions,
        Func<EventSourceFamilyOwnershipDefinition, string> selector,
        string subject,
        ICollection<string> errors)
    {
        var values = definitions.Select(selector).ToArray();
        if (values.Any(string.IsNullOrWhiteSpace))
        {
            errors.Add($"{subject} inventory contains an empty value");
        }

        AddDuplicates(values, subject, errors, StringComparer.OrdinalIgnoreCase);
    }

    private static void AddDuplicates<T>(
        IEnumerable<T> values,
        string subject,
        ICollection<string> errors,
        IEqualityComparer<T> comparer)
    {
        var duplicates = values
            .GroupBy(value => value, comparer)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToArray();
        if (duplicates.Length != 0)
        {
            errors.Add($"{subject} inventory contains duplicate ownership: {Join(duplicates)}");
        }
    }

    private static string Join<T>(IEnumerable<T> values) =>
        string.Join(", ", values.Select(value => value?.ToString() ?? "<null>"));

    private static void ThrowIfInvalid(IReadOnlyCollection<string> errors)
    {
        if (errors.Count != 0)
        {
            throw new InvalidOperationException(
                $"Event source-family ownership validation failed:{Environment.NewLine}- " +
                string.Join($"{Environment.NewLine}- ", errors));
        }
    }
}
