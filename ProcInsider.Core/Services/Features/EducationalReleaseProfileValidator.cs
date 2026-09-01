using System.Collections.ObjectModel;
using ProcInsider.Models.Agent;
using ProcInsider.Models.Features;

namespace ProcInsider.Services.Features;

/// <summary>
/// Core-owned deterministic, attachment-friendly description of one compiled educational release profile.
/// </summary>
public sealed class EducationalReleaseProfileReport
{
    internal EducationalReleaseProfileReport(
        string releaseId,
        IReadOnlyList<FeatureId> published,
        IReadOnlyList<FeatureId> readyHidden,
        IReadOnlyList<FeatureId> inDevelopment,
        InfrastructurePublicationGroupReport? infrastructurePublication)
    {
        ReleaseId = releaseId;
        Published = published;
        ReadyHidden = readyHidden;
        InDevelopment = inDevelopment;
        InfrastructurePublication = infrastructurePublication;
    }

    public string ReleaseId { get; }

    public IReadOnlyList<FeatureId> Published { get; }

    public IReadOnlyList<FeatureId> ReadyHidden { get; }

    public IReadOnlyList<FeatureId> InDevelopment { get; }

    public InfrastructurePublicationGroupReport? InfrastructurePublication { get; }

    public string ToText() =>
        $"release_id={ReleaseId}\n" +
        $"published[{Published.Count}]={Format(Published)}\n" +
        $"ready_hidden[{ReadyHidden.Count}]={Format(ReadyHidden)}\n" +
        $"in_development[{InDevelopment.Count}]={Format(InDevelopment)}\n" +
        (InfrastructurePublication?.ToText() ?? string.Empty);

    public override string ToString() => ToText();

    private static string Format(IReadOnlyList<FeatureId> featureIds) =>
        featureIds.Count == 0 ? "(none)" : string.Join(",", featureIds);
}

public sealed class InfrastructurePublicationGroupReport
{
    internal InfrastructurePublicationGroupReport(
        InfrastructurePublicationGroupDefinition definition,
        IReadOnlyList<FeatureId> published,
        IReadOnlyList<FeatureId> readyHidden,
        IReadOnlyList<FeatureId> inDevelopment)
    {
        Definition = definition;
        Published = published;
        ReadyHidden = readyHidden;
        InDevelopment = inDevelopment;
    }

    public InfrastructurePublicationGroupDefinition Definition { get; }

    public IReadOnlyList<FeatureId> Published { get; }

    public IReadOnlyList<FeatureId> ReadyHidden { get; }

    public IReadOnlyList<FeatureId> InDevelopment { get; }

    public string ToText() =>
        $"publication_group={Definition.Id} deployment_mode={Definition.DeploymentMode} profile_id={Definition.ProfileId} protocol_generation={Definition.ProtocolGeneration} root_feature={Definition.RootFeatureId}\n" +
        $"infrastructure_published[{Published.Count}]={Format(Published)}\n" +
        $"infrastructure_ready_hidden[{ReadyHidden.Count}]={Format(ReadyHidden)}\n" +
        $"infrastructure_in_development[{InDevelopment.Count}]={Format(InDevelopment)}\n";

    private static string Format(IReadOnlyList<FeatureId> featureIds) =>
        featureIds.Count == 0 ? "(none)" : string.Join(",", featureIds);
}

/// <summary>
/// Final release audit for the compiled feature inventory and the shared viewer/agent
/// command classification. The lower-level <see cref="FeatureCatalog"/> still rejects
/// invalid graphs at construction; this validator checks the complete public profile.
/// </summary>
public static class EducationalReleaseProfileValidator
{
    public static EducationalReleaseProfileReport Validate(
        IFeatureCatalog catalog,
        IEnumerable<FeatureId> knownFeatureIds,
        InfrastructurePublicationGroupDefinition? infrastructurePublication = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(knownFeatureIds);

        var errors = new List<string>();
        var releaseId = string.IsNullOrWhiteSpace(catalog.ReleaseId)
            ? "<missing>"
            : catalog.ReleaseId;
        if (string.IsNullOrWhiteSpace(catalog.ReleaseId))
        {
            errors.Add("the release ID is empty");
        }

        var expectedIds = knownFeatureIds.ToArray();
        var emptyExpectedCount = expectedIds.Count(featureId => featureId.IsEmpty);
        if (emptyExpectedCount != 0)
        {
            errors.Add($"the known feature inventory contains {emptyExpectedCount} empty ID(s)");
        }

        AddDuplicateErrors(errors, expectedIds, "known feature inventory");
        var expectedSet = expectedIds.Where(featureId => !featureId.IsEmpty).ToHashSet();

        var definitions = catalog.Features?.ToArray() ?? [];
        var nullDefinitionCount = definitions.Count(definition => definition is null);
        if (nullDefinitionCount != 0)
        {
            errors.Add($"the catalog contains {nullDefinitionCount} null definition(s)");
        }

        var validDefinitions = definitions.Where(definition => definition is not null).ToArray();
        AddDuplicateErrors(errors, validDefinitions.Select(definition => definition.Id), "catalog");

        var definitionsById = validDefinitions
            .Where(definition => !definition.Id.IsEmpty)
            .GroupBy(definition => definition.Id)
            .ToDictionary(group => group.Key, group => group.First());
        var actualSet = definitionsById.Keys.ToHashSet();
        AddSetDifferenceError(errors, expectedSet, actualSet, "missing known feature IDs");
        AddSetDifferenceError(errors, actualSet, expectedSet, "unexpected feature IDs");

        foreach (var definition in definitionsById.Values.OrderBy(definition => definition.Id.Value, StringComparer.Ordinal))
        {
            if (!Enum.IsDefined(definition.State))
            {
                errors.Add($"feature '{definition.Id}' has invalid release state '{(int)definition.State}'");
            }

            var unknownDependencies = definition.Dependencies
                .Where(dependency => !definitionsById.ContainsKey(dependency))
                .Distinct()
                .OrderBy(dependency => dependency.Value, StringComparer.Ordinal)
                .ToArray();
            if (unknownDependencies.Length != 0)
            {
                errors.Add(
                    $"feature '{definition.Id}' depends on unknown feature ID(s): {Join(unknownDependencies)}");
            }

            if (definition.State == FeatureReleaseState.Published)
            {
                var hiddenDependencies = definition.Dependencies
                    .Where(definitionsById.ContainsKey)
                    .Where(dependency => definitionsById[dependency].State != FeatureReleaseState.Published)
                    .Distinct()
                    .OrderBy(dependency => dependency.Value, StringComparer.Ordinal)
                    .ToArray();
                if (hiddenDependencies.Length != 0)
                {
                    errors.Add(
                        $"published feature '{definition.Id}' has unpublished dependency ID(s): {Join(hiddenDependencies)}");
                }
            }

            ValidateCatalogQueryContract(catalog, definition, errors);
        }

        ValidateAcyclic(definitionsById, errors);
        ValidateUnknownIdsFailClosed(catalog, actualSet, errors);
        ValidateAgentClassifications(catalog, errors);
        var infrastructureReport = ValidateInfrastructurePublication(
            catalog,
            infrastructurePublication,
            errors);

        if (errors.Count != 0)
        {
            throw new InvalidOperationException(
                $"Educational release profile '{releaseId}' failed validation:{Environment.NewLine}- " +
                string.Join($"{Environment.NewLine}- ", errors));
        }

        return new EducationalReleaseProfileReport(
            catalog.ReleaseId,
            SelectState(definitionsById.Values, FeatureReleaseState.Published),
            SelectState(definitionsById.Values, FeatureReleaseState.ReadyHidden),
            SelectState(definitionsById.Values, FeatureReleaseState.InDevelopment),
            infrastructureReport);
    }

    private static InfrastructurePublicationGroupReport? ValidateInfrastructurePublication(
        IFeatureCatalog catalog,
        InfrastructurePublicationGroupDefinition? definition,
        ICollection<string> errors)
    {
        if (definition is null)
        {
            return null;
        }

        if (!string.Equals(definition.ReleaseId, catalog.ReleaseId, StringComparison.Ordinal))
        {
            errors.Add(
                $"Infrastructure deployment profile release '{definition.ReleaseId}' does not match catalog release '{catalog.ReleaseId}'");
        }

        var expectedComponents = Enum.GetValues<InfrastructureComponentKind>()
            .Where(component => component != InfrastructureComponentKind.Unknown)
            .ToHashSet();
        if (!definition.Components.ToHashSet().SetEquals(expectedComponents))
        {
            errors.Add("Infrastructure publication component inventory is incomplete or contains unknown values");
        }

        var expectedEntryPoints = Enum.GetValues<InfrastructureEntryPointKind>()
            .Where(entryPoint => entryPoint != InfrastructureEntryPointKind.Unknown)
            .ToHashSet();
        if (!definition.ProtectedEntryPoints.ToHashSet().SetEquals(expectedEntryPoints))
        {
            errors.Add("Infrastructure publication entry-point inventory is incomplete or contains unknown values");
        }

        var expectedFeatureAreas = Enum.GetValues<InfrastructureFeatureArea>()
            .Where(featureArea => featureArea != InfrastructureFeatureArea.Unknown)
            .ToHashSet();
        if (!definition.UserVisibleFeatures.Keys.ToHashSet().SetEquals(expectedFeatureAreas))
        {
            errors.Add("Infrastructure user-visible feature-area inventory is incomplete or contains unknown values");
        }

        var groupFeatureIds = definition.UserVisibleFeatures.Values
            .Prepend(definition.RootFeatureId)
            .ToArray();
        var duplicateGroupIds = groupFeatureIds
            .GroupBy(featureId => featureId)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .OrderBy(featureId => featureId.Value, StringComparer.Ordinal)
            .ToArray();
        if (duplicateGroupIds.Length != 0)
        {
            errors.Add($"Infrastructure publication group contains duplicate feature IDs: {Join(duplicateGroupIds)}");
        }

        var unknownGroupIds = groupFeatureIds
            .Where(featureId => !catalog.IsKnown(featureId))
            .Distinct()
            .OrderBy(featureId => featureId.Value, StringComparer.Ordinal)
            .ToArray();
        if (unknownGroupIds.Length != 0)
        {
            errors.Add($"Infrastructure publication group references unknown feature IDs: {Join(unknownGroupIds)}");
        }

        var rootState = catalog.GetReleaseState(definition.RootFeatureId);
        foreach (var featureId in definition.UserVisibleFeatures.Values.Distinct())
        {
            if (!catalog.GetDependencies(featureId).Contains(definition.RootFeatureId))
            {
                errors.Add(
                    $"Infrastructure user-visible feature '{featureId}' does not depend on root '{definition.RootFeatureId}'");
            }

            var featureState = catalog.GetReleaseState(featureId);
            if (rootState is not null && featureState is not null &&
                Maturity(featureState.Value) > Maturity(rootState.Value))
            {
                errors.Add(
                    $"Infrastructure user-visible feature '{featureId}' is more mature than root '{definition.RootFeatureId}'");
            }
        }

        var knownGroupDefinitions = groupFeatureIds
            .Distinct()
            .Select(featureId => catalog.TryGetDefinition(featureId, out var catalogDefinition)
                ? catalogDefinition
                : null)
            .Where(catalogDefinition => catalogDefinition is not null)
            .Cast<FeatureDefinition>()
            .ToArray();
        return new InfrastructurePublicationGroupReport(
            definition,
            SelectState(knownGroupDefinitions, FeatureReleaseState.Published),
            SelectState(knownGroupDefinitions, FeatureReleaseState.ReadyHidden),
            SelectState(knownGroupDefinitions, FeatureReleaseState.InDevelopment));
    }

    private static int Maturity(FeatureReleaseState state) => state switch
    {
        FeatureReleaseState.InDevelopment => 0,
        FeatureReleaseState.ReadyHidden => 1,
        FeatureReleaseState.Published => 2,
        _ => int.MaxValue
    };

    private static void AddDuplicateErrors(
        ICollection<string> errors,
        IEnumerable<FeatureId> featureIds,
        string subject)
    {
        var duplicates = featureIds
            .Where(featureId => !featureId.IsEmpty)
            .GroupBy(featureId => featureId)
            .Where(group => group.Count() > 1)
            .OrderBy(group => group.Key.Value, StringComparer.Ordinal)
            .Select(group => $"{group.Key} ({group.Count()} entries)")
            .ToArray();
        if (duplicates.Length != 0)
        {
            errors.Add($"the {subject} contains duplicate feature IDs: {string.Join(", ", duplicates)}");
        }
    }

    private static void AddSetDifferenceError(
        ICollection<string> errors,
        IReadOnlySet<FeatureId> source,
        IReadOnlySet<FeatureId> other,
        string subject)
    {
        var difference = source
            .Except(other)
            .OrderBy(featureId => featureId.Value, StringComparer.Ordinal)
            .ToArray();
        if (difference.Length != 0)
        {
            errors.Add($"{subject}: {Join(difference)}");
        }
    }

    private static void ValidateCatalogQueryContract(
        IFeatureCatalog catalog,
        FeatureDefinition definition,
        ICollection<string> errors)
    {
        if (!catalog.IsKnown(definition.Id))
        {
            errors.Add($"feature '{definition.Id}' is present but IsKnown returned false");
        }

        if (catalog.IsPublished(definition.Id) != (definition.State == FeatureReleaseState.Published))
        {
            errors.Add($"feature '{definition.Id}' publication query disagrees with its catalog state");
        }

        if (catalog.GetReleaseState(definition.Id) != definition.State)
        {
            errors.Add($"feature '{definition.Id}' release-state query disagrees with its catalog state");
        }

        if (!catalog.TryGetDefinition(definition.Id, out var queriedDefinition) ||
            queriedDefinition != definition)
        {
            errors.Add($"feature '{definition.Id}' cannot be read back consistently through TryGetDefinition");
        }

        if (!catalog.GetDependencies(definition.Id).SequenceEqual(definition.Dependencies))
        {
            errors.Add($"feature '{definition.Id}' dependency query disagrees with its catalog definition");
        }
    }

    private static void ValidateAcyclic(
        IReadOnlyDictionary<FeatureId, FeatureDefinition> definitions,
        ICollection<string> errors)
    {
        var visitState = new Dictionary<FeatureId, int>();
        var path = new List<FeatureId>();
        foreach (var featureId in definitions.Keys.OrderBy(featureId => featureId.Value, StringComparer.Ordinal))
        {
            if (!Visit(featureId))
            {
                return;
            }
        }

        return;

        bool Visit(FeatureId featureId)
        {
            if (visitState.TryGetValue(featureId, out var state))
            {
                if (state == 2)
                {
                    return true;
                }

                var cycleStart = path.IndexOf(featureId);
                var cycle = path.Skip(Math.Max(0, cycleStart)).Append(featureId);
                errors.Add($"feature dependency graph contains a cycle: {string.Join(" -> ", cycle)}");
                return false;
            }

            visitState[featureId] = 1;
            path.Add(featureId);
            foreach (var dependency in definitions[featureId].Dependencies.Where(definitions.ContainsKey))
            {
                if (!Visit(dependency))
                {
                    return false;
                }
            }

            path.RemoveAt(path.Count - 1);
            visitState[featureId] = 2;
            return true;
        }
    }

    private static void ValidateUnknownIdsFailClosed(
        IFeatureCatalog catalog,
        IReadOnlySet<FeatureId> actualIds,
        ICollection<string> errors)
    {
        var suffix = 0;
        FeatureId unknown;
        do
        {
            unknown = new FeatureId($"__release-profile-validator-unknown-{suffix++}");
        }
        while (actualIds.Contains(unknown));

        var definitionFound = catalog.TryGetDefinition(unknown, out var definition);
        if (catalog.IsKnown(unknown) ||
            catalog.IsPublished(unknown) ||
            catalog.GetReleaseState(unknown) != null ||
            catalog.GetDependencies(unknown).Count != 0 ||
            definitionFound ||
            definition != null)
        {
            errors.Add($"unknown feature ID '{unknown}' did not fail closed across catalog queries");
        }
    }

    private static void ValidateAgentClassifications(
        IFeatureCatalog catalog,
        ICollection<string> errors)
    {
        var expectedCommandKinds = Enum.GetValues<AgentCommandKind>()
            .Where(kind => kind != AgentCommandKind.Unknown)
            .OrderBy(kind => (int)kind)
            .ToArray();
        if (!AgentCommandFeaturePolicy.ClassifiedCommandKinds.SequenceEqual(expectedCommandKinds))
        {
            errors.Add("agent command classification is incomplete or contains duplicate/unexpected command kinds");
        }

        var expectedJobKinds = Enum.GetValues<JobKind>()
            .Where(kind => kind != JobKind.Unknown)
            .OrderBy(kind => (int)kind)
            .ToArray();
        if (!AgentCommandFeaturePolicy.ClassifiedJobKinds.SequenceEqual(expectedJobKinds))
        {
            errors.Add("agent job classification is incomplete or contains duplicate/unexpected job kinds");
        }

        var unknownClassifiedFeatures = AgentCommandFeaturePolicy.ClassifiedFeatureIds
            .Where(featureId => !catalog.IsKnown(featureId))
            .OrderBy(featureId => featureId.Value, StringComparer.Ordinal)
            .ToArray();
        if (unknownClassifiedFeatures.Length != 0)
        {
            errors.Add(
                $"agent command/job classifications reference feature IDs absent from the profile: {Join(unknownClassifiedFeatures)}");
        }

        var snapshot = AgentCommandFeaturePolicy.CreateReleaseProfileSnapshot(catalog, catalog.ReleaseId);
        if (!string.Equals(snapshot.ReleaseId, catalog.ReleaseId, StringComparison.Ordinal) ||
            !string.Equals(snapshot.ViewerReleaseId, catalog.ReleaseId, StringComparison.Ordinal) ||
            snapshot.Match != AgentReleaseProfileMatch.Match)
        {
            errors.Add("viewer/agent release-profile snapshot does not agree with the compiled catalog release ID");
        }

        var duplicateCapabilities = snapshot.PublishedCommandCapabilities
            .GroupBy(capability => capability.CommandKind)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToArray();
        if (duplicateCapabilities.Length != 0)
        {
            errors.Add($"agent release snapshot contains duplicate command capabilities: {string.Join(", ", duplicateCapabilities)}");
        }

        foreach (var capability in snapshot.PublishedCommandCapabilities)
        {
            foreach (var featureValue in capability.PublishedFeatureIds)
            {
                var featureId = new FeatureId(featureValue);
                if (!catalog.IsPublished(featureId))
                {
                    errors.Add(
                        $"agent capability '{capability.CommandKind}' advertises unpublished/unknown feature '{featureId}'");
                }
            }
        }
    }

    private static IReadOnlyList<FeatureId> SelectState(
        IEnumerable<FeatureDefinition> definitions,
        FeatureReleaseState state) =>
        new ReadOnlyCollection<FeatureId>(definitions
            .Where(definition => definition.State == state)
            .Select(definition => definition.Id)
            .OrderBy(featureId => featureId.Value, StringComparer.Ordinal)
            .ToArray());

    private static string Join(IEnumerable<FeatureId> featureIds) =>
        string.Join(", ", featureIds);
}
