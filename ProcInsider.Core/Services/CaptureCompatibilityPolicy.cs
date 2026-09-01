using System.IO;
using System.Security.Cryptography;
using System.Text;
using ProcInsider.Models;

namespace ProcInsider.Services;

/// <summary>Core-owned, side-effect-free capture compatibility and migration metadata policy.</summary>
public static class CaptureCompatibilityPolicy
{
    public const int CurrentManifestSchemaVersion = 1;
    public const int MinimumSupportedManifestSchemaVersion = 1;
    public const int CurrentEvidenceFormatVersion = 1;
    public const int MinimumSupportedEvidenceFormatVersion = 1;

    public static IReadOnlyList<CaptureMigrationDefinition> Migrations { get; } =
        BuildMigrationDefinitions();

    public static CaptureMigrationDefinition GetMigration(string migrationId)
        => Migrations.FirstOrDefault(
               definition => string.Equals(definition.MigrationId, migrationId, StringComparison.Ordinal))
           ?? throw new ArgumentOutOfRangeException(nameof(migrationId), migrationId, "Unknown capture migration ID.");

    private static IReadOnlyList<CaptureMigrationDefinition> BuildMigrationDefinitions()
    {
        var definitions = new[]
        {
            Define(10, "001_initial_sqlite_staging", CaptureMigrationKind.PrimaryEvidence,
                "Initial SQLite staging schema.", []),
            Define(20, "002_phase3c_listing_indexes", CaptureMigrationKind.RebuildableAnalysisState,
                "Phase 3C: additive process listing indexes for filter and sort columns.", ["001_initial_sqlite_staging"]),
            Define(30, "003_phase5f_bookmarks", CaptureMigrationKind.PrimaryEvidence,
                "Phase 5F: stable target bookmark table and lookup indexes.", ["001_initial_sqlite_staging"]),
            Define(40, "004_phase6b_search_index", CaptureMigrationKind.RebuildableAnalysisState,
                "Phase 6B: unified FTS5 search index over staged telemetry records.", ["003_phase5f_bookmarks"]),
            Define(50, "005_phase6d_memory_dumps", CaptureMigrationKind.PrimaryEvidence,
                "Phase 6D: process memory dump metadata table and indexes.", ["003_phase5f_bookmarks"]),
            Define(60, "006_phase6f_pe_analysis", CaptureMigrationKind.PrimaryEvidence,
                "Phase 6F: PE analysis metadata table and indexes.", ["005_phase6d_memory_dumps"]),
            Define(70, "007_phase6g_network_captures", CaptureMigrationKind.PrimaryEvidence,
                "Phase 6G: network capture segment metadata table and indexes.", ["006_phase6f_pe_analysis"]),
            Define(80, "008_phase6h_zeek_artifacts", CaptureMigrationKind.PrimaryEvidence,
                "Phase 6H: Zeek network artifact metadata, raw identity, and correlation fields.", ["007_phase6g_network_captures"]),
            Define(90, "009_phase6i_filesystem_artifacts", CaptureMigrationKind.PrimaryEvidence,
                "Phase 6I: generic filesystem artifact import metadata and indexes.", ["008_phase6h_zeek_artifacts"]),
            Define(100, "010_v2_evidence_identity", CaptureMigrationKind.PrimaryEvidence,
                "App V2 A05: case/session/capture/source/host/execution identity columns and indexes.", ["009_phase6i_filesystem_artifacts"]),
            Define(110, "011_v3_sqlite_live_indexes", CaptureMigrationKind.RebuildableAnalysisState,
                "App V3 SQLite01: lean live capture indexes for agent write-time lookups.", ["010_v2_evidence_identity"]),
            Define(120, "012_v3_memory_volatility", CaptureMigrationKind.PrimaryEvidence,
                "App V3 Memory01: full system memory image metadata, Volatility plugin runs, and normalized memory process rows.", ["010_v2_evidence_identity"]),
            Define(125, "012_v3_sqlite_analysis_indexes", CaptureMigrationKind.RebuildableAnalysisState,
                "App V3 SQLite01: viewer browsing/search indexes and rebuilt FTS search index.", ["012_v3_memory_volatility"]),
            Define(130, "013_v3_zeek_flow_context", CaptureMigrationKind.PrimaryEvidence,
                "App V3 Network01: Zeek connection duration, packet/byte counters, TLS/QUIC/weird context, and flow-review fields.", ["012_v3_memory_volatility"]),
            Define(140, "014_pe_file_freshness", CaptureMigrationKind.PrimaryEvidence,
                "PE performance stage 4: process-image last-write freshness metadata.", ["013_v3_zeek_flow_context"]),
            Define(150, "015_pe_string_analysis_state", CaptureMigrationKind.PrimaryEvidence,
                "PE performance stage 5: explicit deferred/completed string-analysis state.", ["014_pe_file_freshness"]),
            Define(160, "016_pe_analysis_performance", CaptureMigrationKind.PrimaryEvidence,
                "PE performance stage 6: compact per-analysis phase timings.", ["015_pe_string_analysis_state"]),
            Define(170, "017_process_entity_identity", CaptureMigrationKind.PrimaryEvidence,
                "Add scoped process entities, aliases, parent links, and deterministic evidence-link backfill.", ["016_pe_analysis_performance"]),
            Define(180, "018_source_run_provenance", CaptureMigrationKind.PrimaryEvidence,
                "Add immutable source runs, job/raw lineage, exact writer provenance, and legacy diagnostics.", ["017_process_entity_identity"]),
            Define(190, "019_process_observations_projection", CaptureMigrationKind.PrimaryEvidence,
                "Add immutable process observations, deterministic persisted projection, field provenance, and rebuild diagnostics.", ["018_source_run_provenance"]),
            Define(200, "020_evidence_relations", CaptureMigrationKind.PrimaryEvidence,
                "Add typed auditable evidence relations, deterministic correlation decisions, derivation chains, and compatibility backfill.", ["019_process_observations_projection"]),
            Define(210, "021_evidence_recorrelation", CaptureMigrationKind.RebuildableAnalysisState,
                "Preserve process-bearing correlation inputs and add bounded deterministic re-correlation diagnostics.", ["020_evidence_relations"]),
            Define(220, "022_process_source_pipeline", CaptureMigrationKind.PrimaryEvidence,
                "Persist adapter and observation-kind identity for the unified process-producing source pipeline.", ["020_evidence_relations"]),
            Define(230, "023_process_attached_evidence", CaptureMigrationKind.PrimaryEvidence,
                "Link process statistics, events, modules, handles, dumps, and PE analyses to scoped entities and source runs.", ["022_process_source_pipeline"]),
            Define(240, "024_independent_artifact_lineage", CaptureMigrationKind.PrimaryEvidence,
                "Link network, Zeek, filesystem, memory, raw, and generic artifacts through exact source-run and derivation relations.", ["023_process_attached_evidence"]),
            Define(250, "025_authenticode_verification", CaptureMigrationKind.PrimaryEvidence,
                "Add immutable process-image Authenticode verification observations, exact provenance, and bounded query indexes.", ["024_independent_artifact_lineage"]),
            Define(260, "026_process_risk_projection", CaptureMigrationKind.RebuildableAnalysisState,
                "Add rebuildable process-risk projections, source coverage, and ordered evidence-backed contributors.", ["025_authenticode_verification"]),
            Define(270, "027_sigma_risk_inputs", CaptureMigrationKind.RebuildableAnalysisState,
                "Add normalized hash-bound Sigma inputs for atomic process-risk projection rebuilds.", ["026_process_risk_projection"]),
            Define(280, "028_baseline_risk_inputs", CaptureMigrationKind.RebuildableAnalysisState,
                "Add normalized hash-bound Baseline inputs for atomic process-risk projection rebuilds.", ["027_sigma_risk_inputs"]),
            Define(290, "029_yara_analysis_results", CaptureMigrationKind.RebuildableAnalysisState,
                "Add normalized exact-scope YARA scan, match, tag, and metadata analysis state.", ["028_baseline_risk_inputs"]),
            Define(300, "030_yara_risk_inputs", CaptureMigrationKind.RebuildableAnalysisState,
                "Add exact review-gated process-attributed YARA inputs for atomic process-risk rebuilds.", ["029_yara_analysis_results"]),
            Define(310, "031_reputation_attributions", CaptureMigrationKind.RebuildableAnalysisState,
                "Add immutable exact-evidence process reputation attributions and bounded query indexes.", ["030_yara_risk_inputs"]),
            Define(320, "032_infrastructure_evidence_outbox", CaptureMigrationKind.PrimaryEvidence,
                "Add the inert transactional Infrastructure evidence outbox and durable acknowledgement ledger.", ["025_authenticode_verification"])
        };

        ValidateMigrationDefinitions(definitions);
        return definitions;
    }

    private static CaptureMigrationDefinition Define(
        int sequence,
        string migrationId,
        CaptureMigrationKind kind,
        string description,
        IReadOnlyList<string> prerequisites)
        => new(
            sequence,
            migrationId,
            CurrentEvidenceFormatVersion,
            CurrentEvidenceFormatVersion,
            kind,
            description,
            ComputeMigrationDefinitionHash(sequence, migrationId, kind, description),
            prerequisites,
            kind == CaptureMigrationKind.PrimaryEvidence);

    public static CaptureCompatibilityAssessment Assess(CaptureCompatibilityInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var missingPrimary = new List<string>();
        var missingAnalysis = new List<string>();
        var unknown = new List<string>();
        var mismatches = new List<string>();
        var analysisState = input.Evidence == null
            ? CaptureAnalysisState.NotAssessed
            : CaptureAnalysisState.Current;

        CaptureCompatibilityState? failure = null;
        var message = string.Empty;

        if (!string.IsNullOrWhiteSpace(input.InspectionFailure))
        {
            failure = CaptureCompatibilityState.CorruptVersionMetadata;
            message = $"Capture compatibility metadata could not be inspected: {input.InspectionFailure}";
        }
        else if (!input.PathsAreContained)
        {
            failure = CaptureCompatibilityState.InvalidContainedPath;
            message = "The capture manifest resolves one or more paths outside the selected package root.";
        }
        else if (input.Manifest != null)
        {
            failure = AssessManifest(input.Manifest.SchemaVersion, out message);
        }

        if (failure == null && input.Evidence != null)
        {
            failure = AssessEvidenceVersion(input.Evidence, out message);
        }

        if (failure == null && input.Manifest != null && input.Evidence != null)
        {
            if (input.Manifest.DeclaredEvidenceFormatVersion is int declaredFormat &&
                input.Evidence.FormatVersion is int actualFormat &&
                declaredFormat != actualFormat)
            {
                failure = CaptureCompatibilityState.ManifestEvidenceVersionMismatch;
                message = $"session.json declares evidence format {declaredFormat}, but the database reports format {actualFormat}.";
            }
            else if (!string.IsNullOrWhiteSpace(input.Manifest.SessionId) &&
                     !string.IsNullOrWhiteSpace(input.Evidence.EvidenceSessionId) &&
                     !string.Equals(input.Manifest.SessionId, input.Evidence.EvidenceSessionId, StringComparison.Ordinal))
            {
                failure = CaptureCompatibilityState.SessionIdentityMismatch;
                message = $"session.json identifies session '{input.Manifest.SessionId}', but the evidence database identifies '{input.Evidence.EvidenceSessionId}'.";
            }
        }

        if (failure == null && input.Evidence != null &&
            !string.IsNullOrWhiteSpace(input.ExpectedEvidenceSessionId) &&
            !string.IsNullOrWhiteSpace(input.Evidence.EvidenceSessionId) &&
            !string.Equals(input.ExpectedEvidenceSessionId, input.Evidence.EvidenceSessionId, StringComparison.Ordinal))
        {
            failure = CaptureCompatibilityState.SessionIdentityMismatch;
            message = $"The requested session is '{input.ExpectedEvidenceSessionId}', but the evidence database identifies '{input.Evidence.EvidenceSessionId}'.";
        }

        var migrationState = failure == null && input.Evidence != null
            ? AssessMigrations(input, missingPrimary, missingAnalysis, unknown, mismatches, out message)
            : null;
        failure ??= migrationState;
        if (missingAnalysis.Count > 0)
        {
            analysisState = CaptureAnalysisState.RebuildRequired;
        }

        var state = failure ?? CaptureCompatibilityState.CompatibleCurrent;
        if (state == CaptureCompatibilityState.CompatibleCurrent && string.IsNullOrWhiteSpace(message))
        {
            message = analysisState == CaptureAnalysisState.RebuildRequired
                ? "The capture evidence format is current; rebuildable analysis state may be prepared by an allowed maintenance context."
                : "The capture manifest and evidence format are current and complete.";
        }

        var capabilities = GetCapabilities(
            state,
            input.Context,
            input.ArtifactKind,
            input.Evidence != null);
        return new CaptureCompatibilityAssessment
        {
            State = state,
            AnalysisState = analysisState,
            Context = input.Context,
            ArtifactKind = input.ArtifactKind,
            ManifestSchemaVersion = input.Manifest?.SchemaVersion,
            EvidenceFormatVersion = input.Evidence?.FormatVersion,
            MinimumSupportedManifestSchemaVersion = MinimumSupportedManifestSchemaVersion,
            MaximumSupportedManifestSchemaVersion = CurrentManifestSchemaVersion,
            MinimumSupportedEvidenceFormatVersion = MinimumSupportedEvidenceFormatVersion,
            MaximumSupportedEvidenceFormatVersion = CurrentEvidenceFormatVersion,
            Capabilities = capabilities,
            StatusCode = GetStatusCode(state),
            Message = message,
            MissingPrimaryMigrations = missingPrimary,
            MissingAnalysisMigrations = missingAnalysis,
            UnknownMigrations = unknown,
            DefinitionMismatches = mismatches,
            SafeNextAction = GetSafeNextAction(state, input.Context)
        };
    }

    public static void EnsureAllowed(
        CaptureCompatibilityAssessment assessment,
        CaptureOpenCapability requiredCapability)
    {
        ArgumentNullException.ThrowIfNull(assessment);
        if (assessment.Allows(requiredCapability))
        {
            return;
        }

        throw new InvalidDataException(
            $"{FormatDiagnostic(assessment)} " +
            $"The {assessment.Context} context does not allow {requiredCapability}.");
    }

    public static string FormatDiagnostic(
        CaptureCompatibilityAssessment assessment,
        string artifactPath = "",
        bool packageLeftUntouched = true,
        string recoveryCopyPath = "")
    {
        ArgumentNullException.ThrowIfNull(assessment);
        var displayName = string.IsNullOrWhiteSpace(artifactPath)
            ? "the selected capture"
            : Path.GetFullPath(artifactPath);
        var manifest = assessment.ManifestSchemaVersion?.ToString() ?? "unknown";
        var evidence = assessment.EvidenceFormatVersion?.ToString() ?? "unknown";
        var untouched = packageLeftUntouched ? " The package was left untouched." : string.Empty;
        var recovery = string.IsNullOrWhiteSpace(recoveryCopyPath)
            ? string.Empty
            : $" Recovery copy: {Path.GetFullPath(recoveryCopyPath)}.";
        return $"{assessment.StatusCode}: {displayName}: {assessment.Message} " +
               $"Detected manifest/evidence versions: {manifest}/{evidence}; supported manifest range " +
               $"{assessment.MinimumSupportedManifestSchemaVersion}-{assessment.MaximumSupportedManifestSchemaVersion}; " +
               $"supported evidence range {assessment.MinimumSupportedEvidenceFormatVersion}-{assessment.MaximumSupportedEvidenceFormatVersion}." +
               untouched + recovery + $" Next action: {assessment.SafeNextAction}";
    }

    public static string ComputeMigrationDefinitionHash(
        int sequence,
        string migrationId,
        CaptureMigrationKind kind,
        string description)
    {
        var text = string.Join(
            '\n',
            CurrentEvidenceFormatVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            sequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            migrationId,
            kind.ToString(),
            description);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    }

    public static void ValidateMigrationDefinitions(
        IReadOnlyList<CaptureMigrationDefinition> definitions)
    {
        ArgumentNullException.ThrowIfNull(definitions);
        if (definitions.Count == 0)
        {
            throw CatalogError("migration.catalog.empty", "The SQLite evidence migration catalog is empty.");
        }

        var duplicateIds = definitions
            .GroupBy(definition => definition.MigrationId, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        if (duplicateIds.Length > 0)
        {
            throw CatalogError(
                "migration.catalog.duplicate-id",
                $"Duplicate migration IDs: {string.Join(", ", duplicateIds)}.");
        }

        var duplicateSequences = definitions
            .GroupBy(definition => definition.Sequence)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .OrderBy(value => value)
            .ToArray();
        if (duplicateSequences.Length > 0)
        {
            throw CatalogError(
                "migration.catalog.duplicate-sequence",
                $"Duplicate migration sequences: {string.Join(", ", duplicateSequences)}.");
        }

        var ordered = definitions.OrderBy(definition => definition.Sequence).ToArray();
        if (ordered.Any(definition => definition.Sequence <= 0) ||
            !ordered.SequenceEqual(definitions))
        {
            throw CatalogError(
                "migration.catalog.order",
                "Migration definitions must use positive, monotonically increasing sequence values.");
        }

        var byId = ordered.ToDictionary(definition => definition.MigrationId, StringComparer.Ordinal);
        for (var index = 0; index < ordered.Length; index++)
        {
            var definition = ordered[index];
            if (string.IsNullOrWhiteSpace(definition.MigrationId) ||
                string.IsNullOrWhiteSpace(definition.Description))
            {
                throw CatalogError(
                    "migration.catalog.invalid-definition",
                    $"Migration sequence {definition.Sequence} is missing an ID or description.");
            }

            if (definition.SourceEvidenceFormatVersion <= 0 ||
                definition.TargetEvidenceFormatVersion < definition.SourceEvidenceFormatVersion ||
                definition.TargetEvidenceFormatVersion > CurrentEvidenceFormatVersion)
            {
                throw CatalogError(
                    "migration.catalog.unsupported-target",
                    $"Migration {definition.MigrationId} targets unsupported evidence format " +
                    $"{definition.SourceEvidenceFormatVersion}->{definition.TargetEvidenceFormatVersion}.");
            }

            if (definition.Kind == CaptureMigrationKind.PrimaryEvidence &&
                !definition.RequiresExclusiveLiveDatabaseOwnership)
            {
                throw CatalogError(
                    "migration.catalog.authority",
                    $"Primary-evidence migration {definition.MigrationId} must require exclusive live-database ownership.");
            }

            if (index > 0 && definition.PrerequisiteMigrationIds.Count == 0)
            {
                throw CatalogError(
                    "migration.catalog.gap",
                    $"Migration {definition.MigrationId} has no prerequisite and would create an untracked catalog gap.");
            }

            var duplicatePrerequisites = definition.PrerequisiteMigrationIds
                .GroupBy(value => value, StringComparer.Ordinal)
                .Where(group => group.Count() > 1)
                .Select(group => group.Key)
                .ToArray();
            if (duplicatePrerequisites.Length > 0)
            {
                throw CatalogError(
                    "migration.catalog.duplicate-prerequisite",
                    $"Migration {definition.MigrationId} repeats prerequisites: {string.Join(", ", duplicatePrerequisites)}.");
            }

            foreach (var prerequisiteId in definition.PrerequisiteMigrationIds)
            {
                if (!byId.TryGetValue(prerequisiteId, out var prerequisite))
                {
                    throw CatalogError(
                        "migration.catalog.missing-prerequisite",
                        $"Migration {definition.MigrationId} requires unknown migration {prerequisiteId}.");
                }

                if (prerequisite.Sequence >= definition.Sequence)
                {
                    throw CatalogError(
                        "migration.catalog.prerequisite-order",
                        $"Migration {definition.MigrationId} prerequisite {prerequisiteId} is not earlier in the catalog.");
                }
            }

            var expectedHash = ComputeMigrationDefinitionHash(
                definition.Sequence,
                definition.MigrationId,
                definition.Kind,
                definition.Description);
            if (!string.Equals(expectedHash, definition.DefinitionHash, StringComparison.Ordinal))
            {
                throw CatalogError(
                    "migration.catalog.definition-hash",
                    $"Migration {definition.MigrationId} does not match its deterministic definition hash.");
            }
        }
    }

    private static InvalidDataException CatalogError(string code, string message)
        => new($"{code}: {message}");

    private static CaptureCompatibilityState? AssessManifest(int? schemaVersion, out string message)
    {
        if (!schemaVersion.HasValue)
        {
            message = "session.json is missing its manifest schema version.";
            return CaptureCompatibilityState.MissingVersionMetadata;
        }

        if (schemaVersion.Value <= 0)
        {
            message = $"session.json contains invalid manifest schema version {schemaVersion.Value}.";
            return CaptureCompatibilityState.CorruptVersionMetadata;
        }

        if (schemaVersion.Value > CurrentManifestSchemaVersion)
        {
            message = $"session.json uses newer manifest schema version {schemaVersion.Value}; this reader supports through {CurrentManifestSchemaVersion}.";
            return CaptureCompatibilityState.NewerManifestVersion;
        }

        if (schemaVersion.Value < MinimumSupportedManifestSchemaVersion)
        {
            message = $"session.json uses unsupported older manifest schema version {schemaVersion.Value}; the minimum supported version is {MinimumSupportedManifestSchemaVersion}.";
            return CaptureCompatibilityState.UnsupportedOlderManifestVersion;
        }

        message = string.Empty;
        return null;
    }

    private static CaptureCompatibilityState? AssessEvidenceVersion(
        CaptureEvidenceCompatibilityMetadata evidence,
        out string message)
    {
        if (!evidence.FormatVersion.HasValue)
        {
            message = "The evidence database is missing SchemaInfo.EvidenceFormatVersion/SchemaVersion metadata.";
            return CaptureCompatibilityState.MissingVersionMetadata;
        }

        if (evidence.FormatVersion.Value <= 0)
        {
            message = $"The evidence database contains invalid format version {evidence.FormatVersion.Value}.";
            return CaptureCompatibilityState.CorruptVersionMetadata;
        }

        if (evidence.FormatVersion.Value > CurrentEvidenceFormatVersion)
        {
            message = $"The evidence database uses newer format version {evidence.FormatVersion.Value}; this reader supports through {CurrentEvidenceFormatVersion}.";
            return CaptureCompatibilityState.NewerEvidenceFormatVersion;
        }

        if (evidence.FormatVersion.Value < MinimumSupportedEvidenceFormatVersion)
        {
            message = $"The evidence database uses unsupported older format version {evidence.FormatVersion.Value}; the minimum supported version is {MinimumSupportedEvidenceFormatVersion}.";
            return CaptureCompatibilityState.UnsupportedOlderEvidenceFormatVersion;
        }

        if (!evidence.HasRequiredSchema)
        {
            message = "The evidence database is missing required format metadata or core evidence tables.";
            return CaptureCompatibilityState.MissingRequiredEvidenceSchema;
        }

        message = string.Empty;
        return null;
    }

    private static CaptureCompatibilityState? AssessMigrations(
        CaptureCompatibilityInput input,
        List<string> missingPrimary,
        List<string> missingAnalysis,
        List<string> unknown,
        List<string> mismatches,
        out string message)
    {
        var evidence = input.Evidence!;
        var duplicates = evidence.AppliedMigrations
            .GroupBy(migration => migration.MigrationId, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        if (duplicates.Length > 0)
        {
            message = $"The migration ledger contains duplicate IDs: {string.Join(", ", duplicates)}.";
            return CaptureCompatibilityState.CorruptVersionMetadata;
        }

        var definitions = Migrations.ToDictionary(
            definition => definition.MigrationId,
            StringComparer.Ordinal);
        foreach (var applied in evidence.AppliedMigrations)
        {
            if (!definitions.TryGetValue(applied.MigrationId, out var definition))
            {
                unknown.Add(applied.MigrationId);
                continue;
            }

            var appliedHash = string.IsNullOrWhiteSpace(applied.DefinitionHash)
                ? ComputeMigrationDefinitionHash(
                    definition.Sequence,
                    applied.MigrationId,
                    definition.Kind,
                    applied.Description)
                : applied.DefinitionHash.Trim().ToLowerInvariant();
            if (!string.Equals(appliedHash, definition.DefinitionHash, StringComparison.Ordinal))
            {
                mismatches.Add(applied.MigrationId);
            }

            if (applied.Sequence.HasValue && applied.Sequence.Value != definition.Sequence)
            {
                message = $"Migration '{applied.MigrationId}' records sequence {applied.Sequence.Value}, but the catalog requires {definition.Sequence}.";
                return CaptureCompatibilityState.CorruptVersionMetadata;
            }
        }

        unknown.Sort(StringComparer.Ordinal);
        mismatches.Sort(StringComparer.Ordinal);
        if (unknown.Count > 0)
        {
            message = $"The migration ledger contains unknown IDs: {string.Join(", ", unknown)}. Evidence semantics will not be guessed.";
            return CaptureCompatibilityState.UnknownMigrationHistory;
        }

        if (mismatches.Count > 0)
        {
            message = $"Known migration definitions do not match the reader catalog: {string.Join(", ", mismatches)}.";
            return CaptureCompatibilityState.MigrationDefinitionMismatch;
        }

        var appliedIds = evidence.AppliedMigrations
            .Select(migration => migration.MigrationId)
            .ToHashSet(StringComparer.Ordinal);
        var appliedDefinitions = evidence.AppliedMigrations
            .Where(applied => definitions.TryGetValue(applied.MigrationId, out var definition) &&
                              definition.Kind == CaptureMigrationKind.PrimaryEvidence)
            .Select(applied => new
            {
                Applied = applied,
                Definition = definitions[applied.MigrationId]
            })
            .ToArray();
        for (var index = 1; index < appliedDefinitions.Length; index++)
        {
            if (appliedDefinitions[index].Definition.Sequence < appliedDefinitions[index - 1].Definition.Sequence)
            {
                message = $"The migration ledger is out of catalog order at '{appliedDefinitions[index].Applied.MigrationId}'.";
                return CaptureCompatibilityState.IncompleteMigration;
            }
        }

        foreach (var item in appliedDefinitions)
        {
            var missingPrerequisites = item.Definition.PrerequisiteMigrationIds
                .Where(prerequisite => !appliedIds.Contains(prerequisite))
                .ToArray();
            if (missingPrerequisites.Length > 0)
            {
                message = $"Migration '{item.Applied.MigrationId}' is recorded without prerequisites: {string.Join(", ", missingPrerequisites)}.";
                return CaptureCompatibilityState.IncompleteMigration;
            }
        }
        missingPrimary.AddRange(Migrations
            .Where(definition => definition.Kind == CaptureMigrationKind.PrimaryEvidence &&
                                 !appliedIds.Contains(definition.MigrationId))
            .OrderBy(definition => definition.Sequence)
            .Select(definition => definition.MigrationId));
        missingAnalysis.AddRange(Migrations
            .Where(definition => definition.Kind == CaptureMigrationKind.RebuildableAnalysisState &&
                                 !appliedIds.Contains(definition.MigrationId))
            .OrderBy(definition => definition.Sequence)
            .Select(definition => definition.MigrationId));

        if (missingPrimary.Count == 0)
        {
            message = string.Empty;
            return null;
        }

        var highestAppliedPrimarySequence = Migrations
            .Where(definition => definition.Kind == CaptureMigrationKind.PrimaryEvidence &&
                                 appliedIds.Contains(definition.MigrationId))
            .Select(definition => definition.Sequence)
            .DefaultIfEmpty(0)
            .Max();
        var hasGap = Migrations.Any(definition =>
            definition.Kind == CaptureMigrationKind.PrimaryEvidence &&
            definition.Sequence < highestAppliedPrimarySequence &&
            !appliedIds.Contains(definition.MigrationId));
        if (hasGap)
        {
            message = $"The evidence migration ledger is incomplete; missing non-terminal migrations: {string.Join(", ", missingPrimary)}.";
            return CaptureCompatibilityState.IncompleteMigration;
        }

        if (input.Context == CaptureOpenContext.AgentWritableLive)
        {
            message = $"The live evidence database requires agent-owned additive migrations before capture writes: {string.Join(", ", missingPrimary)}.";
            return CaptureCompatibilityState.MigrationRequired;
        }

        message = $"The evidence database is a recognized format-1 legacy revision missing newer additive migrations: {string.Join(", ", missingPrimary)}.";
        return CaptureCompatibilityState.SupportedLegacy;
    }

    private static CaptureOpenCapability GetCapabilities(
        CaptureCompatibilityState state,
        CaptureOpenContext context,
        CaptureArtifactKind artifactKind,
        bool hasEvidenceMetadata)
    {
        var capabilities = CaptureOpenCapability.InspectMetadata;
        if (!hasEvidenceMetadata)
        {
            return capabilities;
        }
        if (state is CaptureCompatibilityState.MigrationRequired or CaptureCompatibilityState.IncompleteMigration)
        {
            return context == CaptureOpenContext.AgentWritableLive &&
                   artifactKind == CaptureArtifactKind.LiveAuthoritativeDatabase
                ? capabilities | CaptureOpenCapability.MigratePrimaryEvidence
                : capabilities;
        }

        if (state is not (CaptureCompatibilityState.CompatibleCurrent or CaptureCompatibilityState.SupportedLegacy))
        {
            return capabilities;
        }

        return context switch
        {
            CaptureOpenContext.AgentWritableLive when
                state == CaptureCompatibilityState.CompatibleCurrent &&
                artifactKind == CaptureArtifactKind.LiveAuthoritativeDatabase =>
                capabilities | CaptureOpenCapability.ReadEvidence | CaptureOpenCapability.WritePrimaryEvidence,
            CaptureOpenContext.ViewerLiveSourceReadOnly when
                artifactKind == CaptureArtifactKind.LiveAuthoritativeDatabase =>
                capabilities | CaptureOpenCapability.ReadEvidence,
            CaptureOpenContext.ViewerLiveSnapshot =>
                capabilities | CaptureOpenCapability.ReadEvidence | CaptureOpenCapability.MaintainAnalysisState,
            CaptureOpenContext.ViewerArchivedReadOnly =>
                capabilities | CaptureOpenCapability.ReadEvidence,
            CaptureOpenContext.ArchivedAnalysisMaintenance =>
                capabilities | CaptureOpenCapability.ReadEvidence | CaptureOpenCapability.MaintainAnalysisState,
            _ => capabilities
        };
    }

    private static string GetSafeNextAction(
        CaptureCompatibilityState state,
        CaptureOpenContext context)
        => state switch
        {
            CaptureCompatibilityState.CompatibleCurrent => "Continue with the requested open mode.",
            CaptureCompatibilityState.SupportedLegacy =>
                "Open read-only with this viewer, or reconnect the matching live agent to migrate the authoritative live database.",
            CaptureCompatibilityState.MigrationRequired or CaptureCompatibilityState.IncompleteMigration
                when context == CaptureOpenContext.AgentWritableLive =>
                "Let the authorized agent complete or resume migration before accepting capture jobs.",
            CaptureCompatibilityState.NewerManifestVersion or CaptureCompatibilityState.NewerEvidenceFormatVersion =>
                "Use a newer compatible viewer or agent; do not modify this package.",
            CaptureCompatibilityState.SessionIdentityMismatch or CaptureCompatibilityState.ManifestEvidenceVersionMismatch =>
                "Select the matching session manifest and evidence database.",
            CaptureCompatibilityState.InvalidContainedPath =>
                "Repair or re-export the package so every recorded path remains inside the selected capture root.",
            CaptureCompatibilityState.UnknownMigrationHistory or CaptureCompatibilityState.MigrationDefinitionMismatch =>
                "Use the application release that created the package or make an explicit diagnostic copy.",
            CaptureCompatibilityState.MissingVersionMetadata or CaptureCompatibilityState.CorruptVersionMetadata or
                CaptureCompatibilityState.MissingRequiredEvidenceSchema =>
                "Inspect a copy with the producing release; do not activate evidence reads or writes.",
            CaptureCompatibilityState.UnsupportedOlderManifestVersion or CaptureCompatibilityState.UnsupportedOlderEvidenceFormatVersion =>
                "Use a compatible legacy reader or an explicit upgrade-a-copy workflow.",
            _ => "Leave the package untouched and inspect compatibility diagnostics."
        };

    private static string GetStatusCode(CaptureCompatibilityState state)
        => state switch
        {
            CaptureCompatibilityState.CompatibleCurrent => "capture.compatible.current",
            CaptureCompatibilityState.SupportedLegacy => "capture.compatible.legacy",
            CaptureCompatibilityState.MigrationRequired => "capture.migration.required",
            CaptureCompatibilityState.IncompleteMigration => "capture.migration.incomplete",
            CaptureCompatibilityState.MissingVersionMetadata => "capture.version.missing",
            CaptureCompatibilityState.CorruptVersionMetadata => "capture.version.corrupt",
            CaptureCompatibilityState.UnsupportedOlderManifestVersion => "capture.manifest.unsupported-old",
            CaptureCompatibilityState.UnsupportedOlderEvidenceFormatVersion => "capture.evidence.unsupported-old",
            CaptureCompatibilityState.NewerManifestVersion => "capture.manifest.newer",
            CaptureCompatibilityState.NewerEvidenceFormatVersion => "capture.evidence.newer",
            CaptureCompatibilityState.UnknownMigrationHistory => "capture.migration.unknown",
            CaptureCompatibilityState.MigrationDefinitionMismatch => "capture.migration.definition-mismatch",
            CaptureCompatibilityState.ManifestEvidenceVersionMismatch => "capture.version.manifest-evidence-mismatch",
            CaptureCompatibilityState.SessionIdentityMismatch => "capture.identity.mismatch",
            CaptureCompatibilityState.InvalidContainedPath => "capture.path.outside-package",
            CaptureCompatibilityState.MissingRequiredEvidenceSchema => "capture.schema.missing",
            _ => "capture.compatibility.unknown"
        };

}
