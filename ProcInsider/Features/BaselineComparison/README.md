# Baseline Comparison Feature Slice

Start here for the optional Data-window Baseline Comparison feature. This directory is the discoverable owner for its comparison models, snapshot query, verdict engine, analyst policy, presentation view models, view, and activation/workspace adapter.

## Ownership

- `BaselineComparisonFeatureModule.cs` is the slice entry point. Its immutable typed viewer definition co-locates the stable `FeatureIds.BaselineComparison` dependency, activation adapter, and `DataTabKeys.Baseline` descriptor/view metadata; the module instance forwards workspace attach/detach and active-snapshot changes to the feature workflow.
- `SnapshotComparisonQueryService.cs` reads selected SQLite snapshots through the shared read-only query boundary.
- `SnapshotComparisonService.cs` owns artifact identity, meaningful/volatile fingerprints, verdicts, and accepted-policy application.
- `SnapshotComparisonCompletionService.cs` owns the immutable, cancellation-aware completion envelope. It resolves exactly one saved Baseline metadata record, hashes both compared files before and after the read-only comparison, and derives the comparison id only from the comparison version, saved Baseline id, and those hashes.
- `BaselineRiskEvidenceNormalizer.cs` reuses those exact Process stable-key/fingerprint semantics and emits the portable informational Process Risk input only for one confidence-1, non-legacy persisted process observation. It does not persist, rebuild scores, or consume presentation text.
- `BaselineRiskEvidenceMaterializer.cs` validates one completed version/hash-bound comparison, indexes at most 10,000 valid persisted current process observations once by that same exact stable key/fingerprint, delegates up to 1,000 findings to the normalizer, and returns deterministic per-process rows/typed diagnostics. Missing, ambiguous, duplicate, or over-64 groups fail closed without PID/latest-row fallback; persistence and rebuild scheduling remain outside the slice.
- `BaselineRiskProjectionUpdateService.cs` is the narrow viewer workflow boundary. It accepts only the exact current `ViewerSnapshotSqlite`, rechecks workspace/path/snapshot generations around the bounded observation query and atomic #374 store operation, preserves prior Baseline input for unavailable, stale, failed, or nonempty zero-match results, and permits a genuinely empty completed comparison to clear the Baseline generation.
- `BaselinePolicyService.cs` owns session `baseline-policy.json` metadata and accepted rules.
- `SnapshotComparisonModels.cs` contains only Baseline-specific comparison and policy contracts.
- `SnapshotComparisonViewModel.cs`, `SnapshotComparisonFindingRowViewModel.cs`, and `DataBaselineComparisonView.xaml` own the complete Baseline presentation workflow.

Shared `SessionPathService`, `SqliteStagingQueryService`, capture compatibility, feature catalog/publication, tab navigation, and shell composition remain outside this directory. Baseline code consumes those boundaries; it does not copy or bypass them.

## Layout And Namespace Rules

Feature-owned files live together under `ProcInsider/Features/BaselineComparison/`. New Baseline-only types use the `ProcInsider.Features.BaselineComparison` namespace. Existing model, service, and view-model types retain their `ProcInsider.Models`, `ProcInsider.Services`, and `ProcInsider.ViewModels` namespaces to avoid gratuitous compatibility churn during this representative move. A later namespace migration needs a concrete consumer benefit and explicit compatibility analysis.

Do not add concrete references from another feature slice. Put reusable contracts in the existing shared model/service boundary, then inject or compose them from `MainViewModel`. Keep the stable feature ID, Data tab key/order, publication state, and accepted-policy format unchanged unless a separately scoped issue owns that product change.

## Lifecycle And Extension Points

`MainViewModel` remains the WPF composition root. It adds the slice definition to `ViewerFeatureRegistry`, which validates it against the authoritative publication catalog without running factories, requires the explicit `module => module.Dispose()` cleanup delegate, registers its typed activation in `FeatureActivationRegistry`, and supplies its Data descriptor to `FeatureTabSet`. The composition root calls the module only when an already activated Baseline feature must receive a workspace or snapshot transition. Hidden Baseline remains unconstructed because descriptor creation and the risk-publication factory are lazy and `FeatureActivationRegistry` rejects unpublished activation before running either factory. Workspace/snapshot replacement and disposal cancel an in-flight publication and clear retained comparison identity.

When extending the feature:

1. Add comparison/policy behavior and Baseline-specific contracts in this directory.
2. Consume snapshot evidence through `SnapshotComparisonQueryService` and shared read-only query services; never open a live writer or modify compared databases.
3. Store analyst metadata only through `BaselinePolicyService` at `SessionPathService.BaselinePolicyPath`.
4. Put substantial UI in `DataBaselineComparisonView.xaml` and workflow state in its view model; keep code-behind WPF-only.
5. Change `BaselineComparisonFeatureModule` only for its typed definition, activation, view construction, or workspace lifecycle. `CurrentEducationalReleaseProfile` remains authoritative for publication state/dependencies, `FeatureTabSet` for combined shell order/fallback, and `AgentCommandFeaturePolicy` for agent commands/jobs; change those shared policies only when their stable cross-feature contract changes.

## Validation

Run the full Release solution build plus:

- `BaselineComparisonSelfTest.dll` for hash-stable completion, metadata ambiguity/unavailability, comparison and publication cancellation, exact live-snapshot baseline-risk publication, zero-match retention, empty replacement, bounds/ambiguity/group suppression, policy republish, workspace-rebind, hidden zero-construction, and repeated-disposal coverage;
- `FeatureCatalogSelfTest.dll` for hidden/publication and lazy-activation behavior;
- `ArchitectureSelfTest.dll` for feature-module and persistence boundaries;
- `CaptureWorkspaceSelfTest.dll` for session policy routing and archived read-only preservation;
- `tools/dev/Test-AiDocumentation.ps1` and `git diff --check` for routing integrity.

## Locality Measurement And Follow-Up Lessons

Before this slice, eight feature-owned production files were spread across four roots (`Models/Telemetry`, `Services`, `ViewModels`, and `Views/Features/Baseline`), while `MainViewModel` also knew the service graph, view type, and lifecycle calls. There was no focused Baseline test or single feature entry point.

After this slice, nine feature-owned production files and this guide live under one root. A representative verdict, policy, or Baseline UI change begins in one production directory and one focused test project; `MainViewModel` changes only when the shared registration or workspace contract changes. The routed architecture documents remain cross-cutting maps, not prerequisites for discovering the implementation.

This representative move produced two follow-ups: typed registration consolidates stable metadata without hiding publication or navigation policy, and `tools/dev/FeatureScaffoldSelfTest` can now generate only the requested proven directory, entry module, focused view/view model, optional workflow/read-only query boundary, README, and focused test shape. It never generates feature-to-feature references, duplicate shared infrastructure, reflection discovery, evidence writers, or a general dependency-injection layer.
