# Explorer Search Feature Slice

Start here for the optional Explorer Search feature. This directory is the discoverable owner for Search parsing, presentation behavior, its focused WPF view, the narrow read-only query use case, and the typed activation/workspace adapter.

## Ownership

- `SearchFeatureModule.cs` is the slice entry point. Its immutable typed viewer definition co-locates `FeatureIds.SearchAndSigma` dependencies, lazy activation, explicit cleanup, and the stable `ExplorerTabKeys.Search` descriptor/view metadata. The module owns result-count forwarding and maps shared snapshot-analysis state into Search availability.
- `SearchQueryService.cs` is the narrow read-only use-case boundary. It delegates to the shared `TelemetryProjectionService`; it never opens SQLite or writes evidence.
- `AdvancedSearchParser.cs` owns the established Boolean, grouping, phrase, and allowlisted field syntax.
- `SearchViewModel.cs` owns query construction, parser diagnostics, cancellation/supersession, stale-result rejection, result state, and navigation commands.
- `ExplorerSearchView.xaml` owns the query controls, category toggles, result grid, status/progress presentation, Enter submission, and row double-click navigation.

Shared `TelemetryQueryModels`, `TelemetryProjectionService`, `SqliteReadQueryContext`, `SqliteStagingQueryService`, `SqliteAnalysisIndexMaintenanceService`, `ViewerNavigationCoordinator`, capture workspace/session state, feature catalog/publication, and shell composition remain outside this directory. Sigma retains its own view model, parser/evaluator services, and Explorer view even though it intentionally shares the stable Search/Sigma feature ID.

## Layout And Namespace Rules

Search-owned files live together under `ProcInsider/Features/Search/`. `SearchFeatureModule`, `SearchQueryService`, and the focused view use `ProcInsider.Features.Search`. `SearchViewModel` and `AdvancedSearchParser` retain their existing public namespaces to avoid gratuitous compatibility churn during this ownership move.

Do not add concrete references to another optional feature slice. Reusable telemetry query/result contracts stay in the shared model boundary, read-only execution stays behind `ISearchQueryService`, and navigation stays behind the composition callback supplied by `MainViewModel`. Keep the existing feature ID, Explorer tab key/order, query semantics, result identity, publication state, and analysis-index behavior unchanged unless a separately scoped issue owns that product change.

## Lifecycle And Extension Points

`MainViewModel` remains the WPF composition root. It adds the Search definition to `ViewerFeatureRegistry`, supplies the existing shared projection/navigation/catalog dependencies, and projects snapshot lifecycle inputs and result counts. The registry validates Search metadata without running its factory, registers the module in `FeatureActivationRegistry`, and supplies the lazy Explorer descriptor to `FeatureTabSet`. Hidden Search remains unconstructed.

Workspace/index transitions call `SearchFeatureModule.ApplyAvailability` only when the module is already active. Preparing, ready, canceled, and failed transitions project the coordinator's stage and elapsed-time/allocation diagnostics into Search status. Unavailable, canceled, failed, detach, clear, and disposal transitions cancel current Search work and invalidate its generation, so completion from an older workspace cannot replace current results. Archived captures remain searchable through the shared read-only projection only after deterministic analysis-index/FTS readiness.

When extending Search:

1. Add Search presentation and parser/use-case behavior in this directory.
2. Consume evidence through `ISearchQueryService`; extend shared query contracts/services only when the behavior is genuinely reusable and never open SQLite from the feature.
3. Preserve `TelemetrySearchResult.ProcessEntityId` and exact `ProcessKey` navigation; never add PID-only correlation.
4. Keep substantial UI in `ExplorerSearchView.xaml` and code-behind limited to WPF event translation.
5. Change `SearchFeatureModule` only for Search registration, presentation construction, lifecycle, or count projection. Shared publication, tab fallback, workspace, analysis-index, and navigation policies keep their existing owners.

## Validation

Run the full Release solution build plus:

- `SearchFeatureSelfTest.dll` for parsing/query equivalence, lazy typed activation, cancellation, stale-result rejection, rebinding, navigation, and repeated cleanup;
- `FeatureCatalogSelfTest.dll` for shared Search/Sigma publication and stable Explorer registration;
- `FeatureScaffoldSelfTest.dll` for the reusable vertical-feature convention;
- `CaptureWorkspaceSelfTest.dll` for live/archived workspace and analysis-index behavior;
- `ArchitectureSelfTest.dll` for feature-module, SQLite, and optional-feature isolation;
- `tools/dev/Test-AiDocumentation.ps1` and `git diff --check` for routing integrity.

## Locality Measurement

Before this slice, four Search-owned production files were spread across `Services`, `ViewModels`, and `Views/Features/Search`; `MainViewModel` also owned the Search factory, cleanup subscription, Explorer descriptor, result-count observation, and analysis-state message mapping. A representative parser, presentation, cancellation, or registration change required three production roots plus shared composition context, and there was no focused Search self-test or entry guide.

After this slice, six Search-owned production files and this guide live under one feature root, with one focused self-test project. A representative Search behavior or UI change begins in one production directory and one test directory. `MainViewModel` changes only when the shared projection, navigation, workspace-input, or shell-count contract changes. Intentionally retained shared files are `TelemetryQueryModels`, `TelemetryProjectionService`, `SqliteReadQueryContext`, `SqliteStagingQueryService`, analysis-index maintenance, `ViewerNavigationCoordinator`, the typed catalog/tab foundation, and all Sigma-owned files.
