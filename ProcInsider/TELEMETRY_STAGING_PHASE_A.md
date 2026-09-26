# ProcInsider Telemetry Staging - Phase A Design

> **Historical design only.** This document records the retired viewer-owned staging design and must not guide production changes. The current boundary is agent-owned acquisition and `AgentStagingWriter` persistence, with SQLite-only viewer projections and no `TelemetryStore` fallback. Start with `docs/ai/ARCHITECTURE.md`, `docs/ai/DATA_FLOW.md`, and the staged-telemetry routes in `docs/ai/FEATURE_INDEX.md`.

## Objective

Move ProcInsider from a live task-manager style UI toward a process telemetry recorder with an on-demand viewer.

Collectors should run independently in the background and write to a central in-memory staging store. The UI should refresh from that staging store only when requested, so process selection, tab contents, and historical telemetry do not disappear during refresh.

Phase A is the architecture and implementation handoff for:

- central memory staging
- process/event migration
- ETW/Sysmon module capture
- snapshot module enrichment
- handle history capture
- manual-first UI refresh

Disk persistence and global search are intentionally deferred, but the staging model should make both straightforward later.

## Current Code Shape

The current app already has useful pieces, but they are split by UI surface:

- `ProcessTracker` owns process history and PID/start-time identity.
- `ProcessEventStore` owns bounded event buffers, one store per event source.
- `EventCollectorService` routes Security, PowerShell, Windows Logs, Sysmon, DNS, and runtime events into source-specific stores.
- `ConfigurableEtwService` routes real ETW provider events into its own store and already observes ImageLoad events.
- `ModulesViewModel` and `HandlesViewModel` still mostly use selected-process snapshots.
- `ProcessInfo.CachedModules` and `ProcessInfo.CachedHandles` preserve some data, but they are snapshot caches rather than lifecycle history.

Phase A should keep these pieces working while introducing a central store that can gradually replace the view-specific caches.

## Core Principle

The UI must not be the data model.

Collectors write to `TelemetryStore`. View models query `TelemetryStore` when the user selects a process, refreshes a tab, changes filters, or runs a search.

Live UI updates may remain as an optional mode later, but the default model should be:

1. Collect continuously.
2. Stage and index telemetry.
3. Refresh UI projections on request.

## New Core Service

Add a central service:

```csharp
ProcInsider.Services.TelemetryStore
```

Initial implementation should be memory-only and thread-safe.

Responsibilities:

- own retained process records
- own retained event records
- own retained module observations
- own retained handle observations
- correlate incoming telemetry to process keys
- expose read-only snapshots for UI refresh
- enforce retention and memory limits
- provide stable sequence IDs for ordered display

Do not add disk persistence in Phase A.

## Store Interfaces

Recommended public methods:

```csharp
public sealed class TelemetryStore
{
    public ProcessRecord UpsertProcess(ProcessInfo process, DateTime observedUtc, string source);
    public ProcessRecord? MarkProcessExited(int processId, DateTime exitUtc, string source);
    public ProcessRecord? ResolveProcess(ProcessCorrelationHint hint);

    public TelemetryEventRecord AddEvent(ProcessEventInfo processEvent, string source);
    public ModuleObservationRecord AddModuleObservation(ModuleObservationInput input);
    public IReadOnlyList<ModuleObservationRecord> AddModuleSnapshot(ProcessInfo process, IReadOnlyList<ModuleInfo> modules, DateTime observedUtc, string source);
    public IReadOnlyList<HandleObservationRecord> AddHandleSnapshot(ProcessInfo process, IReadOnlyList<HandleInfo> handles, DateTime observedUtc, string source);

    public IReadOnlyList<ProcessRecord> GetProcesses(TelemetryQueryOptions options);
    public IReadOnlyList<TelemetryEventRecord> GetEventsForProcess(string processKey, int maxCount);
    public IReadOnlyList<ModuleObservationRecord> GetModulesForProcess(string processKey, bool includeUnloaded);
    public IReadOnlyList<HandleObservationRecord> GetHandlesForProcess(string processKey, bool includeClosed);

    public TelemetryStoreStats GetStats();
    public void Prune(DateTime nowUtc);
    public void Clear();
}
```

Keep the first implementation deliberately boring: one lock around internal dictionaries/lists is acceptable. Optimize after the behavior is correct.

## Core Records

### ProcessRecord

`ProcessRecord` should be the staged version of `ProcessInfo`.

Fields:

- `ProcessKey`
- `ProcessId`
- `ProcessGuid`
- `StartTimeUtc`
- `EndTimeUtc`
- `Status`
- `ParentProcessId`
- `ParentProcessKey`
- `ProcessName`
- `ProcessPath`
- `CommandLine`
- `UserName`
- `SessionId`
- `Architecture`
- `CompanyName`
- `FileDescription`
- `Sha256Hash`
- `FirstObservedUtc`
- `LastObservedUtc`
- `LastSource`
- current metrics such as CPU/memory

Important invariant:

`ProcessKey` remains compatible with current `ProcessInfo.GetUniqueKey()` during migration.

### TelemetryEventRecord

This wraps or replaces `ProcessEventInfo`.

Fields:

- `SequenceId`
- `TimestampUtc`
- `Source`
- `ProcessKey`
- `ProcessId`
- `ProcessGuid`
- `ProcessName`
- `Category`
- `Action`
- `EventCode`
- `Target`
- `Summary`
- `Details`
- `RiskFlags`
- `IsInteresting`
- `RawProvider`
- `RawLogName`
- `RawRecordId`
- `CorrelationMethod`

Recommended `CorrelationMethod` values:

- `ProcessGuid`
- `PidAndTime`
- `PidLatest`
- `PathAndTime`
- `ExternalProcessCreated`
- `Unresolved`

Unresolved records may be retained globally later, but Phase A can skip adding UI-visible unresolved records.

### ModuleObservationRecord

Modules must become lifecycle observations, not a replace-only list.

Fields:

- `SequenceId`
- `ProcessKey`
- `ProcessId`
- `ProcessGuid`
- `ModuleKey`
- `ModuleName`
- `FullPath`
- `BaseAddress`
- `ModuleMemorySize`
- `FileVersion`
- `CompanyName`
- `Description`
- `Sha256Hash`
- `FirstSeenUtc`
- `LastSeenUtc`
- `UnloadedUtc`
- `State`
- `Sources`
- `LastSource`

Recommended state enum:

```csharp
public enum ModuleObservationState
{
    Loaded,
    Unloaded,
    Observed
}
```

`ModuleKey` should initially be:

```text
ProcessKey + "|" + NormalizedFullPath + "|" + NormalizedBaseAddress
```

If base address is missing, use:

```text
ProcessKey + "|" + NormalizedFullPath
```

Do not require hashes for identity; hashes are enrichment.

### HandleObservationRecord

Handles are snapshot/diff based.

Fields:

- `SequenceId`
- `ProcessKey`
- `ProcessId`
- `HandleKey`
- `HandleValue`
- `HandleValueNumeric`
- `ObjectType`
- `ObjectName`
- `GrantedAccess`
- `GrantedAccessValue`
- `HandleAttributes`
- `HandleAttributesValue`
- `ObjectAddress`
- `FirstSeenUtc`
- `LastSeenUtc`
- `ClosedUtc`
- `State`
- `LastSource`

Recommended state enum:

```csharp
public enum HandleObservationState
{
    Open,
    Closed,
    Observed
}
```

`HandleKey` should initially be:

```text
ProcessKey + "|" + HandleValueNumeric + "|" + ObjectType + "|" + ObjectAddress
```

If `ObjectAddress` is unavailable, use object type and object name as fallback.

## Correlation Rules

Correlation order should be consistent across collectors:

1. Sysmon `ProcessGuid`.
2. Exact `ProcessKey`, if already known.
3. PID + event timestamp within process lifetime.
4. PID + compatible process name/path.
5. Path + timestamp fallback.
6. Create external process record from strong source, such as Sysmon process create.
7. Drop or retain as unresolved depending on source policy.

`ProcessTracker.GetBestProcessMatch` already contains useful logic. Phase A should move equivalent logic into `TelemetryStore.ResolveProcess` or wrap the existing tracker during migration.

## Process Migration Plan

Do this incrementally.

Step 1:

- Add `TelemetryStore`.
- Inject it into `MainViewModel`.
- On every process refresh, call `TelemetryStore.UpsertProcess`.
- On every WMI start/stop event, call `TelemetryStore.UpsertProcess` or `MarkProcessExited`.
- Keep `ProcessTracker` as the short-term owner of live process detection.

Step 2:

- Make process grid refresh read from staged process records.
- Keep `ProcessRowViewModel` wrapping `ProcessInfo` initially, or add a light conversion from `ProcessRecord` to `ProcessInfo`.
- Do not delete current process tracker history yet.

Step 3:

- Move counters to query staged data.
- Stop live grid mutation by default.

## Event Migration Plan

The current `ProcessEventStore` can be retained as a compatibility adapter briefly, but the target is:

- all collectors call `TelemetryStore.AddEvent`
- event tabs query `TelemetryStore.GetEventsForProcess`
- source-specific counts are computed from staged events by source/category

Recommended source labels:

- `Runtime`
- `ETW`
- `Security`
- `PowerShell`
- `WindowsOther`
- `Sysmon`

Medium-model implementation can first keep the existing event stores and mirror writes into `TelemetryStore`. Once UI reads are moved, the old stores can be removed or turned into a view adapter.

## Module Capture Design

Use a hybrid model.

### Event-driven capture

Primary sources:

- Sysmon Event ID `7` ImageLoad
- Kernel ImageLoad ETW

On each image load:

1. Resolve process by ProcessGuid or PID/time.
2. Build `ModuleObservationInput`.
3. Call `TelemetryStore.AddModuleObservation`.
4. Also add or link a `TelemetryEventRecord` so the event tab still shows the image load.

This is the best path for short-lived process modules.

### Snapshot enrichment

Keep `ModuleInspector.GetModulesAsync`, but make it enrichment.

Use snapshots when:

- selected process module tab is manually refreshed
- background module capture is enabled
- process is still running

Diff behavior:

- module in new snapshot and not previously known: state `Loaded`
- module in old snapshot and missing now: state `Unloaded`
- module still present: update `LastSeenUtc`

If a module was observed by ETW/Sysmon but later enriched by snapshot, merge file version, company, description, size, and hash.

## Handle Capture Design

Handles are snapshot/diff only.

Add a background service:

```csharp
ProcInsider.Services.HandleCaptureService
```

Responsibilities:

- periodically enumerate handles for running staged processes when enabled
- use `HandleInspector.GetHandlesAsync`
- write snapshots into `TelemetryStore.AddHandleSnapshot`
- avoid concurrent handle scans for the same process
- throttle work to avoid UI and CPU pressure

Default behavior:

- disabled by default or enabled with conservative interval
- interval: 30 seconds initially
- max concurrent scans: 1 or 2
- skip protected/access-denied processes quietly

Diff behavior:

- handle in new snapshot and not previously known: state `Open`
- handle in old snapshot and missing now: state `Closed`
- handle still present: update `LastSeenUtc`

Short-lived process limitation:

Handle snapshots can still miss very short-lived processes. That is acceptable. Sysmon/ETW are strong for modules, but Windows does not provide an equally complete global handle lifecycle feed.

## Module Capture Service

Add a matching service:

```csharp
ProcInsider.Services.ModuleCaptureService
```

Responsibilities:

- optional background snapshot enrichment for running staged processes
- route manual module refresh snapshots into staging
- do not duplicate event-driven module observations
- throttle module scans

Default interval:

- 30 seconds if enabled

## Menu Toggles

Keep these ingestion toggles:

- `Collect ETW Events`
- `Collect Windows Audit Logs`
- `Collect PowerShell Logs`
- `Collect Windows Logs (Other)`
- `Collect Sysmon Logs`

Add these toggles:

- `Collect Modules`
- `Collect Handles`

Important behavior:

- toggles only affect ProcInsider collection
- toggles do not change OS logging
- existing staged data remains visible until cleared or pruned

## Manual-First UI Refresh

The UI should become a projection over staging.

Default behavior:

- process grid refreshes only on `Refresh Now`
- selected process tabs refresh when selected or when tab refresh button is clicked
- background collectors do not mutate visible grids by default
- optional live UI mode can remain as a later feature

Benefits:

- no selection loss
- no jumping process list
- no disappearing short-lived data
- easier search and disk persistence later

## Retention And Memory

Initial defaults:

- process history: 1 hour, max 10,000 exited processes
- events: 1 hour, existing 512 MB cap
- modules: 1 hour, cap by observation count
- handles: 1 hour, cap by observation count

Suggested first caps:

- modules: 500,000 observations
- handles: 1,000,000 observations

Eviction rule:

- remove oldest observations first
- when removing a process, remove attached events/modules/handles
- preserve running processes regardless of age

## Search Preparation

Do not build search in Phase A, but index-friendly fields should be normalized now:

- process name
- process path
- command line
- user
- module name/path/hash/company
- handle type/name
- event target/details
- DNS names
- registry keys
- file paths

Keep normalized lowercase fields or provide helper methods later. Do not build a complex inverted index in Phase A.

## Medium Model Implementation Batches

### Batch A1: Store Foundation

Files to add:

- `Models/Telemetry/ProcessRecord.cs`
- `Models/Telemetry/TelemetryEventRecord.cs`
- `Models/Telemetry/ModuleObservationRecord.cs`
- `Models/Telemetry/HandleObservationRecord.cs`
- `Models/Telemetry/ProcessCorrelationHint.cs`
- `Models/Telemetry/TelemetryStoreStats.cs`
- `Services/TelemetryStore.cs`

Tasks:

- implement memory-only store
- implement process upsert
- implement event add/query
- implement module observation add/query
- implement handle snapshot diff/query
- add simple retention pruning

### Batch A2: Process And Event Mirroring

Tasks:

- inject `TelemetryStore` into `MainViewModel`
- mirror `ProcessTracker` process changes into store
- mirror existing event store writes into store
- keep existing UI behavior
- build and verify no regressions

### Batch A3: UI Reads From Staging

Tasks:

- process grid reads from `TelemetryStore.GetProcesses`
- event tabs read from `TelemetryStore.GetEventsForProcess`
- manual refresh rebuilds visible rows from staging
- keep source toggles
- keep old stores only if needed as adapters

### Batch A4: Module Observations

Tasks:

- route Sysmon Event ID `7` into `TelemetryStore.AddModuleObservation`
- route Kernel ImageLoad ETW into `TelemetryStore.AddModuleObservation`
- make Loaded Modules tab read staged modules
- manual module refresh writes snapshot into staging
- add `Collect Modules` menu toggle

### Batch A5: Handle Observations

Tasks:

- add `HandleCaptureService`
- add `Collect Handles` menu toggle
- background scan running staged processes
- write snapshot diffs into `TelemetryStore`
- make Handles tab read staged handles
- preserve closed handles for exited processes

## High-Risk Points

1. Process identity drift

PID reuse is the main danger. Always prefer PID + start time, Sysmon ProcessGuid, and event timestamp.

2. Duplicate events

Keep source + log record ID + event timestamp + process key as a dedup key where available.

3. Handle capture cost

Global handle scans can be expensive. Start with a conservative interval and one worker.

4. Module duplication

ETW/Sysmon may report the same module multiple times. Merge by normalized full path and base address.

5. UI accidental live mutation

The UI should query snapshots. Do not let collectors directly mutate visible collections.

## Definition Of Done For Phase A Implementation

- process list can be refreshed from staged process records
- event tabs can be refreshed from staged events
- ETW/Sysmon ImageLoad creates module observations
- exited processes retain staged modules
- handle tab can show closed/removed handles from staged snapshots
- `Collect Modules` and `Collect Handles` toggles exist
- source toggles stop ProcInsider ingestion without affecting system logging
- Release build passes

