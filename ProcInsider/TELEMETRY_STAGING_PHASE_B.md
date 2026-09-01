# ProcInsider Telemetry Staging - Phase B Design

> **Historical design only.** This document records the retired viewer-owned staging migration and must not guide production changes. The current boundary is agent-owned acquisition and `AgentStagingWriter` persistence, with SQLite-only viewer projections and no `TelemetryStore` fallback. Start with `docs/ai/ARCHITECTURE.md`, `docs/ai/DATA_FLOW.md`, and the staged-telemetry routes in `docs/ai/FEATURE_INDEX.md`.

## Objective

Phase B moves ProcInsider from "collectors mirror into staging" to "the UI reads staged telemetry as explicit projections."

After Phase B implementation:

- collectors continue writing to `TelemetryStore`
- the process grid refreshes from `TelemetryStore`
- event tabs refresh from `TelemetryStore`
- module and handle tabs refresh from `TelemetryStore`
- counters are computed from staged data
- background collectors do not mutate visible grids by default
- the old per-source `ProcessEventStore` instances can be retired or kept only as temporary adapters

This is the step that makes ProcInsider feel like a recorder with a manual viewer instead of a live task manager.

## Current Phase A State

Phase A added:

- `TelemetryStore`
- process/event/module/handle staged records
- event mirroring from `ProcessEventStore` into `TelemetryStore`
- process upserts from `MainViewModel`
- manual module/handle snapshots into staging
- background module/handle capture services
- `Collect Modules` and `Collect Handles` menu toggles

Remaining issue:

The UI still mostly reads from existing view-model collections and per-source event stores. Staging is collecting data, but it is not yet the main UI projection source.

## Core Principle

View models should not own truth. They should own visible projections.

Recommended pattern:

```text
Collector -> TelemetryStore -> Projection Query -> ViewModel ObservableCollection
```

Avoid:

```text
Collector -> ViewModel ObservableCollection
```

## New Projection Service

Add:

```csharp
ProcInsider.Services.TelemetryProjectionService
```

This service should convert staged records into existing row/view-model friendly shapes.

Why add this service:

- keeps `MainViewModel` smaller
- avoids duplicating conversion code across tabs
- lets search reuse the same query semantics later
- allows old `ProcessInfo`, `ProcessEventInfo`, `ModuleInfo`, and `HandleInfo` row models to remain during migration

Recommended constructor:

```csharp
public sealed class TelemetryProjectionService
{
    public TelemetryProjectionService(TelemetryStore telemetryStore);
}
```

Recommended methods:

```csharp
public IReadOnlyList<ProcessInfo> GetProcessList(ProcessProjectionQuery query);
public ProcessProjectionCounts GetProcessCounts();
public ProcessArtifactCounts GetArtifactCounts(string processKey);
public ProcessSourceEventCounts GetEventCounts(string processKey);

public IReadOnlyList<ProcessEventInfo> GetEventsForProcess(EventProjectionQuery query);
public IReadOnlyList<ModuleInfo> GetModulesForProcess(ModuleProjectionQuery query);
public IReadOnlyList<HandleInfo> GetHandlesForProcess(HandleProjectionQuery query);
```

## Projection Query Models

Add query models under:

```text
Models/Telemetry/Projection
```

Recommended classes:

```csharp
public sealed class ProcessProjectionQuery
{
    public bool IncludeExited { get; set; } = true;
    public int MaxCount { get; set; } = 10000;
    public string SortColumn { get; set; } = "Tree";
    public bool SortAscending { get; set; } = true;
}
```

```csharp
public sealed class EventProjectionQuery
{
    public string ProcessKey { get; set; } = string.Empty;
    public string? Source { get; set; }
    public int MaxCount { get; set; } = 10000;
}
```

```csharp
public sealed class ModuleProjectionQuery
{
    public string ProcessKey { get; set; } = string.Empty;
    public bool IncludeUnloaded { get; set; } = true;
}
```

```csharp
public sealed class HandleProjectionQuery
{
    public string ProcessKey { get; set; } = string.Empty;
    public bool IncludeClosed { get; set; } = true;
}
```

Count models:

```csharp
public sealed class ProcessArtifactCounts
{
    public int ModuleCount { get; set; }
    public int HandleCount { get; set; }
}
```

```csharp
public sealed class ProcessSourceEventCounts
{
    public int Runtime { get; set; }
    public int Etw { get; set; }
    public int Security { get; set; }
    public int PowerShell { get; set; }
    public int WindowsOther { get; set; }
    public int Sysmon { get; set; }
}
```

```csharp
public sealed class ProcessProjectionCounts
{
    public int Total { get; set; }
    public int Running { get; set; }
    public int Exited { get; set; }
}
```

## Required TelemetryStore Additions

`TelemetryStore` already has useful primitives, but Phase B should add grouped/count queries so UI refresh does not perform many lock-heavy per-row calls.

Add:

```csharp
public IReadOnlyDictionary<string, int> CountEventsByProcess(string? source = null);
public IReadOnlyDictionary<string, int> CountActiveModulesByProcess();
public IReadOnlyDictionary<string, int> CountOpenHandlesByProcess();
public IReadOnlyDictionary<string, ProcessSourceEventCounts> CountEventsByProcessAndSource();
```

Optional but useful:

```csharp
public IReadOnlyList<TelemetryEventRecord> GetEventsForProcess(string processKey, string? source, int maxCount);
```

Rationale:

The process grid should be rebuilt with one grouped count pass, not one `Count...` call per row per source.

## Source Semantics

Use these source labels consistently:

- `Runtime`
- `ETW`
- `Security`
- `PowerShell`
- `WindowsOther`
- `Sysmon`

Event tabs map to sources:

- Runtime Events tab -> `Runtime`
- ETW Providers tab -> `ETW`
- Windows Audit Log tab -> `Security`
- PowerShell Logs tab -> `PowerShell`
- Windows Logs (Other) tab -> `WindowsOther`
- Sysmon tab -> `Sysmon`

Process list event columns should count retained staged events by source.

## Counter Semantics

Use these meanings:

- `Mods`: currently loaded or observed-not-unloaded modules.
- `Handles`: currently open handles.
- Event source columns: total retained staged events for that process and source.

Closed handles and unloaded modules should remain visible in their tabs, but should not count as active in the process-grid `Mods` / `Handles` columns.

Later search can expose total historical module/handle observations separately.

## Manual Refresh Behavior

### Refresh Now

Expected behavior:

1. Ask `ProcessTracker` to refresh so current process metrics enter staging.
2. Rebuild process grid from `TelemetryProjectionService.GetProcessList`.
3. Recompute grouped counts from staging.
4. Preserve selected process by `ProcessKey`, then PID/name fallback.
5. Refresh selected detail tabs from staging.

Do not directly rely on `ProcessTracker.GetAllProcesses` for final process grid contents.

### Process Selection

Expected behavior:

1. Load process properties from staged process projection.
2. Load modules from staged module observations.
3. Load handles from staged handle observations.
4. Load each event tab from staged event records for its source.

No event-log backfill should run automatically if the source collection toggle is off.

### Tab Refresh

Expected behavior:

- Event tab refresh queries staged events for selected process and source.
- Module tab refresh optionally runs manual module snapshot enrichment if process is running, then queries staged modules.
- Handle tab refresh optionally runs manual handle snapshot enrichment if process is running, then queries staged handles.

### Collector Toggle Change

Expected behavior:

- enabling starts ProcInsider ingestion
- disabling stops ProcInsider ingestion
- staged data remains visible
- next UI refresh reflects whatever is already staged

### Auto Refresh

Recommended Phase B behavior:

- auto-refresh disabled by default or left as currently configured, but it should call the same projection refresh path as `Refresh Now`
- no collector should mutate visible grids directly
- event live UI append should be disabled by default

The user-facing mental model should be:

```text
Collectors keep recording. Refresh redraws what you ask to see.
```

## View Model Migration

### MainViewModel

Replace process-grid data source logic.

Current:

```text
ProcessTracker -> UpdateProcessList(List<ProcessInfo>)
```

Target:

```text
ProcessTracker refresh/upsert -> TelemetryStore
TelemetryProjectionService -> ProcessRowViewModel rows
```

Implementation tasks:

- add `_telemetryProjectionService`
- add `RefreshProcessProjection()`
- make `RefreshProcessesCoreAsync` call tracker refresh, then projection refresh
- stop `OnProcessesUpdated` from rebuilding the grid when auto refresh is off
- eventually remove event-count live deltas from `EventsAdded`

Short-term compromise:

`OnProcessesUpdated` may keep staging process updates, but should not mutate `Processes` unless live UI mode is explicitly enabled.

### EventsViewModel

Add an alternate constructor that reads from projections instead of `ProcessEventStore`.

Recommended shape:

```csharp
public EventsViewModel(
    TelemetryProjectionService projectionService,
    InspectorPaneViewModel inspectorPaneViewModel,
    string? source,
    Action<(string ProcessKey, int ProcessId, string ProcessName)>? beforeRefresh = null)
```

Target behavior:

- `LoadEventsForProcess` stores selected process metadata, runs optional backfill, then queries projection service
- `RefreshEvents` queries projection service
- remove dependence on `ProcessEventStore.EventsAdded` for default mode
- keep current constructor temporarily for compatibility if needed

### ModulesViewModel

Target behavior:

- `LoadModulesForProcess` queries staged modules first
- if user clicks refresh and process is running, run manual snapshot enrichment, then query staged modules
- no automatic live append from module capture service

The current staged path already exists. Phase B should make it the only normal read path.

### HandlesViewModel

Target behavior:

- `LoadHandlesForProcess` queries staged handles first
- if user clicks refresh and process is running, run manual snapshot enrichment, then query staged handles
- preserve closed handles by default

The current staged path already exists. Phase B should make it the only normal read path.

## Retirement Plan For Old Event Stores

Do this in stages.

Stage 1:

- keep existing `ProcessEventStore` instances
- continue mirroring to `TelemetryStore`
- UI reads from `TelemetryProjectionService`

Stage 2:

- remove `EventsViewModel` subscriptions to `ProcessEventStore.EventsAdded`
- keep stores only as collector compatibility outputs

Stage 3:

- change collectors to write directly to `TelemetryStore`
- remove or shrink `ProcessEventStore`

Do not jump straight to Stage 3 unless the medium model has time for a wider refactor.

## Search Preparation

Phase B should not build full global search UI yet, but projection APIs should make it easy.

Add a future-facing query model:

```csharp
public sealed class TelemetrySearchQuery
{
    public string Text { get; set; } = string.Empty;
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
    public bool IncludeProcesses { get; set; } = true;
    public bool IncludeEvents { get; set; } = true;
    public bool IncludeModules { get; set; } = true;
    public bool IncludeHandles { get; set; } = true;
    public int MaxResults { get; set; } = 1000;
}
```

Add later, not necessarily in Phase B implementation:

```csharp
public IReadOnlyList<TelemetrySearchResult> Search(TelemetrySearchQuery query);
```

Search result shape:

- `Kind`: Process/Event/Module/Handle
- `TimestampUtc`
- `ProcessKey`
- `ProcessId`
- `ProcessName`
- `Title`
- `Subtitle`
- `MatchedText`
- `Source`

This should live on `TelemetryProjectionService`, not directly in view models.

## Memory And Retention Controls

Phase B implementation should expose stats, but not necessarily a full settings UI.

Required store stats:

- process count
- running process count
- exited process count
- event count
- module observation count
- handle observation count
- estimated memory
- total collected counts

Add one app action:

- `Clear Staged Telemetry`

Behavior:

- clears staged telemetry only
- does not clear Windows logs
- does not stop collectors
- should require confirmation

Do not reuse `Clear Monitoring Logs`; that destroys system telemetry and is a separate action.

## UI Placement

Recommended menu:

```text
Security Monitoring
  Collect ETW Events
  Collect Windows Audit Logs
  Collect PowerShell Logs
  Collect Windows Logs (Other)
  Collect Sysmon Logs
  Collect Modules
  Collect Handles
  Clear Staged Telemetry
  ...
```

Optional status line later:

```text
Staged: 2,148 processes | 84,232 events | 9,421 modules | 31,902 handles | ~186 MB
```

## Disk Persistence Design Placeholder

Do not implement SQLite during Phase B UI projection migration.

But the projection layer should assume staged records may later be backed by SQLite.

Keep these rules:

- avoid exposing mutable internal lists
- avoid requiring object references to remain stable
- query by keys and timestamps
- return detached snapshots
- keep source labels and sequence IDs stable

Likely future tables:

- `Processes`
- `Events`
- `Modules`
- `Handles`
- `StoreMetadata`

Likely indexes:

- `Processes(ProcessKey)`
- `Processes(ProcessId, StartTimeUtc, EndTimeUtc)`
- `Events(ProcessKey, Source, TimestampUtc)`
- `Events(Target)`
- `Modules(ProcessKey, FullPath)`
- `Modules(Sha256Hash)`
- `Handles(ProcessKey, ObjectType, ObjectName)`

## Medium Model Implementation Batches

### Batch B1: Projection Service

Files to add:

- `Services/TelemetryProjectionService.cs`
- `Models/Telemetry/Projection/ProcessProjectionQuery.cs`
- `Models/Telemetry/Projection/EventProjectionQuery.cs`
- `Models/Telemetry/Projection/ModuleProjectionQuery.cs`
- `Models/Telemetry/Projection/HandleProjectionQuery.cs`
- `Models/Telemetry/Projection/ProjectionCounts.cs`

Tasks:

- implement process list projection
- implement source-specific event projection
- implement module/handle projections
- implement grouped count methods in `TelemetryStore`
- build

### Batch B2: Process Grid Reads From Staging

Tasks:

- instantiate `TelemetryProjectionService`
- make `Refresh Now` rebuild process grid from projection
- compute row counters from grouped staged counts
- preserve selected process
- stop grid mutation from background process updates when manual mode is active
- build

### Batch B3: Event Tabs Read From Staging

Tasks:

- add projection-backed `EventsViewModel` constructor
- route each event tab to the right source label
- make tab refresh query staged events
- disable live event append by default
- keep backfill hooks source-toggle-aware
- build

### Batch B4: Modules And Handles Projection Cleanup

Tasks:

- make staged module/handle read path primary
- keep manual snapshot refresh as enrichment
- include unloaded/closed observations in tabs
- make counts use active-only staged observations
- build

### Batch B5: Staging Stats And Clear Action

Tasks:

- expose `TelemetryStoreStats` in `MainViewModel`
- add `Clear Staged Telemetry` menu action
- require confirmation
- refresh UI after clear
- build

## High-Risk Points

1. Stale counters

Counters should refresh on request from grouped staged data. Avoid live deltas in manual mode.

2. Duplicate event reads

If old event stores still mirror to staging, event tabs must not read both old store and staging at the same time.

3. Selection preservation

Always preserve by `ProcessKey` first, then PID/name fallback.

4. Source labels

A typo in source labels will make counters or tabs appear empty. Centralize source labels as constants if possible.

5. Manual refresh semantics

Collectors should keep recording even when UI is not refreshing. UI refresh should never pause collectors.

## Definition Of Done

- process grid can rebuild entirely from `TelemetryStore`
- all event tabs can rebuild from `TelemetryStore`
- module and handle tabs read staged observations by default
- process counters come from staged grouped counts
- no visible grid is mutated by collectors when manual mode is active
- source toggles still stop ProcInsider ingestion only
- `Clear Staged Telemetry` exists and does not clear Windows logs
- Release build passes

