# DFIRoscope Live

Open-source Windows investigation and cybersecurity learning platform.

Observe, correlate and reconstruct Windows activity.

Formerly developed under the ProcInsider codename. Source directories and bounded compatibility identifiers retain that name where required; current viewer and agent commands use `DFIRoscope.Live` and `DFIRoscope.Agent`.

## Distribution

Source-built releases currently use the framework-dependent Windows x64 portable artifacts `DFIRoscope-Live-Portable-<version>-x64.zip` and `DFIRoscope-Live-<version>-SHA256.txt`. The archive starts with `DFIRoscope.Live.exe`, includes `DFIRoscope.Agent.exe`, and places the official waiting `dfiroscope.cmd` terminal launcher beside the primary viewer; bounded `ProcInsider.exe` and `ProcInsider.Agent.exe` aliases remain for existing automation.

The repository does not currently define or emit an installer. It does not register a service, shortcut, scheduled task, firewall rule, file association, or uninstall entry. See [`../docs/DFIROSCOPE_LIVE_RELEASE.md`](../docs/DFIROSCOPE_LIVE_RELEASE.md) for the exact build/package command, checksum verification, compatibility gate, and portable cleanup behavior.

## Command Line

Launching `DFIRoscope.Live.exe` with no arguments opens the WPF viewer. Any nonempty argument list enters the same executable's headless CLI. From a portable/build folder, `dfiroscope.cmd` is the canonical waiting terminal name and forwards to that adjacent primary viewer only. Current examples:

```powershell
.\dfiroscope.cmd --help
.\dfiroscope.cmd shell
.\DFIRoscope.Live.exe --help
.\DFIRoscope.Live.exe --version
.\DFIRoscope.Live.exe agent discover --output json
.\DFIRoscope.Live.exe agent status --session "C:\Cases\DFIRoscope-Session-20260807-120000" --output json
.\DFIRoscope.Live.exe agent capabilities --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json"
.\DFIRoscope.Live.exe agent capture configuration show --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json"
.\DFIRoscope.Live.exe agent capture configuration check --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --file "C:\Cases\capture.json"
.\DFIRoscope.Live.exe agent capture configuration save --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --file "C:\Cases\capture.json"
.\DFIRoscope.Live.exe agent capture start --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --wait
.\DFIRoscope.Live.exe agent capture source stop --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --source PowerShell
.\DFIRoscope.Live.exe agent job list --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --output json
.\DFIRoscope.Live.exe agent job wait --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --job-id "11111111-2222-3333-4444-555555555555"
.\DFIRoscope.Live.exe agent evidence enrich --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --all --modules --handles --wait
.\DFIRoscope.Live.exe agent process dump --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --process-key "4624_638902620000000000" --kind mini --yes --wait
.\DFIRoscope.Live.exe agent filesystem import --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --path "C:\Cases\Artifacts" --recurse --max-files 1000
.\DFIRoscope.Live.exe agent network start --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json"
.\DFIRoscope.Live.exe agent zeek run --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --pcap-path "C:\Cases\capture.pcapng" --wsl-distribution Ubuntu-24.04
.\DFIRoscope.Live.exe agent procmon import --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --input "C:\Cases\procmon.csv" --max-rows 200000
.\DFIRoscope.Live.exe agent sqlite benchmark start --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --wait
.\DFIRoscope.Live.exe agent start --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --live-buffer-memory-mb 1024
.\DFIRoscope.Live.exe agent reconnect --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json"
.\DFIRoscope.Live.exe agent stop --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json" --yes
.\DFIRoscope.Live.exe agent pairing status --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json"
.\DFIRoscope.Live.exe shell --session "C:\Cases\DFIRoscope-Session-20260807-120000\session.json"
```

Session-bound commands require an existing absolute unsealed live-session root or its canonical `session.json`. The interactive shell accepts the same product commands, plus bounded help/session/last-exit/clear/exit built-ins, through the same parser, dispatcher, handlers, and safety checks. It never acts as an OS shell. Explicit start/reconnect/stop and pairing status/rotate/revoke use the shared fail-closed lifecycle coordinator; typed capture configuration, configured capture/source actions, and job list/status/wait/cancel use the shared WPF/CLI capture-action service; enrichment, exact-process dumps, and bounded filesystem imports use the shared evidence-action service; network, Zeek, Process Monitor, and isolated benchmark commands use the shared tool-action service. The elevated agent revalidates typed scope, EULA, tool mode, paths, bounds, and authoritative stop/duplicate state, and it owns every durable write. Neither mode creates a default session, exposes raw IPC, deploys host monitoring, pauses/resumes jobs, or writes evidence directly. `ProcInsider.exe` remains a former-name flat-output alias with the same managed behavior; new automation should use `DFIRoscope.Live.exe`.

Use `dfiroscope.cmd` for reliable waiting and exact exit codes in interactive CMD; PowerShell and explicitly waiting process runners may also invoke `DFIRoscope.Live.exe` directly. See [`../docs/DFIROSCOPE_CLI.md`](../docs/DFIROSCOPE_CLI.md) for the exact one-shot/shell grammar, JSON v1/NDJSON contracts, exit codes, quoting, safety model, and exhaustive command disposition.

## Features

### Core Functionality

- **Real-time Process Monitoring**: Automatically refreshes process list every 10 seconds by default
- **Process History**: Preserves exited processes with end times for forensic analysis
- **Process Tree Display**: Shows parent-child relationships with visual indentation
- **Dual-Panel Interface**: Split view with process list on left, details on right

### Left Panel: Process Tree Table

#### Columns
- **Process Name** (with tree indentation)
- **PID** - Process ID
- **Parent PID** - Parent process ID
- **Parent Process Name**
- **Process Path** - Full path to executable
- **Command Line** - Full command-line arguments
- **User Name** - Account running the process
- **Session ID** - Windows session
- **Architecture** - x86 or x64 (where available)
- **Start Time** - When process started
- **End Time** - When process exited (if exited)
- **Status** - Running or Exited
- **Memory Usage** - Formatted (KB/MB/GB)
- **Company Name** - File metadata
- **File Description** - File metadata
- **SHA256 Hash** - Executable hash (cached for performance)

#### Features
- **Tree-Aware Sorting**: Click column headers to sort; process tree structure preserved for ProcessName
- **Per-Column Filtering**: Type in filter boxes below columns for case-insensitive filtering
- **UI Virtualization**: Handles large process lists efficiently
- **Exited Process Display**: Gray italics for exited processes
- **Process Identity**: Uses PID + StartTime (Windows reuses PIDs)

### Right Panel: Detail Tabs

#### Tab 1: Process Notes
- **Editable Text Editor**: Add notes for each process
- **Session Annotation Storage**: Notes are saved in the active investigation's `annotations.sqlite`
- **Auto-Load**: Opens notes when you select a process
- **Save/Reload Buttons**: Manual save and reload controls
- **Unsaved Indicator**: Visual indicator (*) for unsaved changes

#### Tab 2: Loaded Modules/DLLs
- **Module Table** with columns:
  - Module Name
  - Full Path
  - Base Address (hex)
  - Size (formatted)
  - File Version
  - Company Name
  - Description
  - SHA256 Hash
- **Sortable Columns**: Click headers to sort
- **Error Handling**: Friendly messages for access denied, exited processes, etc.
- **Refresh Button**: Manually reload modules

### Toolbar & Status Bar

- **Refresh from db**: Creates a fresh viewer snapshot from the live SQLite database
- **Snapshot Status**: Shows the active snapshot timestamp and age
- **Clear Filters**: Reset all column filters
- **Process Statistics**: Total, Running, and Exited counts
- **Status Messages**: Displays current operation status

## Technical Architecture

### MVVM Pattern
- **MainViewModel**: Coordinates all services and child view models
- **ProcessRowViewModel**: Wraps ProcessInfo for UI binding
- **ModuleRowViewModel**: Wraps ModuleInfo for module list display
- **ProcessNotesViewModel**: Loads and saves stable process annotation targets
- **ModulesViewModel**: Manages module inspection results

### Services

The process collector/tracker, module/handle inspectors, PE analysis, filesystem/dump/network/Process Monitor/memory/Volatility/Zeek tools, active built-in adapter base/registry/implementation/factory families, and bounded legacy archive parser/snapshot/command/adapter family compile from the sibling `ProcInsider.Infrastructure.Windows` project under their unchanged namespaces. The legacy adapter remains unpublished and compatibility-only. The agent owns live adapter construction, scheduling, authorization, publication, and durable writes.

#### ProcessDataCollector
- Collects process information using `System.Diagnostics.Process`
- Uses WMI for command line and parent PID queries
- Caches file hashes and metadata to avoid repeated computation
- Handles access denied errors gracefully
- Extracts file version info and SHA256 hashes

#### ProcessTracker
- Maintains historical record of processes
- Detects process exits and marks with EndTime
- Resolves process tree relationships (parent names, tree depth)
- Preserves exited processes in memory for forensic analysis

#### ModuleInspector
- Enumerates loaded DLLs/modules for a process
- Retrieves file version information
- Computes SHA256 hashes (cached)
- Handles 32-bit/64-bit architecture mismatches
- Graceful error handling for protected/exited processes

#### AnnotationDatabaseService
- Owns analyst bookmarks and notes in the active session's `annotations.sqlite`
- Keys process notes by stable target identity instead of process name alone
- Keeps analyst annotations separate from live evidence and viewer snapshots
- Remains writable for archived investigations without modifying sealed evidence

#### ProcessFilterService
- Applies column-specific filters
- Preserves parent processes for context when filtering children
- Implements tree-aware sorting for ProcessName column

### Error Handling

All access denied and permission errors display user-friendly messages:
- `<access denied>` - Permission denied
- `<not available>` - Information cannot be retrieved
- `<unknown>` - Unexpected state
- `<exited>` - Parent process has exited
- Process exit detection: gracefully handles process disappearing during inspection

### Performance Optimizations

- **UI Virtualization**: DataGrid rows only rendered when visible
- **Async Operations**: Process collection runs on background thread
- **Caching**: File hashes and metadata cached in memory
- **WMI Cache**: Command line/parent PID cached for 10 seconds
- **Efficient Updates**: Only changed properties trigger UI refresh
- **Cancellation Tokens**: Long operations can be cancelled

## Requirements

- **.NET 10** (net10.0-windows)
- **Windows 10/11**
- **Visual Studio 2022+**
- Administrator privileges (recommended for full process access)

## Dependencies

- `CommunityToolkit.Mvvm` v8.4.0 - MVVM framework
- `System.Management` v9.0.0 - WMI queries

## Manifest

The application requests administrator privileges via `app.manifest` for:
- Better access to process information
- Ability to read protected process details
- Access to all user sessions

## Getting Started

1. **Build**: `dotnet build ProcInsider.slnx -c Release`
2. **Run viewer**: `dotnet run --project ProcInsider/ProcInsider.csproj` or launch `DFIRoscope.Live.exe` from the build output
3. **Select Process**: Click any row in the left table
4. **View Details**: Check tabs on right panel
5. **Edit Notes**: Click in notes editor and save
6. **Inspect Modules**: View loaded DLLs in modules tab
7. **Filter**: Type in filter boxes below process table headers
8. **Sort**: Click column headers (tree structure preserved for ProcessName)

## File Structure

```
ProcInsider/
├── Models/
│   ├── ProcessInfo.cs          - Process data model
│   └── ModuleInfo.cs           - Module data model
├── Services/
│   ├── AnnotationDatabaseService.cs - Session annotation storage
│   └── ProcessFilterService.cs - Filtering & sorting
├── ViewModels/
│   ├── ViewModelBase.cs
│   ├── MainViewModel.cs
│   ├── ProcessRowViewModel.cs
│   ├── ModuleRowViewModel.cs
│   ├── ProcessNotesViewModel.cs
│   └── ModulesViewModel.cs
├── Converters/
│   └── BoolToVisibilityConverter.cs - XAML converters
├── MainWindow.xaml             - Main UI layout
├── MainWindow.xaml.cs          - Code-behind
├── App.xaml                    - Application resources
├── App.xaml.cs                 - Application startup
└── app.manifest                - Administrator manifest

ProcInsider.Infrastructure.Windows/
└── Services/
    ├── ProcessDataCollector.cs - WMI/Process enumeration
    ├── ProcessTracker.cs       - History & tree management
    ├── ModuleInspector.cs      - DLL/module enumeration
    ├── HandleInspector.cs      - Native handle enumeration
    └── PeAnalysisService.cs    - PE metadata analysis
```

Runtime notes are stored only in the active session's `annotations.sqlite`; the viewer does not create an application-directory `ProcessNotes` fallback.

## Key Design Decisions

1. **PID + StartTime as Identity**: Windows reuses PIDs, so we use both PID and process start time for unique identification

2. **No Process Removal**: Exited processes remain visible, marked as "Exited", for forensic analysis

3. **Cached Hashing**: File hashes computed once and cached to avoid expensive re-computation

4. **WMI for Command Lines**: Process object doesn't reliably provide full command line, so WMI is used

5. **Tree Structure Preservation**: Special sorting logic for ProcessName to maintain parent-child relationships

6. **Graceful Degradation**: Every access failure results in user-friendly placeholder text, never crashes

7. **Async Background Work**: Heavy operations (WMI, hashing) run off UI thread to keep UI responsive

## Limitations & Future Enhancements

Current limitations:
- No network connection info
- No registry/file system hooking info
- No child process handle inspection
- Limited to local machine (no remote process inspection)

Potential enhancements:
- Export to CSV/JSON
- Process timeline visualization
- Hash comparison against VirusTotal
- Behavioral analysis graphs
- Persistence mechanism detection
- API call hooking display
- Memory dumps/forensic analysis
- Multi-machine monitoring

## License & Usage

Built for malware analysts and incident responders. Requires administrator privileges for full functionality.

## Notes for Analysts

- **Suspicious Processes**: Look for unusual parent PIDs, command lines with encoded data, paths in Temp directories
- **DLL Injection**: Check loaded modules for unexpected DLLs, unusual base addresses, or mismatched versions
- **Process Notes**: Use to document findings, IOCs, and analysis notes per process
- **History Preservation**: Exited processes retained for complete timeline analysis
- **Hash Lookups**: SHA256 hashes can be checked against threat intelligence feeds
